/**
 * @file        codegen/phase_discover.cpp
 * @brief       Discover phase: iterative function block discovery
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include "codegen_flags.h"
#include "decoded_binary.h"
#include <rex/codegen/function_scanner.h>
#include <rex/codegen/jump_table_recovery.h>

#include <algorithm>
#include <array>
#include <bitset>
#include <chrono>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <rex/codegen/phases.h>
#include "phase_helpers.h"

#include <rex/codegen/vtable_scanner.h>
#include <rex/logging.h>

#include "codegen_logging.h"
#include <rex/memory/utils.h>

#include <ppc.h>

using rex::codegen::ppc::Opcode;
using rex::memory::load_and_swap;

namespace rex::codegen {

namespace {

struct EntryReferenceSet {
  std::vector<uint32_t> directCallSites;
  std::vector<uint32_t> rejectedReferenceSites;
  std::vector<std::string> referenceRejections;
};

bool SupportsEntryRegisterDomain(FunctionAuthority authority) {
  return authority == FunctionAuthority::PDATA || authority == FunctionAuthority::CONFIG ||
         authority == FunctionAuthority::DISCOVERED;
}

bool IsDenseZeroBased(const std::vector<uint32_t>& values) {
  if (values.empty())
    return false;
  for (size_t index = 0; index < values.size(); ++index) {
    if (values[index] != index)
      return false;
  }
  return true;
}

class EntryRegisterDomainAnalyzer {
 public:
  EntryRegisterDomainAnalyzer(CodegenContext& ctx,
                              const std::unordered_set<uint32_t>& knownFunctions)
      : ctx_(ctx), knownFunctions_(knownFunctions) {
    BuildReferenceIndex();
  }

  JumpTableEntryRegisterDomainEvidence Analyze(uint32_t entryAddress, uint8_t registerIndex,
                                               const JumpTableRecoveryLimits& limits) {
    JumpTableEntryRegisterDomainEvidence output;
    output.entryAddress = entryAddress;
    output.registerIndex = registerIndex;
    const auto reject = [&](std::string reason) {
      if (output.rejection.empty())
        output.rejection = std::move(reason);
    };

    const auto* entry = ctx_.graph.getFunction(entryAddress);
    if (!entry || !SupportsEntryRegisterDomain(entry->authority())) {
      reject("entry_is_not_trusted_immutable_callable");
      return output;
    }
    if (entryAddress == ctx_.binary().entryPoint()) {
      reject("entry_is_image_entrypoint");
      return output;
    }

    const auto found = references_.find(entryAddress);
    if (found == references_.end()) {
      reject("entry_has_no_static_inbound_references");
      return output;
    }
    const auto& references = found->second;
    output.directCallSites = references.directCallSites;
    output.rejectedReferenceSites = references.rejectedReferenceSites;
    output.referenceRejections = references.referenceRejections;
    if (references.directCallSites.empty()) {
      reject(references.rejectedReferenceSites.empty()
                 ? "entry_has_no_direct_call_references"
                 : "entry_has_only_non_call_or_address_escape_references");
      return output;
    }
    if (!references.rejectedReferenceSites.empty()) {
      reject("entry_has_non_call_or_address_escape_reference");
      return output;
    }
    output.allReferencesDirectCalls = true;

    std::set<uint32_t> finiteValues;
    bool allCallsitesComplete = true;
    for (uint32_t callAddress : references.directCallSites) {
      const auto* caller = ctx_.graph.getFunctionContaining(callAddress);
      JumpTableEntryCallsiteDomainEvidence callsite;
      callsite.callAddress = callAddress;
      callsite.targetAddress = entryAddress;
      callsite.registerIndex = registerIndex;
      if (!caller || caller->authority() != FunctionAuthority::PDATA) {
        callsite.rejections.push_back("caller_is_not_trusted_pdata");
        output.callsites.push_back(std::move(callsite));
        allCallsitesComplete = false;
        continue;
      }
      callsite.callerAddress = caller->base();
      const auto* blocks = CallerBlocks(*caller);
      if (!blocks) {
        callsite.rejections.push_back("caller_preliminary_cfg_unavailable");
        output.callsites.push_back(std::move(callsite));
        allCallsitesComplete = false;
        continue;
      }
      callsite = AnalyzeDirectCallArgumentDomain(ctx_.decoded(), *blocks, caller->base(),
                                                 callAddress, entryAddress, registerIndex, limits);
      if (!callsite.complete) {
        allCallsitesComplete = false;
      } else {
        finiteValues.insert(callsite.finiteValues.begin(), callsite.finiteValues.end());
      }
      output.callsites.push_back(std::move(callsite));
    }

    output.finiteValues.assign(finiteValues.begin(), finiteValues.end());
    if (!allCallsitesComplete) {
      reject("one_or_more_callsite_domains_incomplete");
      return output;
    }
    if (output.finiteValues.size() > limits.maxEntries) {
      reject("entry_domain_exceeds_entry_limit");
      return output;
    }
    if (!IsDenseZeroBased(output.finiteValues)) {
      reject("entry_domain_not_dense_zero_based");
      return output;
    }
    output.finiteDenseDomain = true;
    return output;
  }

 private:
  void AddRejectedReference(uint32_t target, uint32_t site, std::string reason) {
    auto& references = references_[target];
    for (size_t index = 0; index < references.rejectedReferenceSites.size(); ++index) {
      if (references.rejectedReferenceSites[index] == site &&
          references.referenceRejections[index] == reason) {
        return;
      }
    }
    references.rejectedReferenceSites.push_back(site);
    references.referenceRejections.push_back(std::move(reason));
  }

  bool IsPdataMetadataSlot(uint32_t storage) const {
    const uint32_t start = ctx_.binary().exceptionDirectoryAddr();
    const uint32_t size = ctx_.binary().exceptionDirectorySize();
    return start != 0 && size >= 8 && storage >= start && storage < start + size &&
           ((storage - start) % 8) == 0;
  }

  void BuildReferenceIndex() {
    constexpr uint32_t kMaterializationWindow = 8;
    for (const auto& section : ctx_.binary().sections()) {
      if (!section.readable && !section.executable)
        continue;
      for (uint32_t offset = 0; offset + 4 <= section.size; offset += 4) {
        const uint32_t address = section.baseAddress + offset;
        if (section.readable) {
          const uint32_t target = load_and_swap<uint32_t>(section.data + offset);
          if (ctx_.binary().isExecutable(target) && !IsPdataMetadataSlot(address)) {
            AddRejectedReference(target, address, "aligned_static_code_pointer_reference");
          }
        }
        if (!section.executable)
          continue;
        const auto* instruction = ctx_.decoded().get(address);
        if (!instruction)
          continue;
        if (instruction->branch_target && ctx_.binary().isExecutable(*instruction->branch_target)) {
          auto& references = references_[*instruction->branch_target];
          if (instruction->opcode == Opcode::bl) {
            references.directCallSites.push_back(address);
          } else {
            AddRejectedReference(*instruction->branch_target, address, "non_call_branch_reference");
          }
        }
        if (instruction->opcode != Opcode::lis)
          continue;

        const uint32_t highRaw = static_cast<uint32_t>(instruction->code);
        const uint8_t highRegister = static_cast<uint8_t>((highRaw >> 21) & 0x1F);
        const uint32_t highValue = (highRaw & 0xFFFF) << 16;
        for (uint32_t distance = 1; distance <= kMaterializationWindow; ++distance) {
          const uint32_t lowAddress = address + distance * 4;
          if (lowAddress + 4 > section.end())
            break;
          const auto* low = ctx_.decoded().get(lowAddress);
          if (!low)
            break;
          const uint32_t raw = static_cast<uint32_t>(low->code);
          std::optional<uint32_t> value;
          if (low->opcode == Opcode::addi && ((raw >> 16) & 0x1F) == highRegister) {
            value = highValue + static_cast<int16_t>(raw & 0xFFFF);
          } else if (low->opcode == Opcode::ori && ((raw >> 21) & 0x1F) == highRegister) {
            value = highValue | (raw & 0xFFFF);
          }
          if (value && ctx_.binary().isExecutable(*value)) {
            AddRejectedReference(*value, address, "bounded_code_address_materialization");
          }
          const auto writes = low->get_register_writes();
          if (std::find(writes.begin(), writes.end(), highRegister) != writes.end())
            break;
        }
      }
    }

    for (auto& [unused, references] : references_) {
      std::sort(references.directCallSites.begin(), references.directCallSites.end());
      references.directCallSites.erase(
          std::unique(references.directCallSites.begin(), references.directCallSites.end()),
          references.directCallSites.end());
      std::vector<std::pair<uint32_t, std::string>> rejected;
      for (size_t index = 0; index < references.rejectedReferenceSites.size(); ++index) {
        rejected.emplace_back(references.rejectedReferenceSites[index],
                              references.referenceRejections[index]);
      }
      std::sort(rejected.begin(), rejected.end());
      references.rejectedReferenceSites.clear();
      references.referenceRejections.clear();
      for (auto& [site, reason] : rejected) {
        references.rejectedReferenceSites.push_back(site);
        references.referenceRejections.push_back(std::move(reason));
      }
    }
  }

  const std::vector<Block>* CallerBlocks(const FunctionNode& caller) {
    auto existing = callerBlocks_.find(caller.base());
    if (existing != callerBlocks_.end())
      return &existing->second;
    if (!caller.jumpTablePreliminaryBlocks().empty()) {
      return &callerBlocks_.emplace(caller.base(), caller.jumpTablePreliminaryBlocks())
                  .first->second;
    }
    const auto size = ctx_.scan.pdataSizes.find(caller.base());
    if (size == ctx_.scan.pdataSizes.end())
      return nullptr;
    const CodeRegion* region = nullptr;
    for (const auto& candidate : ctx_.scan.codeRegions) {
      if (candidate.contains(caller.base())) {
        region = &candidate;
        break;
      }
    }
    if (!region)
      return nullptr;
    auto preliminary = discoverPreliminaryBlocks(ctx_.decoded(), caller.base(), *region,
                                                 knownFunctions_, size->second);
    if (preliminary.blocks.empty())
      return nullptr;
    return &callerBlocks_.emplace(caller.base(), std::move(preliminary.blocks)).first->second;
  }

  CodegenContext& ctx_;
  std::unordered_set<uint32_t> knownFunctions_;
  std::unordered_map<uint32_t, EntryReferenceSet> references_;
  std::unordered_map<uint32_t, std::vector<Block>> callerBlocks_;
};

//=============================================================================
// Discover Phase: iterative function block discovery
//=============================================================================

void discoverFunction(CodegenContext& ctx, uint32_t funcAddr,
                      const std::unordered_set<uint32_t>& knownFunctions,
                      EntryRegisterDomainAnalyzer* entryDomainAnalyzer) {
  auto& graph = ctx.graph;
  auto& binary = ctx.binary();
  auto& decoded = ctx.decoded();

  auto* node = graph.getFunction(funcAddr);
  if (!node)
    return;

  // Skip if already discovered
  if (!node->canDiscover()) {
    REXCODEGEN_TRACE("Analyze: function 0x{:08X} already discovered, skipping", funcAddr);
    return;
  }

  // Imports don't need block discovery
  if (node->isImport()) {
    node->discoverAsImport();
    return;
  }

  REXCODEGEN_TRACE("Analyze: discovering function 0x{:08X} ({})", funcAddr, node->name());

  // Lookup pdataSize for exception handler boundary
  uint32_t pdataSize = 0;

  // For CONFIG functions: use only the explicitly declared size (if any)
  // If no size specified (size=0), let discovery find natural boundaries via region
  // Don't inherit PDATA sizes for CONFIG functions - they're user hints for entry points
  if (node->authority() == FunctionAuthority::CONFIG) {
    pdataSize = node->size();  // 0 if not specified, which is correct
    REXCODEGEN_TRACE("Analyze: 0x{:08X} is CONFIG, using declared size={}", funcAddr, pdataSize);
  } else {
    // For non-CONFIG functions, use PDATA size if available
    auto pdataIt = ctx.scan.pdataSizes.find(funcAddr);
    if (pdataIt != ctx.scan.pdataSizes.end()) {
      pdataSize = pdataIt->second;
      REXCODEGEN_TRACE("Analyze: 0x{:08X} using PDATA size={}", funcAddr, pdataSize);
    }
  }

  // Find the code region containing this function
  const CodeRegion* region = nullptr;
  for (const auto& r : ctx.scan.codeRegions) {
    if (r.contains(funcAddr)) {
      region = &r;
      break;
    }
  }
  if (!region) {
    REXCODEGEN_WARN("Analyze: function 0x{:08X} not in any code region", funcAddr);
    return;
  }

  // Pass pdataSize so forward branches within function extent are correctly identified
  auto result = discoverBlocks(decoded, funcAddr, *region, knownFunctions, pdataSize,
                               &ctx.Config().switchTables);

  if (entryDomainAnalyzer && SupportsEntryRegisterDomain(node->authority())) {
    std::set<uint8_t> candidateRegisters;
    for (const auto& site : result.indirectSites) {
      if (!site.dataflow || site.dataflow->tableBaseCandidates.size() != 1 ||
          site.dataflow->tableLoadInputRegisters.size() != 1) {
        continue;
      }
      if (std::find(site.failures.begin(), site.failures.end(), JumpTableFailure::MissingBound) !=
          site.failures.end()) {
        const uint8_t reg = site.dataflow->tableLoadInputRegisters.front();
        if (reg >= 3 && reg <= 10)
          candidateRegisters.insert(reg);
      }
    }
    if (!candidateRegisters.empty()) {
      JumpTableEntryRegisterDomainMap domainsByRegister;
      for (uint8_t reg : candidateRegisters) {
        domainsByRegister.emplace(
            reg, entryDomainAnalyzer->Analyze(funcAddr, reg, result.jumpTableLimits));
      }

      JumpTableEntryRegisterDomainsBySite domainsBySite;
      bool hasFiniteDomain = false;
      for (const auto& site : result.indirectSites) {
        if (!site.dataflow || site.dataflow->tableLoadInputRegisters.size() != 1 ||
            std::find(site.failures.begin(), site.failures.end(), JumpTableFailure::MissingBound) ==
                site.failures.end()) {
          continue;
        }
        const uint8_t reg = site.dataflow->tableLoadInputRegisters.front();
        const auto domain = domainsByRegister.find(reg);
        if (domain == domainsByRegister.end())
          continue;
        domainsBySite[site.site].emplace(reg, domain->second);
        hasFiniteDomain = hasFiniteDomain || domain->second.finiteDenseDomain;
      }

      if (hasFiniteDomain) {
        auto initialStats = result.jumpTableRecovery;
        result = discoverBlocks(decoded, funcAddr, *region, knownFunctions, pdataSize,
                                &ctx.Config().switchTables, &domainsBySite);
        // The second pass supplies the final census. Retain only work/timing
        // from the diagnostic first pass so counts describe final site state.
        result.jumpTableRecovery.elapsedMicroseconds += initialStats.elapsedMicroseconds;
        result.jumpTableRecovery.preliminaryCfgMicroseconds +=
            initialStats.preliminaryCfgMicroseconds;
        result.jumpTableRecovery.caseExpansionCfgMicroseconds +=
            initialStats.caseExpansionCfgMicroseconds;
        result.jumpTableRecovery.indirectSiteClassificationMicroseconds +=
            initialStats.indirectSiteClassificationMicroseconds;
        result.jumpTableRecovery.fixpointOverheadMicroseconds +=
            initialStats.fixpointOverheadMicroseconds;
        result.jumpTableRecovery.functionFixpointMicroseconds +=
            initialStats.functionFixpointMicroseconds;
        result.jumpTableRecovery.decodedInstructions += initialStats.decodedInstructions;
        result.jumpTableRecovery.analysisLimitHit =
            result.jumpTableRecovery.analysisLimitHit || initialStats.analysisLimitHit;
      } else {
        // Rejected domains are report evidence only. Attaching them to their
        // exact candidate sites avoids repeating CFG/recovery work that cannot
        // change acceptance, while retaining the full failure vector.
        for (auto& site : result.indirectSites) {
          const auto siteDomains = domainsBySite.find(site.site);
          if (siteDomains == domainsBySite.end() || !site.dataflow)
            continue;
          for (const auto& domain : siteDomains->second)
            site.dataflow->entryRegisterDomains.push_back(domain.second);
          FinalizeJumpTableSiteDisposition(site);
        }
      }
    }
  }

  if (result.blocks.empty()) {
    REXCODEGEN_WARN("Analyze: no blocks found for function 0x{:08X}", funcAddr);
    return;
  }

  graph.setJumpTableRecoveryForFunction(funcAddr, std::move(result.indirectSites),
                                        std::move(result.preliminaryBlocks));

  // snooper the function with the discovered blocks and instructions
  node->discover(std::move(result.blocks), std::move(result.instructions),
                 std::move(result.labels));
  auto& recovery = ctx.analysisState().jumpTableRecovery;
  ctx.analysisState().jumpTableLimits = result.jumpTableLimits;
  recovery.elapsedMicroseconds += result.jumpTableRecovery.elapsedMicroseconds;
  recovery.preliminaryCfgMicroseconds += result.jumpTableRecovery.preliminaryCfgMicroseconds;
  recovery.caseExpansionCfgMicroseconds += result.jumpTableRecovery.caseExpansionCfgMicroseconds;
  recovery.indirectSiteClassificationMicroseconds +=
      result.jumpTableRecovery.indirectSiteClassificationMicroseconds;
  recovery.fixpointOverheadMicroseconds += result.jumpTableRecovery.fixpointOverheadMicroseconds;
  recovery.functionFixpointMicroseconds += result.jumpTableRecovery.functionFixpointMicroseconds;
  recovery.decodedInstructions += result.jumpTableRecovery.decodedInstructions;
  recovery.fixpointIterations =
      std::max(recovery.fixpointIterations, result.jumpTableRecovery.fixpointIterations);
  recovery.indirectSites += result.jumpTableRecovery.indirectSites;
  recovery.recoveredTables += result.jumpTableRecovery.recoveredTables;
  recovery.manualTables += result.jumpTableRecovery.manualTables;
  recovery.unresolvedSites += result.jumpTableRecovery.unresolvedSites;
  recovery.analysisLimitHit =
      recovery.analysisLimitHit || result.jumpTableRecovery.analysisLimitHit;

  // Add jump tables (targets become labels in the function)
  for (const auto& jt : result.jumpTables) {
    graph.addJumpTableToFunction(funcAddr, jt);
  }

  // Register external call targets as new functions (bl only, not b)
  for (uint32_t target : result.externalCalls) {
    if (!graph.isEntryPoint(target) && !graph.isImport(target)) {
      if (binary.isInImportExportRange(target)) {
        continue;
      }
      graph.addFunction(target, 4, FunctionAuthority::DISCOVERED, true);
    }
  }

  // Add unresolved branches for later resolution
  for (const auto& branch : result.unresolvedBranches) {
    graph.addUnresolvedJumpToFunction(funcAddr, branch.site, branch.target, branch.isCall,
                                      branch.isConditional);
  }

  // Scan exception handler regions for branches not in discovered blocks
  if (pdataSize > 0) {
    std::unordered_set<uint32_t> discoveredAddrs;
    for (const auto& block : result.blocks) {
      for (uint32_t addr = block.base; addr < block.base + block.size; addr += 4) {
        discoveredAddrs.insert(addr);
      }
    }

    uint32_t pdataEnd = funcAddr + pdataSize;
    const uint8_t* funcData = binary.translate(funcAddr);
    if (funcData) {
      for (uint32_t offset = 0; offset < pdataSize; offset += 4) {
        uint32_t site = funcAddr + offset;

        // Skip if already discovered by normal control flow
        if (discoveredAddrs.count(site))
          continue;

        // Skip if marked invalid
        auto invalidIt = ctx.analysisState().invalidInstructions.find(site);
        if (invalidIt != ctx.analysisState().invalidInstructions.end()) {
          continue;
        }

        uint32_t insn = load_and_swap<uint32_t>(funcData + offset);
        uint32_t opcode = PPC_OP(insn);

        if (opcode != PPC_OP_B && opcode != PPC_OP_BC)
          continue;

        uint32_t target = 0;
        bool isCall = PPC_BL(insn);
        bool isAbsolute = PPC_BA(insn);

        if (opcode == PPC_OP_B) {
          int32_t branchOffset = PPC_BI(insn);
          target = isAbsolute ? static_cast<uint32_t>(branchOffset) : site + branchOffset;
        } else {
          int32_t branchOffset = PPC_BD(insn);
          target = isAbsolute ? static_cast<uint32_t>(branchOffset) : site + branchOffset;
        }

        // Skip internal jumps within pdata region
        if (!isCall && target >= funcAddr && target < pdataEnd) {
          continue;
        }

        graph.addUnresolvedJumpToFunction(funcAddr, site, target, isCall, false);

        // Register call targets as new functions
        if (isCall && !graph.isEntryPoint(target) && !graph.isImport(target)) {
          if (binary.isInImportExportRange(target)) {
            continue;
          }
          graph.addFunction(target, 4, FunctionAuthority::DISCOVERED, true);
        }
      }
    }
  }
}

size_t DiscoverPendingFunctions(CodegenContext& ctx,
                                const std::unordered_set<uint32_t>& knownFunctions,
                                EntryRegisterDomainAnalyzer* entryDomainAnalyzer);

void discoverAllFunctions(CodegenContext& ctx) {
  REXCODEGEN_TRACE("Analyze: starting iterative discovery...");

  auto& graph = ctx.graph;
  auto& binary = ctx.binary();
  const auto initialKnownFunctions = buildKnownFunctions(graph);
  EntryRegisterDomainAnalyzer entryDomainAnalyzer(ctx, initialKnownFunctions);

  // Iterative discovery
  size_t iteration = 0;
  size_t lastFunctionCount = 0;
  const size_t maxIterations = REXCVAR_GET(max_discovery_iterations);

  while (iteration < maxIterations) {
    iteration++;

    size_t currentFunctionCount = graph.functionCount();
    if (currentFunctionCount == lastFunctionCount && iteration > 1) {
      REXCODEGEN_DEBUG("Analyze: fixed point at iteration {} ({} functions)", iteration,
                       currentFunctionCount);
      break;
    }

    lastFunctionCount = currentFunctionCount;

    auto knownFunctions = buildKnownFunctions(graph);
    if (DiscoverPendingFunctions(ctx, knownFunctions, &entryDomainAnalyzer) == 0) {
      break;
    }
  }

  REXCODEGEN_TRACE("Analyze: {} functions after call graph expansion", graph.functionCount());

  // VTable scanning
  {
    VTableScanner vtScanner(binary);
    auto vtables = vtScanner.scan();

    size_t newFunctions = 0;

    for (const auto& vt : vtables) {
      for (size_t i = 0; i < vt.slots.size(); i++) {
        uint32_t funcAddr = vt.slots[i];

        if (graph.isEntryPoint(funcAddr))
          continue;
        if (binary.isInImportExportRange(funcAddr))
          continue;

        graph.addFunction(funcAddr, 4, FunctionAuthority::VTABLE, true);
        newFunctions++;
      }
    }

    REXCODEGEN_TRACE("Analyze: VTable scan found {} vtables, {} new functions", vtables.size(),
                     newFunctions);

    // Continue discovery for vtable functions
    if (newFunctions > 0) {
      size_t vtableIteration = 0;
      const size_t maxVtableIterations = REXCVAR_GET(max_vtable_iterations);

      while (vtableIteration < maxVtableIterations) {
        vtableIteration++;

        auto knownFunctions = buildKnownFunctions(graph);
        if (DiscoverPendingFunctions(ctx, knownFunctions, &entryDomainAnalyzer) == 0)
          break;

        if (graph.functionCount() == lastFunctionCount)
          break;
        lastFunctionCount = graph.functionCount();
      }
    }
  }

  REXCODEGEN_TRACE("Analyze: {} total functions after vtable scan", graph.functionCount());
}

//=============================================================================
// Function Pointer Scan: find lis/addi pairs loading code addresses
// TODO(tomc): THIS IS WIP AND PROB A BAD IDEA LOL LETS SEE
//=============================================================================
void functionPointerScan(CodegenContext& ctx) {
  if (!ctx.hasDecoded()) {
    REXCODEGEN_WARN("functionPointerScan: DecodedBinary not initialized, skipping");
    return;
  }

  auto& graph = ctx.graph;
  auto& decoded = ctx.decoded();
  const auto& codeRegions = decoded.codeRegions();

  if (codeRegions.empty()) {
    REXCODEGEN_WARN("functionPointerScan: no code regions, skipping");
    return;
  }

  // Build set of existing functions to avoid duplicates
  std::unordered_set<uint32_t> existingFunctions;
  for (const auto& [addr, node] : graph.functions()) {
    existingFunctions.insert(addr);
  }

  // Track lis values: register -> (high_value, lis_address)
  // We scan linearly and track the most recent lis for each register
  // PPC has exactly 32 GPRs, so a fixed-size array is more efficient than a map
  std::array<std::pair<uint32_t, uint32_t>, 32> lisValues{};
  std::bitset<32> lisValid;

  size_t foundCount = 0;

  for (const auto& region : codeRegions) {
    lisValid.reset();  // Reset tracking at region boundaries

    for (uint32_t addr = region.start; addr < region.end; addr += 4) {
      auto* insn = decoded.get(addr);
      if (!insn)
        continue;

      // Track lis rD, IMM
      if (isLis(*insn)) {
        uint8_t rd = static_cast<uint8_t>(insn->D.RT);
        uint32_t hi = static_cast<uint32_t>(static_cast<int16_t>(insn->D.d)) << 16;
        lisValues[rd] = {hi, addr};
        lisValid.set(rd);
        continue;
      }

      // Check for addi rD, rA, IMM where rA was set by lis
      if (insn->opcode == rex::codegen::ppc::Opcode::addi) {
        uint8_t ra = static_cast<uint8_t>(insn->D.RA);
        if (ra == 0)
          continue;  // li pseudo-op, not addi

        if (!lisValid.test(ra))
          continue;

        uint32_t hi = lisValues[ra].first;
        int16_t lo = static_cast<int16_t>(insn->D.d);
        uint32_t fullAddr = hi + lo;  // Sign-extended add

        // PPC instructions are 4-byte aligned
        if (fullAddr & 0x3)
          continue;

        // Check if this address is in a code region
        const CodeRegion* targetRegion = decoded.regionContaining(fullAddr);
        if (!targetRegion)
          continue;

        // Skip if already a known function
        if (existingFunctions.contains(fullAddr))
          continue;

        // Skip if it's an internal address (within same function's likely range)
        // Heuristic: if target is very close to current address, probably internal label
        int32_t distance = static_cast<int32_t>(fullAddr) - static_cast<int32_t>(addr);
        if (distance > -0x1000 && distance < 0x1000) {
          // Could be local label, skip for now
          continue;
        }

        // Register as function with DISCOVERED authority and hasXrefs=true
        graph.addFunction(fullAddr, 4, FunctionAuthority::DISCOVERED, true);
        existingFunctions.insert(fullAddr);
        foundCount++;

        REXCODEGEN_TRACE("functionPointerScan: found 0x{:08X} via lis/addi at 0x{:08X}", fullAddr,
                         addr);
      }

      // Also check ori rD, rA, IMM (alternative to addi for unsigned)
      if (insn->opcode == rex::codegen::ppc::Opcode::ori) {
        uint8_t ra = static_cast<uint8_t>(insn->D.RA);
        if (!lisValid.test(ra))
          continue;

        uint32_t hi = lisValues[ra].first;
        uint16_t lo = static_cast<uint16_t>(insn->D.d);
        uint32_t fullAddr = hi | lo;  // Unsigned OR

        // PPC instructions are 4-byte aligned
        if (fullAddr & 0x3)
          continue;

        const CodeRegion* targetRegion = decoded.regionContaining(fullAddr);
        if (!targetRegion)
          continue;

        if (existingFunctions.contains(fullAddr))
          continue;

        int32_t distance = static_cast<int32_t>(fullAddr) - static_cast<int32_t>(addr);
        if (distance > -0x1000 && distance < 0x1000)
          continue;

        graph.addFunction(fullAddr, 4, FunctionAuthority::DISCOVERED, true);
        existingFunctions.insert(fullAddr);
        foundCount++;

        REXCODEGEN_TRACE("functionPointerScan: found 0x{:08X} via lis/ori at 0x{:08X}", fullAddr,
                         addr);
      }

      // Clear lis tracking if register is overwritten by other instruction
      // (Simplified: we clear on any write to the register)
      // This is conservative - could miss some patterns but avoids false positives
    }
  }

  REXCODEGEN_TRACE("functionPointerScan: found {} new function pointer targets", foundCount);
}

size_t DiscoverPendingFunctions(CodegenContext& ctx,
                                const std::unordered_set<uint32_t>& knownFunctions,
                                EntryRegisterDomainAnalyzer* entryDomainAnalyzer) {
  std::vector<uint32_t> pending;
  for (const auto& [addr, node] : ctx.graph.functions()) {
    if (node->canDiscover())
      pending.push_back(addr);
  }
  for (uint32_t funcAddr : pending)
    discoverFunction(ctx, funcAddr, knownFunctions, entryDomainAnalyzer);
  return pending.size();
}

}  // anonymous namespace

/// Discover blocks for all pending functions (shared helper, declared in phase_helpers.h).
size_t discoverPendingFunctions(CodegenContext& ctx,
                                const std::unordered_set<uint32_t>& knownFunctions) {
  return DiscoverPendingFunctions(ctx, knownFunctions, nullptr);
}

namespace phases {

VoidResult Discover(CodegenContext& ctx, ProgressReporter* reporter) {
  (void)reporter;
  discoverAllFunctions(ctx);
  return Ok();
}

}  // namespace phases

}  // namespace rex::codegen
