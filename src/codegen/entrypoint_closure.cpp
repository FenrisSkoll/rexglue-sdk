/**
 * @file        codegen/entrypoint_closure.cpp
 * @brief       Report-only static code-pointer and entrypoint closure analysis
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <rex/codegen/entrypoint_closure.h>
#include <rex/codegen/codegen_context.h>

#include "decoded_binary.h"
#include "file_io.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <rex/codegen/vtable_scanner.h>
#include <rex/memory/utils.h>

namespace rex::codegen {

namespace {

using ppc::Instruction;
using ppc::Opcode;
using rex::memory::load_and_swap;

std::string Hex(uint32_t value) {
  return fmt::format("0x{:08X}", value);
}

bool IsExecutableAddress(const BinaryView& binary, uint32_t address) {
  return (address & 3) == 0 && binary.isExecutable(address) &&
         !binary.isInImportExportRange(address);
}

bool IsStrongAddressTakenEvidence(EntrypointEvidenceKind kind) {
  switch (kind) {
    case EntrypointEvidenceKind::RelocationBackedPointer:
    case EntrypointEvidenceKind::ReadonlyCodePointer:
    case EntrypointEvidenceKind::WritableCodePointer:
    case EntrypointEvidenceKind::PointerTableRun:
    case EntrypointEvidenceKind::RttiVtable:
    case EntrypointEvidenceKind::CallbackTable:
    case EntrypointEvidenceKind::CodeMaterializationXref:
      return true;
    default:
      return false;
  }
}

bool EvidenceLess(const EntrypointEvidence& a, const EntrypointEvidence& b) {
  if (a.targetAddress != b.targetAddress)
    return a.targetAddress < b.targetAddress;
  if (a.kind != b.kind)
    return std::string_view(EntrypointEvidenceKindName(a.kind)) <
           std::string_view(EntrypointEvidenceKindName(b.kind));
  if (a.storageAddress != b.storageAddress)
    return a.storageAddress < b.storageAddress;
  if (a.sourceAddress != b.sourceAddress)
    return a.sourceAddress < b.sourceAddress;
  if (a.sourceSection != b.sourceSection)
    return a.sourceSection < b.sourceSection;
  if (a.provenance != b.provenance)
    return a.provenance < b.provenance;
  return a.attributes < b.attributes;
}

void SortUniqueEvidence(std::vector<EntrypointEvidence>& evidence) {
  std::sort(evidence.begin(), evidence.end(), EvidenceLess);
  evidence.erase(std::unique(evidence.begin(), evidence.end(),
                             [](const EntrypointEvidence& a, const EntrypointEvidence& b) {
                               return !EvidenceLess(a, b) && !EvidenceLess(b, a);
                             }),
                 evidence.end());
}

const EntrypointFunctionSeed* FindExactSeed(std::span<const EntrypointFunctionSeed> seeds,
                                            uint32_t address) {
  auto it = std::lower_bound(
      seeds.begin(), seeds.end(), address,
      [](const EntrypointFunctionSeed& seed, uint32_t value) { return seed.range.start < value; });
  if (it != seeds.end() && it->range.start == address)
    return &*it;
  return nullptr;
}

const EntrypointFunctionSeed* FindContainingSeed(std::span<const EntrypointFunctionSeed> seeds,
                                                 uint32_t address) {
  auto it = std::upper_bound(
      seeds.begin(), seeds.end(), address,
      [](uint32_t value, const EntrypointFunctionSeed& seed) { return value < seed.range.start; });
  while (it != seeds.begin()) {
    --it;
    if (it->range.contains(address))
      return &*it;
    if (it->range.end <= address)
      break;
  }
  return nullptr;
}

bool IsBlockStart(const EntrypointFunctionSeed& seed, uint32_t address) {
  return std::any_of(
      seed.blocks.begin(), seed.blocks.end(),
      [address](const EntrypointAddressRange& block) { return block.start == address; });
}

bool SameOwnedBlockContains(const EntrypointFunctionSeed& seed, uint32_t a, uint32_t b) {
  return std::any_of(seed.blocks.begin(), seed.blocks.end(),
                     [a, b](const EntrypointAddressRange& block) {
                       return block.contains(a) && block.contains(b);
                     });
}

struct PointerRun {
  uint32_t start = 0;
  std::vector<uint32_t> targets;
  const SectionView* section = nullptr;
  bool rtti = false;
};

struct WorkingSet {
  std::map<uint32_t, EntrypointCandidate> candidates;
  std::vector<PointerRun> pointerRuns;
  std::unordered_map<uint32_t, uint32_t> pointerTargetByStorage;
  std::unordered_set<uint32_t> rttiStorage;
  std::unordered_map<uint32_t, std::vector<EntrypointDirectEdge>> directByTarget;
  uint32_t pointerStorageSites = 0;
};

bool IsSemanticPointerStorageSection(const SectionView& section) {
  static constexpr std::array<std::string_view, 5> kPeMetadataSections{".pdata", ".reloc", ".edata",
                                                                       ".idata", ".XBLD"};
  return std::find(kPeMetadataSections.begin(), kPeMetadataSections.end(), section.name) ==
         kPeMetadataSections.end();
}

EntrypointCandidate& CandidateAt(WorkingSet& work, uint32_t address) {
  auto [it, inserted] = work.candidates.try_emplace(address);
  if (inserted)
    it->second.address = address;
  return it->second;
}

bool AddEvidence(WorkingSet& work, EntrypointEvidence evidence) {
  auto& existing = CandidateAt(work, evidence.targetAddress).evidence;
  if (std::any_of(existing.begin(), existing.end(), [&](const auto& item) {
        return !EvidenceLess(item, evidence) && !EvidenceLess(evidence, item);
      })) {
    return false;
  }
  existing.push_back(std::move(evidence));
  return true;
}

std::vector<PointerRun> FindPointerRuns(const BinaryView& binary,
                                        const EntrypointClosureLimits& limits) {
  std::vector<PointerRun> runs;
  for (const auto& section : binary.sections()) {
    if (!section.readable || !section.data || section.size < 4 ||
        !IsSemanticPointerStorageSection(section))
      continue;

    PointerRun current;
    auto flush = [&]() {
      const size_t threshold = section.executable ? 3 : 2;
      if (current.targets.size() >= threshold) {
        current.section = &section;
        runs.push_back(current);
      }
      current = {};
    };

    for (uint32_t offset = 0; offset + 4 <= section.size; offset += 4) {
      const uint32_t storage = section.baseAddress + offset;
      const uint32_t value = load_and_swap<uint32_t>(section.data + offset);
      if (!IsExecutableAddress(binary, value)) {
        flush();
        continue;
      }

      if (current.targets.empty())
        current.start = storage;
      if (current.targets.size() >= limits.maxPointerRunEntries) {
        flush();
        current.start = storage;
      }
      current.targets.push_back(value);
    }
    flush();
  }
  std::sort(runs.begin(), runs.end(),
            [](const PointerRun& a, const PointerRun& b) { return a.start < b.start; });
  return runs;
}

void ScanRttiVtables(const BinaryView& binary, WorkingSet& work) {
  VTableScanner scanner(binary);
  for (const auto& vtable : scanner.scan()) {
    for (size_t index = 0; index < vtable.slots.size(); ++index) {
      const uint32_t storage = vtable.vtableAddress + static_cast<uint32_t>(index * 4);
      work.rttiStorage.insert(storage);
      AddEvidence(work, EntrypointEvidence{
                            .kind = EntrypointEvidenceKind::RttiVtable,
                            .targetAddress = vtable.slots[index],
                            .sourceAddress = storage,
                            .storageAddress = storage,
                            .sourceSection = ".rdata",
                            .provenance = "ReXGlue VTableScanner RTTI traversal",
                            .attributes = {{"class", vtable.className},
                                           {"complete_object_locator", Hex(vtable.colAddress)},
                                           {"slot", std::to_string(index)},
                                           {"vtable", Hex(vtable.vtableAddress)}},
                        });
    }
  }
}

void ScanStoragePointers(const BinaryView& binary, const EntrypointClosureInput& input,
                         WorkingSet& work) {
  work.pointerRuns = FindPointerRuns(binary, input.limits);
  std::unordered_map<uint32_t, const PointerRun*> runByStorage;
  for (auto& run : work.pointerRuns) {
    for (size_t index = 0; index < run.targets.size(); ++index) {
      if (work.rttiStorage.contains(run.start + static_cast<uint32_t>(index * 4))) {
        run.rtti = true;
        break;
      }
    }
    for (size_t index = 0; index < run.targets.size(); ++index) {
      runByStorage.emplace(run.start + static_cast<uint32_t>(index * 4), &run);
    }
  }

  for (const auto& section : binary.sections()) {
    if (!section.readable || !section.data || section.size < 4 ||
        !IsSemanticPointerStorageSection(section))
      continue;
    for (uint32_t offset = 0; offset + 4 <= section.size; offset += 4) {
      const uint32_t storage = section.baseAddress + offset;
      const uint32_t target = load_and_swap<uint32_t>(section.data + offset);
      if (!IsExecutableAddress(binary, target))
        continue;

      auto runIt = runByStorage.find(storage);
      const bool inRun = runIt != runByStorage.end();
      if (section.executable && !inRun)
        continue;

      work.pointerStorageSites++;
      work.pointerTargetByStorage.emplace(storage, target);
      const auto pointerKind = section.writable ? EntrypointEvidenceKind::WritableCodePointer
                                                : EntrypointEvidenceKind::ReadonlyCodePointer;
      std::map<std::string, std::string> pointerAttributes{
          {"executable", section.executable ? "true" : "false"},
          {"inline_executable_storage", section.executable ? "true" : "false"},
          {"readable", section.readable ? "true" : "false"},
          {"writable", section.writable ? "true" : "false"},
      };
      if (offset >= 4) {
        pointerAttributes.emplace("previous_value",
                                  Hex(load_and_swap<uint32_t>(section.data + offset - 4)));
      }
      if (offset + 8 <= section.size) {
        pointerAttributes.emplace("next_value",
                                  Hex(load_and_swap<uint32_t>(section.data + offset + 4)));
      }
      AddEvidence(work, EntrypointEvidence{
                            .kind = pointerKind,
                            .targetAddress = target,
                            .sourceAddress = storage,
                            .storageAddress = storage,
                            .sourceSection = std::string(section.name),
                            .provenance = "aligned big-endian 32-bit executable pointer",
                            .attributes = std::move(pointerAttributes),
                        });

      if (input.relocationStorageAddresses.contains(storage)) {
        AddEvidence(work, EntrypointEvidence{
                              .kind = EntrypointEvidenceKind::RelocationBackedPointer,
                              .targetAddress = target,
                              .sourceAddress = storage,
                              .storageAddress = storage,
                              .sourceSection = std::string(section.name),
                              .provenance = "PE base-relocation target backs pointer storage",
                          });
      }

      if (inRun) {
        const auto& run = *runIt->second;
        const size_t slot = (storage - run.start) / 4;
        AddEvidence(
            work,
            EntrypointEvidence{
                .kind = EntrypointEvidenceKind::PointerTableRun,
                .targetAddress = target,
                .sourceAddress = run.start,
                .storageAddress = storage,
                .sourceSection = std::string(section.name),
                .provenance = "contiguous executable-pointer run",
                .attributes =
                    {
                        {"entries", std::to_string(run.targets.size())},
                        {"run_end", Hex(run.start + static_cast<uint32_t>(run.targets.size() * 4))},
                        {"run_start", Hex(run.start)},
                        {"slot", std::to_string(slot)},
                    },
            });
      }
    }
  }
}

void ScanMaterializations(const BinaryView& binary, const DecodedBinary& decoded,
                          const EntrypointClosureInput& input, WorkingSet& work) {
  for (const auto& section : binary.sections()) {
    if (!section.executable)
      continue;
    for (uint32_t highAddress = section.baseAddress; highAddress + 4 <= section.end();
         highAddress += 4) {
      const auto* high = decoded.get(highAddress);
      if (!high || high->opcode != Opcode::lis)
        continue;

      const uint32_t highRaw = static_cast<uint32_t>(high->code);
      const uint8_t highRegister = static_cast<uint8_t>((highRaw >> 21) & 0x1F);
      const uint32_t highValue =
          static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(highRaw & 0xFFFF)) << 16);

      for (uint32_t distance = 1; distance <= input.limits.materializationWindow; ++distance) {
        const uint32_t lowAddress = highAddress + distance * 4;
        if (lowAddress + 4 > section.end())
          break;
        const auto* low = decoded.get(lowAddress);
        if (!low)
          break;
        const uint32_t raw = static_cast<uint32_t>(low->code);
        std::optional<uint32_t> value;
        std::string form;
        uint8_t destination = 0;

        if (low->opcode == Opcode::addi && ((raw >> 16) & 0x1F) == highRegister) {
          destination = static_cast<uint8_t>((raw >> 21) & 0x1F);
          value = highValue + static_cast<int16_t>(raw & 0xFFFF);
          form = "lis/addi";
        } else if (low->opcode == Opcode::ori && ((raw >> 21) & 0x1F) == highRegister) {
          destination = static_cast<uint8_t>((raw >> 16) & 0x1F);
          value = highValue | (raw & 0xFFFF);
          form = "lis/ori";
        }

        if (value && IsExecutableAddress(binary, *value)) {
          AddEvidence(work,
                      EntrypointEvidence{
                          .kind = EntrypointEvidenceKind::CodeMaterializationXref,
                          .targetAddress = *value,
                          .sourceAddress = highAddress,
                          .sourceSection = std::string(section.name),
                          .provenance = "bounded PPC address materialization",
                          .attributes = {{"destination_register", fmt::format("r{}", destination)},
                                         {"form", form},
                                         {"high_site", Hex(highAddress)},
                                         {"low_site", Hex(lowAddress)}},
                      });
        }

        if (value) {
          std::vector<std::pair<uint32_t, uint32_t>> referencedPointers;
          const PointerRun* referencedRun = nullptr;
          if (auto pointer = work.pointerTargetByStorage.find(*value);
              pointer != work.pointerTargetByStorage.end()) {
            referencedPointers.emplace_back(pointer->first, pointer->second);
          }
          for (const auto& run : work.pointerRuns) {
            if (run.start != *value)
              continue;
            referencedRun = &run;
            for (size_t slot = 0; slot < run.targets.size(); ++slot) {
              referencedPointers.emplace_back(run.start + static_cast<uint32_t>(slot * 4),
                                              run.targets[slot]);
            }
            break;
          }
          std::sort(referencedPointers.begin(), referencedPointers.end());
          referencedPointers.erase(
              std::unique(referencedPointers.begin(), referencedPointers.end()),
              referencedPointers.end());
          for (const auto& [storage, target] : referencedPointers) {
            AddEvidence(work, {.kind = EntrypointEvidenceKind::PointerTableRun,
                               .targetAddress = target,
                               .sourceAddress = highAddress,
                               .storageAddress = storage,
                               .sourceSection = std::string(section.name),
                               .provenance = "bounded PPC xref to pointer storage/table",
                               .attributes = {{"form", form},
                                              {"high_site", Hex(highAddress)},
                                              {"low_site", Hex(lowAddress)},
                                              {"table_or_storage", Hex(*value)}}});
            if (referencedRun && !referencedRun->rtti && !referencedRun->section->executable) {
              const size_t slot = (storage - referencedRun->start) / 4;
              AddEvidence(
                  work,
                  {.kind = EntrypointEvidenceKind::CallbackTable,
                   .targetAddress = target,
                   .sourceAddress = highAddress,
                   .storageAddress = storage,
                   .sourceSection = std::string(referencedRun->section->name),
                   .provenance = "non-RTTI pointer array referenced by PPC address materialization",
                   .attributes = {{"entries", std::to_string(referencedRun->targets.size())},
                                  {"form", form},
                                  {"high_site", Hex(highAddress)},
                                  {"low_site", Hex(lowAddress)},
                                  {"run_start", Hex(referencedRun->start)},
                                  {"slot", std::to_string(slot)}}});
            }
          }
        }

        const auto writes = low->get_register_writes();
        if (std::find(writes.begin(), writes.end(), highRegister) != writes.end())
          break;
      }
    }
  }
}

void AddSeedEvidence(const BinaryView& binary, const EntrypointClosureInput& input,
                     WorkingSet& work) {
  if (IsExecutableAddress(binary, input.image.entryPoint)) {
    AddEvidence(work, EntrypointEvidence{
                          .kind = EntrypointEvidenceKind::XexEntrypoint,
                          .targetAddress = input.image.entryPoint,
                          .provenance = "XEX_HEADER_ENTRY_POINT",
                      });
  }
  for (const auto& [address, name] : input.peExports) {
    AddEvidence(work, EntrypointEvidence{
                          .kind = EntrypointEvidenceKind::PeExport,
                          .targetAddress = address,
                          .provenance = "PE/XEX export table",
                          .attributes = {{"name", name}},
                      });
  }
  for (uint32_t address : input.tlsCallbacks) {
    AddEvidence(work, EntrypointEvidence{
                          .kind = EntrypointEvidenceKind::TlsCallback,
                          .targetAddress = address,
                          .provenance = "PE TLS callback array",
                      });
  }
  for (const auto& manual : input.manualEvidence) {
    for (auto kind : manual.kinds) {
      AddEvidence(work, EntrypointEvidence{
                            .kind = kind,
                            .targetAddress = manual.address,
                            .provenance = manual.provenance,
                            .attributes = {{"verified_size", Hex(manual.size)}},
                        });
    }
  }
}

void IndexDirectEdges(const EntrypointClosureInput& input, WorkingSet& work) {
  for (const auto& seed : input.functionSeeds) {
    for (const auto& edge : seed.directEdges) {
      work.directByTarget[edge.target].push_back(edge);
      if (!FindExactSeed(input.functionSeeds, edge.target)) {
        AddEvidence(work, {.kind = edge.kind == "inter_function_tail_branch"
                                       ? EntrypointEvidenceKind::InterFunctionTailBranch
                                       : EntrypointEvidenceKind::DirectBranchLink,
                           .targetAddress = edge.target,
                           .sourceAddress = edge.site,
                           .provenance = "ReXGlue FunctionGraph direct edge",
                           .attributes = {{"owner", Hex(edge.source)}}});
      }
    }
  }
  for (auto& [target, edges] : work.directByTarget) {
    std::sort(edges.begin(), edges.end(), [](const auto& a, const auto& b) {
      if (a.site != b.site)
        return a.site < b.site;
      if (a.source != b.source)
        return a.source < b.source;
      return a.kind < b.kind;
    });
  }
}

struct TraversalResult {
  std::optional<EntrypointAddressRange> range;
  std::vector<EntrypointBasicBlock> blocks;
  std::vector<EntrypointDirectEdge> edges;
  std::vector<EntrypointIndirectSite> indirectSites;
  std::vector<std::string> conflicts;
  std::vector<std::string> rejections;
  std::vector<std::pair<uint32_t, std::string>> exposedTargets;
  std::string boundaryProvenance;
  bool complete = true;
  bool instructionLimit = false;
  bool depthLimit = false;
};

bool IsDirectBranch(const Instruction& insn) {
  return insn.branch_target.has_value();
}

TraversalResult TraverseCandidate(const BinaryView& binary, const DecodedBinary& decoded,
                                  const EntrypointClosureInput& input, uint32_t entry) {
  TraversalResult result;
  std::deque<std::pair<uint32_t, uint32_t>> pending;
  std::set<uint32_t> queued;
  std::set<uint32_t> visitedInstructions;
  pending.emplace_back(entry, 0);
  queued.insert(entry);
  uint32_t maximumEnd = entry;
  std::set<std::string> boundaryKinds;
  const auto* preliminaryOwner = FindContainingSeed(input.functionSeeds, entry);
  if (preliminaryOwner && !preliminaryOwner->preliminary)
    preliminaryOwner = nullptr;

  while (!pending.empty()) {
    const auto [blockStart, depth] = pending.front();
    pending.pop_front();
    if (depth > input.limits.maxTraversalDepth) {
      result.complete = false;
      result.depthLimit = true;
      result.conflicts.push_back("maximum traversal depth exhausted at " + Hex(blockStart));
      continue;
    }
    if (!IsExecutableAddress(binary, blockStart)) {
      result.complete = false;
      result.rejections.push_back("control flow left executable memory at " + Hex(blockStart));
      continue;
    }

    uint32_t address = blockStart;
    uint32_t blockEnd = blockStart;
    std::string termination;
    bool blockTerminated = false;
    while (!blockTerminated) {
      if (visitedInstructions.contains(address)) {
        termination = "joins_visited_block";
        break;
      }
      if (visitedInstructions.size() >= input.limits.maxInstructionsPerCandidate) {
        result.complete = false;
        result.instructionLimit = true;
        termination = "instruction_limit";
        break;
      }

      const auto* instruction = decoded.get(address);
      if (!instruction || isInvalid(*instruction)) {
        result.complete = false;
        result.rejections.push_back("invalid or data-like instruction at " + Hex(address));
        termination = "invalid_instruction";
        break;
      }
      visitedInstructions.insert(address);
      maximumEnd = std::max(maximumEnd, address + 4);
      blockEnd = std::max(blockEnd, address + 4);

      if (instruction->is_return()) {
        termination = "return";
        boundaryKinds.insert("valid_return");
        blockTerminated = true;
      } else if (instruction->is_indirect_branch()) {
        const bool link = instruction->is_call();
        result.indirectSites.push_back({.site = address,
                                        .ownerAddress = entry,
                                        .link = link,
                                        .kind = link ? "indirect_call" : "indirect_tail_transfer"});
        if (link) {
          address += 4;
          continue;
        }
        termination = "indirect_tail_transfer";
        boundaryKinds.insert("indirect_tail_transfer");
        blockTerminated = true;
      } else if (IsDirectBranch(*instruction)) {
        const uint32_t target = *instruction->branch_target;
        const bool call = instruction->is_call();
        const bool conditional = instruction->is_conditional();
        const std::string kind =
            call ? "direct_branch_link" : (conditional ? "conditional_branch" : "tail_branch");
        result.edges.push_back({.site = address, .source = entry, .target = target, .kind = kind});

        if (call) {
          result.exposedTargets.emplace_back(target, "direct_branch_link");
          address += 4;
          continue;
        }

        const auto* exactSeed = FindExactSeed(input.functionSeeds, target);
        const bool externalBoundary =
            exactSeed && target != entry && (exactSeed->trusted || exactSeed->preliminary);
        const bool leavesPreliminaryOwner =
            preliminaryOwner && !preliminaryOwner->range.contains(target);
        if (!externalBoundary && !leavesPreliminaryOwner && IsExecutableAddress(binary, target)) {
          if (queued.insert(target).second)
            pending.emplace_back(target, depth + 1);
        } else if (externalBoundary || leavesPreliminaryOwner) {
          result.exposedTargets.emplace_back(target, "inter_function_tail_branch");
          boundaryKinds.insert(externalBoundary && exactSeed->trusted
                                   ? "external_tail_branch"
                                   : "preliminary_ownership_boundary");
        }

        if (conditional) {
          const uint32_t fallthrough = address + 4;
          if (queued.insert(fallthrough).second)
            pending.emplace_back(fallthrough, depth + 1);
          termination = (externalBoundary || leavesPreliminaryOwner) ? "conditional_external_branch"
                                                                     : "conditional_branch";
        } else {
          termination = (externalBoundary || leavesPreliminaryOwner) ? "external_tail_branch"
                                                                     : "unconditional_branch";
        }
        blockTerminated = true;
      } else {
        const uint32_t next = address + 4;
        const auto* boundary = FindExactSeed(input.functionSeeds, next);
        const bool preliminaryEnd = preliminaryOwner && next >= preliminaryOwner->range.end;
        if ((boundary && next != entry && (boundary->trusted || boundary->preliminary)) ||
            preliminaryEnd) {
          termination = "trusted_boundary";
          boundaryKinds.insert(boundary && boundary->trusted ? "trusted_boundary"
                                                             : "preliminary_ownership_boundary");
          blockTerminated = true;
        } else if (!IsExecutableAddress(binary, next)) {
          result.complete = false;
          result.rejections.push_back("fallthrough left executable memory at " + Hex(next));
          termination = "out_of_range_fallthrough";
          blockTerminated = true;
        } else {
          address = next;
        }
      }
    }

    if (blockEnd > blockStart) {
      result.blocks.push_back(
          {.range = {blockStart, blockEnd}, .ownerAddress = entry, .termination = termination});
    }
  }

  if (maximumEnd > entry)
    result.range = EntrypointAddressRange{entry, maximumEnd};
  if (boundaryKinds.empty()) {
    result.boundaryProvenance = result.complete ? "bounded_cfg_fixpoint" : "incomplete_bounded_cfg";
  } else {
    result.boundaryProvenance.clear();
    for (const auto& kind : boundaryKinds) {
      if (!result.boundaryProvenance.empty())
        result.boundaryProvenance += "+";
      result.boundaryProvenance += kind;
    }
  }

  std::sort(result.blocks.begin(), result.blocks.end(),
            [](const auto& a, const auto& b) { return a.range.start < b.range.start; });
  std::sort(result.edges.begin(), result.edges.end(), [](const auto& a, const auto& b) {
    if (a.site != b.site)
      return a.site < b.site;
    return a.target < b.target;
  });
  std::sort(result.indirectSites.begin(), result.indirectSites.end(),
            [](const auto& a, const auto& b) { return a.site < b.site; });
  std::sort(result.conflicts.begin(), result.conflicts.end());
  std::sort(result.rejections.begin(), result.rejections.end());
  return result;
}

void ClassifyCandidate(const BinaryView& binary, const DecodedBinary& decoded,
                       const EntrypointClosureInput& input, WorkingSet& work,
                       EntrypointCandidate& candidate,
                       std::vector<std::pair<uint32_t, std::string>>& exposed) {
  candidate.proposedRange.reset();
  candidate.basicBlocks.clear();
  candidate.directEdges.clear();
  candidate.indirectSites.clear();
  candidate.conflicts.clear();
  candidate.rejectionReasons.clear();
  candidate.completeTraversal = false;
  candidate.hitInstructionLimit = false;
  candidate.hitDepthLimit = false;

  if ((candidate.address & 3) != 0) {
    candidate.classification = EntrypointClassification::RejectedOutOfRange;
    candidate.confidence = EntrypointConfidence::Rejected;
    candidate.rejectionReasons.push_back("candidate is not four-byte aligned");
    return;
  }
  if (!IsExecutableAddress(binary, candidate.address)) {
    candidate.classification = EntrypointClassification::RejectedOutOfRange;
    candidate.confidence = EntrypointConfidence::Rejected;
    candidate.rejectionReasons.push_back("candidate is outside executable ranges");
    return;
  }

  const auto* first = decoded.get(candidate.address);
  candidate.decodedInstruction = first ? first->to_string() : "<unmapped>";
  if (!first || isInvalid(*first)) {
    candidate.classification = EntrypointClassification::RejectedNonCode;
    candidate.confidence = EntrypointConfidence::Rejected;
    candidate.rejectionReasons.push_back("production PPC decoder rejected the first instruction");
    return;
  }

  const auto* exact = FindExactSeed(input.functionSeeds, candidate.address);
  const auto* containing = FindContainingSeed(input.functionSeeds, candidate.address);

  if (auto edgeIt = work.directByTarget.find(candidate.address);
      edgeIt != work.directByTarget.end()) {
    for (const auto& edge : edgeIt->second) {
      candidate.evidence.push_back(
          EntrypointEvidence{.kind = edge.kind == "inter_function_tail_branch"
                                         ? EntrypointEvidenceKind::InterFunctionTailBranch
                                         : EntrypointEvidenceKind::DirectBranchLink,
                             .targetAddress = candidate.address,
                             .sourceAddress = edge.site,
                             .provenance = "ReXGlue FunctionGraph direct edge",
                             .attributes = {{"owner", Hex(edge.source)}}});
    }
  }

  if (exact) {
    EntrypointEvidenceKind seedKind = EntrypointEvidenceKind::RexglueDiscovered;
    if (exact->manifest)
      seedKind = EntrypointEvidenceKind::ExistingManifest;
    else if (exact->authority == "pdata")
      seedKind = exact->exceptionFunction ? EntrypointEvidenceKind::PdataException
                                          : EntrypointEvidenceKind::PdataFunction;
    else if (exact->authority == "vtable")
      seedKind = EntrypointEvidenceKind::RttiVtable;
    else if (exact->authority == "helper")
      seedKind = EntrypointEvidenceKind::AbiHelper;
    candidate.evidence.push_back({.kind = seedKind,
                                  .targetAddress = candidate.address,
                                  .provenance = "existing ReXGlue FunctionGraph boundary"});
    candidate.proposedRange = exact->range;
    candidate.completeTraversal = true;
    candidate.boundaryProvenance =
        "existing_function_graph_range+independent_address_taken_evidence";
    candidate.knownRangeRelationship = "exact_existing_entry";
    candidate.classification = EntrypointClassification::ConfirmedExistingFunction;
    candidate.confidence = EntrypointConfidence::Confirmed;
    return;
  }

  auto traversal = TraverseCandidate(binary, decoded, input, candidate.address);
  candidate.proposedRange = traversal.range;
  candidate.basicBlocks = std::move(traversal.blocks);
  candidate.directEdges = std::move(traversal.edges);
  candidate.indirectSites = std::move(traversal.indirectSites);
  candidate.conflicts = std::move(traversal.conflicts);
  candidate.rejectionReasons = std::move(traversal.rejections);
  candidate.completeTraversal = traversal.complete;
  candidate.hitInstructionLimit = traversal.instructionLimit;
  candidate.hitDepthLimit = traversal.depthLimit;
  candidate.boundaryProvenance = std::move(traversal.boundaryProvenance);
  exposed.insert(exposed.end(), traversal.exposedTargets.begin(), traversal.exposedTargets.end());

  if (containing && containing->trusted && !containing->preliminary) {
    candidate.knownRangeRelationship =
        fmt::format("inside_trusted_function_{}", Hex(containing->range.start));
    if (containing->jumpTableTargets.contains(candidate.address)) {
      candidate.classification = EntrypointClassification::JumpTableCase;
      candidate.confidence = EntrypointConfidence::Confirmed;
      candidate.rejectionReasons.push_back("target is an owned jump-table case label");
    } else if (containing->exceptionEntries.contains(candidate.address)) {
      candidate.classification = EntrypointClassification::ExceptionLandingPad;
      candidate.confidence = EntrypointConfidence::Confirmed;
      candidate.rejectionReasons.push_back("target is owned exception landing-pad code");
    } else if (containing->labels.contains(candidate.address) ||
               IsBlockStart(*containing, candidate.address)) {
      candidate.classification = EntrypointClassification::CallableMidFunctionEntry;
      candidate.confidence = EntrypointConfidence::Probable;
      candidate.conflicts.push_back("address is a callable label inside an existing function");
    } else {
      candidate.classification = EntrypointClassification::RejectedOverlap;
      candidate.confidence = EntrypointConfidence::Rejected;
      candidate.rejectionReasons.push_back("target falls in the middle of an owned basic block");
    }
    return;
  }

  if (containing) {
    candidate.knownRangeRelationship =
        fmt::format("inside_preliminary_function_{}", Hex(containing->range.start));
  } else {
    candidate.knownRangeRelationship = "unowned_executable_address";
  }

  if (candidate.address >= 4) {
    if (const auto* predecessorOwner =
            FindContainingSeed(input.functionSeeds, candidate.address - 4);
        predecessorOwner && predecessorOwner->trusted &&
        SameOwnedBlockContains(*predecessorOwner, candidate.address - 4, candidate.address)) {
      candidate.classification = EntrypointClassification::RejectedOverlap;
      candidate.confidence = EntrypointConfidence::Rejected;
      candidate.rejectionReasons.push_back(
          "predecessor falls through into a non-boundary inside a trusted block");
      return;
    }
  }

  if (candidate.proposedRange) {
    for (const auto& seed : input.functionSeeds) {
      if (!seed.trusted || seed.preliminary)
        continue;
      if (candidate.proposedRange->overlaps(seed.range)) {
        candidate.classification = EntrypointClassification::RejectedOverlap;
        candidate.confidence = EntrypointConfidence::Rejected;
        candidate.rejectionReasons.push_back(
            fmt::format("proposed range overlaps trusted function {}-{}", Hex(seed.range.start),
                        Hex(seed.range.end)));
        return;
      }
    }
  }

  std::set<EntrypointEvidenceKind> corroboratingKinds;
  bool hasDirectCallEvidence = false;
  bool hasTailBranchEvidence = false;
  bool hasReliableSeedEvidence = false;
  for (const auto& evidence : candidate.evidence) {
    switch (evidence.kind) {
      case EntrypointEvidenceKind::RelocationBackedPointer:
      case EntrypointEvidenceKind::PointerTableRun:
      case EntrypointEvidenceKind::RttiVtable:
      case EntrypointEvidenceKind::CallbackTable:
      case EntrypointEvidenceKind::CodeMaterializationXref:
        corroboratingKinds.insert(evidence.kind);
        break;
      default:
        break;
    }
    hasDirectCallEvidence |= evidence.kind == EntrypointEvidenceKind::DirectBranchLink;
    hasTailBranchEvidence |= evidence.kind == EntrypointEvidenceKind::InterFunctionTailBranch;
    hasReliableSeedEvidence |= evidence.kind == EntrypointEvidenceKind::XexEntrypoint ||
                               evidence.kind == EntrypointEvidenceKind::PeExport ||
                               evidence.kind == EntrypointEvidenceKind::TlsCallback ||
                               evidence.kind == EntrypointEvidenceKind::ManualVerified ||
                               evidence.kind == EntrypointEvidenceKind::FaultWalkerVerified;
  }

  if (!candidate.completeTraversal || !candidate.proposedRange) {
    candidate.classification = EntrypointClassification::AmbiguousCodePointer;
    candidate.confidence = EntrypointConfidence::Review;
  } else if (hasReliableSeedEvidence || hasDirectCallEvidence || corroboratingKinds.size() >= 2 ||
             corroboratingKinds.contains(EntrypointEvidenceKind::RttiVtable) ||
             corroboratingKinds.contains(EntrypointEvidenceKind::RelocationBackedPointer)) {
    candidate.classification = EntrypointClassification::StrongNewFunction;
    candidate.confidence = EntrypointConfidence::Strong;
  } else if (hasTailBranchEvidence || !corroboratingKinds.empty()) {
    candidate.classification = EntrypointClassification::ProbableNewFunction;
    candidate.confidence = EntrypointConfidence::Probable;
  } else {
    candidate.classification = EntrypointClassification::AmbiguousCodePointer;
    candidate.confidence = EntrypointConfidence::Review;
  }
}

void FinalizeFixtures(const EntrypointClosureInput& input, EntrypointClosureReport& report) {
  for (const auto& expected : input.fixtures) {
    EntrypointFixtureResult result;
    result.expected = expected;
    auto it = std::lower_bound(report.candidates.begin(), report.candidates.end(), expected.address,
                               [](const EntrypointCandidate& candidate, uint32_t address) {
                                 return candidate.address < address;
                               });
    if (it == report.candidates.end() || it->address != expected.address) {
      result.result = "candidate_not_found";
      report.fixtureResults.push_back(std::move(result));
      continue;
    }

    result.present = true;
    result.rangeMatches = it->proposedRange && it->proposedRange->start == expected.address &&
                          it->proposedRange->size() == expected.size;
    std::set<EntrypointEvidenceKind> independent;
    for (const auto& evidence : it->evidence) {
      if (!IsStrongAddressTakenEvidence(evidence.kind))
        continue;
      independent.insert(evidence.kind);
      if (evidence.storageAddress)
        result.storageAddresses.push_back(*evidence.storageAddress);
      if (evidence.kind == EntrypointEvidenceKind::CodeMaterializationXref) {
        if (evidence.sourceAddress)
          result.materializationSites.push_back(*evidence.sourceAddress);
        auto low = evidence.attributes.find("low_site");
        if (low != evidence.attributes.end()) {
          result.materializationSites.push_back(
              static_cast<uint32_t>(std::stoul(low->second, nullptr, 0)));
        }
      }
    }
    result.independentEvidence.assign(independent.begin(), independent.end());
    std::sort(result.storageAddresses.begin(), result.storageAddresses.end());
    result.storageAddresses.erase(
        std::unique(result.storageAddresses.begin(), result.storageAddresses.end()),
        result.storageAddresses.end());
    std::sort(result.materializationSites.begin(), result.materializationSites.end());
    result.materializationSites.erase(
        std::unique(result.materializationSites.begin(), result.materializationSites.end()),
        result.materializationSites.end());
    result.independentlyRediscovered = result.rangeMatches && !independent.empty();
    result.result = result.independentlyRediscovered ? "pass" : "fail";
    report.fixtureResults.push_back(std::move(result));
  }
  std::sort(report.fixtureResults.begin(), report.fixtureResults.end(),
            [](const auto& a, const auto& b) { return a.expected.address < b.expected.address; });
}

uint32_t RecordCandidateOverlapConflicts(std::vector<EntrypointCandidate>& candidates) {
  auto isReviewRange = [](const EntrypointCandidate& candidate) {
    return candidate.proposedRange &&
           (candidate.classification == EntrypointClassification::StrongNewFunction ||
            candidate.classification == EntrypointClassification::ProbableNewFunction ||
            candidate.classification == EntrypointClassification::AmbiguousCodePointer);
  };

  uint32_t pairs = 0;
  for (size_t leftIndex = 0; leftIndex < candidates.size(); ++leftIndex) {
    auto& left = candidates[leftIndex];
    if (!isReviewRange(left))
      continue;
    for (size_t rightIndex = leftIndex + 1; rightIndex < candidates.size(); ++rightIndex) {
      auto& right = candidates[rightIndex];
      if (right.address >= left.proposedRange->end)
        break;
      if (!isReviewRange(right) || !left.proposedRange->overlaps(*right.proposedRange))
        continue;

      left.conflicts.push_back(
          fmt::format("proposed range {}-{} overlaps candidate {}-{}",
                      Hex(left.proposedRange->start), Hex(left.proposedRange->end),
                      Hex(right.proposedRange->start), Hex(right.proposedRange->end)));
      right.conflicts.push_back(
          fmt::format("proposed range {}-{} overlaps candidate {}-{}",
                      Hex(right.proposedRange->start), Hex(right.proposedRange->end),
                      Hex(left.proposedRange->start), Hex(left.proposedRange->end)));
      ++pairs;
    }
  }
  for (auto& candidate : candidates) {
    std::sort(candidate.conflicts.begin(), candidate.conflicts.end());
    candidate.conflicts.erase(std::unique(candidate.conflicts.begin(), candidate.conflicts.end()),
                              candidate.conflicts.end());
  }
  return pairs;
}

void ComputeCounts(const WorkingSet& work, EntrypointClosureReport& report) {
  for (const auto& seed : report.functionRanges) {
    report.counts.trustedRanges += seed.trusted ? 1u : 0u;
    report.counts.preliminaryRanges += seed.preliminary ? 1u : 0u;
  }
  report.counts.candidates = static_cast<uint32_t>(report.candidates.size());
  report.counts.pointerStorageSites = work.pointerStorageSites;
  report.counts.pointerRuns = static_cast<uint32_t>(work.pointerRuns.size());
  report.counts.indirectSites = static_cast<uint32_t>(report.indirectSites.size());
  for (const auto& candidate : report.candidates) {
    switch (candidate.classification) {
      case EntrypointClassification::StrongNewFunction:
        report.counts.strongNewFunctions++;
        break;
      case EntrypointClassification::ProbableNewFunction:
        report.counts.probableNewFunctions++;
        break;
      case EntrypointClassification::AmbiguousCodePointer:
        report.counts.ambiguousCandidates++;
        break;
      case EntrypointClassification::RejectedNonCode:
      case EntrypointClassification::RejectedOverlap:
      case EntrypointClassification::RejectedOutOfRange:
        report.counts.rejectedCandidates++;
        break;
      default:
        break;
    }
  }
}

}  // namespace

const char* EntrypointEvidenceKindName(EntrypointEvidenceKind kind) {
  switch (kind) {
    case EntrypointEvidenceKind::XexEntrypoint:
      return "xex_entrypoint";
    case EntrypointEvidenceKind::PeExport:
      return "pe_export";
    case EntrypointEvidenceKind::TlsCallback:
      return "tls_callback";
    case EntrypointEvidenceKind::PdataFunction:
      return "pdata_function";
    case EntrypointEvidenceKind::PdataException:
      return "pdata_exception";
    case EntrypointEvidenceKind::DirectBranchLink:
      return "direct_branch_link";
    case EntrypointEvidenceKind::InterFunctionTailBranch:
      return "inter_function_tail_branch";
    case EntrypointEvidenceKind::RelocationBackedPointer:
      return "relocation_backed_pointer";
    case EntrypointEvidenceKind::ReadonlyCodePointer:
      return "readonly_code_pointer";
    case EntrypointEvidenceKind::WritableCodePointer:
      return "writable_code_pointer";
    case EntrypointEvidenceKind::PointerTableRun:
      return "pointer_table_run";
    case EntrypointEvidenceKind::RttiVtable:
      return "rtti_vtable";
    case EntrypointEvidenceKind::CallbackTable:
      return "callback_table";
    case EntrypointEvidenceKind::CodeMaterializationXref:
      return "code_materialization_xref";
    case EntrypointEvidenceKind::ExistingManifest:
      return "existing_manifest";
    case EntrypointEvidenceKind::ManualVerified:
      return "manual_verified";
    case EntrypointEvidenceKind::FaultWalkerVerified:
      return "fault_walker_verified";
    case EntrypointEvidenceKind::AbiHelper:
      return "abi_helper";
    case EntrypointEvidenceKind::RexglueDiscovered:
      return "rexglue_discovered";
    case EntrypointEvidenceKind::ReservedGhidraImport:
      return "reserved_ghidra_import";
    case EntrypointEvidenceKind::ReservedJumpTableRecovery:
      return "reserved_jump_table_recovery";
    case EntrypointEvidenceKind::ReservedXeniaTrace:
      return "reserved_xenia_trace";
    case EntrypointEvidenceKind::ReservedRuntimeBulkImport:
      return "reserved_runtime_bulk_import";
  }
  return "unknown";
}

const char* EntrypointClassificationName(EntrypointClassification classification) {
  switch (classification) {
    case EntrypointClassification::ConfirmedExistingFunction:
      return "confirmed_existing_function";
    case EntrypointClassification::StrongNewFunction:
      return "strong_new_function";
    case EntrypointClassification::ProbableNewFunction:
      return "probable_new_function";
    case EntrypointClassification::CallableMidFunctionEntry:
      return "callable_mid_function_entry";
    case EntrypointClassification::JumpTableCase:
      return "jump_table_case";
    case EntrypointClassification::ExceptionLandingPad:
      return "exception_landing_pad";
    case EntrypointClassification::AmbiguousCodePointer:
      return "ambiguous_code_pointer";
    case EntrypointClassification::RejectedNonCode:
      return "rejected_non_code";
    case EntrypointClassification::RejectedOverlap:
      return "rejected_overlap";
    case EntrypointClassification::RejectedOutOfRange:
      return "rejected_out_of_range";
  }
  return "ambiguous_code_pointer";
}

const char* EntrypointConfidenceName(EntrypointConfidence confidence) {
  switch (confidence) {
    case EntrypointConfidence::Confirmed:
      return "confirmed";
    case EntrypointConfidence::Strong:
      return "strong";
    case EntrypointConfidence::Probable:
      return "probable";
    case EntrypointConfidence::Review:
      return "review";
    case EntrypointConfidence::Rejected:
      return "rejected";
  }
  return "review";
}

static EntrypointClosureReport AnalyzeEntrypointClosureDecoded(const BinaryView& binary,
                                                               const DecodedBinary& decoded,
                                                               EntrypointClosureInput input) {
  EntrypointClosureReport report;
  report.image = std::move(input.image);
  report.jumpTableRecovery = std::move(input.jumpTableRecovery);
  std::map<std::string, JumpTableClusterSummary> clusterMap;
  for (auto& site : report.jumpTableRecovery.indirectSites) {
    if (!site.usesCtr || site.link)
      continue;

    if (!site.dataflow)
      site.dataflow = std::make_shared<JumpTableSiteDataflowEvidence>();
    auto& dataflow = *site.dataflow;
    if (dataflow.dispatchKind == "other")
      dataflow.dispatchKind = site.conditional ? "conditional_bctr" : "bctr";
    if (dataflow.clusterId.empty()) {
      std::string failures = "none";
      if (!site.failures.empty()) {
        failures.clear();
        for (auto failure : site.failures) {
          if (!failures.empty())
            failures += '+';
          failures += JumpTableFailureName(failure);
        }
      }
      dataflow.clusterId = "dispatch=" + dataflow.dispatchKind +
                           "|form=unknown|element=unknown|scale=0|bound=none|index=none|cfg="
                           "acyclic|merge=unknown|base=unknown_or_runtime|slice=|stage=" +
                           dataflow.failureStage + "|reason=" + failures;
      dataflow.switchLikelihood = site.selectedTable
                                      ? JumpTableSwitchLikelihood::ResolvedSwitch
                                      : JumpTableSwitchLikelihood::OpaqueNonTableDispatch;
    }

    auto& cluster = clusterMap[dataflow.clusterId];
    cluster.clusterId = dataflow.clusterId;
    ++cluster.siteCount;
    if (site.selectedTable)
      ++cluster.recoveredCount;
    else
      ++cluster.unresolvedCount;
    if (cluster.representativeSites.size() < 5)
      cluster.representativeSites.push_back(site.site);
    for (auto failure : site.failures)
      ++cluster.failureCounts[JumpTableFailureName(failure)];
    ++cluster.switchLikelihoodCounts[JumpTableSwitchLikelihoodName(dataflow.switchLikelihood)];
    if (cluster.normalizedSlice.empty())
      cluster.normalizedSlice = dataflow.normalizedTargetExpression;
    auto addEvidence = [&](std::string evidence) {
      if (std::find(cluster.switchEvidence.begin(), cluster.switchEvidence.end(), evidence) ==
          cluster.switchEvidence.end()) {
        cluster.switchEvidence.push_back(std::move(evidence));
      }
    };
    if (dataflow.elementWidth)
      addEvidence("table_like_indexed_load");
    const bool matchingFiniteBound = std::any_of(
        dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(), [&](const auto& bound) {
          return bound.finiteDenseDomain && dataflow.indexRegister != 0xFF &&
                 bound.indexRegister == dataflow.indexRegister;
        });
    const bool unmatchedFiniteBound =
        !matchingFiniteBound &&
        std::any_of(dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(),
                    [](const auto& bound) { return bound.finiteDenseDomain; });
    const bool selfDelimitedInlineExtent =
        std::any_of(dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(),
                    [](const auto& bound) { return bound.selfDelimitedInlineTableExtent; });
    if (matchingFiniteBound)
      addEvidence("finite_dominating_bound_for_table_index");
    if (unmatchedFiniteBound)
      addEvidence("finite_bound_for_unrelated_register");
    if (selfDelimitedInlineExtent)
      addEvidence("self_delimiting_inline_table_extent");
    if (dataflow.reachingDefinitionInScc)
      addEvidence("loop_carried_reaching_definition");
    if (dataflow.diagnosticProbe.hypothesisComplete && dataflow.diagnosticProbe.allTargetsValid) {
      addEvidence("report_probe_complete_valid_table");
    }
    if (dataflow.diagnosticProbe.mixedValidity)
      addEvidence("report_probe_mixed_validity");
    if (site.selectedTable)
      addEvidence("production_table_recovered");
    if (dataflow.mergeShape == "finite_loop_phi" || dataflow.mergeShape == "finite_cfg_domain" ||
        dataflow.mergeShape == "bounded_direct_index" ||
        dataflow.mergeShape == "interprocedural_entry_domain" || selfDelimitedInlineExtent)
      cluster.syntheticFixtureExists = true;
  }
  for (auto& [unused, cluster] : clusterMap) {
    const auto count = [&](JumpTableSwitchLikelihood likelihood) {
      auto found = cluster.switchLikelihoodCounts.find(JumpTableSwitchLikelihoodName(likelihood));
      return found == cluster.switchLikelihoodCounts.end() ? 0u : found->second;
    };
    cluster.blocksPhase3Closure = count(JumpTableSwitchLikelihood::ConfirmedSwitchMiss) != 0 ||
                                  count(JumpTableSwitchLikelihood::ProbableSwitchMiss) != 0 ||
                                  count(JumpTableSwitchLikelihood::PlausibleSwitchCandidate) != 0;
    if (count(JumpTableSwitchLikelihood::ProbableSwitchMiss) != 0) {
      cluster.proposedGenericCorrection =
          "reconcile the production recognizer with the complete report-only table hypothesis";
    } else if (count(JumpTableSwitchLikelihood::PlausibleSwitchCandidate) != 0) {
      cluster.proposedGenericCorrection =
          "inspect the bounded symbolic slice; retain rejection until every target validates";
    } else {
      cluster.proposedGenericCorrection = "none_without_additional_static_evidence";
    }
    std::sort(cluster.switchEvidence.begin(), cluster.switchEvidence.end());
    report.jumpTableRecovery.clusters.push_back(std::move(cluster));
  }
  report.limits = input.limits;
  report.limitDiagnostics = input.producerDiagnostics;
  report.counts.relocationStorageSites =
      static_cast<uint32_t>(input.relocationStorageAddresses.size());
  report.counts.peExports = static_cast<uint32_t>(input.peExports.size());
  report.counts.tlsCallbacks = static_cast<uint32_t>(input.tlsCallbacks.size());
  std::sort(input.functionSeeds.begin(), input.functionSeeds.end(),
            [](const auto& a, const auto& b) {
              if (a.range.start != b.range.start)
                return a.range.start < b.range.start;
              return a.range.end < b.range.end;
            });

  for (const auto& section : binary.sections()) {
    report.sections.push_back({.name = std::string(section.name),
                               .range = {section.baseAddress, section.end()},
                               .sha256 = {},
                               .executable = section.executable,
                               .readable = section.readable,
                               .writable = section.writable});
  }
  std::sort(report.sections.begin(), report.sections.end(),
            [](const auto& a, const auto& b) { return a.range.start < b.range.start; });

  WorkingSet work;
  IndexDirectEdges(input, work);
  ScanRttiVtables(binary, work);
  ScanStoragePointers(binary, input, work);
  ScanMaterializations(binary, decoded, input, work);
  AddSeedEvidence(binary, input, work);

  if (work.candidates.size() > input.limits.maxCandidates) {
    report.limitDiagnostics.push_back(
        {.limit = "max_candidates",
         .configured = input.limits.maxCandidates,
         .observed = work.candidates.size(),
         .detail = "candidate collection truncated in ascending guest-address order"});
    auto it = work.candidates.begin();
    std::advance(it, input.limits.maxCandidates);
    work.candidates.erase(it, work.candidates.end());
  }

  for (uint32_t iteration = 1; iteration <= input.limits.maxIterations; ++iteration) {
    EntrypointFixpointIteration iterationRecord;
    iterationRecord.iteration = iteration;
    iterationRecord.candidatesBefore = static_cast<uint32_t>(work.candidates.size());
    std::vector<std::pair<uint32_t, std::string>> exposed;

    for (auto& [address, candidate] : work.candidates) {
      const auto before = candidate.classification;
      ClassifyCandidate(binary, decoded, input, work, candidate, exposed);
      SortUniqueEvidence(candidate.evidence);
      if (iteration > 1 && candidate.classification != before)
        iterationRecord.classificationsChanged++;
    }

    std::sort(exposed.begin(), exposed.end());
    exposed.erase(std::unique(exposed.begin(), exposed.end()), exposed.end());
    for (const auto& [target, kind] : exposed) {
      if (!IsExecutableAddress(binary, target) || FindExactSeed(input.functionSeeds, target))
        continue;
      if (work.candidates.size() >= input.limits.maxCandidates) {
        report.limitDiagnostics.push_back({.limit = "max_candidates",
                                           .configured = input.limits.maxCandidates,
                                           .observed = work.candidates.size() + 1,
                                           .address = target,
                                           .detail = "fixpoint target was not added"});
        continue;
      }
      const bool existed = work.candidates.contains(target);
      if (AddEvidence(work, EntrypointEvidence{
                                .kind = kind == "direct_branch_link"
                                            ? EntrypointEvidenceKind::DirectBranchLink
                                            : EntrypointEvidenceKind::InterFunctionTailBranch,
                                .targetAddress = target,
                                .provenance = "entrypoint-closure fixpoint traversal",
                            })) {
        iterationRecord.newEvidenceRecords++;
      }
      if (!existed) {
        if (kind == "direct_branch_link")
          iterationRecord.newDirectCallTargets++;
        else
          iterationRecord.newTailBranchTargets++;
      }
    }

    iterationRecord.candidatesAfter = static_cast<uint32_t>(work.candidates.size());
    report.fixpointIterations.push_back(iterationRecord);
    if (iterationRecord.candidatesAfter == iterationRecord.candidatesBefore &&
        iterationRecord.classificationsChanged == 0 && iterationRecord.newEvidenceRecords == 0) {
      report.fixpointReached = true;
      break;
    }
  }
  if (!report.fixpointReached) {
    report.limitDiagnostics.push_back(
        {.limit = "max_iterations",
         .configured = input.limits.maxIterations,
         .observed = report.fixpointIterations.size(),
         .detail = "entrypoint closure did not reach a stable fixpoint"});
  }

  for (auto& [address, candidate] : work.candidates) {
    if (candidate.hitInstructionLimit) {
      report.limitDiagnostics.push_back({.limit = "max_instructions_per_candidate",
                                         .configured = input.limits.maxInstructionsPerCandidate,
                                         .observed = input.limits.maxInstructionsPerCandidate,
                                         .address = address,
                                         .detail = "bounded CFG traversal stopped"});
    }
    if (candidate.hitDepthLimit) {
      report.limitDiagnostics.push_back({.limit = "max_traversal_depth",
                                         .configured = input.limits.maxTraversalDepth,
                                         .observed = input.limits.maxTraversalDepth + 1,
                                         .address = address,
                                         .detail = "bounded CFG traversal stopped"});
    }
    report.candidates.push_back(std::move(candidate));
  }
  std::sort(report.candidates.begin(), report.candidates.end(),
            [](const auto& a, const auto& b) { return a.address < b.address; });
  report.counts.candidateOverlapPairs = RecordCandidateOverlapConflicts(report.candidates);
  for (const auto& candidate : report.candidates) {
    if (candidate.classification == EntrypointClassification::JumpTableCase)
      report.jumpTableRecovery.staticCandidatesReclassifiedAsCases.push_back(candidate.address);
  }

  report.functionRanges = std::move(input.functionSeeds);
  for (const auto& seed : report.functionRanges) {
    report.directEdges.insert(report.directEdges.end(), seed.directEdges.begin(),
                              seed.directEdges.end());
  }
  std::sort(report.directEdges.begin(), report.directEdges.end(), [](const auto& a, const auto& b) {
    if (a.site != b.site)
      return a.site < b.site;
    if (a.source != b.source)
      return a.source < b.source;
    return a.target < b.target;
  });
  report.directEdges.erase(std::unique(report.directEdges.begin(), report.directEdges.end(),
                                       [](const auto& a, const auto& b) {
                                         return a.site == b.site && a.source == b.source &&
                                                a.target == b.target && a.kind == b.kind;
                                       }),
                           report.directEdges.end());

  for (const auto& candidate : report.candidates) {
    report.indirectSites.insert(report.indirectSites.end(), candidate.indirectSites.begin(),
                                candidate.indirectSites.end());
  }
  std::sort(report.indirectSites.begin(), report.indirectSites.end(),
            [](const auto& a, const auto& b) {
              if (a.site != b.site)
                return a.site < b.site;
              return a.ownerAddress < b.ownerAddress;
            });
  report.indirectSites.erase(std::unique(report.indirectSites.begin(), report.indirectSites.end(),
                                         [](const auto& a, const auto& b) {
                                           return a.site == b.site &&
                                                  a.ownerAddress == b.ownerAddress &&
                                                  a.link == b.link && a.kind == b.kind;
                                         }),
                             report.indirectSites.end());

  std::sort(report.limitDiagnostics.begin(), report.limitDiagnostics.end(),
            [](const auto& a, const auto& b) {
              if (a.limit != b.limit)
                return a.limit < b.limit;
              return a.address < b.address;
            });
  FinalizeFixtures(input, report);
  ComputeCounts(work, report);
  return report;
}

EntrypointClosureReport AnalyzeEntrypointClosure(const BinaryView& binary,
                                                 EntrypointClosureInput input) {
  DecodedBinary decoded(binary);
  decoded.decode();
  return AnalyzeEntrypointClosureDecoded(binary, decoded, std::move(input));
}

EntrypointClosureReport AnalyzeEntrypointClosure(const CodegenContext& context,
                                                 EntrypointClosureInput input) {
  return AnalyzeEntrypointClosureDecoded(context.binary(), context.decoded(), std::move(input));
}

namespace {

using Json = nlohmann::ordered_json;

Json RangeJson(const EntrypointAddressRange& range) {
  return Json{{"start", Hex(range.start)}, {"end", Hex(range.end)}, {"size", Hex(range.size())}};
}

Json OptionalAddressJson(const std::optional<uint32_t>& address) {
  return address ? Json(Hex(*address)) : Json(nullptr);
}

Json EvidenceJson(const EntrypointEvidence& evidence) {
  Json attributes = Json::object();
  for (const auto& [key, value] : evidence.attributes)
    attributes[key] = value;

  return Json{{"kind", EntrypointEvidenceKindName(evidence.kind)},
              {"target_address", Hex(evidence.targetAddress)},
              {"source_address", OptionalAddressJson(evidence.sourceAddress)},
              {"storage_address", OptionalAddressJson(evidence.storageAddress)},
              {"source_section", evidence.sourceSection},
              {"provenance", evidence.provenance},
              {"attributes", std::move(attributes)}};
}

Json BasicBlockJson(const EntrypointBasicBlock& block) {
  return Json{{"range", RangeJson(block.range)},
              {"owner_address", Hex(block.ownerAddress)},
              {"termination", block.termination}};
}

Json DirectEdgeJson(const EntrypointDirectEdge& edge) {
  return Json{{"site", Hex(edge.site)},
              {"source", Hex(edge.source)},
              {"target", Hex(edge.target)},
              {"kind", edge.kind}};
}

Json IndirectSiteJson(const EntrypointIndirectSite& site) {
  return Json{{"site", Hex(site.site)},
              {"owner_address", Hex(site.ownerAddress)},
              {"link", site.link},
              {"kind", site.kind}};
}

Json JumpInstructionEvidenceJson(const JumpTableInstructionEvidence& evidence) {
  return Json{{"address", Hex(evidence.address)},
              {"raw_instruction", Hex(evidence.rawInstruction)},
              {"role", evidence.role},
              {"instruction", evidence.instruction}};
}

Json JumpTableJson(const JumpTable& table) {
  Json targets = Json::array();
  for (uint32_t target : table.targets)
    targets.push_back(Hex(target));
  Json rawEntries = Json::array();
  for (const auto& entry : table.rawEntries) {
    rawEntries.push_back(Json{{"storage_address", Hex(entry.storageAddress)},
                              {"raw_value", Hex(entry.rawValue)},
                              {"target", Hex(entry.target)}});
  }
  Json evidence = Json::array();
  for (const auto& item : table.evidence)
    evidence.push_back(JumpInstructionEvidenceJson(item));
  return Json{
      {"dispatch_address", Hex(table.bctrAddress)},
      {"owner_address", Hex(table.ownerAddress)},
      {"origin", JumpTableOriginName(table.origin)},
      {"manual_comparison", JumpTableManualComparisonName(table.manualComparison)},
      {"kind", JumpTableKindName(table.kind)},
      {"table_address", Hex(table.tableAddress)},
      {"storage_end", Hex(table.storageEnd)},
      {"storage_size", Hex(table.storageEnd - table.tableAddress)},
      {"table_in_executable_section", table.tableInExecutableSection},
      {"index_register", table.indexRegister},
      {"bound_value", table.boundValue},
      {"bound_value_is_finite_index_domain", table.boundValueIsFiniteIndexDomain},
      {"bound_inclusive", table.boundInclusive},
      {"bound_semantics", table.boundSemantics},
      {"case_count", table.caseCount},
      {"default_target", table.defaultTarget ? Json(Hex(table.defaultTarget)) : Json(nullptr)},
      {"default_is_return", table.defaultIsReturn},
      {"element_width", table.elementWidth},
      {"element_signed", table.elementSigned},
      {"anchor_address", table.anchorAddress ? Json(Hex(table.anchorAddress)) : Json(nullptr)},
      {"target_scale", table.targetScale},
      {"targets", std::move(targets)},
      {"raw_entries", std::move(rawEntries)},
      {"instruction_evidence", std::move(evidence)},
      {"confidence", table.confidence},
      {"conflicts", table.conflicts}};
}

Json HexAddressArray(const std::vector<uint32_t>& addresses) {
  Json output = Json::array();
  for (uint32_t address : addresses)
    output.push_back(Hex(address));
  return output;
}

Json RegisterArray(const std::vector<uint8_t>& registers) {
  Json output = Json::array();
  for (uint8_t reg : registers)
    output.push_back(reg);
  return output;
}

Json StringArray(const std::vector<std::string>& values) {
  Json output = Json::array();
  for (const auto& value : values)
    output.push_back(value);
  return output;
}

Json JumpLoopEvidenceJson(const JumpTableLoopEvidence& loop) {
  return Json{{"register", loop.registerIndex},
              {"header_address", Hex(loop.headerAddress)},
              {"entry_definition_addresses", HexAddressArray(loop.entryDefinitionAddresses)},
              {"backedge_definition_addresses", HexAddressArray(loop.backedgeDefinitionAddresses)},
              {"entry_values", loop.entryValues},
              {"backedge_values", loop.backedgeValues},
              {"finite_values", loop.finiteValues},
              {"identity_backedge", loop.identityBackedge},
              {"finite_entry_domain", loop.finiteEntryDomain},
              {"converged", loop.converged}};
}

Json JumpCfgEdgeJson(const JumpTableCfgEdgeEvidence& edge) {
  return Json{{"source", Hex(edge.source)}, {"target", Hex(edge.target)}};
}

Json JumpBoundCandidateJson(const JumpTableBoundCandidateEvidence& bound) {
  Json finiteValues = Json::array();
  for (uint32_t value : bound.finiteValues)
    finiteValues.push_back(value);
  Json normalizedFiniteValues = Json::array();
  for (uint32_t value : bound.normalizedFiniteValues)
    normalizedFiniteValues.push_back(value);
  Json inheritedCaseEdges = Json::array();
  for (const auto& edge : bound.inheritedCaseEdges)
    inheritedCaseEdges.push_back(JumpCfgEdgeJson(edge));
  return Json{
      {"compare_address", bound.compareAddress ? Json(Hex(bound.compareAddress)) : Json(nullptr)},
      {"guard_address", bound.guardAddress ? Json(Hex(bound.guardAddress)) : Json(nullptr)},
      {"domain_origin_address",
       bound.domainOriginAddress ? Json(Hex(bound.domainOriginAddress)) : Json(nullptr)},
      {"value", bound.value},
      {"case_count", bound.caseCount},
      {"default_target", bound.defaultTarget ? Json(Hex(bound.defaultTarget)) : Json(nullptr)},
      {"index_register", bound.indexRegister == 0xFF ? Json(nullptr) : Json(bound.indexRegister)},
      {"inclusive", bound.inclusive},
      {"signed_compare", bound.signedCompare},
      {"default_is_return", bound.defaultIsReturn},
      {"dominates_dispatch", bound.dominatesDispatch},
      {"finite_dense_domain", bound.finiteDenseDomain},
      {"prior_exact_revalidation", bound.priorExactRevalidation},
      {"prior_direct_bounded_index_revalidation", bound.priorDirectBoundedIndexRevalidation},
      {"inherited_case_edge_proof", bound.inheritedCaseEdgeProof},
      {"inherited_finite_case_domain", bound.inheritedFiniteCaseDomain},
      {"finite_cfg_domain", bound.finiteCfgDomain},
      {"interprocedural_entry_domain", bound.interproceduralEntryDomain},
      {"self_delimited_inline_table_extent", bound.selfDelimitedInlineTableExtent},
      {"table_storage_start",
       bound.tableStorageStart ? Json(Hex(bound.tableStorageStart)) : Json(nullptr)},
      {"table_storage_end",
       bound.tableStorageEnd ? Json(Hex(bound.tableStorageEnd)) : Json(nullptr)},
      {"inline_boundary_cfg_verified", bound.inlineBoundaryCfgVerified},
      {"inline_boundary_block_start",
       bound.inlineBoundaryBlockStart ? Json(Hex(bound.inlineBoundaryBlockStart)) : Json(nullptr)},
      {"inline_boundary_block_end",
       bound.inlineBoundaryBlockEnd ? Json(Hex(bound.inlineBoundaryBlockEnd)) : Json(nullptr)},
      {"inline_boundary_terminator",
       bound.inlineBoundaryTerminator ? Json(Hex(bound.inlineBoundaryTerminator)) : Json(nullptr)},
      {"inline_case_loop_cfg_verified", bound.inlineCaseLoopCfgVerified},
      {"inline_case_loop_target",
       bound.inlineCaseLoopTarget ? Json(Hex(bound.inlineCaseLoopTarget)) : Json(nullptr)},
      {"inline_case_loop_header",
       bound.inlineCaseLoopHeader ? Json(Hex(bound.inlineCaseLoopHeader)) : Json(nullptr)},
      {"finite_values", std::move(finiteValues)},
      {"normalized_finite_values", std::move(normalizedFiniteValues)},
      {"inherited_case_edges", std::move(inheritedCaseEdges)},
      {"stack_spill_address",
       bound.stackSpillAddress ? Json(Hex(bound.stackSpillAddress)) : Json(nullptr)},
      {"stack_reload_address",
       bound.stackReloadAddress ? Json(Hex(bound.stackReloadAddress)) : Json(nullptr)},
      {"stack_slot_offset", bound.stackSlotOffset},
      {"stack_slot_width", bound.stackSlotWidth},
      {"rejection", bound.rejection.empty() ? Json(nullptr) : Json(bound.rejection)}};
}

Json JumpEntryCallsiteDomainJson(const JumpTableEntryCallsiteDomainEvidence& callsite) {
  return Json{
      {"caller_address", Hex(callsite.callerAddress)},
      {"call_address", Hex(callsite.callAddress)},
      {"target_address", Hex(callsite.targetAddress)},
      {"compare_address",
       callsite.compareAddress ? Json(Hex(callsite.compareAddress)) : Json(nullptr)},
      {"guard_address", callsite.guardAddress ? Json(Hex(callsite.guardAddress)) : Json(nullptr)},
      {"register", callsite.registerIndex == 0xFF ? Json(nullptr) : Json(callsite.registerIndex)},
      {"definition_addresses", HexAddressArray(callsite.definitionAddresses)},
      {"finite_values", callsite.finiteValues},
      {"caller_cfg_kind",
       callsite.callerCfgKind.empty() ? Json(nullptr) : Json(callsite.callerCfgKind)},
      {"caller_cfg_jump_table_sites", HexAddressArray(callsite.callerCfgJumpTableSites)},
      {"reachable_only_after_case_expansion", callsite.reachableOnlyAfterCaseExpansion},
      {"proof_kind", callsite.proofKind.empty() ? Json(nullptr) : Json(callsite.proofKind)},
      {"rejections", StringArray(callsite.rejections)},
      {"exhausted_budget",
       callsite.exhaustedBudget.empty() ? Json(nullptr) : Json(callsite.exhaustedBudget)},
      {"budget_limit", callsite.budgetLimit},
      {"budget_observed", callsite.budgetObserved},
      {"complete", callsite.complete},
      {"limit_hit", callsite.limitHit}};
}

Json JumpEntryRegisterDomainJson(const JumpTableEntryRegisterDomainEvidence& domain) {
  Json callsites = Json::array();
  for (const auto& callsite : domain.callsites)
    callsites.push_back(JumpEntryCallsiteDomainJson(callsite));
  return Json{
      {"entry_address", Hex(domain.entryAddress)},
      {"register", domain.registerIndex == 0xFF ? Json(nullptr) : Json(domain.registerIndex)},
      {"finite_values", domain.finiteValues},
      {"direct_call_sites", HexAddressArray(domain.directCallSites)},
      {"rejected_reference_sites", HexAddressArray(domain.rejectedReferenceSites)},
      {"reference_rejections", StringArray(domain.referenceRejections)},
      {"callsites", std::move(callsites)},
      {"all_references_direct_calls", domain.allReferencesDirectCalls},
      {"finite_dense_domain", domain.finiteDenseDomain},
      {"rejection", domain.rejection.empty() ? Json(nullptr) : Json(domain.rejection)}};
}

Json JumpBudgetExhaustionJson(const JumpTableBudgetExhaustionEvidence& exhaustion) {
  return Json{{"budget", exhaustion.budget},
              {"limit", exhaustion.limit},
              {"observed", exhaustion.observed}};
}

Json JumpReachingDefinitionPathJson(const JumpTableReachingDefinitionPathEvidence& path) {
  return Json{{"register", path.registerIndex},
              {"merge_address", Hex(path.mergeAddress)},
              {"predecessor", Hex(path.predecessor)},
              {"loop_header", Hex(path.loopHeader)},
              {"backedge", path.backedge},
              {"limit_hit", path.limitHit},
              {"expression", path.expression},
              {"normalized_expression", path.normalizedExpression},
              {"disposition", path.disposition}};
}

Json JumpDiagnosticProbeJson(const JumpTableDiagnosticProbe& probe) {
  return Json{{"attempted", probe.attempted},
              {"report_only", probe.reportOnly},
              {"hypothesis_complete", probe.hypothesisComplete},
              {"all_targets_valid", probe.allTargetsValid},
              {"mixed_validity", probe.mixedValidity},
              {"decoded_entries", probe.decodedEntries},
              {"aligned_executable_targets", probe.alignedExecutableTargets},
              {"assumptions", StringArray(probe.assumptions)},
              {"rejections", StringArray(probe.rejections)},
              {"candidate_table",
               probe.candidateTable ? JumpTableJson(*probe.candidateTable) : Json(nullptr)}};
}

Json JumpSiteDataflowJson(const JumpTableSiteDataflowEvidence& dataflow) {
  Json caseEdges = Json::array();
  for (const auto& edge : dataflow.caseExpansionEdges)
    caseEdges.push_back(JumpCfgEdgeJson(edge));
  Json backedges = Json::array();
  for (const auto& edge : dataflow.backedges)
    backedges.push_back(JumpCfgEdgeJson(edge));
  Json bounds = Json::array();
  for (const auto& bound : dataflow.boundCandidates)
    bounds.push_back(JumpBoundCandidateJson(bound));
  Json entryDomains = Json::array();
  for (const auto& domain : dataflow.entryRegisterDomains)
    entryDomains.push_back(JumpEntryRegisterDomainJson(domain));
  Json exhaustedBudgets = Json::array();
  for (const auto& exhaustion : dataflow.exhaustedBudgets)
    exhaustedBudgets.push_back(JumpBudgetExhaustionJson(exhaustion));
  Json reachingPaths = Json::array();
  for (const auto& path : dataflow.reachingDefinitionPaths)
    reachingPaths.push_back(JumpReachingDefinitionPathJson(path));
  return Json{
      {"preliminary_cfg_block", dataflow.preliminaryBlockStart
                                    ? Json{{"start", Hex(dataflow.preliminaryBlockStart)},
                                           {"end", Hex(dataflow.preliminaryBlockEnd)}}
                                    : Json(nullptr)},
      {"predecessors", HexAddressArray(dataflow.predecessors)},
      {"case_expanded_cfg", dataflow.caseExpandedCfg},
      {"case_expansion_edges", std::move(caseEdges)},
      {"source_in_scc", dataflow.sourceInScc},
      {"reaching_definition_in_scc", dataflow.reachingDefinitionInScc},
      {"loop_headers", HexAddressArray(dataflow.loopHeaders)},
      {"backedges", std::move(backedges)},
      {"loop_carried_registers", RegisterArray(dataflow.loopCarriedRegisters)},
      {"ctr_source_register",
       dataflow.ctrSourceRegister == 0xFF ? Json(nullptr) : Json(dataflow.ctrSourceRegister)},
      {"target_expression", dataflow.targetExpression},
      {"normalized_target_expression", dataflow.normalizedTargetExpression},
      {"reaching_definition_alternatives", StringArray(dataflow.reachingDefinitionAlternatives)},
      {"normalized_reaching_definitions", StringArray(dataflow.normalizedReachingDefinitions)},
      {"reaching_definition_paths", std::move(reachingPaths)},
      {"table_base_candidates", HexAddressArray(dataflow.tableBaseCandidates)},
      {"anchor_candidates", HexAddressArray(dataflow.anchorCandidates)},
      {"index_register",
       dataflow.indexRegister == 0xFF ? Json(nullptr) : Json(dataflow.indexRegister)},
      {"table_load_input_registers", RegisterArray(dataflow.tableLoadInputRegisters)},
      {"index_transform_chain", StringArray(dataflow.indexTransformChain)},
      {"element_width", dataflow.elementWidth},
      {"element_signedness", dataflow.elementSignedness},
      {"target_scale", dataflow.targetScale},
      {"bound_candidates", std::move(bounds)},
      {"entry_register_domains", std::move(entryDomains)},
      {"table_kind_hypothesis", dataflow.tableKindHypothesis},
      {"table_base_construction", dataflow.tableBaseConstruction},
      {"merge_shape", dataflow.mergeShape},
      {"failure_stage", dataflow.failureStage},
      {"dispatch_kind", dataflow.dispatchKind},
      {"cluster_id", dataflow.clusterId},
      {"switch_likelihood", JumpTableSwitchLikelihoodName(dataflow.switchLikelihood)},
      {"rejection_evidence", StringArray(dataflow.rejectionEvidence)},
      {"exhausted_budgets", std::move(exhaustedBudgets)},
      {"diagnostic_probe", JumpDiagnosticProbeJson(dataflow.diagnosticProbe)}};
}

const JumpTableSiteDataflowEvidence& JumpSiteDataflow(const IndirectSiteAnalysis& site) {
  static const JumpTableSiteDataflowEvidence empty;
  return site.dataflow ? *site.dataflow : empty;
}

Json JumpIndirectSiteJson(const IndirectSiteAnalysis& site) {
  Json failures = Json::array();
  for (auto failure : site.failures)
    failures.push_back(JumpTableFailureName(failure));
  Json evidence = Json::array();
  for (const auto& item : site.evidence)
    evidence.push_back(JumpInstructionEvidenceJson(item));
  Json limitRetry = nullptr;
  if (site.limitRetry) {
    Json initialFailures = Json::array();
    for (auto failure : site.limitRetry->initialFailures)
      initialFailures.push_back(JumpTableFailureName(failure));
    Json retryFailures = Json::array();
    for (auto failure : site.limitRetry->retryFailures)
      retryFailures.push_back(JumpTableFailureName(failure));
    Json initialExhaustedBudgets = Json::array();
    for (const auto& exhausted : site.limitRetry->initialExhaustedBudgets)
      initialExhaustedBudgets.push_back(JumpBudgetExhaustionJson(exhausted));
    Json retryExhaustedBudgets = Json::array();
    for (const auto& exhausted : site.limitRetry->retryExhaustedBudgets)
      retryExhaustedBudgets.push_back(JumpBudgetExhaustionJson(exhausted));
    limitRetry = Json{{"exhausted_budget", site.limitRetry->exhaustedBudget.empty()
                                               ? Json(nullptr)
                                               : Json(site.limitRetry->exhaustedBudget)},
                      {"initial_budget_value", site.limitRetry->initialBudgetValue},
                      {"retry_budget_value", site.limitRetry->retryBudgetValue},
                      {"initial_failures", std::move(initialFailures)},
                      {"retry_failures", std::move(retryFailures)},
                      {"initial_exhausted_budgets", std::move(initialExhaustedBudgets)},
                      {"retry_exhausted_budgets", std::move(retryExhaustedBudgets)},
                      {"exact_prior_table_match", site.limitRetry->exactPriorTableMatch},
                      {"accepted", site.limitRetry->accepted}};
  }
  Json loops = Json::array();
  for (const auto& loop : site.loopEvidence)
    loops.push_back(JumpLoopEvidenceJson(loop));
  return Json{
      {"site", Hex(site.site)},
      {"owner_address", Hex(site.ownerAddress)},
      {"classification", IndirectSiteClassificationName(site.classification)},
      {"link", site.link},
      {"conditional", site.conditional},
      {"uses_ctr", site.usesCtr},
      {"failures", std::move(failures)},
      {"limit_retry", std::move(limitRetry)},
      {"loop_evidence", std::move(loops)},
      {"dataflow", site.usesCtr && !site.link && site.dataflow
                       ? JumpSiteDataflowJson(*site.dataflow)
                       : Json(nullptr)},
      {"instruction_evidence", std::move(evidence)},
      {"automatic_table",
       site.automaticTable ? JumpTableJson(*site.automaticTable) : Json(nullptr)},
      {"selected_table", site.selectedTable ? JumpTableJson(*site.selectedTable) : Json(nullptr)}};
}

Json JumpClusterJson(const JumpTableClusterSummary& cluster) {
  return Json{{"cluster_id", cluster.clusterId},
              {"site_count", cluster.siteCount},
              {"recovered_count", cluster.recoveredCount},
              {"unresolved_count", cluster.unresolvedCount},
              {"representative_sites", HexAddressArray(cluster.representativeSites)},
              {"failure_counts", cluster.failureCounts},
              {"switch_likelihood_counts", cluster.switchLikelihoodCounts},
              {"normalized_slice", cluster.normalizedSlice},
              {"switch_evidence", StringArray(cluster.switchEvidence)},
              {"proposed_generic_correction", cluster.proposedGenericCorrection},
              {"synthetic_fixture_exists", cluster.syntheticFixtureExists},
              {"blocks_phase3_closure", cluster.blocksPhase3Closure}};
}

Json BoundaryEffectJson(const JumpTableBoundaryEffect& effect) {
  Json preliminaryBlocks = Json::array();
  for (const auto& block : effect.preliminaryBlocks)
    preliminaryBlocks.push_back(RangeJson(block));
  Json finalBlocks = Json::array();
  for (const auto& block : effect.finalBlocks)
    finalBlocks.push_back(RangeJson(block));
  Json cases = Json::array();
  for (uint32_t target : effect.caseTargets)
    cases.push_back(Hex(target));
  Json callable = Json::array();
  for (uint32_t target : effect.independentlyCallableCases)
    callable.push_back(Hex(target));
  return Json{{"owner_address", Hex(effect.ownerAddress)},
              {"owner_authority", effect.ownerAuthority},
              {"pdata_associated", effect.pdataAssociated},
              {"changed", effect.changed},
              {"preliminary_extent",
               effect.preliminaryExtent ? RangeJson(*effect.preliminaryExtent) : Json(nullptr)},
              {"final_extent", effect.finalExtent ? RangeJson(*effect.finalExtent) : Json(nullptr)},
              {"preliminary_blocks", std::move(preliminaryBlocks)},
              {"final_blocks", std::move(finalBlocks)},
              {"case_targets", std::move(cases)},
              {"independently_callable_cases", std::move(callable)}};
}

Json JumpTableRecoveryJson(const EntrypointJumpTableRecovery& recovery,
                           const EntrypointImageIdentity& image) {
  Json sites = Json::array();
  for (const auto& site : recovery.indirectSites)
    sites.push_back(JumpIndirectSiteJson(site));
  Json effects = Json::array();
  for (const auto& effect : recovery.boundaryEffects)
    effects.push_back(BoundaryEffectJson(effect));
  Json reclassified = Json::array();
  for (uint32_t address : recovery.staticCandidatesReclassifiedAsCases)
    reclassified.push_back(Hex(address));
  Json clusters = Json::array();
  for (const auto& cluster : recovery.clusters)
    clusters.push_back(JumpClusterJson(cluster));
  return Json{
      {"schema_version", recovery.schemaVersion},
      {"analyzer_version", recovery.analyzerVersion},
      {"image_identity",
       Json{{"patched_image_sha256", image.patchedImageSha256},
            {"executable_memory_fingerprint_algorithm", image.executableMemoryFingerprintAlgorithm},
            {"executable_memory_fingerprint", image.executableMemoryFingerprint},
            {"image_base", Hex(image.imageBase)},
            {"image_size", Hex(image.imageSize)},
            {"title_id", Hex(image.titleId)},
            {"media_id", Hex(image.mediaId)},
            {"version", image.version}}},
      {"limits", Json{{"max_backward_instructions", recovery.limits.maxBackwardInstructions},
                      {"max_predecessors", recovery.limits.maxPredecessors},
                      {"max_states", recovery.limits.maxStates},
                      {"max_cfg_topology_nodes", recovery.limits.maxCfgTopologyNodes},
                      {"max_entries", recovery.limits.maxEntries},
                      {"max_fixpoint_iterations", recovery.limits.maxFixpointIterations}}},
      {"stats", Json{{"decoded_instructions", recovery.stats.decodedInstructions},
                     {"max_function_fixpoint_iterations", recovery.stats.fixpointIterations},
                     {"indirect_sites", recovery.stats.indirectSites},
                     {"recovered_tables", recovery.stats.recoveredTables},
                     {"manual_tables", recovery.stats.manualTables},
                     {"unresolved_relevant_ctr_sites", recovery.stats.unresolvedSites},
                     {"analysis_limit_hit", recovery.stats.analysisLimitHit}}},
      {"indirect_sites", std::move(sites)},
      {"structural_clusters", std::move(clusters)},
      {"boundary_effects", std::move(effects)},
      {"static_candidates_reclassified_as_cases", std::move(reclassified)},
      {"manual_tables_authoritative", true},
      {"case_targets_are_functions_by_default", false}};
}

Json FunctionSeedJson(const EntrypointFunctionSeed& seed) {
  Json provenance = Json::array();
  for (const auto& item : seed.boundaryProvenance)
    provenance.push_back(item);
  Json blocks = Json::array();
  for (const auto& block : seed.blocks)
    blocks.push_back(RangeJson(block));
  Json edges = Json::array();
  for (const auto& edge : seed.directEdges)
    edges.push_back(DirectEdgeJson(edge));
  Json labels = Json::array();
  for (uint32_t address : seed.labels)
    labels.push_back(Hex(address));
  Json jumpTargets = Json::array();
  for (uint32_t address : seed.jumpTableTargets)
    jumpTargets.push_back(Hex(address));
  Json exceptionEntries = Json::array();
  for (uint32_t address : seed.exceptionEntries)
    exceptionEntries.push_back(Hex(address));

  return Json{{"range", RangeJson(seed.range)},
              {"authority", seed.authority},
              {"boundary_provenance", std::move(provenance)},
              {"trusted", seed.trusted},
              {"preliminary", seed.preliminary},
              {"manifest", seed.manifest},
              {"exception_function", seed.exceptionFunction},
              {"basic_blocks", std::move(blocks)},
              {"direct_edges", std::move(edges)},
              {"labels", std::move(labels)},
              {"jump_table_targets", std::move(jumpTargets)},
              {"exception_entries", std::move(exceptionEntries)}};
}

Json CandidateJson(const EntrypointCandidate& candidate) {
  Json evidence = Json::array();
  for (const auto& item : candidate.evidence)
    evidence.push_back(EvidenceJson(item));
  Json blocks = Json::array();
  for (const auto& block : candidate.basicBlocks)
    blocks.push_back(BasicBlockJson(block));
  Json edges = Json::array();
  for (const auto& edge : candidate.directEdges)
    edges.push_back(DirectEdgeJson(edge));
  Json indirectSites = Json::array();
  for (const auto& site : candidate.indirectSites)
    indirectSites.push_back(IndirectSiteJson(site));

  return Json{{"address", Hex(candidate.address)},
              {"proposed_range",
               candidate.proposedRange ? RangeJson(*candidate.proposedRange) : Json(nullptr)},
              {"classification", EntrypointClassificationName(candidate.classification)},
              {"confidence", EntrypointConfidenceName(candidate.confidence)},
              {"known_range_relationship", candidate.knownRangeRelationship},
              {"decoded_instruction", candidate.decodedInstruction},
              {"boundary_provenance", candidate.boundaryProvenance},
              {"evidence", std::move(evidence)},
              {"basic_blocks", std::move(blocks)},
              {"direct_edges", std::move(edges)},
              {"indirect_sites", std::move(indirectSites)},
              {"conflicts", candidate.conflicts},
              {"rejection_reasons", candidate.rejectionReasons},
              {"complete_traversal", candidate.completeTraversal},
              {"hit_instruction_limit", candidate.hitInstructionLimit},
              {"hit_depth_limit", candidate.hitDepthLimit}};
}

std::string CsvEscape(std::string value) {
  size_t position = 0;
  while ((position = value.find('"', position)) != std::string::npos) {
    value.insert(position, 1, '"');
    position += 2;
  }
  return '"' + value + '"';
}

std::string MarkdownTableEscape(std::string value) {
  size_t position = 0;
  while ((position = value.find('|', position)) != std::string::npos) {
    value.insert(position, 1, '\\');
    position += 2;
  }
  return value;
}

std::string JoinEvidenceKinds(const EntrypointCandidate& candidate) {
  std::set<std::string> kinds;
  for (const auto& evidence : candidate.evidence)
    kinds.emplace(EntrypointEvidenceKindName(evidence.kind));
  std::ostringstream stream;
  bool first = true;
  for (const auto& kind : kinds) {
    if (!first)
      stream << ';';
    stream << kind;
    first = false;
  }
  return stream.str();
}

std::string JoinAddresses(const EntrypointCandidate& candidate, bool storageAddresses) {
  std::set<uint32_t> addresses;
  for (const auto& evidence : candidate.evidence) {
    const auto& address = storageAddresses ? evidence.storageAddress : evidence.sourceAddress;
    if (address)
      addresses.insert(*address);
  }
  std::ostringstream stream;
  bool first = true;
  for (uint32_t address : addresses) {
    if (!first)
      stream << ';';
    stream << Hex(address);
    first = false;
  }
  return stream.str();
}

std::string JoinStrings(const std::vector<std::string>& values) {
  std::ostringstream stream;
  for (size_t i = 0; i < values.size(); ++i) {
    if (i)
      stream << ';';
    stream << values[i];
  }
  return stream.str();
}

bool WriteReportFile(const std::filesystem::path& path, std::string_view content) {
  return WriteIfChanged(path, content) != WriteOutcome::Failed;
}

Json FixtureJson(const EntrypointFixtureResult& fixture) {
  Json independentEvidence = Json::array();
  for (auto kind : fixture.independentEvidence)
    independentEvidence.push_back(EntrypointEvidenceKindName(kind));
  Json storageAddresses = Json::array();
  for (uint32_t address : fixture.storageAddresses)
    storageAddresses.push_back(Hex(address));
  Json materializationSites = Json::array();
  for (uint32_t address : fixture.materializationSites)
    materializationSites.push_back(Hex(address));
  return Json{
      {"expected", Json{{"address", Hex(fixture.expected.address)},
                        {"size", Hex(fixture.expected.size)},
                        {"verified_classification", fixture.expected.verifiedClassification}}},
      {"present", fixture.present},
      {"range_matches", fixture.rangeMatches},
      {"independently_rediscovered", fixture.independentlyRediscovered},
      {"independent_evidence", std::move(independentEvidence)},
      {"storage_addresses", std::move(storageAddresses)},
      {"materialization_sites", std::move(materializationSites)},
      {"result", fixture.result}};
}

template <typename Range, typename Convert>
void StreamJsonArray(std::ostream& output, const Range& values, Convert convert) {
  output << '[';
  bool first = true;
  for (const auto& value : values) {
    if (!first)
      output << ',';
    output << convert(value).dump();
    first = false;
  }
  output << ']';
}

void StreamEntrypointClosureJson(std::ostream& output, const EntrypointClosureReport& report) {
  const auto& image = report.image;
  const auto& limits = report.limits;
  const auto& counts = report.counts;
  output << "{\"schema_version\":" << report.schemaVersion
         << ",\"analyzer_version\":" << Json(report.analyzerVersion).dump()
         << ",\"image_identity\":"
         << Json{{"identity_method", image.identityMethod},
                 {"base_xex_sha256", image.baseXexSha256},
                 {"title_update_sha256", image.titleUpdateSha256},
                 {"patched_image_sha256", image.patchedImageSha256},
                 {"executable_memory_fingerprint_algorithm",
                  image.executableMemoryFingerprintAlgorithm},
                 {"executable_memory_fingerprint", image.executableMemoryFingerprint},
                 {"image_base", Hex(image.imageBase)},
                 {"image_size", Hex(image.imageSize)},
                 {"entry_point", Hex(image.entryPoint)},
                 {"title_id", Hex(image.titleId)},
                 {"media_id", Hex(image.mediaId)},
                 {"version", image.version},
                 {"pe_time_date_stamp", Hex(image.peTimeDateStamp)}}
                .dump()
         << ",\"sections\":";
  StreamJsonArray(output, report.sections, [](const auto& section) {
    return Json{{"name", section.name},         {"range", RangeJson(section.range)},
                {"sha256", section.sha256},     {"executable", section.executable},
                {"readable", section.readable}, {"writable", section.writable}};
  });
  output << ",\"executable_ranges\":[";
  bool firstExecutable = true;
  for (const auto& section : report.sections) {
    if (!section.executable)
      continue;
    if (!firstExecutable)
      output << ',';
    output << Json{{"section", section.name}, {"range", RangeJson(section.range)}}.dump();
    firstExecutable = false;
  }
  output << "],\"limits\":"
         << Json{{"max_iterations", limits.maxIterations},
                 {"max_candidates", limits.maxCandidates},
                 {"max_instructions_per_candidate", limits.maxInstructionsPerCandidate},
                 {"max_traversal_depth", limits.maxTraversalDepth},
                 {"max_pointer_run_entries", limits.maxPointerRunEntries},
                 {"materialization_window", limits.materializationWindow}}
                .dump()
         << ",\"counts\":"
         << Json{{"trusted_ranges", counts.trustedRanges},
                 {"preliminary_ranges", counts.preliminaryRanges},
                 {"candidates", counts.candidates},
                 {"strong_new_functions", counts.strongNewFunctions},
                 {"probable_new_functions", counts.probableNewFunctions},
                 {"ambiguous_candidates", counts.ambiguousCandidates},
                 {"rejected_candidates", counts.rejectedCandidates},
                 {"pointer_storage_sites", counts.pointerStorageSites},
                 {"pointer_runs", counts.pointerRuns},
                 {"relocation_storage_sites", counts.relocationStorageSites},
                 {"pe_exports", counts.peExports},
                 {"tls_callbacks", counts.tlsCallbacks},
                 {"indirect_sites", counts.indirectSites},
                 {"candidate_overlap_pairs", counts.candidateOverlapPairs}}
                .dump()
         << ",\"function_ranges\":";
  StreamJsonArray(output, report.functionRanges,
                  [](const auto& seed) { return FunctionSeedJson(seed); });
  output << ",\"direct_edges\":";
  StreamJsonArray(output, report.directEdges,
                  [](const auto& edge) { return DirectEdgeJson(edge); });
  output << ",\"indirect_sites\":";
  StreamJsonArray(output, report.indirectSites,
                  [](const auto& site) { return IndirectSiteJson(site); });
  output << ",\"jump_table_recovery\":"
         << JumpTableRecoveryJson(report.jumpTableRecovery, report.image).dump();
  output << ",\"candidates\":";
  StreamJsonArray(output, report.candidates,
                  [](const auto& candidate) { return CandidateJson(candidate); });
  output << ",\"fixpoint\":{\"reached\":" << (report.fixpointReached ? "true" : "false")
         << ",\"iterations\":";
  StreamJsonArray(output, report.fixpointIterations, [](const auto& iteration) {
    return Json{{"iteration", iteration.iteration},
                {"candidates_before", iteration.candidatesBefore},
                {"candidates_after", iteration.candidatesAfter},
                {"new_direct_call_targets", iteration.newDirectCallTargets},
                {"new_tail_branch_targets", iteration.newTailBranchTargets},
                {"new_evidence_records", iteration.newEvidenceRecords},
                {"classifications_changed", iteration.classificationsChanged}};
  });
  output << "},\"limit_diagnostics\":";
  StreamJsonArray(output, report.limitDiagnostics, [](const auto& diagnostic) {
    return Json{{"limit", diagnostic.limit},
                {"configured", diagnostic.configured},
                {"observed", diagnostic.observed},
                {"address", OptionalAddressJson(diagnostic.address)},
                {"detail", diagnostic.detail}};
  });
  output << ",\"fixture_results\":";
  StreamJsonArray(output, report.fixtureResults,
                  [](const auto& fixture) { return FixtureJson(fixture); });
  output << ",\"manifest_comparison\":"
         << Json{{"existing_manifest_ranges",
                  std::count_if(report.functionRanges.begin(), report.functionRanges.end(),
                                [](const auto& seed) { return seed.manifest; })},
                 {"strong_new_functions", counts.strongNewFunctions},
                 {"probable_new_functions", counts.probableNewFunctions}}
                .dump()
         << ",\"safety\":"
         << Json{{"mode", "report_only"},
                 {"manifest_mutation_attempted", report.manifestMutationAttempted},
                 {"review_toml_is_non_authoritative", true}}
                .dump()
         << ",\"run_metadata\":{\"separate_file\":" << Json("entrypoint-closure-run.json").dump()
         << "}}\n";
}

}  // namespace

std::string SerializeEntrypointClosureJson(const EntrypointClosureReport& report) {
  std::ostringstream output;
  StreamEntrypointClosureJson(output, report);
  return output.str();
}

Result<void> WriteEntrypointClosureReports(const EntrypointClosureReport& report,
                                           const EntrypointClosureRunMetadata& runMetadata,
                                           const std::filesystem::path& outputDirectory,
                                           bool writeReviewToml) {
  using Clock = std::chrono::steady_clock;
  const auto serializationStarted = Clock::now();
  auto elapsedMicroseconds = [](Clock::time_point started) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started).count());
  };
  uint64_t jsonMicroseconds = 0;
  uint64_t csvMicroseconds = 0;
  uint64_t markdownMicroseconds = 0;
  uint64_t reviewTomlMicroseconds = 0;

  std::error_code error;
  std::filesystem::create_directories(outputDirectory, error);
  if (error) {
    return Err(ErrorCategory::IO, fmt::format("Unable to create analysis output directory '{}': {}",
                                              outputDirectory.string(), error.message()));
  }

  auto formatStarted = Clock::now();
  std::ofstream jsonOutput(outputDirectory / "entrypoint-closure.json",
                           std::ios::binary | std::ios::trunc);
  if (!jsonOutput) {
    return Err(ErrorCategory::IO, "Unable to open entrypoint-closure.json for writing");
  }
  StreamEntrypointClosureJson(jsonOutput, report);
  jsonOutput.close();
  if (!jsonOutput)
    return Err(ErrorCategory::IO, "Unable to write entrypoint-closure.json");
  jsonMicroseconds += elapsedMicroseconds(formatStarted);

  formatStarted = Clock::now();
  std::ostringstream csv;
  csv << "address,end,size,classification,confidence,known_range_relationship,"
         "complete_traversal,evidence_kinds,storage_addresses,source_addresses,"
         "conflicts,rejection_reasons,boundary_provenance\n";
  for (const auto& candidate : report.candidates) {
    csv << Hex(candidate.address) << ',';
    if (candidate.proposedRange) {
      csv << Hex(candidate.proposedRange->end) << ',' << Hex(candidate.proposedRange->size());
    } else {
      csv << ',';
    }
    csv << ',' << EntrypointClassificationName(candidate.classification) << ','
        << EntrypointConfidenceName(candidate.confidence) << ','
        << CsvEscape(candidate.knownRangeRelationship) << ','
        << (candidate.completeTraversal ? "true" : "false") << ','
        << CsvEscape(JoinEvidenceKinds(candidate)) << ','
        << CsvEscape(JoinAddresses(candidate, true)) << ','
        << CsvEscape(JoinAddresses(candidate, false)) << ','
        << CsvEscape(JoinStrings(candidate.conflicts)) << ','
        << CsvEscape(JoinStrings(candidate.rejectionReasons)) << ','
        << CsvEscape(candidate.boundaryProvenance) << '\n';
  }
  if (!WriteReportFile(outputDirectory / "entrypoint-closure.csv", csv.str())) {
    return Err(ErrorCategory::IO, "Unable to write entrypoint-closure.csv");
  }
  csvMicroseconds += elapsedMicroseconds(formatStarted);

  formatStarted = Clock::now();
  std::ostringstream markdown;
  markdown << "# Static entrypoint-closure report\n\n"
           << "Authoritative data: `entrypoint-closure.json` (schema " << report.schemaVersion
           << ", analyser " << report.analyzerVersion
           << "). Volatile measurements are in `entrypoint-closure-run.json`.\n\n"
           << "- Patched image SHA-256: `" << report.image.patchedImageSha256 << "`\n"
           << "- Executable-memory fingerprint (`"
           << report.image.executableMemoryFingerprintAlgorithm << "`): `"
           << report.image.executableMemoryFingerprint << "`\n"
           << "- Image: `" << Hex(report.image.imageBase) << "` + `" << Hex(report.image.imageSize)
           << "`\n"
           << "- Fixpoint reached: " << (report.fixpointReached ? "yes" : "no") << " after "
           << report.fixpointIterations.size() << " iteration(s)\n"
           << "- Trusted/preliminary ranges: " << report.counts.trustedRanges << "/"
           << report.counts.preliminaryRanges << "\n"
           << "- Candidates: " << report.counts.candidates << "\n"
           << "- Strong/probable new functions: " << report.counts.strongNewFunctions << "/"
           << report.counts.probableNewFunctions << "\n"
           << "- Ambiguous/rejected candidates: " << report.counts.ambiguousCandidates << "/"
           << report.counts.rejectedCandidates << "\n"
           << "- Proposed candidate-range overlap pairs: " << report.counts.candidateOverlapPairs
           << "\n"
           << "- Safety-limit diagnostics: " << report.limitDiagnostics.size()
           << "\n\n## Acceptance fixtures\n\n"
           << "| Address | Expected range | Independent | Storage / xref sites | Result |\n"
           << "|---|---:|:---:|---|---|\n";
  for (const auto& fixture : report.fixtureResults) {
    std::ostringstream sites;
    for (uint32_t address : fixture.storageAddresses)
      sites << Hex(address) << " ";
    for (uint32_t address : fixture.materializationSites)
      sites << Hex(address) << " ";
    markdown << "| `" << Hex(fixture.expected.address) << "` | `" << Hex(fixture.expected.address)
             << "-" << Hex(fixture.expected.address + fixture.expected.size) << "` | "
             << (fixture.independentlyRediscovered ? "yes" : "no") << " | `" << sites.str()
             << "` | " << fixture.result << " |\n";
  }
  markdown << "\n## Review queue\n\n";
  for (const auto& candidate : report.candidates) {
    if (candidate.classification != EntrypointClassification::StrongNewFunction &&
        candidate.classification != EntrypointClassification::ProbableNewFunction)
      continue;
    markdown << "- `" << Hex(candidate.address) << "` — "
             << EntrypointClassificationName(candidate.classification);
    if (candidate.proposedRange)
      markdown << ", proposed size `" << Hex(candidate.proposedRange->size()) << "`";
    markdown << ", evidence: " << JoinEvidenceKinds(candidate) << "\n";
  }
  if (!WriteReportFile(outputDirectory / "entrypoint-closure.md", markdown.str())) {
    return Err(ErrorCategory::IO, "Unable to write entrypoint-closure.md");
  }
  markdownMicroseconds += elapsedMicroseconds(formatStarted);

  formatStarted = Clock::now();
  const auto jumpJson = JumpTableRecoveryJson(report.jumpTableRecovery, report.image);
  if (!WriteReportFile(outputDirectory / "jump-table-recovery.json", jumpJson.dump(2) + '\n')) {
    return Err(ErrorCategory::IO, "Unable to write jump-table-recovery.json");
  }
  jsonMicroseconds += elapsedMicroseconds(formatStarted);

  formatStarted = Clock::now();
  std::ostringstream jumpCsv;
  jumpCsv << "site,owner,classification,link,conditional,uses_ctr,recovered,origin,kind,"
             "table_start,table_end,case_count,targets,failures,manual_comparison,cluster_id,"
             "switch_likelihood,preliminary_block,predecessors,case_expanded_cfg,source_in_scc,"
             "loop_headers,ctr_source_register,normalized_target_expression,"
             "table_load_input_registers,index_transforms,"
             "element_width,element_signedness,target_scale,bound_candidates,"
             "entry_register_domains,diagnostic_probe,reaching_definition_paths,"
             "exhausted_budgets,limit_retry,rejection_evidence\n";
  for (const auto& site : report.jumpTableRecovery.indirectSites) {
    const JumpTable* table = site.selectedTable ? &*site.selectedTable : nullptr;
    const auto& dataflow = JumpSiteDataflow(site);
    std::ostringstream targets;
    if (table) {
      for (size_t index = 0; index < table->targets.size(); ++index) {
        if (index)
          targets << ';';
        targets << Hex(table->targets[index]);
      }
    }
    std::ostringstream failures;
    for (size_t index = 0; index < site.failures.size(); ++index) {
      if (index)
        failures << ';';
      failures << JumpTableFailureName(site.failures[index]);
    }
    std::ostringstream predecessors;
    for (size_t index = 0; index < dataflow.predecessors.size(); ++index) {
      if (index)
        predecessors << ';';
      predecessors << Hex(dataflow.predecessors[index]);
    }
    std::ostringstream loopHeaders;
    for (size_t index = 0; index < dataflow.loopHeaders.size(); ++index) {
      if (index)
        loopHeaders << ';';
      loopHeaders << Hex(dataflow.loopHeaders[index]);
    }
    std::ostringstream bounds;
    for (size_t index = 0; index < dataflow.boundCandidates.size(); ++index) {
      if (index)
        bounds << ';';
      const auto& bound = dataflow.boundCandidates[index];
      std::string proofKind = "current_guard";
      if (bound.priorDirectBoundedIndexRevalidation)
        proofKind = "direct_bounded_prior";
      else if (bound.priorExactRevalidation)
        proofKind = "exact_prior";
      else if (bound.inheritedFiniteCaseDomain)
        proofKind = "inherited_finite_case_domain";
      else if (bound.selfDelimitedInlineTableExtent)
        proofKind = "self_delimited_inline_table_extent";
      else if (bound.inheritedCaseEdgeProof)
        proofKind = "inherited_case_edge";
      else if (bound.finiteCfgDomain)
        proofKind = "finite_cfg_domain";
      else if (bound.interproceduralEntryDomain)
        proofKind = "interprocedural_entry_domain";
      const char* domainDisposition = bound.selfDelimitedInlineTableExtent ? "finite_table_extent"
                                      : bound.finiteDenseDomain            ? "finite"
                                                                           : "rejected";
      bounds << (bound.compareAddress ? Hex(bound.compareAddress) : Hex(bound.domainOriginAddress))
             << ':' << bound.caseCount << ':'
             << (bound.dominatesDispatch ? "dominates" : "not_dominating") << ':'
             << domainDisposition << ':' << proofKind;
      if (!bound.rejection.empty())
        bounds << ':' << bound.rejection;
    }
    std::ostringstream entryDomains;
    for (size_t index = 0; index < dataflow.entryRegisterDomains.size(); ++index) {
      if (index)
        entryDomains << ';';
      const auto& domain = dataflow.entryRegisterDomains[index];
      entryDomains << Hex(domain.entryAddress) << ":r"
                   << static_cast<uint32_t>(domain.registerIndex) << ":refs="
                   << (domain.allReferencesDirectCalls ? "all_direct_calls" : "incomplete")
                   << ":domain=" << (domain.finiteDenseDomain ? "finite_dense" : "rejected")
                   << ":values=";
      for (size_t valueIndex = 0; valueIndex < domain.finiteValues.size(); ++valueIndex) {
        if (valueIndex)
          entryDomains << '|';
        entryDomains << domain.finiteValues[valueIndex];
      }
      entryDomains << ":calls=";
      for (size_t callIndex = 0; callIndex < domain.callsites.size(); ++callIndex) {
        if (callIndex)
          entryDomains << '|';
        const auto& callsite = domain.callsites[callIndex];
        entryDomains << Hex(callsite.callAddress) << '/'
                     << (callsite.complete ? callsite.proofKind : "rejected");
        if (!callsite.exhaustedBudget.empty()) {
          entryDomains << "/budget=" << callsite.exhaustedBudget << ':' << callsite.budgetLimit
                       << ':' << callsite.budgetObserved;
        } else if (callsite.limitHit) {
          entryDomains << "/limit=unattributed";
        }
        if (!callsite.rejections.empty())
          entryDomains << "/reason=" << JoinStrings(callsite.rejections);
      }
      if (!domain.rejection.empty())
        entryDomains << ":reason=" << domain.rejection;
    }
    std::string probe = "not_attempted";
    if (dataflow.diagnosticProbe.attempted) {
      if (dataflow.diagnosticProbe.hypothesisComplete && dataflow.diagnosticProbe.allTargetsValid) {
        probe = "complete_valid";
      } else if (dataflow.diagnosticProbe.mixedValidity) {
        probe = "mixed_validity";
      } else {
        probe = "rejected:" + JoinStrings(dataflow.diagnosticProbe.rejections);
      }
    }
    std::ostringstream reachingPaths;
    for (size_t index = 0; index < dataflow.reachingDefinitionPaths.size(); ++index) {
      if (index)
        reachingPaths << ';';
      const auto& path = dataflow.reachingDefinitionPaths[index];
      reachingPaths << 'r' << static_cast<uint32_t>(path.registerIndex) << ':'
                    << Hex(path.mergeAddress) << "<-" << Hex(path.predecessor) << ':'
                    << path.normalizedExpression << ':' << path.disposition;
    }
    std::ostringstream exhaustedBudgets;
    for (size_t index = 0; index < dataflow.exhaustedBudgets.size(); ++index) {
      if (index)
        exhaustedBudgets << ';';
      const auto& budget = dataflow.exhaustedBudgets[index];
      exhaustedBudgets << budget.budget << ':' << budget.limit << ':' << budget.observed;
    }
    std::ostringstream limitRetry;
    if (site.limitRetry) {
      limitRetry << site.limitRetry->exhaustedBudget << ':' << site.limitRetry->initialBudgetValue
                 << "->" << site.limitRetry->retryBudgetValue
                 << ":exact=" << (site.limitRetry->exactPriorTableMatch ? "true" : "false")
                 << ":accepted=" << (site.limitRetry->accepted ? "true" : "false")
                 << ":initial_failures=";
      for (size_t index = 0; index < site.limitRetry->initialFailures.size(); ++index) {
        if (index)
          limitRetry << '+';
        limitRetry << JumpTableFailureName(site.limitRetry->initialFailures[index]);
      }
      limitRetry << ":retry_failures=";
      for (size_t index = 0; index < site.limitRetry->retryFailures.size(); ++index) {
        if (index)
          limitRetry << '+';
        limitRetry << JumpTableFailureName(site.limitRetry->retryFailures[index]);
      }
      limitRetry << ":initial_exhausted=";
      for (size_t index = 0; index < site.limitRetry->initialExhaustedBudgets.size(); ++index) {
        if (index)
          limitRetry << '+';
        const auto& budget = site.limitRetry->initialExhaustedBudgets[index];
        limitRetry << budget.budget << ':' << budget.limit << ':' << budget.observed;
      }
      limitRetry << ":retry_exhausted=";
      for (size_t index = 0; index < site.limitRetry->retryExhaustedBudgets.size(); ++index) {
        if (index)
          limitRetry << '+';
        const auto& budget = site.limitRetry->retryExhaustedBudgets[index];
        limitRetry << budget.budget << ':' << budget.limit << ':' << budget.observed;
      }
    }
    const std::string preliminaryBlock =
        dataflow.preliminaryBlockStart
            ? Hex(dataflow.preliminaryBlockStart) + "-" + Hex(dataflow.preliminaryBlockEnd)
            : "";
    jumpCsv << Hex(site.site) << ',' << Hex(site.ownerAddress) << ','
            << IndirectSiteClassificationName(site.classification) << ','
            << (site.link ? "true" : "false") << ',' << (site.conditional ? "true" : "false") << ','
            << (site.usesCtr ? "true" : "false") << ',' << (table ? "true" : "false") << ','
            << (table ? JumpTableOriginName(table->origin) : "") << ','
            << (table ? JumpTableKindName(table->kind) : "") << ','
            << (table ? Hex(table->tableAddress) : "") << ','
            << (table ? Hex(table->storageEnd) : "") << ','
            << (table ? std::to_string(table->caseCount) : "") << ',' << CsvEscape(targets.str())
            << ',' << CsvEscape(failures.str()) << ','
            << (table ? JumpTableManualComparisonName(table->manualComparison) : "") << ','
            << CsvEscape(dataflow.clusterId) << ','
            << JumpTableSwitchLikelihoodName(dataflow.switchLikelihood) << ','
            << CsvEscape(preliminaryBlock) << ',' << CsvEscape(predecessors.str()) << ','
            << (dataflow.caseExpandedCfg ? "true" : "false") << ','
            << (dataflow.sourceInScc ? "true" : "false") << ',' << CsvEscape(loopHeaders.str())
            << ','
            << (dataflow.ctrSourceRegister == 0xFF ? ""
                                                   : std::to_string(dataflow.ctrSourceRegister))
            << ',' << CsvEscape(dataflow.normalizedTargetExpression) << ',';
    for (size_t index = 0; index < dataflow.tableLoadInputRegisters.size(); ++index) {
      if (index)
        jumpCsv << ';';
      jumpCsv << static_cast<uint32_t>(dataflow.tableLoadInputRegisters[index]);
    }
    jumpCsv << ',' << CsvEscape(JoinStrings(dataflow.indexTransformChain)) << ','
            << (dataflow.elementWidth ? std::to_string(dataflow.elementWidth) : "") << ','
            << dataflow.elementSignedness << ',' << dataflow.targetScale << ','
            << CsvEscape(bounds.str()) << ',' << CsvEscape(entryDomains.str()) << ','
            << CsvEscape(probe) << ',' << CsvEscape(reachingPaths.str()) << ','
            << CsvEscape(exhaustedBudgets.str()) << ',' << CsvEscape(limitRetry.str()) << ','
            << CsvEscape(JoinStrings(dataflow.rejectionEvidence)) << '\n';
  }
  if (!WriteReportFile(outputDirectory / "jump-table-recovery.csv", jumpCsv.str())) {
    return Err(ErrorCategory::IO, "Unable to write jump-table-recovery.csv");
  }
  csvMicroseconds += elapsedMicroseconds(formatStarted);

  std::map<std::string, uint32_t> classifications;
  std::map<std::string, uint32_t> failures;
  std::map<std::string, uint32_t> switchLikelihoods;
  for (const auto& site : report.jumpTableRecovery.indirectSites) {
    classifications[IndirectSiteClassificationName(site.classification)]++;
    for (auto failure : site.failures)
      failures[JumpTableFailureName(failure)]++;
    if (site.usesCtr && !site.link)
      switchLikelihoods[JumpTableSwitchLikelihoodName(JumpSiteDataflow(site).switchLikelihood)]++;
  }
  formatStarted = Clock::now();
  std::ostringstream jumpMarkdown;
  jumpMarkdown << "# PPC jump-table recovery report\n\n"
               << "Authoritative data: `jump-table-recovery.json` (schema "
               << report.jumpTableRecovery.schemaVersion << ", analyser "
               << report.jumpTableRecovery.analyzerVersion << ").\n\n"
               << "- Patched image SHA-256: `" << report.image.patchedImageSha256 << "`\n"
               << "- Relevant indirect sites: " << report.jumpTableRecovery.stats.indirectSites
               << "\n"
               << "- Automatically recovered tables: "
               << report.jumpTableRecovery.stats.recoveredTables << "\n"
               << "- Manual selected tables: " << report.jumpTableRecovery.stats.manualTables
               << "\n"
               << "- Unresolved relevant CTR sites: "
               << report.jumpTableRecovery.stats.unresolvedSites << "\n"
               << "- Max per-function fixpoint iterations: "
               << report.jumpTableRecovery.stats.fixpointIterations << "\n"
               << "- Decoded instructions visited by recovery: "
               << report.jumpTableRecovery.stats.decodedInstructions << "\n"
               << "- Boundary effects: " << report.jumpTableRecovery.boundaryEffects.size() << " ("
               << std::count_if(report.jumpTableRecovery.boundaryEffects.begin(),
                                report.jumpTableRecovery.boundaryEffects.end(),
                                [](const auto& effect) { return effect.changed; })
               << " changed)\n\n## Classifications\n\n";
  for (const auto& [name, count] : classifications)
    jumpMarkdown << "- `" << name << "`: " << count << "\n";
  jumpMarkdown << "\n## Unresolved reasons\n\n";
  for (const auto& [name, count] : failures)
    jumpMarkdown << "- `" << name << "`: " << count << "\n";
  jumpMarkdown << "\n## Switch-likelihood census\n\n";
  for (const auto& [name, count] : switchLikelihoods)
    jumpMarkdown << "- `" << name << "`: " << count << "\n";
  jumpMarkdown << "\n## Structural clusters\n\n"
                  "| Cluster | Sites | Recovered | Unresolved | Likelihoods | Representatives | "
                  "Blocks closure |\n"
                  "|---|---:|---:|---:|---|---|---|\n";
  for (const auto& cluster : report.jumpTableRecovery.clusters) {
    std::ostringstream likelihoods;
    for (const auto& [name, count] : cluster.switchLikelihoodCounts) {
      if (likelihoods.tellp() > 0)
        likelihoods << "; ";
      likelihoods << name << '=' << count;
    }
    std::ostringstream representatives;
    for (size_t index = 0; index < cluster.representativeSites.size(); ++index) {
      if (index)
        representatives << ' ';
      representatives << '`' << Hex(cluster.representativeSites[index]) << '`';
    }
    jumpMarkdown << "| `" << MarkdownTableEscape(cluster.clusterId) << "` | " << cluster.siteCount
                 << " | " << cluster.recoveredCount << " | " << cluster.unresolvedCount << " | `"
                 << likelihoods.str() << "` | " << representatives.str() << " | "
                 << (cluster.blocksPhase3Closure ? "yes" : "no") << " |\n";
  }
  jumpMarkdown << "\n## Structural-cluster evidence\n\n";
  for (const auto& cluster : report.jumpTableRecovery.clusters) {
    std::ostringstream failureCensus;
    for (const auto& [name, count] : cluster.failureCounts) {
      if (failureCensus.tellp() > 0)
        failureCensus << "; ";
      failureCensus << name << '=' << count;
    }
    jumpMarkdown << "### `" << cluster.clusterId << "`\n\n"
                 << "- Normalized slice: `" << cluster.normalizedSlice << "`\n"
                 << "- Failure census: `" << failureCensus.str() << "`\n"
                 << "- Switch evidence: `" << JoinStrings(cluster.switchEvidence) << "`\n"
                 << "- Proposed generic correction: " << cluster.proposedGenericCorrection << "\n"
                 << "- Synthetic fixture: " << (cluster.syntheticFixtureExists ? "yes" : "no")
                 << "\n"
                 << "- Blocks Phase 3 closure: " << (cluster.blocksPhase3Closure ? "yes" : "no")
                 << "\n\n";
  }
  jumpMarkdown << "\n## Recovered tables\n\n"
                  "| Dispatch | Owner | Kind | Cases | Storage | Manual comparison |\n"
                  "|---|---|---|---:|---|---|\n";
  for (const auto& site : report.jumpTableRecovery.indirectSites) {
    if (!site.selectedTable)
      continue;
    const auto& table = *site.selectedTable;
    jumpMarkdown << "| `" << Hex(site.site) << "` | `" << Hex(site.ownerAddress) << "` | `"
                 << JumpTableKindName(table.kind) << "` | " << table.caseCount << " | `"
                 << Hex(table.tableAddress) << "-" << Hex(table.storageEnd) << "` | `"
                 << JumpTableManualComparisonName(table.manualComparison) << "` |\n";
  }
  jumpMarkdown
      << "\n## Unresolved relevant CTR sites\n\n"
         "| Site | Owner | Classification | Reasons | Switch likelihood | Probe | Cluster |\n"
         "|---|---|---|---|---|---|---|\n";
  for (const auto& site : report.jumpTableRecovery.indirectSites) {
    if (!site.usesCtr || site.link || site.selectedTable)
      continue;
    const auto& dataflow = JumpSiteDataflow(site);
    std::ostringstream reasons;
    for (auto failure : site.failures)
      reasons << JumpTableFailureName(failure) << ' ';
    std::string probe = "not attempted";
    if (dataflow.diagnosticProbe.hypothesisComplete && dataflow.diagnosticProbe.allTargetsValid) {
      probe = "complete valid table";
    } else if (dataflow.diagnosticProbe.mixedValidity) {
      probe = "mixed validity";
    } else if (dataflow.diagnosticProbe.attempted) {
      probe = JoinStrings(dataflow.diagnosticProbe.rejections);
    }
    jumpMarkdown << "| `" << Hex(site.site) << "` | `" << Hex(site.ownerAddress) << "` | `"
                 << IndirectSiteClassificationName(site.classification) << "` | `" << reasons.str()
                 << "` | `" << JumpTableSwitchLikelihoodName(dataflow.switchLikelihood) << "` | "
                 << probe << " | `" << MarkdownTableEscape(dataflow.clusterId) << "` |\n";
  }
  if (!WriteReportFile(outputDirectory / "jump-table-recovery.md", jumpMarkdown.str())) {
    return Err(ErrorCategory::IO, "Unable to write jump-table-recovery.md");
  }
  markdownMicroseconds += elapsedMicroseconds(formatStarted);

  if (writeReviewToml) {
    formatStarted = Clock::now();
    std::ostringstream toml;
    toml << "# REVIEW ONLY: not loaded or applied by ReXGlue.\n"
            "# Verify every boundary against the patched image before editing a manifest.\n\n"
            "[entrypoint.functions]\n";
    for (const auto& candidate : report.candidates) {
      if ((candidate.classification != EntrypointClassification::StrongNewFunction &&
           candidate.classification != EntrypointClassification::ProbableNewFunction) ||
          !candidate.proposedRange)
        continue;
      toml << '"' << Hex(candidate.address)
           << "\" = { size = " << Hex(candidate.proposedRange->size()) << " } # "
           << EntrypointClassificationName(candidate.classification) << '\n';
    }
    if (!WriteReportFile(outputDirectory / "entrypoint-closure-review.toml", toml.str())) {
      return Err(ErrorCategory::IO, "Unable to write entrypoint-closure-review.toml");
    }
    reviewTomlMicroseconds += elapsedMicroseconds(formatStarted);
  }

  const uint64_t totalSerializationMicroseconds = elapsedMicroseconds(serializationStarted);
  const auto& stages = runMetadata.stageTimings;
  Json stageJson{
      {"image_xex_loading", stages.imageLoadMicroseconds},
      {"identity_verification", stages.identityVerificationMicroseconds},
      {"instruction_decode_cache_population", stages.instructionDecodeMicroseconds},
      {"register_phase", stages.registerMicroseconds},
      {"scan_phase", stages.scanMicroseconds},
      {"discover_phase", stages.discoverMicroseconds},
      {"gap_fill_phase", stages.gapFillMicroseconds},
      {"final_ownership_boundary_calculation", stages.finalOwnershipMicroseconds},
      {"validate_phase", stages.validateMicroseconds},
      {"preliminary_cfg_discovery", stages.preliminaryCfgMicroseconds},
      {"indirect_site_classification", stages.indirectSiteClassificationMicroseconds},
      {"jump_table_dataflow_recovery", stages.jumpTableDataflowRecoveryMicroseconds},
      {"case_target_cfg_expansion", stages.caseTargetCfgExpansionMicroseconds},
      {"per_function_fixpoint_work", stages.perFunctionFixpointMicroseconds},
      {"fixpoint_bookkeeping", stages.fixpointOverheadMicroseconds},
      {"function_seed_construction", stages.functionSeedConstructionMicroseconds},
      {"jump_table_report_construction", stages.jumpTableReportConstructionMicroseconds},
      {"entrypoint_closure_integration", stages.closureAnalysisMicroseconds},
      {"section_hashing", stages.sectionHashingMicroseconds},
      {"ghidra_evidence_diff_integration", stages.ghidraIntegrationMicroseconds},
  };
  Json serializationJson{{"json", jsonMicroseconds},
                         {"csv", csvMicroseconds},
                         {"markdown", markdownMicroseconds},
                         {"review_toml", reviewTomlMicroseconds},
                         {"total", totalSerializationMicroseconds}};

  Json volatileJson{{"schema_version", 2},
                    {"authoritative_report", "entrypoint-closure.json"},
                    {"elapsed_milliseconds", runMetadata.elapsedMilliseconds},
                    {"peak_working_set_bytes", runMetadata.peakWorkingSetBytes},
                    {"stage_elapsed_microseconds", stageJson},
                    {"serialization_elapsed_microseconds", serializationJson},
                    {"command_line", runMetadata.commandLine}};
  if (!WriteReportFile(outputDirectory / "entrypoint-closure-run.json",
                       volatileJson.dump(2) + '\n')) {
    return Err(ErrorCategory::IO, "Unable to write entrypoint-closure-run.json");
  }
  Json jumpVolatileJson{
      {"schema_version", 2},
      {"authoritative_report", "jump-table-recovery.json"},
      {"pipeline_elapsed_milliseconds", runMetadata.elapsedMilliseconds},
      {"recovery_pass_elapsed_microseconds", report.jumpTableRecovery.stats.elapsedMicroseconds},
      {"peak_working_set_bytes", runMetadata.peakWorkingSetBytes},
      {"stage_elapsed_microseconds", stageJson},
      {"serialization_elapsed_microseconds", serializationJson},
      {"command_line", runMetadata.commandLine}};
  if (!WriteReportFile(outputDirectory / "jump-table-recovery-run.json",
                       jumpVolatileJson.dump(2) + '\n')) {
    return Err(ErrorCategory::IO, "Unable to write jump-table-recovery-run.json");
  }

  return Ok();
}

}  // namespace rex::codegen
