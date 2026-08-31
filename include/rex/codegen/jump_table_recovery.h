/**
 * @file        rex/codegen/jump_table_recovery.h
 * @brief       Evidence-bearing Xenon/PPC indirect-site and jump-table recovery
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#pragma once

#include <span>
#include <unordered_map>
#include <unordered_set>

#include <rex/codegen/code_region.h>
#include <rex/codegen/function_types.h>

namespace rex::codegen {

class DecodedBinary;

struct JumpTableRecoveryInput {
  uint32_t site = 0;
  uint32_t ownerAddress = 0;
  // Exclusive trusted owner envelope (for example an exact .pdata range).
  // This permits validated case edges across discontinuous executable body
  // fragments without treating the entire envelope as a linear code region.
  uint32_t trustedOwnerEnd = 0;
  std::span<const Block> preliminaryBlocks;
  const CodeRegion* containingRegion = nullptr;
  const std::unordered_set<uint32_t>* independentlyCallableEntries = nullptr;
  const std::unordered_set<uint32_t>* knownIndirectSites = nullptr;
  // Previously validated tables owned by this function. Their case edges are
  // part of the case-expanded CFG used to analyze downstream indirect sites;
  // the current site is excluded and still follows priorAutomaticTable's
  // stricter exact-retention lifecycle.
  const std::unordered_map<uint32_t, JumpTable>* validatedOwnerTables = nullptr;
  // Independently proven finite domains for registers at this existing owner
  // entry. These constrain table recovery only; they never register a function
  // or make a case target independently callable.
  const JumpTableEntryRegisterDomainMap* entryRegisterDomains = nullptr;
  const JumpTable* priorAutomaticTable = nullptr;
  const JumpTable* manualTable = nullptr;
  bool allowPriorLocalSliceRecovery = false;
  JumpTableRecoveryLimits limits;
};

/**
 * Prove the finite value domain of one GPR at a direct callsite.
 *
 * The proof accepts only an exact immediate constant or an unsigned,
 * dominating dense upper-bound guard whose case path reaches the call with the
 * register unmodified. It is a building block for the whole-image inbound
 * reference audit and does not inspect or infer jump-table storage.
 */
JumpTableEntryCallsiteDomainEvidence AnalyzeDirectCallArgumentDomain(
    DecodedBinary& decoded, std::span<const Block> callerBlocks, uint32_t callerAddress,
    uint32_t callAddress, uint32_t expectedTarget, uint8_t registerIndex,
    const JumpTableRecoveryLimits& limits = {});

/**
 * Classify one indirect branch and conservatively recover its switch table.
 *
 * The implementation constructs a bounded local CFG from preliminary owned
 * blocks, computes reaching definitions over predecessor paths, and accepts a
 * table only when every decoded target validates and either a finite index
 * domain or the narrowly supported self-delimiting inline-table extent is
 * proven.
 */
IndirectSiteAnalysis AnalyzeIndirectSite(DecodedBinary& decoded,
                                         const JumpTableRecoveryInput& input,
                                         JumpTableRecoveryStats* stats = nullptr);

/**
 * Re-analyze a previously validated automatic table with a bounded larger
 * state budget when case-expanded CFG growth alone exhausts maxStates.
 *
 * The retry is accepted only when normal recovery fully validates a table
 * that is semantically identical to priorAutomaticTable. Ambiguous, changed,
 * or partially valid tables remain unresolved.
 */
IndirectSiteAnalysis AnalyzeIndirectSiteWithPriorLimitRetry(
    DecodedBinary& decoded, const JumpTableRecoveryInput& input,
    JumpTableRecoveryStats* stats = nullptr);

/**
 * Recompute final failure stage, likelihood, rejection evidence, and stable
 * structural cluster after fixpoint retention or quarantine changes the
 * selected-table disposition.
 */
void FinalizeJumpTableSiteDisposition(IndirectSiteAnalysis& analysis);

}  // namespace rex::codegen
