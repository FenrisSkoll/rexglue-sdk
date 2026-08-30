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
#include <unordered_set>

#include <rex/codegen/code_region.h>
#include <rex/codegen/function_types.h>

namespace rex::codegen {

class DecodedBinary;

struct JumpTableRecoveryInput {
  uint32_t site = 0;
  uint32_t ownerAddress = 0;
  std::span<const Block> preliminaryBlocks;
  const CodeRegion* containingRegion = nullptr;
  const std::unordered_set<uint32_t>* independentlyCallableEntries = nullptr;
  const std::unordered_set<uint32_t>* knownIndirectSites = nullptr;
  const JumpTable* priorAutomaticTable = nullptr;
  const JumpTable* manualTable = nullptr;
  JumpTableRecoveryLimits limits;
};

/**
 * Classify one indirect branch and conservatively recover its switch table.
 *
 * The implementation constructs a bounded local CFG from preliminary owned
 * blocks, computes reaching definitions over predecessor paths, and accepts a
 * table only when a dominating bound and every decoded target validate.
 */
IndirectSiteAnalysis AnalyzeIndirectSite(DecodedBinary& decoded,
                                         const JumpTableRecoveryInput& input,
                                         JumpTableRecoveryStats* stats = nullptr);

/**
 * Re-analyze a previously validated automatic table with bounded larger
 * budgets when case-expanded CFG growth alone exhausts the normal limits.
 *
 * The retry is accepted only when normal recovery fully validates a table
 * that is semantically identical to priorAutomaticTable. Ambiguous, changed,
 * or partially valid tables remain unresolved.
 */
IndirectSiteAnalysis AnalyzeIndirectSiteWithPriorLimitRetry(
    DecodedBinary& decoded, const JumpTableRecoveryInput& input,
    JumpTableRecoveryStats* stats = nullptr);

}  // namespace rex::codegen
