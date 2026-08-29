/**
 * @file        codegen/analyze.cpp
 * @brief       Analysis pipeline orchestrator
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include "decoded_binary.h"

#include <algorithm>
#include <chrono>
#include <map>

#include <rex/codegen/analysis_errors.h>
#include <rex/codegen/analyze.h>
#include <rex/codegen/phases.h>
#include <rex/logging.h>

#include "codegen_logging.h"

namespace rex::codegen {

Result<void> Analyze(CodegenContext& ctx, ProgressReporter* reporter) {
  REXCODEGEN_TRACE("Analyze: starting analysis...");

  using Clock = std::chrono::steady_clock;
  auto elapsedMicroseconds = [](Clock::time_point started) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started).count());
  };
  auto& timings = ctx.analysisState().stageTimings;

  auto stageStarted = Clock::now();
  ctx.initDecoded();
  timings.decodeMicroseconds += elapsedMicroseconds(stageStarted);
  REXCODEGEN_TRACE("Analyze: decoded {} instructions across {} code regions",
                   ctx.decoded().instructionCount(), ctx.decoded().codeRegions().size());

  // 1. Register entry points (imports, helpers, config, pdata)
  if (reporter)
    reporter->phaseChanged("Register");
  stageStarted = Clock::now();
  auto regResult = phases::Register(ctx, reporter);
  timings.registerMicroseconds += elapsedMicroseconds(stageStarted);
  if (!regResult) {
    return regResult;
  }

  // 2. Scan binary into code/data regions
  if (reporter)
    reporter->phaseChanged("Scan");
  stageStarted = Clock::now();
  auto scanResult = phases::Scan(ctx, reporter);
  timings.scanMicroseconds += elapsedMicroseconds(stageStarted);
  if (!scanResult) {
    return scanResult;
  }

  // 3. Discover function blocks iteratively (includes vtable scan)
  if (reporter)
    reporter->phaseChanged("Discover");
  stageStarted = Clock::now();
  auto discoverResult = phases::Discover(ctx, reporter);
  timings.discoverMicroseconds += elapsedMicroseconds(stageStarted);
  if (!discoverResult) {
    return discoverResult;
  }

  // 3.5. Function pointer scan: find lis/addi pairs loading code addresses
  // TODO(tomc): disabled for now, causes too many false positives
  // functionPointerScan(ctx);

  // 4. Gap fill uncovered regions + discover blocks for gap-filled functions + cleanup
  if (reporter)
    reporter->phaseChanged("GapFill");
  stageStarted = Clock::now();
  auto gapFillResult = phases::GapFill(ctx, reporter);
  timings.gapFillMicroseconds += elapsedMicroseconds(stageStarted);
  if (!gapFillResult) {
    return gapFillResult;
  }

  // 5. Merge: resolve jumps and seal functions
  if (reporter)
    reporter->phaseChanged("Merge");
  stageStarted = Clock::now();
  auto mergeResult = phases::Merge(ctx, reporter);
  timings.mergeMicroseconds += elapsedMicroseconds(stageStarted);
  if (!mergeResult) {
    return mergeResult;
  }

  // 6. Validate
  if (reporter)
    reporter->phaseChanged("Validate");
  stageStarted = Clock::now();
  auto validateResult = phases::Validate(ctx, reporter);
  timings.validateMicroseconds += elapsedMicroseconds(stageStarted);
  if (!validateResult) {
    return validateResult;
  }

  REXCODEGEN_TRACE("Analyze: complete - {} functions ready for code generation",
                   ctx.graph.functionCount());

  return Ok();
}

//=============================================================================
// AnalysisErrors implementation
//=============================================================================

const char* AnalysisErrors::CategoryName(Category cat) {
  switch (cat) {
    case Category::UnresolvedCall:
      return "UnresolvedCall";
    case Category::MissingJumpTable:
      return "MissingJumpTable";
    case Category::JumpTargetOutOfBounds:
      return "JumpTargetOutOfBounds";
    case Category::DiscontinuousFunction:
      return "DiscontinuousFunction";
    case Category::UnimplementedInsn:
      return "UnimplementedInsn";
    default:
      return "Unknown";
  }
}

void AnalysisErrors::Add(Category cat, uint32_t addr, const std::string& msg) {
  Add(cat, addr, 0, msg);
}

void AnalysisErrors::Add(Category cat, uint32_t addr, uint32_t secondary, const std::string& msg) {
  entries_.push_back({cat, addr, secondary, msg});
}

size_t AnalysisErrors::Count(Category cat) const {
  return std::count_if(entries_.begin(), entries_.end(),
                       [cat](const Entry& e) { return e.category == cat; });
}

void AnalysisErrors::PrintReport() const {
  if (entries_.empty()) {
    return;
  }

  REXCODEGEN_ERROR("=== ANALYSIS ERRORS ===");

  // Group by category
  std::map<Category, std::vector<const Entry*>> byCategory;
  for (const auto& entry : entries_) {
    byCategory[entry.category].push_back(&entry);
  }

  for (const auto& [cat, entries] : byCategory) {
    REXCODEGEN_ERROR("{} ({}):", CategoryName(cat), entries.size());

    for (const auto* entry : entries) {
      if (entry->secondaryAddress != 0) {
        REXCODEGEN_ERROR("  0x{:08X} from 0x{:08X}: {}", entry->address, entry->secondaryAddress,
                         entry->message);
      } else {
        REXCODEGEN_ERROR("  0x{:08X}: {}", entry->address, entry->message);
      }
    }
  }

  REXCODEGEN_ERROR("Total: {} errors", entries_.size());
}

}  // namespace rex::codegen
