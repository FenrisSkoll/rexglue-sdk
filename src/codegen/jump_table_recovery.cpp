/**
 * @file        jump_table_recovery.cpp
 * @brief       Evidence-bearing Xenon/PPC indirect-site and jump-table recovery
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <rex/codegen/jump_table_recovery.h>

#include "decoded_binary.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace rex::codegen {

namespace {

using ppc::Instruction;
using ppc::Opcode;

enum class ExprKind : uint8_t {
  Unknown,
  Constant,
  InputRegister,
  SymbolicDefinition,
  Add,
  ShiftLeft,
  Load,
  SignExtend,
};

struct Expr;
using ExprPtr = std::shared_ptr<const Expr>;

struct Expr {
  ExprKind kind = ExprKind::Unknown;
  uint32_t value = 0;
  uint8_t width = 0;
  uint8_t reg = 0xFF;
  uint32_t origin = 0;
  ExprPtr lhs;
  ExprPtr rhs;
};

ExprPtr MakeUnknown() {
  return std::make_shared<Expr>();
}

ExprPtr MakeConstant(uint32_t value) {
  auto expression = std::make_shared<Expr>();
  expression->kind = ExprKind::Constant;
  expression->value = value;
  return expression;
}

ExprPtr MakeInputRegister(uint8_t reg) {
  auto expression = std::make_shared<Expr>();
  expression->kind = ExprKind::InputRegister;
  expression->reg = reg;
  return expression;
}

ExprPtr MakeSymbolicDefinition(uint32_t origin) {
  auto expression = std::make_shared<Expr>();
  expression->kind = ExprKind::SymbolicDefinition;
  expression->origin = origin;
  return expression;
}

ExprPtr MakeUnary(ExprKind kind, ExprPtr operand, uint32_t value = 0, uint8_t width = 0,
                  uint32_t origin = 0) {
  auto expression = std::make_shared<Expr>();
  expression->kind = kind;
  expression->lhs = std::move(operand);
  expression->value = value;
  expression->width = width;
  expression->origin = origin;
  return expression;
}

ExprPtr MakeBinary(ExprKind kind, ExprPtr lhs, ExprPtr rhs, uint32_t origin = 0) {
  auto expression = std::make_shared<Expr>();
  expression->kind = kind;
  expression->lhs = std::move(lhs);
  expression->rhs = std::move(rhs);
  expression->origin = origin;
  return expression;
}

std::string ExprKey(const ExprPtr& expression) {
  if (!expression)
    return "null";
  switch (expression->kind) {
    case ExprKind::Unknown:
      return "?";
    case ExprKind::Constant:
      return "c" + std::to_string(expression->value);
    case ExprKind::InputRegister:
      return "r" + std::to_string(expression->reg);
    case ExprKind::SymbolicDefinition:
      return "d" + std::to_string(expression->origin);
    case ExprKind::Add: {
      auto lhs = ExprKey(expression->lhs);
      auto rhs = ExprKey(expression->rhs);
      if (rhs < lhs)
        std::swap(lhs, rhs);
      return "a(" + lhs + "," + rhs + ")";
    }
    case ExprKind::ShiftLeft:
      return "s" + std::to_string(expression->value) + "(" + ExprKey(expression->lhs) + ")";
    case ExprKind::Load:
      return "l" + std::to_string(expression->width) + "(" + ExprKey(expression->lhs) + ")";
    case ExprKind::SignExtend:
      return "x" + std::to_string(expression->width) + "(" + ExprKey(expression->lhs) + ")";
  }
  return "?";
}

bool IsUnknown(const ExprPtr& expression) {
  return !expression || expression->kind == ExprKind::Unknown;
}

bool ContainsExpression(const ExprPtr& expression, const std::string& needle) {
  if (!expression)
    return false;
  if (ExprKey(expression) == needle)
    return true;
  return ContainsExpression(expression->lhs, needle) || ContainsExpression(expression->rhs, needle);
}

bool ContainsLoad(const ExprPtr& expression) {
  if (!expression)
    return false;
  return expression->kind == ExprKind::Load || ContainsLoad(expression->lhs) ||
         ContainsLoad(expression->rhs);
}

void AddFailure(IndirectSiteAnalysis& analysis, JumpTableFailure failure) {
  if (failure == JumpTableFailure::None)
    return;
  if (std::find(analysis.failures.begin(), analysis.failures.end(), failure) ==
      analysis.failures.end()) {
    analysis.failures.push_back(failure);
  }
}

JumpTableInstructionEvidence Evidence(const Instruction& instruction, std::string role) {
  return {instruction.address, static_cast<uint32_t>(instruction.code), std::move(role),
          instruction.to_string()};
}

class LocalCfg {
 public:
  LocalCfg(DecodedBinary& decoded, std::span<const Block> blocks, uint32_t owner)
      : decoded_(decoded), owner_(owner) {
    for (const auto& block : blocks) {
      for (uint32_t address = block.base; address < block.end(); address += 4) {
        if (decoded_.get(address))
          addresses_.insert(address);
      }
    }
    for (uint32_t address : addresses_)
      AddEdges(address);
    for (auto& [address, values] : predecessors_) {
      std::sort(values.begin(), values.end());
      values.erase(std::unique(values.begin(), values.end()), values.end());
    }
  }

  bool contains(uint32_t address) const { return addresses_.contains(address); }
  const std::set<uint32_t>& addresses() const { return addresses_; }

  const std::vector<uint32_t>& predecessors(uint32_t address) const {
    static const std::vector<uint32_t> kEmpty;
    auto it = predecessors_.find(address);
    return it == predecessors_.end() ? kEmpty : it->second;
  }

  const std::vector<uint32_t>& successors(uint32_t address) const {
    static const std::vector<uint32_t> kEmpty;
    auto it = successors_.find(address);
    return it == successors_.end() ? kEmpty : it->second;
  }

  bool Reaches(uint32_t start, uint32_t target, uint32_t excluded,
               const JumpTableRecoveryLimits& limits, bool* limitHit) const {
    if (!contains(start) || !contains(target) || start == excluded)
      return false;
    std::deque<uint32_t> pending{start};
    std::unordered_set<uint32_t> visited;
    while (!pending.empty()) {
      uint32_t address = pending.front();
      pending.pop_front();
      if (address == excluded || !visited.insert(address).second)
        continue;
      if (address == target)
        return true;
      if (visited.size() > limits.maxStates) {
        if (limitHit)
          *limitHit = true;
        return false;
      }
      for (uint32_t successor : successors(address))
        pending.push_back(successor);
    }
    return false;
  }

  bool Dominates(uint32_t candidate, uint32_t target, const JumpTableRecoveryLimits& limits,
                 bool* limitHit) const {
    if (candidate == target)
      return true;
    if (!contains(owner_) || !contains(candidate) || !contains(target))
      return false;
    // If target remains reachable from the owner after removing candidate,
    // candidate does not dominate it.
    return !Reaches(owner_, target, candidate, limits, limitHit);
  }

 private:
  void AddSuccessor(uint32_t source, uint32_t target) {
    if (!addresses_.contains(target))
      return;
    successors_[source].push_back(target);
    predecessors_[target].push_back(source);
  }

  void AddEdges(uint32_t address) {
    const auto* instruction = decoded_.get(address);
    if (!instruction)
      return;
    const uint32_t fallthrough = address + 4;

    if (!instruction->is_branch()) {
      AddSuccessor(address, fallthrough);
      return;
    }
    if (instruction->is_call()) {
      AddSuccessor(address, fallthrough);
      return;
    }
    if (instruction->opcode == Opcode::bclr || instruction->opcode == Opcode::bclrl ||
        instruction->opcode == Opcode::bcctr || instruction->opcode == Opcode::bcctrl) {
      if (instruction->is_conditional())
        AddSuccessor(address, fallthrough);
      return;
    }
    if (instruction->branch_target)
      AddSuccessor(address, *instruction->branch_target);
    if (instruction->is_conditional())
      AddSuccessor(address, fallthrough);
  }

  DecodedBinary& decoded_;
  uint32_t owner_;
  std::set<uint32_t> addresses_;
  std::unordered_map<uint32_t, std::vector<uint32_t>> predecessors_;
  std::unordered_map<uint32_t, std::vector<uint32_t>> successors_;
};

bool WritesRegister(const Instruction& instruction, uint8_t reg) {
  switch (instruction.opcode) {
    case Opcode::addi:
    case Opcode::addis:
    case Opcode::li:
    case Opcode::lis:
    case Opcode::lwz:
    case Opcode::lhz:
    case Opcode::lbz:
    case Opcode::lwzx:
    case Opcode::lhzx:
    case Opcode::lbzx:
    case Opcode::ldx:
      return instruction.D.RT == reg;
    case Opcode::ori:
    case Opcode::oris:
    case Opcode::or_:
    case Opcode::mr:
    case Opcode::extsb:
    case Opcode::extsh:
      return instruction.X.RA == reg;
    case Opcode::add:
      return instruction.XO.RT == reg;
    case Opcode::rlwinm:
      return instruction.M.RA == reg;
    case Opcode::srawi:
      return instruction.X.RA == reg;
    default:
      return false;
  }
}

struct ResolveResult {
  ExprPtr expression;
  bool ambiguous = false;
  bool limitHit = false;
  bool incompleteCaseEntryPath = false;
  std::vector<JumpTableInstructionEvidence> evidence;
};

class Resolver {
 public:
  Resolver(DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableRecoveryLimits& limits,
           const JumpTable* priorAutomaticTable, JumpTableRecoveryStats* stats)
      : decoded_(decoded),
        cfg_(cfg),
        limits_(limits),
        priorAutomaticTable_(priorAutomaticTable),
        stats_(stats) {}

  ResolveResult Resolve(uint8_t reg, uint32_t before) {
    active_.clear();
    visitedStates_ = 0;
    return ResolveBefore(reg, before);
  }

 private:
  bool IsPriorCaseEntry(uint32_t address) const {
    return priorAutomaticTable_ &&
           std::find(priorAutomaticTable_->targets.begin(), priorAutomaticTable_->targets.end(),
                     address) != priorAutomaticTable_->targets.end();
  }

  ResolveResult ResolveBefore(uint8_t reg, uint32_t before) {
    ResolveResult merged;
    std::map<std::string, ResolveResult> alternatives;
    const uint64_t key = (static_cast<uint64_t>(before) << 8) | reg;
    if (!active_.insert(key).second) {
      merged.expression = MakeUnknown();
      merged.ambiguous = true;
      return merged;
    }
    if (++visitedStates_ > limits_.maxStates) {
      merged.expression = MakeUnknown();
      merged.limitHit = true;
      active_.erase(key);
      return merged;
    }

    const auto& predecessors = cfg_.predecessors(before);
    if (predecessors.empty()) {
      merged.expression = MakeInputRegister(reg);
      merged.incompleteCaseEntryPath = IsPriorCaseEntry(before);
      active_.erase(key);
      return merged;
    }
    if (predecessors.size() > limits_.maxPredecessors) {
      merged.expression = MakeUnknown();
      merged.limitHit = true;
      active_.erase(key);
      return merged;
    }

    for (uint32_t predecessor : predecessors) {
      ResolveResult result;
      const auto* instruction = decoded_.get(predecessor);
      if (instruction && WritesRegister(*instruction, reg)) {
        result = ResolveDefinition(*instruction);
      } else {
        result = ResolveBefore(reg, predecessor);
      }
      const std::string expressionKey = ExprKey(result.expression);
      auto alternative = alternatives.find(expressionKey);
      if (alternative == alternatives.end()) {
        alternatives.emplace(expressionKey, std::move(result));
      } else {
        alternative->second.incompleteCaseEntryPath =
            alternative->second.incompleteCaseEntryPath && result.incompleteCaseEntryPath;
      }
    }

    if (alternatives.size() != 1) {
      merged.expression = MakeUnknown();
      merged.ambiguous = true;
      size_t completeAlternatives = 0;
      bool hasIncompleteAlternative = false;
      for (auto& [unused, result] : alternatives) {
        if (result.incompleteCaseEntryPath) {
          hasIncompleteAlternative = true;
        } else {
          ++completeAlternatives;
        }
        merged.limitHit = merged.limitHit || result.limitHit;
        merged.evidence.insert(merged.evidence.end(), result.evidence.begin(),
                               result.evidence.end());
      }
      merged.incompleteCaseEntryPath = completeAlternatives == 1 && hasIncompleteAlternative;
    } else {
      merged = std::move(alternatives.begin()->second);
    }
    active_.erase(key);
    return merged;
  }

  ResolveResult ResolveDefinition(const Instruction& instruction) {
    ResolveResult result;
    if (stats_)
      ++stats_->decodedInstructions;
    result.evidence.push_back(Evidence(instruction, "reaching_definition"));

    auto operand = [&](uint8_t reg) {
      auto resolved = ResolveBefore(reg, instruction.address);
      result.ambiguous = result.ambiguous || resolved.ambiguous;
      result.limitHit = result.limitHit || resolved.limitHit;
      result.incompleteCaseEntryPath =
          result.incompleteCaseEntryPath || resolved.incompleteCaseEntryPath;
      result.evidence.insert(result.evidence.end(), resolved.evidence.begin(),
                             resolved.evidence.end());
      return resolved.expression;
    };

    switch (instruction.opcode) {
      case Opcode::li:
      case Opcode::addi: {
        if (instruction.D.RA == 0) {
          result.expression = MakeConstant(static_cast<uint32_t>(instruction.D.SIMM()));
        } else {
          auto source = ResolveBefore(static_cast<uint8_t>(instruction.D.RA), instruction.address);
          if ((source.ambiguous || source.limitHit || IsUnknown(source.expression)) &&
              !source.incompleteCaseEntryPath) {
            // A bound and table load that both consume this exact local addi
            // definition do not need the value of its live-in. Preserve the
            // definition identity instead of rejecting a switch because the
            // incoming value crosses a large or reentrant CFG. Separately
            // recomputed additions have different origins and remain rejected.
            result.expression = MakeSymbolicDefinition(instruction.address);
          } else {
            result.ambiguous = source.ambiguous;
            result.limitHit = source.limitHit;
            result.incompleteCaseEntryPath = source.incompleteCaseEntryPath;
            result.evidence.insert(result.evidence.end(), source.evidence.begin(),
                                   source.evidence.end());
            result.expression = MakeBinary(
                ExprKind::Add, source.expression,
                MakeConstant(static_cast<uint32_t>(instruction.D.SIMM())), instruction.address);
          }
        }
        break;
      }
      case Opcode::lis:
      case Opcode::addis: {
        const uint32_t immediate = static_cast<uint32_t>(instruction.D.SIMM()) << 16;
        if (instruction.D.RA == 0) {
          result.expression = MakeConstant(immediate);
        } else {
          result.expression =
              MakeBinary(ExprKind::Add, operand(static_cast<uint8_t>(instruction.D.RA)),
                         MakeConstant(immediate), instruction.address);
        }
        break;
      }
      case Opcode::ori:
      case Opcode::oris: {
        auto source = operand(static_cast<uint8_t>(instruction.D.RT));
        const uint32_t immediate =
            instruction.opcode == Opcode::oris ? instruction.D.UIMM() << 16 : instruction.D.UIMM();
        if (source && source->kind == ExprKind::Constant) {
          result.expression = MakeConstant(source->value | immediate);
        } else if (immediate == 0) {
          result.expression = source;
        } else {
          result.expression = MakeUnknown();
        }
        break;
      }
      case Opcode::or_: {
        auto lhs = operand(static_cast<uint8_t>(instruction.X.RT));
        auto rhs = operand(static_cast<uint8_t>(instruction.X.RB));
        result.expression = ExprKey(lhs) == ExprKey(rhs) ? lhs : MakeUnknown();
        break;
      }
      case Opcode::mr:
        result.expression = operand(static_cast<uint8_t>(instruction.X.RT));
        break;
      case Opcode::add: {
        result.expression =
            MakeBinary(ExprKind::Add, operand(static_cast<uint8_t>(instruction.XO.RA)),
                       operand(static_cast<uint8_t>(instruction.XO.RB)), instruction.address);
        break;
      }
      case Opcode::rlwinm: {
        // The common slwi alias: rlwinm rA,rS,SH,0,31-SH.
        if (instruction.M.MB == 0 && instruction.M.SH <= 31 &&
            instruction.M.ME == 31 - instruction.M.SH) {
          result.expression =
              MakeUnary(ExprKind::ShiftLeft, operand(static_cast<uint8_t>(instruction.M.RS)),
                        instruction.M.SH, 0, instruction.address);
        } else if (instruction.M.SH == 0 && instruction.M.ME == 31) {
          // clrlwi preserves the index lineage. Its range is considered by
          // bound recovery; it is not itself sufficient authority for a table.
          result.expression = operand(static_cast<uint8_t>(instruction.M.RS));
        } else {
          // Preserve the identity of an exact local transformation without
          // recursively resolving live-ins that its dominating bound makes
          // irrelevant. Evaluation still requires the table load and bound to
          // use this same definition; a separately recomputed transform has a
          // different key and remains rejected.
          result.expression = MakeSymbolicDefinition(instruction.address);
        }
        break;
      }
      case Opcode::srawi:
        // Preserve the identity of the exact reaching definition without
        // claiming that the recovery evaluator models PPC arithmetic shifts.
        // A dominating bound and an indexed load may still prove that they use
        // this same value. Separately recomputed shifts retain distinct keys.
        result.expression = MakeSymbolicDefinition(instruction.address);
        break;
      case Opcode::lwz:
      case Opcode::lhz:
      case Opcode::lbz: {
        const uint8_t width =
            instruction.opcode == Opcode::lwz ? 4 : (instruction.opcode == Opcode::lhz ? 2 : 1);
        ExprPtr base;
        if (instruction.D.RA == 0) {
          base = MakeConstant(0);
        } else if (instruction.D.RA == 1) {
          // Stack-relative loads commonly reload a switch index saved earlier
          // in a large function. The stack address does not establish the
          // loaded value, and recursively resolving r1 can enumerate the
          // entire CFG before reaching the same symbolic fallback below. Keep
          // stable stack-slot lineage without resolving r1; a bound and table
          // expression must still consume the same load before recovery can
          // validate, and different offsets or widths remain distinct.
          base = MakeInputRegister(1);
        } else {
          auto resolvedBase =
              ResolveBefore(static_cast<uint8_t>(instruction.D.RA), instruction.address);
          if ((resolvedBase.ambiguous || resolvedBase.limitHit ||
               IsUnknown(resolvedBase.expression)) &&
              !resolvedBase.incompleteCaseEntryPath) {
            // As with a local arithmetic transform, the exact result of this
            // load can be the bounded index even when its address live-in is
            // path-dependent. Keep its definition identity; this cannot stand
            // in for another load and cannot make an unknown table base
            // evaluable.
            result.expression = MakeSymbolicDefinition(instruction.address);
            break;
          }
          result.ambiguous = resolvedBase.ambiguous;
          result.limitHit = resolvedBase.limitHit;
          result.incompleteCaseEntryPath = resolvedBase.incompleteCaseEntryPath;
          result.evidence.insert(result.evidence.end(), resolvedBase.evidence.begin(),
                                 resolvedBase.evidence.end());
          base = resolvedBase.expression;
        }
        auto address = MakeBinary(ExprKind::Add, base,
                                  MakeConstant(static_cast<uint32_t>(instruction.D.SIMM())),
                                  instruction.address);
        result.expression = MakeUnary(ExprKind::Load, address, 0, width, instruction.address);
        break;
      }
      case Opcode::lwzx:
      case Opcode::lhzx:
      case Opcode::lbzx:
      case Opcode::ldx: {
        const uint8_t width = instruction.opcode == Opcode::lwzx
                                  ? 4
                                  : (instruction.opcode == Opcode::lhzx
                                         ? 2
                                         : (instruction.opcode == Opcode::lbzx ? 1 : 8));
        ExprPtr base = instruction.X.RA == 0 ? MakeConstant(0)
                                             : operand(static_cast<uint8_t>(instruction.X.RA));
        auto address =
            MakeBinary(ExprKind::Add, base, operand(static_cast<uint8_t>(instruction.X.RB)),
                       instruction.address);
        result.expression = MakeUnary(ExprKind::Load, address, 0, width, instruction.address);
        break;
      }
      case Opcode::extsb:
      case Opcode::extsh: {
        const uint8_t width = instruction.opcode == Opcode::extsb ? 1 : 2;
        result.expression =
            MakeUnary(ExprKind::SignExtend, operand(static_cast<uint8_t>(instruction.X.RT)), 0,
                      width, instruction.address);
        break;
      }
      default:
        result.expression = MakeUnknown();
        break;
    }
    return result;
  }

  DecodedBinary& decoded_;
  const LocalCfg& cfg_;
  const JumpTableRecoveryLimits& limits_;
  const JumpTable* priorAutomaticTable_ = nullptr;
  JumpTableRecoveryStats* stats_;
  uint32_t visitedStates_ = 0;
  std::unordered_set<uint64_t> active_;
};

struct BoundCandidate {
  uint32_t compareAddress = 0;
  uint32_t guardAddress = 0;
  uint32_t value = 0;
  uint32_t caseCount = 0;
  uint32_t defaultTarget = 0;
  uint8_t indexRegister = 0xFF;
  bool inclusive = false;
  bool defaultIsReturn = false;
  ExprPtr indexExpression;
  std::vector<JumpTableInstructionEvidence> evidence;
};

std::optional<bool> BranchWhenCrBitTrue(const Instruction& instruction) {
  uint8_t bo = instruction.format == ppc::InstrFormat::kB ? instruction.B.BO : instruction.XL.BO;
  if (bo == 12)
    return true;
  if (bo == 4)
    return false;
  return std::nullopt;
}

uint8_t BranchConditionBit(const Instruction& instruction) {
  return static_cast<uint8_t>(
      (instruction.format == ppc::InstrFormat::kB ? instruction.B.BI : instruction.XL.BI) % 4);
}

bool MayWriteConditionRegister(const Instruction& instruction) {
  if (instruction.is_record_form())
    return true;
  switch (instruction.opcode) {
    case Opcode::cmp:
    case Opcode::cmpi:
    case Opcode::cmpl:
    case Opcode::cmpli:
    case Opcode::fcmpu:
    case Opcode::fcmpo:
    case Opcode::mtcr:
    case Opcode::addic_:
    case Opcode::andi_:
    case Opcode::andis_:
      return true;
    default:
      return false;
  }
}

std::vector<uint32_t> BackwardReachable(const LocalCfg& cfg, uint32_t site,
                                        const JumpTableRecoveryLimits& limits, bool* limitHit) {
  std::deque<std::pair<uint32_t, uint32_t>> pending{{site, 0}};
  std::set<uint32_t> addresses;
  while (!pending.empty()) {
    auto [address, depth] = pending.front();
    pending.pop_front();
    if (!addresses.insert(address).second)
      continue;
    if (addresses.size() > limits.maxStates || depth > limits.maxBackwardInstructions) {
      if (limitHit)
        *limitHit = true;
      break;
    }
    for (uint32_t predecessor : cfg.predecessors(address))
      pending.emplace_back(predecessor, depth + 1);
  }
  return {addresses.begin(), addresses.end()};
}

struct ReachingCtrDefinitions {
  std::vector<const Instruction*> instructions;
  bool incompletePath = false;
};

ReachingCtrDefinitions FindReachingCtrDefinitions(DecodedBinary& decoded, const LocalCfg& cfg,
                                                  uint32_t site,
                                                  const JumpTableRecoveryLimits& limits,
                                                  bool* limitHit) {
  std::deque<uint32_t> pending;
  for (uint32_t predecessor : cfg.predecessors(site))
    pending.push_back(predecessor);

  std::unordered_set<uint32_t> visited;
  std::map<uint32_t, const Instruction*> definitions;
  ReachingCtrDefinitions result;
  while (!pending.empty()) {
    const uint32_t address = pending.front();
    pending.pop_front();
    if (!visited.insert(address).second)
      continue;
    if (visited.size() > limits.maxStates) {
      if (limitHit)
        *limitHit = true;
      result.incompletePath = true;
      break;
    }

    const auto* instruction = decoded.get(address);
    if (instruction && instruction->opcode == Opcode::mtctr) {
      definitions.emplace(address, instruction);
      continue;
    }

    const auto& predecessors = cfg.predecessors(address);
    if (predecessors.empty()) {
      result.incompletePath = true;
      continue;
    }
    if (predecessors.size() > limits.maxPredecessors) {
      if (limitHit)
        *limitHit = true;
      result.incompletePath = true;
      continue;
    }
    for (uint32_t predecessor : predecessors)
      pending.push_back(predecessor);
  }

  for (const auto& definition : definitions)
    result.instructions.push_back(definition.second);
  return result;
}

std::vector<BoundCandidate> FindBounds(DecodedBinary& decoded, const LocalCfg& cfg,
                                       Resolver& resolver, uint32_t site,
                                       const JumpTableRecoveryLimits& limits, bool* limitHit) {
  std::vector<BoundCandidate> candidates;
  for (uint32_t address : BackwardReachable(cfg, site, limits, limitHit)) {
    const auto* compare = decoded.get(address);
    if (!compare || (compare->opcode != Opcode::cmpli && compare->opcode != Opcode::cmpi))
      continue;
    if (!cfg.Dominates(address, site, limits, limitHit))
      continue;

    // The guard is normally immediately after the compare. Permit a bounded
    // linear schedule of intervening instructions, but never cross another
    // control transfer, unknown opcode, or condition-register write.
    const Instruction* guard = nullptr;
    constexpr uint32_t kMaxGuardLookaheadInstructions = 16;
    for (uint32_t cursor = address + 4;
         cursor < site && cursor <= address + kMaxGuardLookaheadInstructions * 4 &&
         cfg.contains(cursor);
         cursor += 4) {
      const auto* instruction = decoded.get(cursor);
      if (!instruction)
        break;
      if (instruction->opcode == Opcode::kUnknown || MayWriteConditionRegister(*instruction))
        break;
      if (instruction->is_branch()) {
        if (instruction->is_conditional())
          guard = instruction;
        break;
      }
    }
    if (!guard)
      continue;

    const uint8_t compareCr = static_cast<uint8_t>(compare->D.RT >> 2);
    const uint8_t guardBi = guard->format == ppc::InstrFormat::kB ? guard->B.BI : guard->XL.BI;
    if (guardBi / 4 != compareCr)
      continue;
    auto branchTrue = BranchWhenCrBitTrue(*guard);
    if (!branchTrue)
      continue;

    bool takenReachesSite = false;
    bool fallthroughReachesSite = false;
    bool defaultIsReturn = false;
    if (guard->opcode == Opcode::bclr || guard->opcode == Opcode::bclrl) {
      defaultIsReturn = true;
      fallthroughReachesSite = cfg.Reaches(guard->address + 4, site, address, limits, limitHit);
    } else if (guard->branch_target) {
      // Judge the two successors for this dynamic guard occurrence. A default
      // path may loop through the compare and reach the dispatch in a later
      // iteration after recomputing the index; that does not make it a case
      // path for the current bounded transfer.
      takenReachesSite = cfg.Reaches(*guard->branch_target, site, address, limits, limitHit);
      fallthroughReachesSite = cfg.Reaches(guard->address + 4, site, address, limits, limitHit);
    }
    if (takenReachesSite == fallthroughReachesSite)
      continue;

    const bool defaultOnTaken = !takenReachesSite;
    const bool defaultConditionTrue = defaultOnTaken ? *branchTrue : !*branchTrue;
    const uint8_t bit = BranchConditionBit(*guard);  // 0=LT, 1=GT, 2=EQ

    BoundCandidate candidate;
    candidate.compareAddress = address;
    candidate.guardAddress = guard->address;
    candidate.value = compare->opcode == Opcode::cmpli ? compare->D.UIMM()
                                                       : static_cast<uint32_t>(compare->D.SIMM());
    candidate.indexRegister = static_cast<uint8_t>(compare->D.RA);
    candidate.defaultIsReturn = defaultIsReturn;
    if (!defaultIsReturn) {
      candidate.defaultTarget = defaultOnTaken ? *guard->branch_target : guard->address + 4;
    }

    // Accept only guards that prove a dense zero-based upper bound.
    if (bit == 1 && defaultConditionTrue) {  // default when index > value
      candidate.inclusive = true;
      candidate.caseCount = candidate.value + 1;
    } else if (bit == 0 && !defaultConditionTrue) {  // default when !(index < value)
      candidate.inclusive = false;
      candidate.caseCount = candidate.value;
    } else {
      continue;
    }
    if (candidate.caseCount == 0 || candidate.caseCount > limits.maxEntries)
      continue;

    auto resolved = resolver.Resolve(candidate.indexRegister, address);
    if (resolved.ambiguous || resolved.limitHit || IsUnknown(resolved.expression))
      continue;
    candidate.indexExpression = resolved.expression;
    candidate.evidence = std::move(resolved.evidence);
    candidate.evidence.push_back(Evidence(*compare, "case_bound"));
    candidate.evidence.push_back(Evidence(*guard, "default_guard"));
    candidates.push_back(std::move(candidate));
  }
  return candidates;
}

struct Evaluation {
  bool ok = false;
  uint32_t value = 0;
  std::map<uint32_t, std::pair<uint32_t, uint8_t>> loads;
};

Evaluation Evaluate(const ExprPtr& expression, const std::string& indexKey, uint32_t index,
                    DecodedBinary& decoded, uint32_t depth = 0) {
  if (!expression || depth > 64)
    return {};
  if (ExprKey(expression) == indexKey)
    return {true, index, {}};
  switch (expression->kind) {
    case ExprKind::Constant:
      return {true, expression->value, {}};
    case ExprKind::Add: {
      auto lhs = Evaluate(expression->lhs, indexKey, index, decoded, depth + 1);
      auto rhs = Evaluate(expression->rhs, indexKey, index, decoded, depth + 1);
      if (!lhs.ok || !rhs.ok)
        return {};
      lhs.value += rhs.value;
      lhs.loads.insert(rhs.loads.begin(), rhs.loads.end());
      return lhs;
    }
    case ExprKind::ShiftLeft: {
      auto value = Evaluate(expression->lhs, indexKey, index, decoded, depth + 1);
      if (!value.ok || expression->value > 31)
        return {};
      value.value <<= expression->value;
      return value;
    }
    case ExprKind::Load: {
      auto address = Evaluate(expression->lhs, indexKey, index, decoded, depth + 1);
      if (!address.ok)
        return {};
      std::optional<uint32_t> value;
      switch (expression->width) {
        case 1: {
          auto raw = decoded.read<uint8_t>(address.value);
          if (raw)
            value = *raw;
          break;
        }
        case 2: {
          auto raw = decoded.read<uint16_t>(address.value);
          if (raw)
            value = *raw;
          break;
        }
        case 4:
          value = decoded.read<uint32_t>(address.value);
          break;
        default:
          break;
      }
      if (!value)
        return {};
      address.loads[expression->origin] = {address.value, expression->width};
      address.value = *value;
      return address;
    }
    case ExprKind::SignExtend: {
      auto value = Evaluate(expression->lhs, indexKey, index, decoded, depth + 1);
      if (!value.ok)
        return {};
      if (expression->width == 1)
        value.value = static_cast<uint32_t>(static_cast<int32_t>(static_cast<int8_t>(value.value)));
      else if (expression->width == 2)
        value.value =
            static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(value.value)));
      else
        return {};
      return value;
    }
    case ExprKind::Unknown:
    case ExprKind::InputRegister:
    case ExprKind::SymbolicDefinition:
      return {};
  }
  return {};
}

const Expr* FindPrimaryLoad(const ExprPtr& expression, const std::string& indexKey) {
  if (!expression)
    return nullptr;
  if (const Expr* load = FindPrimaryLoad(expression->lhs, indexKey))
    return load;
  if (const Expr* load = FindPrimaryLoad(expression->rhs, indexKey))
    return load;
  if (expression->kind == ExprKind::Load && ContainsExpression(expression->lhs, indexKey))
    return expression.get();
  return nullptr;
}

bool LoadIsSignExtended(const ExprPtr& expression, uint32_t loadOrigin,
                        bool underSignExtend = false) {
  if (!expression)
    return false;
  const bool nowSigned = underSignExtend || expression->kind == ExprKind::SignExtend;
  if (expression->kind == ExprKind::Load && expression->origin == loadOrigin)
    return nowSigned;
  return LoadIsSignExtended(expression->lhs, loadOrigin, nowSigned) ||
         LoadIsSignExtended(expression->rhs, loadOrigin, nowSigned);
}

std::optional<uint32_t> EvaluateConstant(const ExprPtr& expression) {
  if (!expression)
    return std::nullopt;
  if (expression->kind == ExprKind::Constant)
    return expression->value;
  if (expression->kind == ExprKind::Add) {
    auto lhs = EvaluateConstant(expression->lhs);
    auto rhs = EvaluateConstant(expression->rhs);
    if (lhs && rhs)
      return *lhs + *rhs;
  }
  if (expression->kind == ExprKind::ShiftLeft) {
    auto operand = EvaluateConstant(expression->lhs);
    if (operand)
      return *operand << expression->value;
  }
  return std::nullopt;
}

std::optional<uint32_t> ConstantAnchor(const ExprPtr& expression) {
  if (!expression || expression->kind != ExprKind::Add)
    return std::nullopt;
  if (auto lhs = EvaluateConstant(expression->lhs); lhs && ContainsLoad(expression->rhs))
    return lhs;
  if (auto rhs = EvaluateConstant(expression->rhs); rhs && ContainsLoad(expression->lhs))
    return rhs;
  return std::nullopt;
}

uint32_t LoadTargetScale(const ExprPtr& expression, uint32_t loadOrigin, uint32_t scale = 1) {
  if (!expression)
    return 0;
  if (expression->kind == ExprKind::Load && expression->origin == loadOrigin)
    return scale;
  if (expression->kind == ExprKind::ShiftLeft)
    scale <<= expression->value;
  uint32_t lhs = LoadTargetScale(expression->lhs, loadOrigin, scale);
  if (lhs)
    return lhs;
  return LoadTargetScale(expression->rhs, loadOrigin, scale);
}

JumpTableManualComparison CompareManual(const JumpTable& automatic, const JumpTable& manual) {
  if (automatic.targets == manual.targets) {
    if (manual.caseCount != 0 && automatic.caseCount != manual.caseCount)
      return JumpTableManualComparison::ConflictingBounds;
    return JumpTableManualComparison::ExactEquivalent;
  }
  std::set<uint32_t> automaticTargets(automatic.targets.begin(), automatic.targets.end());
  std::set<uint32_t> manualTargets(manual.targets.begin(), manual.targets.end());
  if (automaticTargets == manualTargets)
    return JumpTableManualComparison::ConflictingTargets;
  if (std::includes(automaticTargets.begin(), automaticTargets.end(), manualTargets.begin(),
                    manualTargets.end()))
    return JumpTableManualComparison::AutomaticSuperset;
  if (std::includes(manualTargets.begin(), manualTargets.end(), automaticTargets.begin(),
                    automaticTargets.end()))
    return JumpTableManualComparison::AutomaticSubset;
  return JumpTableManualComparison::ConflictingTargets;
}

}  // namespace

const char* IndirectSiteClassificationName(IndirectSiteClassification classification) {
  switch (classification) {
    case IndirectSiteClassification::SwitchBctr:
      return "switch_bctr";
    case IndirectSiteClassification::ComputedTailBctr:
      return "computed_tail_bctr";
    case IndirectSiteClassification::VirtualOrCallbackBctrl:
      return "virtual_or_callback_bctrl";
    case IndirectSiteClassification::IndirectTailBctrlOrBctr:
      return "indirect_tail_bctrl_or_bctr";
    case IndirectSiteClassification::OrdinaryBlrReturn:
      return "ordinary_blr_return";
    case IndirectSiteClassification::NonstandardBclr:
      return "nonstandard_bclr";
    case IndirectSiteClassification::OpaqueIndirectTransfer:
      return "opaque_indirect_transfer";
  }
  return "opaque_indirect_transfer";
}

const char* JumpTableFailureName(JumpTableFailure failure) {
  switch (failure) {
    case JumpTableFailure::None:
      return "none";
    case JumpTableFailure::MissingBound:
      return "missing_bound";
    case JumpTableFailure::AmbiguousBound:
      return "ambiguous_bound";
    case JumpTableFailure::UnknownTableBase:
      return "unknown_table_base";
    case JumpTableFailure::UnknownIndex:
      return "unknown_index";
    case JumpTableFailure::AmbiguousReachingDefinition:
      return "ambiguous_reaching_definition";
    case JumpTableFailure::UnsupportedRelativeForm:
      return "unsupported_relative_form";
    case JumpTableFailure::InvalidElementWidth:
      return "invalid_element_width";
    case JumpTableFailure::TargetOutOfRange:
      return "target_out_of_range";
    case JumpTableFailure::TargetUnaligned:
      return "target_unaligned";
    case JumpTableFailure::MixedValidityTargets:
      return "mixed_validity_targets";
    case JumpTableFailure::AnalysisLimit:
      return "analysis_limit";
    case JumpTableFailure::NonSwitchIndirect:
      return "non_switch_indirect";
  }
  return "non_switch_indirect";
}

const char* JumpTableKindName(JumpTableKind kind) {
  switch (kind) {
    case JumpTableKind::Unknown:
      return "unknown";
    case JumpTableKind::AbsolutePointer:
      return "absolute_pointer";
    case JumpTableKind::RelativeOffset:
      return "relative_offset";
  }
  return "unknown";
}

const char* JumpTableOriginName(JumpTableOrigin origin) {
  return origin == JumpTableOrigin::Manual ? "manual" : "automatic";
}

const char* JumpTableManualComparisonName(JumpTableManualComparison comparison) {
  switch (comparison) {
    case JumpTableManualComparison::None:
      return "none";
    case JumpTableManualComparison::ExactEquivalent:
      return "exact_equivalent";
    case JumpTableManualComparison::AutomaticSuperset:
      return "automatic_superset";
    case JumpTableManualComparison::AutomaticSubset:
      return "automatic_subset";
    case JumpTableManualComparison::ConflictingTargets:
      return "conflicting_targets";
    case JumpTableManualComparison::ConflictingBounds:
      return "conflicting_bounds";
    case JumpTableManualComparison::UnsupportedManualForm:
      return "unsupported_manual_form";
    case JumpTableManualComparison::NewAutomaticTable:
      return "new_automatic_table";
  }
  return "none";
}

IndirectSiteAnalysis AnalyzeIndirectSite(DecodedBinary& decoded,
                                         const JumpTableRecoveryInput& input,
                                         JumpTableRecoveryStats* stats) {
  const auto started = std::chrono::steady_clock::now();
  IndirectSiteAnalysis analysis;
  analysis.site = input.site;
  analysis.ownerAddress = input.ownerAddress;
  if (stats)
    ++stats->indirectSites;

  const auto finish = [&]() {
    if (stats) {
      stats->elapsedMicroseconds +=
          static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - started)
                                    .count());
      if (!analysis.selectedTable)
        ++stats->unresolvedSites;
    }
    return analysis;
  };

  const auto* dispatch = decoded.get(input.site);
  if (!dispatch || !dispatch->is_branch()) {
    AddFailure(analysis, JumpTableFailure::NonSwitchIndirect);
    return finish();
  }
  analysis.link = dispatch->is_call();
  analysis.conditional = dispatch->is_conditional();
  analysis.usesCtr = dispatch->opcode == Opcode::bcctr || dispatch->opcode == Opcode::bcctrl;
  analysis.evidence.push_back(Evidence(*dispatch, "indirect_dispatch"));

  if (dispatch->opcode == Opcode::bclr && !dispatch->is_conditional()) {
    analysis.classification = IndirectSiteClassification::OrdinaryBlrReturn;
    AddFailure(analysis, JumpTableFailure::NonSwitchIndirect);
    return finish();
  }
  if (dispatch->opcode == Opcode::bclr || dispatch->opcode == Opcode::bclrl) {
    analysis.classification = dispatch->is_conditional()
                                  ? IndirectSiteClassification::NonstandardBclr
                                  : IndirectSiteClassification::VirtualOrCallbackBctrl;
    AddFailure(analysis, JumpTableFailure::NonSwitchIndirect);
    return finish();
  }
  if (dispatch->opcode == Opcode::bcctrl) {
    analysis.classification = IndirectSiteClassification::VirtualOrCallbackBctrl;
    AddFailure(analysis, JumpTableFailure::NonSwitchIndirect);
    return finish();
  }
  if (dispatch->opcode != Opcode::bcctr || dispatch->is_conditional()) {
    analysis.classification = IndirectSiteClassification::IndirectTailBctrlOrBctr;
    AddFailure(analysis, JumpTableFailure::NonSwitchIndirect);
    return finish();
  }

  LocalCfg cfg(decoded, input.preliminaryBlocks, input.ownerAddress);
  Resolver resolver(decoded, cfg, input.limits, input.priorAutomaticTable, stats);

  bool limitHit = false;
  auto ctrDefinitions =
      FindReachingCtrDefinitions(decoded, cfg, input.site, input.limits, &limitHit);
  const Instruction* mtctr =
      ctrDefinitions.instructions.size() == 1 && !ctrDefinitions.incompletePath
          ? ctrDefinitions.instructions.front()
          : nullptr;
  if (limitHit) {
    AddFailure(analysis, JumpTableFailure::AnalysisLimit);
    if (stats)
      stats->analysisLimitHit = true;
  } else if (ctrDefinitions.instructions.size() > 1 || ctrDefinitions.incompletePath) {
    AddFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition);
  }
  if (!mtctr) {
    if (analysis.failures.empty())
      AddFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition);
    analysis.classification = IndirectSiteClassification::OpaqueIndirectTransfer;
  } else {
    analysis.evidence.push_back(Evidence(*mtctr, "ctr_definition"));
    auto target = resolver.Resolve(static_cast<uint8_t>(mtctr->XFX.RS()), mtctr->address);
    analysis.evidence.insert(analysis.evidence.end(), target.evidence.begin(),
                             target.evidence.end());
    if (target.limitHit) {
      AddFailure(analysis, JumpTableFailure::AnalysisLimit);
      analysis.incompleteCaseEntryPaths = target.incompleteCaseEntryPath;
      analysis.classification = IndirectSiteClassification::OpaqueIndirectTransfer;
      if (stats)
        stats->analysisLimitHit = true;
    } else if (target.ambiguous) {
      AddFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition);
      analysis.incompleteCaseEntryPaths = target.incompleteCaseEntryPath;
    } else if (IsUnknown(target.expression) || !ContainsLoad(target.expression)) {
      AddFailure(analysis, JumpTableFailure::UnknownTableBase);
      analysis.classification = IndirectSiteClassification::ComputedTailBctr;
    } else {
      auto bounds = FindBounds(decoded, cfg, resolver, input.site, input.limits, &limitHit);
      // A bounded reachability query can encounter an unrelated loop after a
      // complete dominating bound has already been found. Preserve that valid
      // result, but make a truncated, unsuccessful bound search explicit.
      if (limitHit && bounds.empty()) {
        AddFailure(analysis, JumpTableFailure::AnalysisLimit);
        if (stats)
          stats->analysisLimitHit = true;
      }
      std::vector<BoundCandidate> matchingBounds;
      for (auto& bound : bounds) {
        if (ContainsExpression(target.expression, ExprKey(bound.indexExpression)))
          matchingBounds.push_back(std::move(bound));
      }
      if (matchingBounds.size() > 1) {
        // Repeated loop guards can provide the same proof. Coalesce only
        // bounds whose index expression, range, and default edge are exact;
        // retain the closest proof for deterministic evidence.
        std::map<std::string, BoundCandidate> equivalentBounds;
        for (auto& bound : matchingBounds) {
          const std::string key =
              ExprKey(bound.indexExpression) + ":" + std::to_string(bound.value) + ":" +
              std::to_string(bound.caseCount) + ":" + std::to_string(bound.inclusive) + ":" +
              std::to_string(bound.defaultTarget) + ":" + std::to_string(bound.defaultIsReturn);
          auto existing = equivalentBounds.find(key);
          if (existing == equivalentBounds.end() ||
              existing->second.compareAddress < bound.compareAddress) {
            equivalentBounds[key] = std::move(bound);
          }
        }
        matchingBounds.clear();
        for (auto& [unused, bound] : equivalentBounds)
          matchingBounds.push_back(std::move(bound));

        // An outer range check and a later bound on a normalized index both
        // occur in common compiler output. If one bounded expression strictly
        // contains another, the more-derived expression is the value that the
        // table load consumes. Incomparable or conflicting proofs remain
        // ambiguous.
        std::vector<bool> shadowed(matchingBounds.size(), false);
        for (size_t derived = 0; derived < matchingBounds.size(); ++derived) {
          const std::string derivedKey = ExprKey(matchingBounds[derived].indexExpression);
          for (size_t ancestor = 0; ancestor < matchingBounds.size(); ++ancestor) {
            if (derived == ancestor)
              continue;
            const std::string ancestorKey = ExprKey(matchingBounds[ancestor].indexExpression);
            if (derivedKey != ancestorKey &&
                ContainsExpression(matchingBounds[derived].indexExpression, ancestorKey)) {
              shadowed[ancestor] = true;
            }
          }
        }
        std::vector<BoundCandidate> mostDerivedBounds;
        for (size_t index = 0; index < matchingBounds.size(); ++index) {
          if (!shadowed[index])
            mostDerivedBounds.push_back(std::move(matchingBounds[index]));
        }
        matchingBounds = std::move(mostDerivedBounds);
      }
      if (matchingBounds.empty()) {
        if (!(limitHit && bounds.empty())) {
          AddFailure(analysis, bounds.empty() ? JumpTableFailure::MissingBound
                                              : JumpTableFailure::UnknownIndex);
        }
      } else if (matchingBounds.size() != 1) {
        AddFailure(analysis, JumpTableFailure::AmbiguousBound);
      } else {
        auto& bound = matchingBounds.front();
        const std::string indexKey = ExprKey(bound.indexExpression);
        const Expr* primaryLoad = FindPrimaryLoad(target.expression, indexKey);
        if (!primaryLoad ||
            (primaryLoad->width != 1 && primaryLoad->width != 2 && primaryLoad->width != 4)) {
          AddFailure(analysis, JumpTableFailure::InvalidElementWidth);
        } else {
          JumpTable table;
          table.bctrAddress = input.site;
          table.ownerAddress = input.ownerAddress;
          table.indexRegister = bound.indexRegister;
          table.boundValue = bound.value;
          table.caseCount = bound.caseCount;
          table.boundInclusive = bound.inclusive;
          table.boundSemantics =
              bound.inclusive ? "unsigned_index <= bound" : "unsigned_index < bound";
          table.defaultTarget = bound.defaultTarget;
          table.defaultIsReturn = bound.defaultIsReturn;
          table.elementWidth = primaryLoad->width;
          table.elementSigned = LoadIsSignExtended(target.expression, primaryLoad->origin);
          table.anchorAddress = ConstantAnchor(target.expression).value_or(0);
          table.targetScale = LoadTargetScale(target.expression, primaryLoad->origin);
          if (table.targetScale == 0)
            table.targetScale = 1;
          table.kind = primaryLoad->width == 4 && table.anchorAddress == 0 && table.targetScale == 1
                           ? JumpTableKind::AbsolutePointer
                           : JumpTableKind::RelativeOffset;
          table.confidence = "validated_bound_and_all_targets";
          table.evidence = analysis.evidence;
          table.evidence.insert(table.evidence.end(), bound.evidence.begin(), bound.evidence.end());

          if (primaryLoad->width < 4 && table.anchorAddress == 0) {
            AddFailure(analysis, JumpTableFailure::UnsupportedRelativeForm);
          }

          bool invalid = !analysis.failures.empty();
          JumpTableFailure targetFailure = JumpTableFailure::None;
          uint32_t previousStorage = 0;
          uint32_t storageStride = 0;
          for (uint32_t index = 0; index < bound.caseCount && !invalid; ++index) {
            auto evaluated = Evaluate(target.expression, indexKey, index, decoded);
            auto loadIt = evaluated.loads.find(primaryLoad->origin);
            if (!evaluated.ok || loadIt == evaluated.loads.end()) {
              invalid = true;
              targetFailure = JumpTableFailure::TargetOutOfRange;
              break;
            }
            const uint32_t storage = loadIt->second.first;
            if (index == 0) {
              table.tableAddress = storage;
            } else {
              const uint32_t stride = storage - previousStorage;
              if (index == 1)
                storageStride = stride;
              if (stride != storageStride || stride == 0) {
                invalid = true;
                targetFailure = JumpTableFailure::UnsupportedRelativeForm;
                break;
              }
            }
            previousStorage = storage;

            uint32_t rawValue = 0;
            if (primaryLoad->width == 1)
              rawValue = decoded.read<uint8_t>(storage).value_or(0);
            else if (primaryLoad->width == 2)
              rawValue = decoded.read<uint16_t>(storage).value_or(0);
            else
              rawValue = decoded.read<uint32_t>(storage).value_or(0);

            const uint32_t caseTarget = evaluated.value;
            table.rawEntries.push_back({storage, rawValue, caseTarget});
            if ((caseTarget & 3) != 0) {
              invalid = true;
              targetFailure = JumpTableFailure::TargetUnaligned;
              break;
            }
            const auto* targetInstruction = decoded.get(caseTarget);
            if (!targetInstruction || isInvalid(*targetInstruction) || !input.containingRegion ||
                !input.containingRegion->contains(caseTarget)) {
              invalid = true;
              targetFailure = JumpTableFailure::TargetOutOfRange;
              break;
            }
            table.targets.push_back(caseTarget);
          }

          if (invalid) {
            table.conflicts.push_back(JumpTableFailureName(targetFailure));
            AddFailure(analysis, table.targets.empty() ? targetFailure
                                                       : JumpTableFailure::MixedValidityTargets);
          } else {
            const uint32_t stride = bound.caseCount > 1 ? table.rawEntries[1].storageAddress -
                                                              table.rawEntries[0].storageAddress
                                                        : primaryLoad->width;
            table.storageEnd =
                table.tableAddress + (bound.caseCount - 1) * stride + primaryLoad->width;
            table.tableInExecutableSection = decoded.get(table.tableAddress) != nullptr;
            table.manualComparison = input.manualTable
                                         ? CompareManual(table, *input.manualTable)
                                         : JumpTableManualComparison::NewAutomaticTable;
            analysis.automaticTable = table;
            analysis.classification = IndirectSiteClassification::SwitchBctr;
            analysis.failures.clear();
            if (stats)
              ++stats->recoveredTables;
          }
        }
      }
    }
  }

  if (input.manualTable) {
    JumpTable manual = *input.manualTable;
    manual.origin = JumpTableOrigin::Manual;
    manual.ownerAddress = input.ownerAddress;
    if (analysis.automaticTable) {
      manual.manualComparison = analysis.automaticTable->manualComparison;
    } else {
      manual.manualComparison = JumpTableManualComparison::UnsupportedManualForm;
    }
    analysis.selectedTable = std::move(manual);
    analysis.classification = IndirectSiteClassification::SwitchBctr;
    if (stats)
      ++stats->manualTables;
  } else if (analysis.automaticTable) {
    analysis.selectedTable = analysis.automaticTable;
  }

  if (!analysis.selectedTable &&
      analysis.classification == IndirectSiteClassification::OpaqueIndirectTransfer &&
      dispatch->opcode == Opcode::bcctr) {
    analysis.classification = IndirectSiteClassification::ComputedTailBctr;
  }
  return finish();
}

IndirectSiteAnalysis AnalyzeIndirectSiteWithPriorLimitRetry(
    DecodedBinary& decoded, const JumpTableRecoveryInput& input,
    JumpTableRecoveryStats* stats) {
  auto analysis = AnalyzeIndirectSite(decoded, input, stats);
  if (analysis.selectedTable || !input.priorAutomaticTable || analysis.failures.size() != 1 ||
      analysis.failures.front() != JumpTableFailure::AnalysisLimit) {
    return analysis;
  }

  auto sameRawEntries = [](const std::vector<JumpTableRawEntry>& lhs,
                           const std::vector<JumpTableRawEntry>& rhs) {
    if (lhs.size() != rhs.size())
      return false;
    for (size_t index = 0; index < lhs.size(); ++index) {
      if (lhs[index].storageAddress != rhs[index].storageAddress ||
          lhs[index].rawValue != rhs[index].rawValue || lhs[index].target != rhs[index].target) {
        return false;
      }
    }
    return true;
  };
  auto sameInstructionEvidence = [](const std::vector<JumpTableInstructionEvidence>& lhs,
                                    const std::vector<JumpTableInstructionEvidence>& rhs) {
    if (lhs.size() != rhs.size())
      return false;
    for (size_t index = 0; index < lhs.size(); ++index) {
      if (lhs[index].address != rhs[index].address ||
          lhs[index].rawInstruction != rhs[index].rawInstruction ||
          lhs[index].role != rhs[index].role ||
          lhs[index].instruction != rhs[index].instruction) {
        return false;
      }
    }
    return true;
  };
  auto sameValidatedTable = [&](const JumpTable& lhs, const JumpTable& rhs) {
    return lhs.bctrAddress == rhs.bctrAddress && lhs.tableAddress == rhs.tableAddress &&
           lhs.indexRegister == rhs.indexRegister && lhs.targets == rhs.targets &&
           lhs.kind == rhs.kind && lhs.origin == rhs.origin &&
           lhs.manualComparison == rhs.manualComparison &&
           lhs.ownerAddress == rhs.ownerAddress && lhs.storageEnd == rhs.storageEnd &&
           lhs.boundValue == rhs.boundValue && lhs.caseCount == rhs.caseCount &&
           lhs.defaultTarget == rhs.defaultTarget && lhs.anchorAddress == rhs.anchorAddress &&
           lhs.targetScale == rhs.targetScale && lhs.elementWidth == rhs.elementWidth &&
           lhs.elementSigned == rhs.elementSigned && lhs.boundInclusive == rhs.boundInclusive &&
           lhs.defaultIsReturn == rhs.defaultIsReturn &&
           lhs.tableInExecutableSection == rhs.tableInExecutableSection &&
           lhs.boundSemantics == rhs.boundSemantics &&
           sameRawEntries(lhs.rawEntries, rhs.rawEntries) &&
           sameInstructionEvidence(lhs.evidence, rhs.evidence) && lhs.conflicts == rhs.conflicts;
  };

  JumpTableRecoveryInput retryInput = input;
  const uint64_t grownStates =
      std::max<uint64_t>(static_cast<uint64_t>(input.limits.maxStates) + 1,
                         static_cast<uint64_t>(input.limits.maxStates) * 32);
  retryInput.limits.maxStates =
      static_cast<uint32_t>(std::min<uint64_t>(grownStates, 1000000));
  auto retry = AnalyzeIndirectSite(decoded, retryInput, stats);

  JumpTableLimitRetryEvidence retryEvidence;
  retryEvidence.initialBudgetValue = input.limits.maxStates;
  retryEvidence.retryBudgetValue = retryInput.limits.maxStates;
  retryEvidence.initialFailures = analysis.failures;
  retryEvidence.retryFailures = retry.failures;
  retryEvidence.exhaustedBudget = retry.selectedTable ? "max_states" : "";
  retryEvidence.exactPriorTableMatch =
      retry.selectedTable && retry.automaticTable &&
      retry.selectedTable->origin == JumpTableOrigin::Automatic &&
      sameValidatedTable(*retry.selectedTable, *input.priorAutomaticTable) &&
      sameValidatedTable(*retry.automaticTable, *input.priorAutomaticTable);
  retryEvidence.accepted = retryEvidence.exactPriorTableMatch;

  if (stats) {
    // Both analyses contribute real elapsed and decoded-instruction work, but
    // together they still classify one site and have one final resolution.
    if (stats->indirectSites > 0)
      --stats->indirectSites;
    if (retryEvidence.accepted) {
      if (stats->unresolvedSites > 0)
        --stats->unresolvedSites;
    } else if (retry.selectedTable) {
      if (stats->recoveredTables > 0)
        --stats->recoveredTables;
    } else if (stats->unresolvedSites > 0) {
      --stats->unresolvedSites;
    }
  }

  if (!retryEvidence.accepted) {
    analysis.limitRetry = std::move(retryEvidence);
    return analysis;
  }

  retry.limitRetry = std::move(retryEvidence);
  retry.automaticTable->confidence = "validated_after_expanded_cfg_limit_retry";
  retry.selectedTable->confidence = "validated_after_expanded_cfg_limit_retry";
  return retry;
}

}  // namespace rex::codegen
