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
  FinitePhi,
  LoopPhi,
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
  std::vector<ExprPtr> nestedLoopPhis;
  std::vector<uint32_t> finiteValues;
  std::vector<uint32_t> entryDefinitions;
  std::vector<uint32_t> backedgeDefinitions;
  std::vector<uint32_t> entryValues;
  std::vector<uint32_t> backedgeValues;
  bool identityBackedge = false;
};

ExprPtr MakeUnknown() {
  return std::make_shared<Expr>();
}

ExprPtr MakeConstant(uint32_t value, uint32_t origin = 0) {
  auto expression = std::make_shared<Expr>();
  expression->kind = ExprKind::Constant;
  expression->value = value;
  expression->origin = origin;
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

ExprPtr MakeFinitePhi(uint8_t reg, uint32_t mergeAddress, std::vector<uint32_t> finiteValues,
                      std::vector<uint32_t> definitions) {
  auto expression = std::make_shared<Expr>();
  expression->kind = ExprKind::FinitePhi;
  expression->reg = reg;
  expression->origin = mergeAddress;
  expression->finiteValues = std::move(finiteValues);
  expression->entryDefinitions = std::move(definitions);
  return expression;
}

ExprPtr MakeLoopPhi(uint8_t reg, uint32_t header, std::vector<uint32_t> finiteValues = {},
                    std::vector<uint32_t> entryDefinitions = {},
                    std::vector<uint32_t> backedgeDefinitions = {},
                    std::vector<uint32_t> entryValues = {},
                    std::vector<uint32_t> backedgeValues = {},
                    std::vector<ExprPtr> nestedLoopPhis = {}, bool identityBackedge = false) {
  auto expression = std::make_shared<Expr>();
  expression->kind = ExprKind::LoopPhi;
  expression->reg = reg;
  expression->origin = header;
  expression->finiteValues = std::move(finiteValues);
  expression->entryDefinitions = std::move(entryDefinitions);
  expression->backedgeDefinitions = std::move(backedgeDefinitions);
  expression->entryValues = std::move(entryValues);
  expression->backedgeValues = std::move(backedgeValues);
  expression->nestedLoopPhis = std::move(nestedLoopPhis);
  expression->identityBackedge = identityBackedge;
  return expression;
}

bool SameLoopPhiMeaning(const ExprPtr& lhs, const ExprPtr& rhs) {
  if (!lhs || !rhs || lhs->kind != ExprKind::LoopPhi || rhs->kind != ExprKind::LoopPhi ||
      lhs->reg != rhs->reg || lhs->origin != rhs->origin ||
      lhs->finiteValues != rhs->finiteValues || lhs->entryDefinitions != rhs->entryDefinitions ||
      lhs->backedgeDefinitions != rhs->backedgeDefinitions ||
      lhs->entryValues != rhs->entryValues || lhs->backedgeValues != rhs->backedgeValues ||
      lhs->identityBackedge != rhs->identityBackedge ||
      lhs->nestedLoopPhis.size() != rhs->nestedLoopPhis.size()) {
    return false;
  }
  for (size_t index = 0; index < lhs->nestedLoopPhis.size(); ++index) {
    if (!SameLoopPhiMeaning(lhs->nestedLoopPhis[index], rhs->nestedLoopPhis[index]))
      return false;
  }
  return true;
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
    case ExprKind::FinitePhi:
      return "f" + std::to_string(expression->reg) + "@" + std::to_string(expression->origin);
    case ExprKind::LoopPhi:
      return "p" + std::to_string(expression->reg) + "@" + std::to_string(expression->origin);
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

bool ContainsLoad(const ExprPtr& expression);

std::string ExprShape(const ExprPtr& expression) {
  if (!expression)
    return "null";
  switch (expression->kind) {
    case ExprKind::Unknown:
      return "unknown";
    case ExprKind::Constant:
      return "constant";
    case ExprKind::InputRegister:
      return "input_register";
    case ExprKind::SymbolicDefinition:
      return "symbolic_definition";
    case ExprKind::FinitePhi:
      return "finite_phi";
    case ExprKind::LoopPhi:
      return "loop_phi";
    case ExprKind::Add: {
      auto lhs = ExprShape(expression->lhs);
      auto rhs = ExprShape(expression->rhs);
      if (rhs < lhs)
        std::swap(lhs, rhs);
      return "add(" + lhs + "," + rhs + ")";
    }
    case ExprKind::ShiftLeft:
      return "shift_left_" + std::to_string(expression->value) + "(" + ExprShape(expression->lhs) +
             ")";
    case ExprKind::Load:
      return "load_u" + std::to_string(expression->width * 8) + "(" + ExprShape(expression->lhs) +
             ")";
    case ExprKind::SignExtend:
      return "sign_extend_" + std::to_string(expression->width * 8) + "(" +
             ExprShape(expression->lhs) + ")";
  }
  return "unknown";
}

uint32_t CountUnknownLeaves(const ExprPtr& expression) {
  if (!expression)
    return 0;
  return (expression->kind == ExprKind::Unknown ? 1u : 0u) + CountUnknownLeaves(expression->lhs) +
         CountUnknownLeaves(expression->rhs);
}

void CollectInputRegisters(const ExprPtr& expression, std::set<uint8_t>& registers) {
  if (!expression)
    return;
  if (expression->kind == ExprKind::InputRegister) {
    registers.insert(expression->reg);
    return;
  }
  CollectInputRegisters(expression->lhs, registers);
  CollectInputRegisters(expression->rhs, registers);
}

// Return the coefficient of one input register in a constant-plus-scaled-index
// address. Any other symbolic value makes the form ineligible: an entry-domain
// proof may bound an index, but it may never stand in for a runtime table base.
std::optional<uint32_t> LinearInputCoefficient(const ExprPtr& expression, uint8_t reg) {
  if (!expression)
    return std::nullopt;
  switch (expression->kind) {
    case ExprKind::Constant:
      return 0;
    case ExprKind::InputRegister:
      return expression->reg == reg ? std::optional<uint32_t>(1) : std::nullopt;
    case ExprKind::Add: {
      const auto lhs = LinearInputCoefficient(expression->lhs, reg);
      const auto rhs = LinearInputCoefficient(expression->rhs, reg);
      if (!lhs || !rhs || *lhs > std::numeric_limits<uint32_t>::max() - *rhs)
        return std::nullopt;
      return *lhs + *rhs;
    }
    case ExprKind::ShiftLeft: {
      const auto value = LinearInputCoefficient(expression->lhs, reg);
      if (!value || expression->value >= 32 ||
          *value > (std::numeric_limits<uint32_t>::max() >> expression->value)) {
        return std::nullopt;
      }
      return *value << expression->value;
    }
    default:
      return std::nullopt;
  }
}

const Expr* FindFirstLoad(const ExprPtr& expression);

std::optional<uint32_t> ConstantComponent(const ExprPtr& expression) {
  if (!expression)
    return std::nullopt;
  if (expression->kind == ExprKind::Constant)
    return expression->value;
  if (expression->kind != ExprKind::Add)
    return std::nullopt;
  auto lhs = ConstantComponent(expression->lhs);
  auto rhs = ConstantComponent(expression->rhs);
  if (lhs && rhs)
    return *lhs + *rhs;
  if (lhs)
    return lhs;
  return rhs;
}

void CollectTransformChain(const ExprPtr& expression, uint32_t loadOrigin,
                           std::vector<std::string>& output) {
  if (!expression)
    return;
  if (expression->kind == ExprKind::Load && expression->origin == loadOrigin) {
    output.push_back("indexed_load_u" + std::to_string(expression->width * 8));
    return;
  }
  if (expression->kind == ExprKind::ShiftLeft)
    output.push_back("shift_left_" + std::to_string(expression->value));
  else if (expression->kind == ExprKind::SignExtend)
    output.push_back("sign_extend_" + std::to_string(expression->width * 8));
  else if (expression->kind == ExprKind::Add)
    output.push_back("add");
  if (ContainsLoad(expression->lhs))
    CollectTransformChain(expression->lhs, loadOrigin, output);
  else if (ContainsLoad(expression->rhs))
    CollectTransformChain(expression->rhs, loadOrigin, output);
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

bool WritesRegister(const Instruction& instruction, uint8_t reg);

class LocalCfg {
 public:
  struct ConstantDefinition {
    uint32_t address = 0;
    uint32_t value = 0;
  };

  LocalCfg(DecodedBinary& decoded, std::span<const Block> blocks, uint32_t owner,
           uint32_t currentSite, const JumpTable* priorAutomaticTable = nullptr,
           const std::unordered_map<uint32_t, JumpTable>* validatedOwnerTables = nullptr)
      : decoded_(decoded), owner_(owner), priorAutomaticTable_(priorAutomaticTable) {
    for (const auto& block : blocks) {
      for (uint32_t address = block.base; address < block.end(); address += 4) {
        if (decoded_.get(address))
          addresses_.insert(address);
      }
    }
    for (uint32_t address : addresses_)
      AddEdges(address);
    if (validatedOwnerTables) {
      for (const auto& [site, table] : *validatedOwnerTables) {
        if (site == currentSite || !addresses_.contains(site))
          continue;
        for (uint32_t target : table.targets)
          AddSuccessor(site, target);
      }
    }
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

    // Search backwards from the target with the candidate removed. This both
    // answers the dominance question directly and avoids walking a large,
    // highly branched owner when the candidate is a local guard immediately
    // before the dispatch. Exhaustion is not evidence of dominance: retain the
    // bound only when every predecessor path is completely cut by candidate.
    std::deque<uint32_t> pending{target};
    std::unordered_set<uint32_t> visited;
    while (!pending.empty()) {
      const uint32_t address = pending.front();
      pending.pop_front();
      if (address == candidate || !visited.insert(address).second)
        continue;
      if (address == owner_)
        return false;
      if (visited.size() > limits.maxStates) {
        if (limitHit)
          *limitHit = true;
        return false;
      }
      for (uint32_t predecessor : predecessors(address))
        pending.push_back(predecessor);
    }
    return true;
  }

  bool IsBackedgePredecessor(uint32_t header, uint32_t predecessor,
                             const JumpTableRecoveryLimits& limits, bool* limitHit) const {
    EnsureTopology(limits, limitHit);
    if (topologyLimitHit_)
      return false;
    auto headerComponent = topologyComponent_.find(header);
    auto predecessorComponent = topologyComponent_.find(predecessor);
    return headerComponent != topologyComponent_.end() &&
           predecessorComponent != topologyComponent_.end() &&
           headerComponent->second == predecessorComponent->second &&
           IsCyclicComponent(headerComponent->second);
  }

  uint32_t CanonicalCycleHeader(uint32_t address, const JumpTableRecoveryLimits& limits,
                                bool* limitHit) const {
    EnsureTopology(limits, limitHit);
    auto component = topologyComponent_.find(address);
    return component == topologyComponent_.end() ? address : component->second;
  }

  bool IsInCycle(uint32_t address, const JumpTableRecoveryLimits& limits, bool* limitHit) const {
    EnsureTopology(limits, limitHit);
    auto component = topologyComponent_.find(address);
    return component != topologyComponent_.end() && IsCyclicComponent(component->second);
  }

  bool RegisterUnmodifiedInDispatchCycle(uint32_t definition, uint32_t dispatch, uint8_t reg,
                                         const JumpTableRecoveryLimits& limits,
                                         bool* limitHit) const {
    EnsureTopology(limits, limitHit);
    if (topologyLimitHit_)
      return false;
    const auto dispatchComponent = topologyComponent_.find(dispatch);
    if (dispatchComponent == topologyComponent_.end() ||
        !IsCyclicComponent(dispatchComponent->second)) {
      return true;
    }
    for (const auto& [address, component] : topologyComponent_) {
      if (component != dispatchComponent->second || address == definition)
        continue;
      const auto* instruction = decoded_.get(address);
      if (instruction && WritesRegister(*instruction, reg))
        return false;
    }
    return true;
  }

  bool RegisterUnmodifiedOnEveryPath(uint32_t start, uint32_t target, uint8_t reg,
                                     const JumpTableRecoveryLimits& limits, bool* limitHit) const {
    EnsureTopology(limits, limitHit);
    if (topologyLimitHit_ || !contains(start) || !contains(target))
      return false;

    struct State {
      uint32_t address = 0;
      bool modified = false;
    };
    std::deque<State> pending{{start, false}};
    std::set<std::pair<uint32_t, bool>> visited;
    bool reachedUnmodified = false;
    while (!pending.empty()) {
      const State state = pending.front();
      pending.pop_front();
      if (!visited.insert({state.address, state.modified}).second)
        continue;
      if (visited.size() > limits.maxStates) {
        if (limitHit)
          *limitHit = true;
        return false;
      }
      if (state.address == target) {
        if (state.modified)
          return false;
        reachedUnmodified = true;
        continue;
      }

      const auto* instruction = decoded_.get(state.address);
      const bool modified = state.modified || (instruction && WritesRegister(*instruction, reg));
      for (uint32_t successor : successors(state.address))
        pending.push_back({successor, modified});
    }
    return reachedUnmodified;
  }

  bool RegisterValueAvailableOnEveryPath(uint32_t start, uint32_t target, uint8_t reg,
                                         const JumpTableRecoveryLimits& limits,
                                         bool* limitHit) const {
    EnsureTopology(limits, limitHit);
    if (topologyLimitHit_ || !contains(start) || !contains(target))
      return false;

    struct State {
      uint32_t address = 0;
      bool invalidated = false;
    };
    std::deque<State> pending{{start, false}};
    std::set<std::pair<uint32_t, bool>> visited;
    bool reachedAvailable = false;
    while (!pending.empty()) {
      const State state = pending.front();
      pending.pop_front();
      if (!visited.insert({state.address, state.invalidated}).second)
        continue;
      if (visited.size() > limits.maxStates) {
        if (limitHit)
          *limitHit = true;
        return false;
      }
      if (state.address == target) {
        if (state.invalidated)
          return false;
        reachedAvailable = true;
        continue;
      }

      const auto* instruction = decoded_.get(state.address);
      const bool invalidated =
          state.invalidated || (instruction && (WritesRegister(*instruction, reg) ||
                                                (instruction->is_call() && reg < 14)));
      for (uint32_t successor : successors(state.address))
        pending.push_back({successor, invalidated});
    }
    return reachedAvailable;
  }

  std::optional<ConstantDefinition> FindDominatingConstantDefinition(
      uint8_t reg, uint32_t target, const JumpTableRecoveryLimits& limits, bool* limitHit) const {
    for (uint32_t address : addresses_) {
      const auto* instruction = decoded_.get(address);
      if (!instruction || !WritesRegister(*instruction, reg))
        continue;
      const bool immediateConstant =
          (instruction->opcode == Opcode::li || instruction->opcode == Opcode::addi ||
           instruction->opcode == Opcode::lis || instruction->opcode == Opcode::addis) &&
          instruction->D.RA == 0;
      if (!immediateConstant)
        continue;
      bool dominanceLimit = false;
      if (!Dominates(address, target, limits, &dominanceLimit)) {
        if (dominanceLimit && limitHit)
          *limitHit = true;
        continue;
      }
      bool pathLimit = false;
      if (RegisterUnmodifiedOnEveryPath(address + 4, target, reg, limits, &pathLimit)) {
        bool cycleLimit = false;
        if (!RegisterUnmodifiedInDispatchCycle(address, target, reg, limits, &cycleLimit)) {
          if (cycleLimit && limitHit)
            *limitHit = true;
          continue;
        }
        const uint32_t value =
            instruction->opcode == Opcode::li || instruction->opcode == Opcode::addi
                ? static_cast<uint32_t>(instruction->D.SIMM())
                : static_cast<uint32_t>(instruction->D.SIMM()) << 16;
        return ConstantDefinition{address, value};
      }
      if (pathLimit && limitHit)
        *limitHit = true;
    }
    return std::nullopt;
  }

  bool topologyLimitHit() const { return topologyLimitHit_; }
  uint32_t topologyNodeCount() const { return topologyNodeCount_; }

 private:
  bool IsCyclicComponent(uint32_t component) const {
    auto size = topologyComponentSize_.find(component);
    return size != topologyComponentSize_.end() &&
           (size->second > 1 || topologySelfLoops_.contains(component));
  }

  void EnsureTopology(const JumpTableRecoveryLimits& limits, bool* limitHit) const {
    if (topologyAttempted_) {
      if (topologyLimitHit_ && limitHit)
        *limitHit = true;
      return;
    }
    topologyAttempted_ = true;
    topologyNodeCount_ = static_cast<uint32_t>(
        std::min<size_t>(addresses_.size(), std::numeric_limits<uint32_t>::max()));
    if (addresses_.size() > limits.maxCfgTopologyNodes) {
      topologyLimitHit_ = true;
      if (limitHit)
        *limitHit = true;
      return;
    }

    std::unordered_map<uint32_t, std::vector<uint32_t>> adjacency;
    std::unordered_map<uint32_t, std::vector<uint32_t>> reverse;
    adjacency.reserve(addresses_.size());
    reverse.reserve(addresses_.size());
    for (uint32_t address : addresses_) {
      auto& edges = adjacency[address];
      edges = successors(address);
      if (priorAutomaticTable_ && priorAutomaticTable_->bctrAddress == address) {
        for (uint32_t target : priorAutomaticTable_->targets) {
          if (contains(target))
            edges.push_back(target);
        }
      }
      std::sort(edges.begin(), edges.end());
      edges.erase(std::unique(edges.begin(), edges.end()), edges.end());
      reverse.try_emplace(address);
      for (uint32_t target : edges)
        reverse[target].push_back(address);
    }
    for (auto& [unused, edges] : reverse) {
      std::sort(edges.begin(), edges.end());
      edges.erase(std::unique(edges.begin(), edges.end()), edges.end());
    }

    std::vector<uint32_t> finishOrder;
    finishOrder.reserve(addresses_.size());
    std::unordered_set<uint32_t> visited;
    visited.reserve(addresses_.size());
    for (uint32_t root : addresses_) {
      if (!visited.insert(root).second)
        continue;
      std::vector<std::pair<uint32_t, size_t>> stack{{root, 0}};
      while (!stack.empty()) {
        auto& [address, nextEdge] = stack.back();
        const auto& edges = adjacency[address];
        if (nextEdge < edges.size()) {
          const uint32_t target = edges[nextEdge++];
          if (visited.insert(target).second)
            stack.push_back({target, 0});
          continue;
        }
        finishOrder.push_back(address);
        stack.pop_back();
      }
    }

    visited.clear();
    for (auto orderIt = finishOrder.rbegin(); orderIt != finishOrder.rend(); ++orderIt) {
      const uint32_t root = *orderIt;
      if (!visited.insert(root).second)
        continue;
      std::vector<uint32_t> members;
      std::vector<uint32_t> pending{root};
      uint32_t component = root;
      while (!pending.empty()) {
        const uint32_t address = pending.back();
        pending.pop_back();
        members.push_back(address);
        component = std::min(component, address);
        for (uint32_t predecessor : reverse[address]) {
          if (visited.insert(predecessor).second)
            pending.push_back(predecessor);
        }
      }
      topologyComponentSize_[component] = static_cast<uint32_t>(members.size());
      for (uint32_t member : members) {
        topologyComponent_[member] = component;
        const auto& edges = adjacency[member];
        if (std::find(edges.begin(), edges.end(), member) != edges.end())
          topologySelfLoops_.insert(component);
      }
    }
  }

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
  const JumpTable* priorAutomaticTable_ = nullptr;
  mutable bool topologyAttempted_ = false;
  mutable bool topologyLimitHit_ = false;
  mutable uint32_t topologyNodeCount_ = 0;
  mutable std::unordered_map<uint32_t, uint32_t> topologyComponent_;
  mutable std::unordered_map<uint32_t, uint32_t> topologyComponentSize_;
  mutable std::unordered_set<uint32_t> topologySelfLoops_;
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
    case Opcode::rlwimi:
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
  std::vector<std::string> alternatives;
};

class Resolver {
 public:
  Resolver(DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableRecoveryLimits& limits,
           const JumpTable* priorAutomaticTable, JumpTableRecoveryStats* stats,
           std::vector<JumpTableReachingDefinitionPathEvidence>* pathEvidence)
      : decoded_(decoded),
        cfg_(cfg),
        limits_(limits),
        priorAutomaticTable_(priorAutomaticTable),
        stats_(stats),
        pathEvidence_(pathEvidence) {}

  ResolveResult Resolve(uint8_t reg, uint32_t before) {
    active_.clear();
    visitedStates_ = 0;
    maxStatesLimitHit_ = false;
    return ResolveBefore(reg, before);
  }

  bool maxStatesLimitHit() const { return maxStatesLimitHit_; }
  uint32_t visitedStates() const { return visitedStates_; }

 private:
  struct ConstantInvariant {
    ExprPtr expression;
    bool limitHit = false;
  };

  bool IsPriorCaseEntry(uint32_t address) const {
    return priorAutomaticTable_ &&
           std::find(priorAutomaticTable_->targets.begin(), priorAutomaticTable_->targets.end(),
                     address) != priorAutomaticTable_->targets.end();
  }

  const ConstantInvariant& ConstantInvariantAtDispatch(uint8_t reg) {
    auto [it, inserted] = constantInvariants_.try_emplace(reg);
    if (!inserted)
      return it->second;
    if (!priorAutomaticTable_ || reg == priorAutomaticTable_->indexRegister ||
        !cfg_.contains(priorAutomaticTable_->bctrAddress)) {
      return it->second;
    }
    const auto definition = cfg_.FindDominatingConstantDefinition(
        reg, priorAutomaticTable_->bctrAddress, limits_, &it->second.limitHit);
    if (definition)
      it->second.expression = MakeConstant(definition->value, definition->address);
    return it->second;
  }

  ResolveResult ResolveBefore(uint8_t reg, uint32_t before) {
    ResolveResult merged;
    struct Alternative {
      uint32_t predecessor = 0;
      ResolveResult result;
    };
    std::vector<Alternative> paths;
    const uint64_t key = (static_cast<uint64_t>(before) << 8) | reg;
    if (!active_.insert(key).second) {
      // A recursive query for the same register at the same CFG point is a
      // loop-carried phi, not by itself an incompatible definition. The merge
      // at the loop header below still requires a finite entry definition and
      // permits only identity or finite constant backedge definitions.
      bool limitHit = false;
      const uint32_t loopHeader = cfg_.CanonicalCycleHeader(before, limits_, &limitHit);
      merged.expression = MakeLoopPhi(reg, loopHeader);
      merged.limitHit = limitHit;
      return merged;
    }
    if (++visitedStates_ > limits_.maxStates) {
      merged.expression = MakeUnknown();
      merged.limitHit = true;
      maxStatesLimitHit_ = true;
      active_.erase(key);
      return merged;
    }

    const auto& predecessors = cfg_.predecessors(before);
    if (predecessors.empty()) {
      if (IsPriorCaseEntry(before)) {
        const auto& invariant = ConstantInvariantAtDispatch(reg);
        if (invariant.expression) {
          // The prior automatic table already proves this case edge. Carry
          // only an exact immediate constant which dominates the dispatch and
          // is unmodified on every path to it. Returning the value directly
          // avoids recursively re-traversing every case edge and keeps the
          // reaching-definition budget independent of case count.
          merged.expression = invariant.expression;
          if (const auto* definition = decoded_.get(invariant.expression->origin)) {
            merged.evidence.push_back(Evidence(*definition, "case_edge_loop_invariant_definition"));
          }
          if (pathEvidence_) {
            bool topologyLimit = false;
            const uint32_t loopHeader = cfg_.CanonicalCycleHeader(before, limits_, &topologyLimit);
            pathEvidence_->push_back({.registerIndex = reg,
                                      .mergeAddress = before,
                                      .predecessor = priorAutomaticTable_->bctrAddress,
                                      .loopHeader = loopHeader,
                                      .backedge = false,
                                      .limitHit = topologyLimit,
                                      .expression = ExprKey(invariant.expression),
                                      .normalizedExpression = ExprShape(invariant.expression),
                                      .disposition = "case_edge_loop_invariant_constant"});
            if (topologyLimit) {
              merged.expression = MakeUnknown();
              merged.limitHit = true;
            }
          }
          active_.erase(key);
          return merged;
        }
        if (invariant.limitHit) {
          merged.expression = MakeUnknown();
          merged.limitHit = true;
          active_.erase(key);
          return merged;
        }
      }
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
      paths.push_back({predecessor, std::move(result)});
    }

    std::map<std::string, ResolveResult> alternatives;
    for (auto& path : paths) {
      const std::string expressionKey = ExprKey(path.result.expression);
      auto alternative = alternatives.find(expressionKey);
      if (alternative == alternatives.end()) {
        alternatives.emplace(expressionKey, path.result);
      } else {
        alternative->second.incompleteCaseEntryPath =
            alternative->second.incompleteCaseEntryPath && path.result.incompleteCaseEntryPath;
      }
    }

    if (alternatives.size() != 1) {
      for (const auto& [expressionKey, unused] : alternatives)
        merged.alternatives.push_back(expressionKey);

      // A guarded join inside an established state loop may merge the exact
      // converged loop phi with constants already represented by that phi.
      // Preserve the phi only when every loop definition is identical and
      // every other finite definition is a subset of its proven domain.
      ExprPtr equivalentLoopPhi;
      std::set<uint32_t> joinedFiniteValues;
      bool equivalentLoopJoin = !paths.empty();
      for (const auto& path : paths) {
        const auto& expression = path.result.expression;
        if (path.result.limitHit || path.result.incompleteCaseEntryPath || !expression) {
          equivalentLoopJoin = false;
          break;
        }
        if (expression->kind == ExprKind::LoopPhi && expression->reg == reg &&
            expression->identityBackedge && !expression->entryValues.empty() &&
            !expression->finiteValues.empty()) {
          if (!equivalentLoopPhi) {
            equivalentLoopPhi = expression;
          } else if (!SameLoopPhiMeaning(equivalentLoopPhi, expression)) {
            equivalentLoopJoin = false;
            break;
          }
        } else if (expression->kind == ExprKind::Constant) {
          joinedFiniteValues.insert(expression->value);
        } else if (expression->kind == ExprKind::FinitePhi && expression->reg == reg &&
                   !expression->finiteValues.empty()) {
          joinedFiniteValues.insert(expression->finiteValues.begin(),
                                    expression->finiteValues.end());
        } else {
          equivalentLoopJoin = false;
          break;
        }
      }
      if (equivalentLoopJoin && equivalentLoopPhi &&
          std::all_of(joinedFiniteValues.begin(), joinedFiniteValues.end(), [&](uint32_t value) {
            return std::find(equivalentLoopPhi->finiteValues.begin(),
                             equivalentLoopPhi->finiteValues.end(),
                             value) != equivalentLoopPhi->finiteValues.end();
          })) {
        merged.expression = equivalentLoopPhi;
        for (auto& path : paths) {
          merged.evidence.insert(merged.evidence.end(), path.result.evidence.begin(),
                                 path.result.evidence.end());
          merged.alternatives.insert(merged.alternatives.end(), path.result.alternatives.begin(),
                                     path.result.alternatives.end());
          if (pathEvidence_) {
            pathEvidence_->push_back({.registerIndex = reg,
                                      .mergeAddress = before,
                                      .predecessor = path.predecessor,
                                      .loopHeader = equivalentLoopPhi->origin,
                                      .backedge = true,
                                      .limitHit = false,
                                      .expression = ExprKey(path.result.expression),
                                      .normalizedExpression = ExprShape(path.result.expression),
                                      .disposition = "equivalent_finite_loop_phi"});
          }
        }
        active_.erase(key);
        return merged;
      }

      // While resolving an outer loop, a guarded join can see the bare
      // recursive sentinel for that loop alongside direct finite state
      // assignments. Summarize precisely that identity-or-finite recurrence;
      // it is not independently converged (entryValues stays empty), so it
      // cannot be reused as a nested loop without the outer merge proving a
      // finite entry domain.
      ExprPtr recursiveSentinel;
      std::set<uint32_t> recurrenceValues;
      std::set<uint32_t> recurrenceDefinitions;
      bool finiteRecurrenceJoin = !paths.empty();
      for (const auto& path : paths) {
        const auto& expression = path.result.expression;
        if (path.result.limitHit || path.result.incompleteCaseEntryPath || !expression) {
          finiteRecurrenceJoin = false;
          break;
        }
        if (expression->kind == ExprKind::LoopPhi && expression->reg == reg) {
          if (!recursiveSentinel) {
            recursiveSentinel = expression;
          } else if (recursiveSentinel->origin != expression->origin) {
            finiteRecurrenceJoin = false;
            break;
          }
          recurrenceValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
          recurrenceDefinitions.insert(expression->backedgeDefinitions.begin(),
                                       expression->backedgeDefinitions.end());
        } else if (expression->kind == ExprKind::Constant) {
          recurrenceValues.insert(expression->value);
          recurrenceDefinitions.insert(expression->origin ? expression->origin : path.predecessor);
        } else if (expression->kind == ExprKind::FinitePhi && expression->reg == reg &&
                   !expression->finiteValues.empty()) {
          recurrenceValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
          recurrenceDefinitions.insert(expression->entryDefinitions.begin(),
                                       expression->entryDefinitions.end());
        } else {
          finiteRecurrenceJoin = false;
          break;
        }
      }
      if (finiteRecurrenceJoin && recursiveSentinel && recursiveSentinel->origin != before &&
          !recurrenceValues.empty()) {
        merged.expression = MakeLoopPhi(
            reg, recursiveSentinel->origin, {recurrenceValues.begin(), recurrenceValues.end()}, {},
            {recurrenceDefinitions.begin(), recurrenceDefinitions.end()}, {},
            {recurrenceValues.begin(), recurrenceValues.end()}, {}, true);
        for (auto& path : paths) {
          merged.evidence.insert(merged.evidence.end(), path.result.evidence.begin(),
                                 path.result.evidence.end());
          merged.alternatives.insert(merged.alternatives.end(), path.result.alternatives.begin(),
                                     path.result.alternatives.end());
          if (pathEvidence_) {
            pathEvidence_->push_back({.registerIndex = reg,
                                      .mergeAddress = before,
                                      .predecessor = path.predecessor,
                                      .loopHeader = recursiveSentinel->origin,
                                      .backedge = true,
                                      .limitHit = false,
                                      .expression = ExprKey(path.result.expression),
                                      .normalizedExpression = ExprShape(path.result.expression),
                                      .disposition = "finite_identity_recurrence"});
          }
        }
        active_.erase(key);
        return merged;
      }

      // Preserve an exact finite union at an acyclic or intra-loop join. This
      // is not equivalence and is not collapsed to one definition: the phi
      // retains every constant value and defining instruction. It can feed a
      // surrounding validated loop recurrence, while remaining non-constant
      // if it is encountered as a table base, anchor, width, or scale.
      bool finiteJoin = !paths.empty();
      std::set<uint32_t> finiteJoinValues;
      std::set<uint32_t> finiteJoinDefinitions;
      for (const auto& path : paths) {
        const auto& expression = path.result.expression;
        if (path.result.limitHit || path.result.incompleteCaseEntryPath || !expression) {
          finiteJoin = false;
          break;
        }
        if (expression->kind == ExprKind::Constant) {
          finiteJoinValues.insert(expression->value);
          finiteJoinDefinitions.insert(expression->origin ? expression->origin : path.predecessor);
        } else if (expression->kind == ExprKind::FinitePhi && expression->reg == reg &&
                   !expression->finiteValues.empty()) {
          finiteJoinValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
          finiteJoinDefinitions.insert(expression->entryDefinitions.begin(),
                                       expression->entryDefinitions.end());
        } else {
          finiteJoin = false;
          break;
        }
      }
      if (finiteJoin && !finiteJoinValues.empty()) {
        merged.expression =
            MakeFinitePhi(reg, before, {finiteJoinValues.begin(), finiteJoinValues.end()},
                          {finiteJoinDefinitions.begin(), finiteJoinDefinitions.end()});
        for (auto& path : paths) {
          merged.evidence.insert(merged.evidence.end(), path.result.evidence.begin(),
                                 path.result.evidence.end());
          merged.alternatives.insert(merged.alternatives.end(), path.result.alternatives.begin(),
                                     path.result.alternatives.end());
          if (pathEvidence_) {
            pathEvidence_->push_back(
                {.registerIndex = reg,
                 .mergeAddress = before,
                 .predecessor = path.predecessor,
                 .loopHeader = before,
                 .backedge = false,
                 .limitHit = false,
                 .expression = ExprKey(path.result.expression),
                 .normalizedExpression = ExprShape(path.result.expression),
                 .disposition = path.result.expression->kind == ExprKind::FinitePhi
                                    ? "finite_phi_join"
                                    : "finite_constant_join"});
          }
        }
        active_.erase(key);
        return merged;
      }

      bool loopMerge = true;
      bool sawLoopPhi = false;
      bool sawFiniteEntry = false;
      bool identityBackedge = false;
      std::set<uint32_t> finiteValues;
      std::set<uint32_t> entryDefinitions;
      std::set<uint32_t> backedgeDefinitions;
      std::set<uint32_t> entryValues;
      std::set<uint32_t> backedgeValues;
      std::vector<ExprPtr> nestedLoopPhis;
      bool cycleHeaderLimit = false;
      const uint32_t loopHeader = cfg_.CanonicalCycleHeader(before, limits_, &cycleHeaderLimit);
      if (cycleHeaderLimit)
        loopMerge = false;
      for (auto& path : paths) {
        const auto& expression = path.result.expression;
        bool reachabilityLimit = false;
        const bool backedge =
            cfg_.IsBackedgePredecessor(before, path.predecessor, limits_, &reachabilityLimit);
        JumpTableReachingDefinitionPathEvidence* pathRecord = nullptr;
        if (pathEvidence_) {
          pathEvidence_->push_back({.registerIndex = reg,
                                    .mergeAddress = before,
                                    .predecessor = path.predecessor,
                                    .loopHeader = loopHeader,
                                    .backedge = backedge,
                                    .limitHit = reachabilityLimit || path.result.limitHit,
                                    .expression = ExprKey(expression),
                                    .normalizedExpression = ExprShape(expression),
                                    .disposition = {}});
          pathRecord = &pathEvidence_->back();
        }
        if (reachabilityLimit || path.result.limitHit || !expression) {
          if (pathRecord) {
            pathRecord->disposition = reachabilityLimit      ? "topology_limit"
                                      : path.result.limitHit ? "path_limit"
                                                             : "missing_expression";
          }
          loopMerge = false;
          break;
        }
        if (expression->kind == ExprKind::LoopPhi) {
          if (expression->reg == reg && expression->origin == loopHeader) {
            if (pathRecord)
              pathRecord->disposition = "identity_backedge";
            sawLoopPhi = true;
            identityBackedge = true;
            backedgeDefinitions.insert(expression->backedgeDefinitions.begin(),
                                       expression->backedgeDefinitions.end());
            if (expression->backedgeDefinitions.empty())
              backedgeDefinitions.insert(path.predecessor);
            finiteValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
            backedgeValues.insert(expression->backedgeValues.begin(),
                                  expression->backedgeValues.end());
            continue;
          }

          // An identity-preserving inner loop or loop-invariant source
          // register can feed the entry/backedge of an enclosing state loop.
          // Collapse it only after that source phi has independently
          // converged to a finite domain; a bare recursive sentinel or
          // transformed recurrence is not sufficient.
          if (!expression->identityBackedge || expression->entryValues.empty() ||
              expression->finiteValues.empty()) {
            if (pathRecord)
              pathRecord->disposition = "incompatible_nested_loop";
            loopMerge = false;
            break;
          }
          if (pathRecord) {
            pathRecord->disposition =
                expression->reg == reg ? "finite_nested_loop" : "finite_cross_register_loop";
          }
          nestedLoopPhis.push_back(expression);
          finiteValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
          const auto addDefinitions = [&](std::set<uint32_t>& destination) {
            destination.insert(expression->entryDefinitions.begin(),
                               expression->entryDefinitions.end());
            destination.insert(expression->backedgeDefinitions.begin(),
                               expression->backedgeDefinitions.end());
            if (expression->entryDefinitions.empty() && expression->backedgeDefinitions.empty()) {
              destination.insert(path.predecessor);
            }
          };
          if (backedge) {
            addDefinitions(backedgeDefinitions);
            backedgeValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
          } else {
            sawFiniteEntry = true;
            addDefinitions(entryDefinitions);
            entryValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
          }
          continue;
        }
        if (expression->kind == ExprKind::FinitePhi && expression->reg == reg &&
            !expression->finiteValues.empty()) {
          if (pathRecord)
            pathRecord->disposition = "finite_phi_domain";
          finiteValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
          const auto& definitions = expression->entryDefinitions;
          if (backedge) {
            backedgeDefinitions.insert(definitions.begin(), definitions.end());
            backedgeValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
          } else {
            sawFiniteEntry = true;
            entryDefinitions.insert(definitions.begin(), definitions.end());
            entryValues.insert(expression->finiteValues.begin(), expression->finiteValues.end());
          }
          continue;
        }
        if (expression->kind != ExprKind::Constant) {
          if (pathRecord)
            pathRecord->disposition = "incompatible_definition_kind";
          loopMerge = false;
          break;
        }
        if (pathRecord)
          pathRecord->disposition = backedge ? "finite_constant_backedge" : "finite_constant_entry";
        finiteValues.insert(expression->value);
        const uint32_t definitionAddress =
            expression->origin ? expression->origin : path.predecessor;
        if (backedge) {
          backedgeDefinitions.insert(definitionAddress);
          backedgeValues.insert(expression->value);
        } else {
          sawFiniteEntry = true;
          entryDefinitions.insert(definitionAddress);
          entryValues.insert(expression->value);
        }
      }
      if (loopMerge && sawLoopPhi && sawFiniteEntry) {
        merged.expression = MakeLoopPhi(reg, loopHeader, {finiteValues.begin(), finiteValues.end()},
                                        {entryDefinitions.begin(), entryDefinitions.end()},
                                        {backedgeDefinitions.begin(), backedgeDefinitions.end()},
                                        {entryValues.begin(), entryValues.end()},
                                        {backedgeValues.begin(), backedgeValues.end()},
                                        std::move(nestedLoopPhis), identityBackedge);
        for (auto& path : paths) {
          merged.evidence.insert(merged.evidence.end(), path.result.evidence.begin(),
                                 path.result.evidence.end());
          merged.alternatives.insert(merged.alternatives.end(), path.result.alternatives.begin(),
                                     path.result.alternatives.end());
        }
      } else {
        merged.expression = MakeUnknown();
        merged.ambiguous = true;
      }
      size_t completeAlternatives = 0;
      bool hasIncompleteAlternative = false;
      for (auto& [unused, result] : alternatives) {
        if (result.incompleteCaseEntryPath) {
          hasIncompleteAlternative = true;
        } else {
          ++completeAlternatives;
        }
        merged.limitHit = merged.limitHit || result.limitHit;
        if (!loopMerge || !sawLoopPhi || !sawFiniteEntry) {
          merged.evidence.insert(merged.evidence.end(), result.evidence.begin(),
                                 result.evidence.end());
          merged.alternatives.insert(merged.alternatives.end(), result.alternatives.begin(),
                                     result.alternatives.end());
        }
      }
      merged.incompleteCaseEntryPath = completeAlternatives == 1 && hasIncompleteAlternative;
    } else {
      merged = std::move(alternatives.begin()->second);
    }
    if (merged.ambiguous) {
      std::string detail = "r" + std::to_string(reg) + "@" + std::to_string(before) + "{";
      bool first = true;
      for (const auto& [expressionKey, unused] : alternatives) {
        if (!first)
          detail += ',';
        first = false;
        detail += expressionKey;
      }
      detail += '}';
      merged.alternatives.push_back(std::move(detail));
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
      result.alternatives.insert(result.alternatives.end(), resolved.alternatives.begin(),
                                 resolved.alternatives.end());
      return resolved.expression;
    };

    switch (instruction.opcode) {
      case Opcode::li:
      case Opcode::addi: {
        if (instruction.D.RA == 0) {
          result.expression =
              MakeConstant(static_cast<uint32_t>(instruction.D.SIMM()), instruction.address);
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
  std::vector<JumpTableReachingDefinitionPathEvidence>* pathEvidence_;
  uint32_t visitedStates_ = 0;
  bool maxStatesLimitHit_ = false;
  std::unordered_set<uint64_t> active_;
  std::unordered_map<uint8_t, ConstantInvariant> constantInvariants_;
};

struct BoundCandidate {
  uint32_t compareAddress = 0;
  uint32_t guardAddress = 0;
  uint32_t domainOriginAddress = 0;
  uint32_t value = 0;
  uint32_t caseCount = 0;
  uint32_t defaultTarget = 0;
  uint8_t indexRegister = 0xFF;
  bool inclusive = false;
  bool defaultIsReturn = false;
  bool finiteCfgDomain = false;
  bool interproceduralEntryDomain = false;
  std::vector<uint32_t> finiteValues;
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
    // A signed upper bound alone admits negative indices. CollectBoundEvidence
    // retains cmpi for diagnostics, but production recovery requires an
    // unsigned dense zero-based domain until an independent lower-bound proof
    // exists.
    if (!compare || compare->opcode != Opcode::cmpli)
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

std::vector<JumpTableBoundCandidateEvidence> CollectBoundEvidence(
    DecodedBinary& decoded, const LocalCfg& cfg, uint32_t site,
    const JumpTableRecoveryLimits& limits, bool* limitHit) {
  std::vector<JumpTableBoundCandidateEvidence> output;
  for (uint32_t address : BackwardReachable(cfg, site, limits, limitHit)) {
    const auto* compare = decoded.get(address);
    if (!compare || (compare->opcode != Opcode::cmpli && compare->opcode != Opcode::cmpi))
      continue;

    JumpTableBoundCandidateEvidence evidence;
    evidence.compareAddress = address;
    evidence.value = compare->opcode == Opcode::cmpli ? compare->D.UIMM()
                                                      : static_cast<uint32_t>(compare->D.SIMM());
    evidence.indexRegister = static_cast<uint8_t>(compare->D.RA);
    evidence.signedCompare = compare->opcode == Opcode::cmpi;
    evidence.dominatesDispatch = cfg.Dominates(address, site, limits, limitHit);
    if (!evidence.dominatesDispatch)
      evidence.rejection = "compare_does_not_dominate_dispatch";

    const Instruction* guard = nullptr;
    constexpr uint32_t kMaxGuardLookaheadInstructions = 16;
    for (uint32_t cursor = address + 4; cursor <= address + kMaxGuardLookaheadInstructions * 4;
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
    if (!guard) {
      if (evidence.rejection.empty())
        evidence.rejection = "no_related_conditional_guard";
      output.push_back(std::move(evidence));
      continue;
    }
    evidence.guardAddress = guard->address;

    const uint8_t compareCr = static_cast<uint8_t>(compare->D.RT >> 2);
    const uint8_t guardBi = guard->format == ppc::InstrFormat::kB ? guard->B.BI : guard->XL.BI;
    auto branchTrue = BranchWhenCrBitTrue(*guard);
    if (guardBi / 4 != compareCr || !branchTrue) {
      if (evidence.rejection.empty())
        evidence.rejection = "guard_uses_unrelated_condition";
      output.push_back(std::move(evidence));
      continue;
    }

    bool takenReachesSite = false;
    bool fallthroughReachesSite = false;
    if (guard->opcode == Opcode::bclr || guard->opcode == Opcode::bclrl) {
      evidence.defaultIsReturn = true;
      fallthroughReachesSite = cfg.Reaches(guard->address + 4, site, address, limits, limitHit);
    } else if (guard->branch_target) {
      takenReachesSite = cfg.Reaches(*guard->branch_target, site, address, limits, limitHit);
      fallthroughReachesSite = cfg.Reaches(guard->address + 4, site, address, limits, limitHit);
    }
    if (takenReachesSite == fallthroughReachesSite) {
      if (evidence.rejection.empty())
        evidence.rejection = "guard_does_not_separate_case_and_default_paths";
      output.push_back(std::move(evidence));
      continue;
    }

    const bool defaultOnTaken = !takenReachesSite;
    const bool defaultConditionTrue = defaultOnTaken ? *branchTrue : !*branchTrue;
    const uint8_t bit = BranchConditionBit(*guard);
    if (!evidence.defaultIsReturn)
      evidence.defaultTarget = defaultOnTaken ? *guard->branch_target : guard->address + 4;
    if (bit == 1 && defaultConditionTrue) {
      evidence.inclusive = true;
      evidence.caseCount = evidence.value + 1;
    } else if (bit == 0 && !defaultConditionTrue) {
      evidence.inclusive = false;
      evidence.caseCount = evidence.value;
    } else if (evidence.rejection.empty()) {
      evidence.rejection = "guard_does_not_prove_dense_zero_based_upper_bound";
    }
    evidence.finiteDenseDomain = evidence.dominatesDispatch && !evidence.signedCompare &&
                                 evidence.caseCount != 0 && evidence.caseCount <= limits.maxEntries;
    if (evidence.signedCompare && evidence.rejection.empty())
      evidence.rejection = "signed_upper_bound_does_not_exclude_negative_indices";
    else if (evidence.caseCount > limits.maxEntries && evidence.rejection.empty())
      evidence.rejection = "bound_exceeds_entry_limit";
    output.push_back(std::move(evidence));
  }
  std::sort(output.begin(), output.end(), [](const auto& lhs, const auto& rhs) {
    if (lhs.compareAddress != rhs.compareAddress)
      return lhs.compareAddress < rhs.compareAddress;
    return lhs.guardAddress < rhs.guardAddress;
  });
  return output;
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
    case ExprKind::FinitePhi:
    case ExprKind::LoopPhi:
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

void CollectFiniteCfgDomainExpressions(const ExprPtr& expression,
                                       std::map<std::string, ExprPtr>& output) {
  if (!expression)
    return;
  if (expression->kind == ExprKind::FinitePhi || expression->kind == ExprKind::LoopPhi) {
    output.emplace(ExprKey(expression), expression);
    return;
  }
  CollectFiniteCfgDomainExpressions(expression->lhs, output);
  CollectFiniteCfgDomainExpressions(expression->rhs, output);
}

bool IsDenseZeroBasedDomain(const std::vector<uint32_t>& values) {
  if (values.empty())
    return false;
  for (size_t index = 0; index < values.size(); ++index) {
    if (values[index] != index)
      return false;
  }
  return true;
}

std::vector<BoundCandidate> FindFiniteCfgDomainBounds(
    DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableRecoveryInput& input,
    const ExprPtr& targetExpression, std::vector<JumpTableBoundCandidateEvidence>* reportEvidence,
    bool* limitHit) {
  std::map<std::string, ExprPtr> expressions;
  CollectFiniteCfgDomainExpressions(targetExpression, expressions);

  std::vector<std::pair<std::string, ExprPtr>> indexedDomains;
  for (const auto& [key, expression] : expressions) {
    if (FindPrimaryLoad(targetExpression, key))
      indexedDomains.emplace_back(key, expression);
  }

  std::vector<BoundCandidate> bounds;
  for (const auto& [key, expression] : indexedDomains) {
    JumpTableBoundCandidateEvidence report;
    report.domainOriginAddress = expression->origin;
    report.indexRegister = expression->reg;
    report.finiteCfgDomain = true;
    report.finiteValues = expression->finiteValues;
    report.caseCount = static_cast<uint32_t>(expression->finiteValues.size());
    report.value = expression->finiteValues.empty() ? 0 : expression->finiteValues.back();
    report.inclusive = true;

    const auto reject = [&](std::string reason) {
      if (report.rejection.empty())
        report.rejection = std::move(reason);
    };
    if (indexedDomains.size() != 1) {
      reject("multiple_finite_cfg_domains_in_target_expression");
    } else if (expression->finiteValues.empty()) {
      reject("empty_finite_cfg_domain");
    } else if (expression->finiteValues.size() > input.limits.maxEntries) {
      reject("finite_cfg_domain_exceeds_entry_limit");
    } else if (!IsDenseZeroBasedDomain(expression->finiteValues)) {
      reject("finite_cfg_domain_not_dense_zero_based");
    } else if (expression->kind == ExprKind::FinitePhi && expression->entryDefinitions.empty()) {
      reject("finite_cfg_domain_has_no_definitions");
    } else if (expression->kind == ExprKind::LoopPhi &&
               (!expression->identityBackedge || expression->entryValues.empty())) {
      reject("finite_loop_cfg_domain_not_converged");
    }

    bool dominanceLimit = false;
    if (report.rejection.empty()) {
      report.dominatesDispatch =
          cfg.Dominates(expression->origin, input.site, input.limits, &dominanceLimit);
      if (dominanceLimit) {
        if (limitHit)
          *limitHit = true;
        reject("finite_cfg_domain_dominance_limit");
      } else if (!report.dominatesDispatch) {
        reject("finite_cfg_domain_does_not_dominate_dispatch");
      }
    }

    bool stabilityLimit = false;
    if (report.rejection.empty() &&
        !cfg.RegisterValueAvailableOnEveryPath(expression->origin, input.site, expression->reg,
                                               input.limits, &stabilityLimit)) {
      if (stabilityLimit) {
        if (limitHit)
          *limitHit = true;
        reject("finite_cfg_domain_stability_limit");
      } else {
        reject("finite_cfg_domain_register_not_available_at_dispatch");
      }
    }

    report.finiteDenseDomain = report.rejection.empty();
    if (reportEvidence)
      reportEvidence->push_back(report);
    if (!report.finiteDenseDomain)
      continue;

    BoundCandidate bound;
    bound.domainOriginAddress = expression->origin;
    bound.value = report.value;
    bound.caseCount = report.caseCount;
    bound.indexRegister = expression->reg;
    bound.inclusive = true;
    bound.finiteCfgDomain = true;
    bound.finiteValues = expression->finiteValues;
    bound.indexExpression = expression;
    const auto addDefinitionEvidence = [&](uint32_t address, std::string role) {
      if (const auto* definition = decoded.get(address))
        bound.evidence.push_back(Evidence(*definition, std::move(role)));
    };
    for (uint32_t address : expression->entryDefinitions) {
      addDefinitionEvidence(address, expression->kind == ExprKind::LoopPhi
                                         ? "finite_cfg_domain_entry_definition"
                                         : "finite_cfg_domain_definition");
    }
    for (uint32_t address : expression->backedgeDefinitions)
      addDefinitionEvidence(address, "finite_cfg_domain_backedge_definition");
    bounds.push_back(std::move(bound));
  }
  return bounds;
}

std::vector<BoundCandidate> FindEntryRegisterDomainBounds(
    DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableRecoveryInput& input,
    const ExprPtr& targetExpression, std::vector<JumpTableBoundCandidateEvidence>* reportEvidence,
    bool* limitHit) {
  std::vector<BoundCandidate> bounds;
  if (!input.entryRegisterDomains)
    return bounds;

  std::vector<uint8_t> registers;
  registers.reserve(input.entryRegisterDomains->size());
  for (const auto& [reg, unused] : *input.entryRegisterDomains)
    registers.push_back(reg);
  std::sort(registers.begin(), registers.end());

  for (uint8_t reg : registers) {
    const auto& domain = input.entryRegisterDomains->at(reg);
    JumpTableBoundCandidateEvidence report;
    report.domainOriginAddress = input.ownerAddress;
    report.indexRegister = reg;
    report.interproceduralEntryDomain = true;
    report.finiteValues = domain.finiteValues;
    report.caseCount = static_cast<uint32_t>(domain.finiteValues.size());
    report.value = domain.finiteValues.empty() ? 0 : domain.finiteValues.back();
    report.inclusive = true;

    const auto reject = [&](std::string reason) {
      if (report.rejection.empty())
        report.rejection = std::move(reason);
    };
    if (domain.entryAddress != input.ownerAddress || domain.registerIndex != reg) {
      reject("entry_domain_identity_mismatch");
    } else if (!domain.allReferencesDirectCalls) {
      reject("entry_domain_has_unaccounted_reference");
    } else if (!domain.finiteDenseDomain) {
      reject(domain.rejection.empty() ? "entry_domain_not_finite_dense" : domain.rejection);
    } else if (domain.finiteValues.empty()) {
      reject("entry_domain_empty");
    } else if (domain.finiteValues.size() > input.limits.maxEntries) {
      reject("entry_domain_exceeds_entry_limit");
    } else if (!IsDenseZeroBasedDomain(domain.finiteValues)) {
      reject("entry_domain_not_dense_zero_based");
    }

    bool stabilityLimit = false;
    if (report.rejection.empty()) {
      report.dominatesDispatch = cfg.RegisterUnmodifiedOnEveryPath(
          input.ownerAddress, input.site, reg, input.limits, &stabilityLimit);
      if (stabilityLimit) {
        if (limitHit)
          *limitHit = true;
        reject("entry_domain_owner_stability_limit");
      } else if (!report.dominatesDispatch) {
        reject("entry_domain_register_modified_before_dispatch");
      }
    }
    if (report.rejection.empty()) {
      const Expr* tableLoad = FindFirstLoad(targetExpression);
      const auto coefficient =
          tableLoad ? LinearInputCoefficient(tableLoad->lhs, reg) : std::nullopt;
      if (!tableLoad || !coefficient || *coefficient != tableLoad->width)
        reject("entry_domain_register_not_exact_scaled_table_index");
    }

    report.finiteDenseDomain = report.rejection.empty();
    if (reportEvidence)
      reportEvidence->push_back(report);
    if (!report.finiteDenseDomain)
      continue;

    BoundCandidate bound;
    bound.domainOriginAddress = input.ownerAddress;
    bound.value = report.value;
    bound.caseCount = report.caseCount;
    bound.indexRegister = reg;
    bound.inclusive = true;
    bound.interproceduralEntryDomain = true;
    bound.finiteValues = domain.finiteValues;
    bound.indexExpression = MakeInputRegister(reg);
    for (const auto& callsite : domain.callsites) {
      const auto addEvidence = [&](uint32_t address, std::string role) {
        if (const auto* instruction = decoded.get(address))
          bound.evidence.push_back(Evidence(*instruction, std::move(role)));
      };
      for (uint32_t address : callsite.definitionAddresses)
        addEvidence(address, "entry_domain_callsite_definition");
      addEvidence(callsite.compareAddress, "entry_domain_callsite_bound");
      addEvidence(callsite.guardAddress, "entry_domain_callsite_guard");
      addEvidence(callsite.callAddress, "entry_domain_direct_call");
    }
    bounds.push_back(std::move(bound));
  }
  return bounds;
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

void CollectLoopEvidence(const ExprPtr& expression, std::vector<JumpTableLoopEvidence>& output) {
  if (!expression)
    return;
  if (expression->kind == ExprKind::LoopPhi) {
    auto existing = std::find_if(output.begin(), output.end(), [&](const auto& item) {
      return item.registerIndex == expression->reg && item.headerAddress == expression->origin;
    });
    JumpTableLoopEvidence evidence;
    evidence.registerIndex = expression->reg;
    evidence.headerAddress = expression->origin;
    evidence.entryDefinitionAddresses = expression->entryDefinitions;
    evidence.backedgeDefinitionAddresses = expression->backedgeDefinitions;
    evidence.entryValues = expression->entryValues;
    evidence.backedgeValues = expression->backedgeValues;
    evidence.finiteValues = expression->finiteValues;
    evidence.identityBackedge = expression->identityBackedge;
    evidence.finiteEntryDomain = !expression->entryValues.empty();
    evidence.converged = evidence.finiteEntryDomain && evidence.identityBackedge;
    if (existing == output.end())
      output.push_back(std::move(evidence));
    for (const auto& nested : expression->nestedLoopPhis)
      CollectLoopEvidence(nested, output);
    return;
  }
  CollectLoopEvidence(expression->lhs, output);
  CollectLoopEvidence(expression->rhs, output);
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

JumpTableManualComparison CompareManual(const JumpTable& automatic, const JumpTable& manual);

bool SameRecoveryTableSemantics(const JumpTable& lhs, const JumpTable& rhs) {
  if (lhs.rawEntries.size() != rhs.rawEntries.size())
    return false;
  for (size_t index = 0; index < lhs.rawEntries.size(); ++index) {
    if (lhs.rawEntries[index].storageAddress != rhs.rawEntries[index].storageAddress ||
        lhs.rawEntries[index].rawValue != rhs.rawEntries[index].rawValue ||
        lhs.rawEntries[index].target != rhs.rawEntries[index].target) {
      return false;
    }
  }
  return lhs.bctrAddress == rhs.bctrAddress && lhs.tableAddress == rhs.tableAddress &&
         lhs.indexRegister == rhs.indexRegister && lhs.targets == rhs.targets &&
         lhs.kind == rhs.kind && lhs.origin == rhs.origin &&
         lhs.manualComparison == rhs.manualComparison && lhs.ownerAddress == rhs.ownerAddress &&
         lhs.storageEnd == rhs.storageEnd && lhs.boundValue == rhs.boundValue &&
         lhs.caseCount == rhs.caseCount && lhs.defaultTarget == rhs.defaultTarget &&
         lhs.anchorAddress == rhs.anchorAddress && lhs.targetScale == rhs.targetScale &&
         lhs.elementWidth == rhs.elementWidth && lhs.elementSigned == rhs.elementSigned &&
         lhs.boundInclusive == rhs.boundInclusive && lhs.defaultIsReturn == rhs.defaultIsReturn &&
         lhs.tableInExecutableSection == rhs.tableInExecutableSection &&
         lhs.boundSemantics == rhs.boundSemantics && lhs.conflicts == rhs.conflicts;
}

bool TargetWithinValidatedOwner(const JumpTableRecoveryInput& input, uint32_t target) {
  if (input.containingRegion && input.containingRegion->contains(target))
    return true;
  return input.trustedOwnerEnd > input.ownerAddress && target >= input.ownerAddress &&
         target < input.trustedOwnerEnd;
}

struct LocalBoundIndexLineageValidation {
  bool valid = false;
  bool limitHit = false;
  std::string rejection;
};

LocalBoundIndexLineageValidation ValidateLocalBoundIndexLineage(
    DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableRecoveryLimits& limits,
    const ExprPtr& expression, bool requireStableLoadBase) {
  LocalBoundIndexLineageValidation validation;
  std::unordered_set<const Expr*> visited;
  std::function<bool(const ExprPtr&)> validate = [&](const ExprPtr& current) {
    if (!current) {
      validation.rejection = "missing_bound_index_expression";
      return false;
    }
    if (!visited.insert(current.get()).second)
      return true;
    switch (current->kind) {
      case ExprKind::Unknown:
        validation.rejection = "unknown_bound_index_lineage";
        return false;
      case ExprKind::Constant:
      case ExprKind::InputRegister:
        return true;
      case ExprKind::FinitePhi:
        if (current->finiteValues.empty()) {
          validation.rejection = "empty_finite_bound_index_phi";
          return false;
        }
        return true;
      case ExprKind::LoopPhi:
        if (!current->identityBackedge || current->entryValues.empty() ||
            current->finiteValues.empty()) {
          validation.rejection = "unvalidated_loop_bound_index_phi";
          return false;
        }
        for (const auto& nested : current->nestedLoopPhis) {
          if (!validate(nested))
            return false;
        }
        return true;
      case ExprKind::SymbolicDefinition: {
        const auto* definition = decoded.get(current->origin);
        if (!definition) {
          validation.rejection = "missing_symbolic_bound_index_definition";
          return false;
        }
        bool topologyLimit = false;
        if (cfg.IsInCycle(current->origin, limits, &topologyLimit)) {
          validation.rejection = "symbolic_loop_bound_index_definition";
          return false;
        }
        if (topologyLimit) {
          validation.limitHit = true;
          validation.rejection = "bound_index_topology_limit";
          return false;
        }
        if ((definition->opcode == Opcode::lwz || definition->opcode == Opcode::lhz ||
             definition->opcode == Opcode::lbz) &&
            requireStableLoadBase && definition->D.RA != 0 && definition->D.RA != 1) {
          // A symbolic fallback for an unresolved arbitrary-base load has lost
          // the address lineage that distinguished it from another load. The
          // maxStates fallback may bypass r1 traversal, but may not generalise
          // that exception to an opaque object/global base.
          validation.rejection = "unstable_symbolic_bound_index_load_base";
          return false;
        }
        return true;
      }
      case ExprKind::Load: {
        const auto* load = decoded.get(current->origin);
        if (!load) {
          validation.rejection = "missing_bound_index_load";
          return false;
        }
        if ((load->opcode == Opcode::lwz || load->opcode == Opcode::lhz ||
             load->opcode == Opcode::lbz) &&
            requireStableLoadBase && load->D.RA != 0 && load->D.RA != 1 &&
            !EvaluateConstant(current->lhs)) {
          validation.rejection = "unresolved_bound_index_load_base";
          return false;
        }
        return true;
      }
      case ExprKind::Add:
        return validate(current->lhs) && validate(current->rhs);
      case ExprKind::ShiftLeft:
      case ExprKind::SignExtend:
        return validate(current->lhs);
    }
    validation.rejection = "unsupported_bound_index_lineage";
    return false;
  };
  validation.valid = validate(expression);
  return validation;
}

bool ContainsFreshBoundIndexLoad(DecodedBinary& decoded, const ExprPtr& expression) {
  if (!expression)
    return false;
  if (expression->kind == ExprKind::Load)
    return true;
  if (expression->kind == ExprKind::SymbolicDefinition) {
    const auto* definition = decoded.get(expression->origin);
    return definition && (definition->opcode == Opcode::lwz || definition->opcode == Opcode::lhz ||
                          definition->opcode == Opcode::lbz || definition->opcode == Opcode::lwzx ||
                          definition->opcode == Opcode::lhzx || definition->opcode == Opcode::lbzx);
  }
  return ContainsFreshBoundIndexLoad(decoded, expression->lhs) ||
         ContainsFreshBoundIndexLoad(decoded, expression->rhs);
}

struct FreshBoundIndexDefinition {
  bool valid = false;
  bool limitHit = false;
  std::vector<JumpTableInstructionEvidence> evidence;
  std::string rejection;
};

FreshBoundIndexDefinition FindFreshBoundIndexDefinition(DecodedBinary& decoded, const LocalCfg& cfg,
                                                        const JumpTableRecoveryLimits& limits,
                                                        uint8_t reg, uint32_t before) {
  FreshBoundIndexDefinition result;
  std::unordered_set<uint64_t> visited;
  std::function<bool(uint8_t, uint32_t, uint32_t)> trace = [&](uint8_t currentReg, uint32_t cursor,
                                                               uint32_t depth) {
    if (depth >= limits.maxBackwardInstructions) {
      result.limitHit = true;
      result.rejection = "fresh_bound_definition_trace_limit";
      return false;
    }
    const uint64_t key = (static_cast<uint64_t>(cursor) << 8) | currentReg;
    if (!visited.insert(key).second) {
      result.rejection = "fresh_bound_definition_cycle";
      return false;
    }
    const auto& predecessors = cfg.predecessors(cursor);
    if (predecessors.size() != 1) {
      result.rejection =
          "fresh_bound_definition_predecessor_count_" + std::to_string(predecessors.size());
      return false;
    }
    const auto* instruction = decoded.get(predecessors.front());
    if (!instruction) {
      result.rejection = "fresh_bound_definition_not_decoded";
      return false;
    }
    if (instruction->is_call()) {
      if (currentReg != 3) {
        result.rejection = "fresh_bound_definition_crosses_call";
        return false;
      }
      result.evidence.push_back(Evidence(*instruction, "local_bounded_slice_fresh_call_result"));
      return true;
    }
    if (!WritesRegister(*instruction, currentReg)) {
      if (instruction->is_branch()) {
        result.rejection = "fresh_bound_definition_crosses_branch";
        return false;
      }
      return trace(currentReg, instruction->address, depth + 1);
    }

    result.evidence.push_back(Evidence(*instruction, "local_bounded_slice_fresh_index_definition"));
    switch (instruction->opcode) {
      case Opcode::lwz:
      case Opcode::lhz:
      case Opcode::lbz:
      case Opcode::lwzx:
      case Opcode::lhzx:
      case Opcode::lbzx:
        return true;
      case Opcode::addi:
      case Opcode::addis:
        if (instruction->D.RA == 0) {
          result.rejection = "constant_bound_definition_is_not_fresh";
          return false;
        }
        return trace(static_cast<uint8_t>(instruction->D.RA), instruction->address, depth + 1);
      case Opcode::mr:
      case Opcode::or_:
      case Opcode::extsb:
      case Opcode::extsh:
        return trace(static_cast<uint8_t>(instruction->X.RT), instruction->address, depth + 1);
      case Opcode::rlwinm:
        return trace(static_cast<uint8_t>(instruction->M.RS), instruction->address, depth + 1);
      case Opcode::srawi:
        return trace(static_cast<uint8_t>(instruction->X.RT), instruction->address, depth + 1);
      default:
        result.rejection = "fresh_bound_definition_unsupported_opcode";
        return false;
    }
  };
  result.valid = trace(reg, before, 0);
  if (!result.valid)
    result.evidence.clear();
  return result;
}

struct LocalSliceTrace {
  ExprPtr expression;
  bool limitHit = false;
  std::string rejection;
  std::vector<JumpTableInstructionEvidence> evidence;
};

std::optional<uint32_t> BoundCasePathStart(DecodedBinary& decoded,
                                           const JumpTableBoundCandidateEvidence& bound) {
  const auto* guard = decoded.get(bound.guardAddress);
  if (!guard)
    return std::nullopt;
  if (guard->opcode == Opcode::bclr || guard->opcode == Opcode::bclrl)
    return guard->address + 4;
  if (guard->branch_target && bound.defaultTarget == *guard->branch_target)
    return guard->address + 4;
  if (guard->branch_target && bound.defaultTarget == guard->address + 4)
    return *guard->branch_target;
  return std::nullopt;
}

struct EquivalentBoundIndexRecomputation {
  const Instruction* boundDefinition = nullptr;
  const Instruction* casePathDefinition = nullptr;
};

std::optional<EquivalentBoundIndexRecomputation> FindEquivalentBoundIndexRecomputation(
    DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableRecoveryLimits& limits,
    const JumpTableBoundCandidateEvidence& bound, bool* limitHit) {
  const auto casePathStart = BoundCasePathStart(decoded, bound);
  if (!casePathStart || !cfg.contains(*casePathStart) || !cfg.contains(bound.compareAddress) ||
      !cfg.contains(bound.guardAddress)) {
    return std::nullopt;
  }

  const Instruction* boundDefinition = nullptr;
  uint32_t cursor = bound.compareAddress;
  std::unordered_set<uint32_t> visited;
  for (uint32_t depth = 0; depth < limits.maxBackwardInstructions; ++depth) {
    if (!visited.insert(cursor).second)
      return std::nullopt;
    const auto& predecessors = cfg.predecessors(cursor);
    if (predecessors.size() != 1)
      return std::nullopt;
    const auto* instruction = decoded.get(predecessors.front());
    if (!instruction)
      return std::nullopt;
    if (WritesRegister(*instruction, bound.indexRegister)) {
      boundDefinition = instruction;
      break;
    }
    if (instruction->is_call() || instruction->is_branch())
      return std::nullopt;
    cursor = instruction->address;
  }
  if (!boundDefinition ||
      (boundDefinition->opcode != Opcode::addi && boundDefinition->opcode != Opcode::addis) ||
      boundDefinition->D.RA == 0 || boundDefinition->D.RA == bound.indexRegister) {
    return std::nullopt;
  }

  const Instruction* casePathDefinition = nullptr;
  cursor = *casePathStart;
  visited.clear();
  for (uint32_t depth = 0; depth < limits.maxBackwardInstructions; ++depth) {
    if (!visited.insert(cursor).second)
      return std::nullopt;
    const auto* instruction = decoded.get(cursor);
    if (!instruction)
      return std::nullopt;
    if (WritesRegister(*instruction, bound.indexRegister)) {
      casePathDefinition = instruction;
      break;
    }
    if (instruction->is_call() || instruction->is_branch())
      return std::nullopt;
    const auto& successors = cfg.successors(cursor);
    if (successors.size() != 1)
      return std::nullopt;
    cursor = successors.front();
  }
  if (!casePathDefinition || static_cast<uint32_t>(casePathDefinition->code) !=
                                 static_cast<uint32_t>(boundDefinition->code)) {
    return std::nullopt;
  }

  const uint8_t sourceRegister = static_cast<uint8_t>(boundDefinition->D.RA);
  bool sourceLimit = false;
  const bool sourceReachesGuard = cfg.RegisterValueAvailableOnEveryPath(
      boundDefinition->address + 4, bound.guardAddress, sourceRegister, limits, &sourceLimit);
  const bool sourceReachesRecomputation =
      !sourceLimit &&
      cfg.RegisterValueAvailableOnEveryPath(*casePathStart, casePathDefinition->address,
                                            sourceRegister, limits, &sourceLimit);
  if (sourceLimit) {
    if (limitHit)
      *limitHit = true;
    return std::nullopt;
  }
  if (!sourceReachesGuard || !sourceReachesRecomputation)
    return std::nullopt;

  return EquivalentBoundIndexRecomputation{boundDefinition, casePathDefinition};
}

std::optional<uint32_t> EquivalentBoundCasePathStart(
    DecodedBinary& decoded, const JumpTableBoundCandidateEvidence& canonical,
    const JumpTableBoundCandidateEvidence& candidate) {
  if (candidate.guardAddress == 0 || candidate.signedCompare ||
      candidate.indexRegister != canonical.indexRegister || candidate.value != canonical.value) {
    return std::nullopt;
  }
  const auto* guard = decoded.get(candidate.guardAddress);
  if (!guard)
    return std::nullopt;
  if (guard->opcode == Opcode::bclr || guard->opcode == Opcode::bclrl) {
    return candidate.caseCount == canonical.caseCount ? BoundCasePathStart(decoded, candidate)
                                                      : std::nullopt;
  }
  if (!guard->branch_target)
    return std::nullopt;
  auto branchTrue = BranchWhenCrBitTrue(*guard);
  if (!branchTrue)
    return std::nullopt;
  const uint8_t bit = BranchConditionBit(*guard);
  bool caseOnTaken = false;
  if (canonical.inclusive && bit == 1) {
    // The dense case domain is index <= bound, i.e. CR.GT is false.
    caseOnTaken = !*branchTrue;
  } else if (!canonical.inclusive && bit == 0) {
    // The dense case domain is index < bound, i.e. CR.LT is true.
    caseOnTaken = *branchTrue;
  } else {
    return std::nullopt;
  }
  return caseOnTaken ? *guard->branch_target : guard->address + 4;
}

std::vector<JumpTableBoundCandidateEvidence> RecoverExactPriorBoundEvidence(
    DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableRecoveryInput& input,
    bool* limitHit) {
  std::vector<JumpTableBoundCandidateEvidence> output;
  const auto* prior = input.priorAutomaticTable;
  if (!prior || prior->origin != JumpTableOrigin::Automatic || prior->bctrAddress != input.site ||
      prior->ownerAddress != input.ownerAddress || prior->indexRegister == 0xFF ||
      prior->caseCount == 0 || prior->rawEntries.size() != prior->caseCount ||
      prior->targets.size() != prior->caseCount) {
    return output;
  }

  std::map<uint32_t, uint32_t> exactCompares;
  std::map<uint32_t, uint32_t> exactGuards;
  std::set<uint32_t> directBoundedCompares;
  std::set<uint32_t> directBoundedGuards;
  for (const auto& evidence : prior->evidence) {
    if (evidence.role == "case_bound" || evidence.role == "bounded_index_compare" ||
        evidence.role == "local_bounded_slice_compare" ||
        evidence.role == "local_bounded_slice_prior_exact_compare" ||
        evidence.role == "local_bounded_slice_prior_direct_compare" ||
        evidence.role == "local_bounded_slice_state_limit_compare") {
      exactCompares[evidence.address] = evidence.rawInstruction;
      if (evidence.role == "bounded_index_compare" ||
          evidence.role == "local_bounded_slice_compare" ||
          evidence.role == "local_bounded_slice_prior_direct_compare" ||
          evidence.role == "local_bounded_slice_state_limit_compare") {
        directBoundedCompares.insert(evidence.address);
      }
    } else if (evidence.role == "default_guard" || evidence.role == "bounded_index_guard" ||
               evidence.role == "local_bounded_slice_guard" ||
               evidence.role == "local_bounded_slice_prior_exact_guard" ||
               evidence.role == "local_bounded_slice_prior_direct_guard" ||
               evidence.role == "local_bounded_slice_state_limit_guard") {
      exactGuards[evidence.address] = evidence.rawInstruction;
      if (evidence.role == "bounded_index_guard" || evidence.role == "local_bounded_slice_guard" ||
          evidence.role == "local_bounded_slice_prior_direct_guard" ||
          evidence.role == "local_bounded_slice_state_limit_guard") {
        directBoundedGuards.insert(evidence.address);
      }
    }
  }
  if (exactCompares.empty() || exactGuards.empty() ||
      cfg.addresses().size() > input.limits.maxCfgTopologyNodes) {
    if (cfg.addresses().size() > input.limits.maxCfgTopologyNodes && limitHit)
      *limitHit = true;
    return output;
  }

  const auto recoverPair = [&](const Instruction& compare, const Instruction& guard,
                               bool exactPrior) -> std::optional<JumpTableBoundCandidateEvidence> {
    if (compare.opcode != Opcode::cmpli ||
        static_cast<uint8_t>(compare.D.RA) != prior->indexRegister ||
        compare.D.UIMM() != prior->boundValue || !cfg.contains(compare.address) ||
        !cfg.contains(guard.address)) {
      return std::nullopt;
    }

    const uint8_t compareCr = static_cast<uint8_t>(compare.D.RT >> 2);
    const uint8_t guardBi = guard.format == ppc::InstrFormat::kB ? guard.B.BI : guard.XL.BI;
    auto branchTrue = BranchWhenCrBitTrue(guard);
    if (!branchTrue || guardBi / 4 != compareCr)
      return std::nullopt;
    const uint8_t bit = BranchConditionBit(guard);
    bool caseOnTaken = false;
    if (prior->boundInclusive && bit == 1 && prior->caseCount == prior->boundValue + 1) {
      caseOnTaken = !*branchTrue;
    } else if (!prior->boundInclusive && bit == 0 && prior->caseCount == prior->boundValue) {
      caseOnTaken = *branchTrue;
    } else {
      return std::nullopt;
    }

    uint32_t casePathStart = 0;
    uint32_t defaultTarget = 0;
    bool defaultIsReturn = false;
    if (guard.opcode == Opcode::bclr || guard.opcode == Opcode::bclrl) {
      if (caseOnTaken)
        return std::nullopt;
      casePathStart = guard.address + 4;
      defaultIsReturn = true;
    } else if (guard.branch_target) {
      casePathStart = caseOnTaken ? *guard.branch_target : guard.address + 4;
      defaultTarget = caseOnTaken ? guard.address + 4 : *guard.branch_target;
    } else {
      return std::nullopt;
    }
    if (!cfg.contains(casePathStart))
      return std::nullopt;
    if (exactPrior && (defaultIsReturn != prior->defaultIsReturn ||
                       (!defaultIsReturn && defaultTarget != prior->defaultTarget))) {
      return std::nullopt;
    }

    if (!exactPrior) {
      bool reachabilityLimit = false;
      const bool caseReachesDispatch =
          cfg.Reaches(casePathStart, input.site, compare.address, input.limits, &reachabilityLimit);
      if (reachabilityLimit) {
        if (limitHit)
          *limitHit = true;
        return std::nullopt;
      }
      if (!caseReachesDispatch)
        return std::nullopt;
    }

    JumpTableBoundCandidateEvidence evidence;
    evidence.compareAddress = compare.address;
    evidence.guardAddress = guard.address;
    evidence.value = prior->boundValue;
    evidence.caseCount = prior->caseCount;
    evidence.defaultTarget = exactPrior ? prior->defaultTarget : defaultTarget;
    evidence.indexRegister = prior->indexRegister;
    evidence.inclusive = prior->boundInclusive;
    evidence.defaultIsReturn = exactPrior ? prior->defaultIsReturn : defaultIsReturn;
    evidence.dominatesDispatch = exactPrior;
    evidence.finiteDenseDomain = exactPrior;
    evidence.priorExactRevalidation = exactPrior;
    evidence.priorDirectBoundedIndexRevalidation =
        exactPrior && directBoundedCompares.contains(compare.address) &&
        directBoundedGuards.contains(guard.address);
    if (!exactPrior)
      evidence.rejection = "equivalent_prior_bound_path";
    return evidence;
  };

  // Reconstruct the canonical candidate from the exact evidence addresses and
  // raw instructions retained by the previously validated automatic table.
  // Do not require the compare and guard to be adjacent: schedulers may place
  // non-CR-writing work between them, and the prior proof records their exact
  // relationship explicitly.
  std::vector<JumpTableBoundCandidateEvidence> canonical;
  for (const auto& [compareAddress, compareRaw] : exactCompares) {
    const auto* compare = decoded.get(compareAddress);
    if (!compare || static_cast<uint32_t>(compare->code) != compareRaw)
      continue;
    for (const auto& [guardAddress, guardRaw] : exactGuards) {
      const auto* guard = decoded.get(guardAddress);
      if (!guard || static_cast<uint32_t>(guard->code) != guardRaw)
        continue;
      if (auto evidence = recoverPair(*compare, *guard, true))
        canonical.push_back(std::move(*evidence));
    }
  }
  if (canonical.size() != 1)
    return output;
  output.push_back(canonical.front());

  for (uint32_t address : cfg.addresses()) {
    const auto* compare = decoded.get(address);
    if (!compare || compare->opcode != Opcode::cmpli ||
        static_cast<uint8_t>(compare->D.RA) != prior->indexRegister ||
        compare->D.UIMM() != prior->boundValue) {
      continue;
    }
    const Instruction* guard = nullptr;
    constexpr uint32_t kMaxGuardLookaheadInstructions = 16;
    for (uint32_t cursor = address + 4;
         cursor <= address + kMaxGuardLookaheadInstructions * 4 && cfg.contains(cursor);
         cursor += 4) {
      const auto* instruction = decoded.get(cursor);
      if (!instruction || instruction->opcode == Opcode::kUnknown ||
          MayWriteConditionRegister(*instruction)) {
        break;
      }
      if (instruction->is_branch()) {
        if (instruction->is_conditional())
          guard = instruction;
        break;
      }
    }
    if (!guard)
      continue;

    const auto compareEvidence = exactCompares.find(compare->address);
    const auto guardEvidence = exactGuards.find(guard->address);
    if (compareEvidence != exactCompares.end() && guardEvidence != exactGuards.end() &&
        compareEvidence->second == static_cast<uint32_t>(compare->code) &&
        guardEvidence->second == static_cast<uint32_t>(guard->code)) {
      continue;
    }
    if (auto evidence = recoverPair(*compare, *guard, false))
      output.push_back(std::move(*evidence));
  }
  std::sort(output.begin(), output.end(), [](const auto& lhs, const auto& rhs) {
    if (lhs.compareAddress != rhs.compareAddress)
      return lhs.compareAddress < rhs.compareAddress;
    return lhs.guardAddress < rhs.guardAddress;
  });
  output.erase(std::unique(output.begin(), output.end(),
                           [](const auto& lhs, const auto& rhs) {
                             return lhs.compareAddress == rhs.compareAddress &&
                                    lhs.guardAddress == rhs.guardAddress;
                           }),
               output.end());
  return output;
}

class LocalBoundedSliceTracer {
 public:
  LocalBoundedSliceTracer(DecodedBinary& decoded, const LocalCfg& cfg,
                          const JumpTableRecoveryLimits& limits,
                          const JumpTableBoundCandidateEvidence& bound,
                          std::span<const JumpTableBoundCandidateEvidence> bounds,
                          std::span<const JumpTableCfgEdgeEvidence> inheritedBoundEdges = {})
      : decoded_(decoded), cfg_(cfg), limits_(limits), bound_(bound) {
    casePathStart_ = BoundCasePathStart(decoded_, bound_).value_or(0);
    equivalentIndexRecomputation_ =
        FindEquivalentBoundIndexRecomputation(decoded_, cfg_, limits_, bound_, nullptr);
    for (const auto& candidate : bounds) {
      if (auto start = EquivalentBoundCasePathStart(decoded_, bound_, candidate))
        boundCaseEdges_.insert({candidate.guardAddress, *start});
    }
    for (const auto& edge : inheritedBoundEdges)
      boundCaseEdges_.insert({edge.source, edge.target});
  }

  bool valid() const { return casePathStart_ != 0 && !boundCaseEdges_.empty(); }

  LocalSliceTrace Trace(uint8_t reg, uint32_t before) {
    active_.clear();
    return TraceRegister(reg, before, 0);
  }

 private:
  bool BoundRegisterReaches(uint8_t reg, uint32_t before, bool* limitHit, std::string* rejection,
                            std::vector<JumpTableInstructionEvidence>* evidence) const {
    if (reg != bound_.indexRegister || casePathStart_ == 0 || !cfg_.contains(before) ||
        !cfg_.contains(casePathStart_)) {
      return false;
    }
    // Build the complete reverse slice first. Cycles are not ambiguity by
    // themselves: a case-expanded state machine may preserve the bounded
    // register around an SCC. Every reverse source component must still be
    // reachable from an exact guard/case edge, and every intervening path must
    // preserve the register.
    std::deque<uint32_t> pending{before};
    std::unordered_set<uint32_t> visited;
    std::unordered_map<uint32_t, std::vector<uint32_t>> forward;
    std::unordered_set<uint32_t> boundarySeeds;
    while (!pending.empty()) {
      const uint32_t cursor = pending.front();
      pending.pop_front();
      if (!visited.insert(cursor).second)
        continue;
      if (visited.size() > limits_.maxStates) {
        if (limitHit)
          *limitHit = true;
        if (rejection)
          *rejection = "bounded_path_max_states";
        return false;
      }
      const auto& predecessors = cfg_.predecessors(cursor);
      if (predecessors.empty()) {
        if (rejection)
          *rejection = "bounded_path_reaches_unproved_entry";
        return false;
      }
      for (uint32_t predecessor : predecessors) {
        if (boundCaseEdges_.contains({predecessor, cursor})) {
          boundarySeeds.insert(cursor);
          continue;
        }
        const auto* instruction = decoded_.get(predecessor);
        if (!instruction) {
          if (rejection)
            *rejection = "bounded_path_instruction_not_decoded_at_" + std::to_string(predecessor);
          return false;
        }
        if (WritesRegister(*instruction, reg)) {
          if (equivalentIndexRecomputation_ &&
              instruction->address == equivalentIndexRecomputation_->casePathDefinition->address) {
            boundarySeeds.insert(cursor);
            if (evidence) {
              evidence->push_back(Evidence(*equivalentIndexRecomputation_->boundDefinition,
                                           "local_bounded_slice_original_index_definition"));
              evidence->push_back(Evidence(*equivalentIndexRecomputation_->casePathDefinition,
                                           "local_bounded_slice_equivalent_index_recomputation"));
            }
            continue;
          }
          if (rejection)
            *rejection = "bounded_register_modified_at_" + std::to_string(predecessor);
          return false;
        }
        // The Xenon PPC ABI preserves r14-r31 across a linked call. Volatile
        // GPRs remain opaque and cannot carry an inherited table domain.
        if (instruction->is_call() && reg < 14) {
          if (rejection)
            *rejection = "bounded_volatile_register_crosses_call_at_" + std::to_string(predecessor);
          return false;
        }
        forward[predecessor].push_back(cursor);
        pending.push_back(predecessor);
      }
    }

    std::deque<uint32_t> proven(boundarySeeds.begin(), boundarySeeds.end());
    std::unordered_set<uint32_t> reachesBoundary(boundarySeeds.begin(), boundarySeeds.end());
    while (!proven.empty()) {
      const uint32_t cursor = proven.front();
      proven.pop_front();
      for (uint32_t successor : forward[cursor]) {
        if (reachesBoundary.insert(successor).second)
          proven.push_back(successor);
      }
    }
    if (reachesBoundary.size() != visited.size()) {
      if (rejection)
        *rejection = "bounded_path_has_unproved_source_component";
      return false;
    }
    return true;
  }

  const Instruction* FindDefinition(uint8_t reg, uint32_t before, bool* limitHit,
                                    std::string* rejection) const {
    uint32_t cursor = before;
    std::unordered_set<uint32_t> visited;
    for (uint32_t steps = 0; cursor != casePathStart_; ++steps) {
      if (steps >= limits_.maxBackwardInstructions || !visited.insert(cursor).second) {
        if (limitHit)
          *limitHit = true;
        return nullptr;
      }
      const auto& predecessors = cfg_.predecessors(cursor);
      if (predecessors.size() != 1) {
        if (rejection) {
          *rejection = "predecessor_count_" + std::to_string(predecessors.size()) + "_at_" +
                       std::to_string(cursor);
        }
        return nullptr;
      }
      const uint32_t predecessor = predecessors.front();
      if (predecessor == bound_.guardAddress) {
        if (rejection)
          *rejection = "definition_crosses_guard";
        return nullptr;
      }
      const auto* instruction = decoded_.get(predecessor);
      if (!instruction) {
        if (rejection)
          *rejection = "predecessor_not_decoded";
        return nullptr;
      }
      if (WritesRegister(*instruction, reg))
        return instruction;
      if (instruction->is_call() || instruction->is_branch()) {
        if (rejection)
          *rejection = "definition_crosses_control_transfer";
        return nullptr;
      }
      cursor = predecessor;
    }
    return nullptr;
  }

  LocalSliceTrace TraceRegister(uint8_t reg, uint32_t before, uint32_t depth) {
    LocalSliceTrace result;
    if (depth > 64) {
      result.rejection = "expression_depth_limit";
      return result;
    }
    const uint64_t key = (static_cast<uint64_t>(before) << 8) | reg;
    if (!active_.insert(key).second) {
      result.rejection = "recursive_register_slice";
      return result;
    }
    const auto finish = [&](LocalSliceTrace value) {
      active_.erase(key);
      return value;
    };

    bool boundLimit = false;
    std::string boundRejection;
    if (BoundRegisterReaches(reg, before, &boundLimit, &boundRejection, &result.evidence)) {
      result.expression = MakeSymbolicDefinition(bound_.compareAddress);
      return finish(std::move(result));
    }
    if (boundLimit) {
      result.limitHit = true;
      result.rejection = "bounded_register_trace_limit";
      return finish(std::move(result));
    }

    bool definitionLimit = false;
    std::string definitionRejection;
    const auto* instruction = FindDefinition(reg, before, &definitionLimit, &definitionRejection);
    if (!instruction) {
      result.limitHit = definitionLimit;
      result.rejection = definitionLimit
                             ? "definition_trace_limit"
                             : "definition_not_unique_on_case_path:" +
                                   (!definitionRejection.empty() ? definitionRejection : "none") +
                                   ":bound=" + boundRejection;
      return finish(std::move(result));
    }
    result.evidence.push_back(Evidence(*instruction, "local_bounded_slice_definition"));
    auto operand = [&](uint8_t source) {
      auto traced = TraceRegister(source, instruction->address, depth + 1);
      result.limitHit = result.limitHit || traced.limitHit;
      if (!traced.rejection.empty() && result.rejection.empty()) {
        result.rejection = "operand_r" + std::to_string(source) + "_at_" +
                           std::to_string(instruction->address) + ":" + traced.rejection;
      }
      result.evidence.insert(result.evidence.end(), traced.evidence.begin(), traced.evidence.end());
      return traced.expression;
    };

    switch (instruction->opcode) {
      case Opcode::li:
      case Opcode::addi:
        result.expression =
            instruction->D.RA == 0
                ? MakeConstant(static_cast<uint32_t>(instruction->D.SIMM()), instruction->address)
                : MakeBinary(ExprKind::Add, operand(static_cast<uint8_t>(instruction->D.RA)),
                             MakeConstant(static_cast<uint32_t>(instruction->D.SIMM())),
                             instruction->address);
        break;
      case Opcode::lis:
      case Opcode::addis: {
        const uint32_t immediate = static_cast<uint32_t>(instruction->D.SIMM()) << 16;
        result.expression =
            instruction->D.RA == 0
                ? MakeConstant(immediate, instruction->address)
                : MakeBinary(ExprKind::Add, operand(static_cast<uint8_t>(instruction->D.RA)),
                             MakeConstant(immediate), instruction->address);
        break;
      }
      case Opcode::ori:
      case Opcode::oris: {
        auto source = operand(static_cast<uint8_t>(instruction->D.RT));
        const uint32_t immediate = instruction->opcode == Opcode::oris ? instruction->D.UIMM() << 16
                                                                       : instruction->D.UIMM();
        if (source && source->kind == ExprKind::Constant) {
          result.expression = MakeConstant(source->value | immediate, instruction->address);
        } else if (immediate == 0) {
          result.expression = source;
        }
        break;
      }
      case Opcode::or_: {
        auto lhs = operand(static_cast<uint8_t>(instruction->X.RT));
        auto rhs = operand(static_cast<uint8_t>(instruction->X.RB));
        if (ExprKey(lhs) == ExprKey(rhs))
          result.expression = lhs;
        break;
      }
      case Opcode::mr:
        result.expression = operand(static_cast<uint8_t>(instruction->X.RT));
        break;
      case Opcode::add:
        result.expression =
            MakeBinary(ExprKind::Add, operand(static_cast<uint8_t>(instruction->XO.RA)),
                       operand(static_cast<uint8_t>(instruction->XO.RB)), instruction->address);
        break;
      case Opcode::rlwinm:
        if (instruction->M.MB == 0 && instruction->M.SH <= 31 &&
            instruction->M.ME == 31 - instruction->M.SH) {
          result.expression =
              MakeUnary(ExprKind::ShiftLeft, operand(static_cast<uint8_t>(instruction->M.RS)),
                        instruction->M.SH, 0, instruction->address);
        } else if (instruction->M.SH == 0 && instruction->M.ME == 31) {
          result.expression = operand(static_cast<uint8_t>(instruction->M.RS));
        }
        break;
      case Opcode::lwzx:
      case Opcode::lhzx:
      case Opcode::lbzx: {
        const uint8_t width =
            instruction->opcode == Opcode::lwzx ? 4 : (instruction->opcode == Opcode::lhzx ? 2 : 1);
        auto base = instruction->X.RA == 0 ? MakeConstant(0)
                                           : operand(static_cast<uint8_t>(instruction->X.RA));
        auto index = operand(static_cast<uint8_t>(instruction->X.RB));
        if (base && index) {
          auto address = MakeBinary(ExprKind::Add, base, index, instruction->address);
          result.expression = MakeUnary(ExprKind::Load, address, 0, width, instruction->address);
        }
        break;
      }
      case Opcode::extsb:
      case Opcode::extsh: {
        const uint8_t width = instruction->opcode == Opcode::extsb ? 1 : 2;
        auto source = operand(static_cast<uint8_t>(instruction->X.RT));
        if (source) {
          result.expression =
              MakeUnary(ExprKind::SignExtend, source, 0, width, instruction->address);
        }
        break;
      }
      default:
        break;
    }
    if (result.limitHit)
      result.expression.reset();
    if (!result.expression && result.rejection.empty())
      result.rejection = "unsupported_definition_opcode";
    return finish(std::move(result));
  }

  DecodedBinary& decoded_;
  const LocalCfg& cfg_;
  const JumpTableRecoveryLimits& limits_;
  const JumpTableBoundCandidateEvidence& bound_;
  uint32_t casePathStart_ = 0;
  std::optional<EquivalentBoundIndexRecomputation> equivalentIndexRecomputation_;
  std::set<std::pair<uint32_t, uint32_t>> boundCaseEdges_;
  std::unordered_set<uint64_t> active_;
};

struct LocalBoundedSliceRecovery {
  bool applicable = false;
  bool limitHit = false;
  bool priorMismatch = false;
  JumpTableFailure failure = JumpTableFailure::None;
  std::optional<JumpTable> table;
  std::vector<std::string> rejections;
};

struct InheritedBoundProof {
  std::vector<JumpTableCfgEdgeEvidence> edges;
  std::vector<uint32_t> sourceDispatches;
};

bool IsExactBoundCompareEvidenceRole(const std::string& role) {
  return role == "case_bound" || role == "bounded_index_compare" ||
         role == "local_bounded_slice_compare" ||
         role == "local_bounded_slice_state_limit_compare" ||
         role == "local_bounded_slice_equivalent_recomputation_compare" ||
         role == "local_bounded_slice_prior_exact_compare" ||
         role == "local_bounded_slice_prior_direct_compare" ||
         role == "inherited_bound_source_compare";
}

bool IsExactBoundGuardEvidenceRole(const std::string& role) {
  return role == "default_guard" || role == "bounded_index_guard" ||
         role == "local_bounded_slice_guard" || role == "local_bounded_slice_state_limit_guard" ||
         role == "local_bounded_slice_equivalent_recomputation_guard" ||
         role == "local_bounded_slice_prior_exact_guard" ||
         role == "local_bounded_slice_prior_direct_guard" || role == "inherited_bound_source_guard";
}

std::vector<JumpTableBoundCandidateEvidence> CollectInheritedBoundEvidence(
    DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableRecoveryInput& input) {
  std::vector<JumpTableBoundCandidateEvidence> output;
  if (!input.validatedOwnerTables)
    return output;
  for (const auto& [site, table] : *input.validatedOwnerTables) {
    if (site == input.site || table.origin != JumpTableOrigin::Automatic ||
        table.ownerAddress != input.ownerAddress || !cfg.contains(site) ||
        table.indexRegister == 0xFF || table.caseCount == 0 ||
        table.targets.size() != table.caseCount || table.rawEntries.size() != table.caseCount ||
        !std::all_of(table.targets.begin(), table.targets.end(),
                     [&](uint32_t target) { return cfg.contains(target); })) {
      continue;
    }
    std::vector<const Instruction*> compares;
    std::vector<const Instruction*> guards;
    for (const auto& evidence : table.evidence) {
      const auto* instruction = decoded.get(evidence.address);
      if (!instruction || static_cast<uint32_t>(instruction->code) != evidence.rawInstruction) {
        continue;
      }
      if (IsExactBoundCompareEvidenceRole(evidence.role))
        compares.push_back(instruction);
      else if (IsExactBoundGuardEvidenceRole(evidence.role))
        guards.push_back(instruction);
    }
    for (const auto* compare : compares) {
      if (compare->opcode != Opcode::cmpli ||
          static_cast<uint8_t>(compare->D.RA) != table.indexRegister ||
          compare->D.UIMM() != table.boundValue || !cfg.contains(compare->address)) {
        continue;
      }
      for (const auto* guard : guards) {
        if (!cfg.contains(guard->address))
          continue;
        const uint8_t compareCr = static_cast<uint8_t>(compare->D.RT >> 2);
        const uint8_t guardBi = guard->format == ppc::InstrFormat::kB ? guard->B.BI : guard->XL.BI;
        const auto branchTrue = BranchWhenCrBitTrue(*guard);
        if (!branchTrue || guardBi / 4 != compareCr)
          continue;
        const uint8_t bit = BranchConditionBit(*guard);
        bool caseOnTaken = false;
        if (table.boundInclusive && bit == 1 && table.caseCount == table.boundValue + 1) {
          caseOnTaken = !*branchTrue;
        } else if (!table.boundInclusive && bit == 0 && table.caseCount == table.boundValue) {
          caseOnTaken = *branchTrue;
        } else {
          continue;
        }
        uint32_t defaultTarget = 0;
        bool defaultIsReturn = false;
        if (guard->opcode == Opcode::bclr || guard->opcode == Opcode::bclrl) {
          if (caseOnTaken)
            continue;
          defaultIsReturn = true;
        } else if (guard->branch_target) {
          defaultTarget = caseOnTaken ? guard->address + 4 : *guard->branch_target;
        } else {
          continue;
        }
        if (defaultIsReturn != table.defaultIsReturn ||
            (!defaultIsReturn && defaultTarget != table.defaultTarget)) {
          continue;
        }
        output.push_back({
            .compareAddress = compare->address,
            .guardAddress = guard->address,
            .value = table.boundValue,
            .caseCount = table.caseCount,
            .defaultTarget = table.defaultTarget,
            .indexRegister = table.indexRegister,
            .inclusive = table.boundInclusive,
            .signedCompare = false,
            .defaultIsReturn = table.defaultIsReturn,
            .dominatesDispatch = false,
            .finiteDenseDomain = true,
            .priorExactRevalidation = false,
            .priorDirectBoundedIndexRevalidation = false,
            .inheritedCaseEdgeProof = true,
            .finiteCfgDomain = false,
            .finiteValues = {},
            .rejection = {},
        });
      }
    }
  }
  std::sort(output.begin(), output.end(), [](const auto& lhs, const auto& rhs) {
    return lhs.compareAddress != rhs.compareAddress ? lhs.compareAddress < rhs.compareAddress
                                                    : lhs.guardAddress < rhs.guardAddress;
  });
  output.erase(std::unique(output.begin(), output.end(),
                           [](const auto& lhs, const auto& rhs) {
                             return lhs.compareAddress == rhs.compareAddress &&
                                    lhs.guardAddress == rhs.guardAddress;
                           }),
               output.end());
  return output;
}

InheritedBoundProof FindInheritedBoundProof(DecodedBinary& decoded,
                                            const JumpTableRecoveryInput& input,
                                            const JumpTableBoundCandidateEvidence& bound) {
  InheritedBoundProof proof;
  if (!input.validatedOwnerTables)
    return proof;
  const auto* compare = decoded.get(bound.compareAddress);
  const auto* guard = decoded.get(bound.guardAddress);
  if (!compare || !guard)
    return proof;

  for (const auto& [site, table] : *input.validatedOwnerTables) {
    if (site == input.site || table.origin != JumpTableOrigin::Automatic ||
        table.ownerAddress != input.ownerAddress || table.indexRegister != bound.indexRegister ||
        table.boundValue != bound.value || table.caseCount != bound.caseCount ||
        table.boundInclusive != bound.inclusive || table.defaultIsReturn != bound.defaultIsReturn ||
        (!bound.defaultIsReturn && table.defaultTarget != bound.defaultTarget) ||
        table.targets.size() != table.caseCount || table.rawEntries.size() != table.caseCount) {
      continue;
    }
    const bool exactCompare =
        std::any_of(table.evidence.begin(), table.evidence.end(), [&](const auto& evidence) {
          return evidence.address == bound.compareAddress &&
                 evidence.rawInstruction == static_cast<uint32_t>(compare->code) &&
                 IsExactBoundCompareEvidenceRole(evidence.role);
        });
    const bool exactGuard =
        std::any_of(table.evidence.begin(), table.evidence.end(), [&](const auto& evidence) {
          return evidence.address == bound.guardAddress &&
                 evidence.rawInstruction == static_cast<uint32_t>(guard->code) &&
                 IsExactBoundGuardEvidenceRole(evidence.role);
        });
    if (!exactCompare || !exactGuard)
      continue;
    proof.sourceDispatches.push_back(site);
    for (uint32_t target : table.targets)
      proof.edges.push_back({site, target});
  }
  std::sort(proof.sourceDispatches.begin(), proof.sourceDispatches.end());
  proof.sourceDispatches.erase(
      std::unique(proof.sourceDispatches.begin(), proof.sourceDispatches.end()),
      proof.sourceDispatches.end());
  std::sort(proof.edges.begin(), proof.edges.end(), [](const auto& lhs, const auto& rhs) {
    return lhs.source != rhs.source ? lhs.source < rhs.source : lhs.target < rhs.target;
  });
  proof.edges.erase(std::unique(proof.edges.begin(), proof.edges.end()), proof.edges.end());
  return proof;
}

const Instruction* FindPostMergeBoundIndexNormalization(
    DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableBoundCandidateEvidence& bound) {
  if (!bound.priorExactRevalidation || bound.compareAddress < 4)
    return nullptr;
  const auto& predecessors = cfg.predecessors(bound.compareAddress);
  if (predecessors.size() != 1 || predecessors.front() != bound.compareAddress - 4)
    return nullptr;
  const auto* definition = decoded.get(predecessors.front());
  if (!definition || !WritesRegister(*definition, bound.indexRegister))
    return nullptr;
  // This covers the observed compiler family: a path-dependent state is
  // normalized into a fresh zero-based switch index immediately before the
  // exact unsigned guard. Identity copies remain subject to loop/phi proof.
  if ((definition->opcode != Opcode::addi && definition->opcode != Opcode::addis) ||
      definition->D.RA == 0 || definition->D.SIMM() == 0) {
    return nullptr;
  }
  return definition;
}

LocalBoundedSliceRecovery RecoverLocalBoundedSlice(
    DecodedBinary& decoded, const LocalCfg& cfg, Resolver& resolver,
    const JumpTableRecoveryInput& input, const Instruction& mtctr,
    const std::vector<JumpTableBoundCandidateEvidence>& boundEvidence,
    const std::vector<JumpTableInstructionEvidence>& instructionEvidence,
    bool requireCompatibleBoundIndexPaths, bool requireStableBoundIndexLineage,
    bool freshTransformedBoundedIndex, bool equivalentBoundIndexRecomputation) {
  LocalBoundedSliceRecovery recovery;
  const auto reject = [&](std::string reason) {
    if (std::find(recovery.rejections.begin(), recovery.rejections.end(), reason) ==
        recovery.rejections.end()) {
      recovery.rejections.push_back(std::move(reason));
    }
  };
  std::vector<JumpTable> candidates;
  for (const auto& bound : boundEvidence) {
    const auto inheritedBound = FindInheritedBoundProof(decoded, input, bound);
    std::vector<JumpTableInstructionEvidence> freshBoundEvidence;
    if (!bound.finiteDenseDomain || bound.signedCompare ||
        (!bound.dominatesDispatch && !bound.inheritedCaseEdgeProof) || bound.guardAddress == 0 ||
        bound.caseCount == 0 || bound.caseCount > input.limits.maxEntries) {
      continue;
    }
    const auto* postMergeNormalization = FindPostMergeBoundIndexNormalization(decoded, cfg, bound);
    const bool exactPriorAfterRetryStateLimit =
        input.priorAutomaticTable && input.allowPriorLocalSliceRecovery &&
        requireStableBoundIndexLineage && bound.priorExactRevalidation;
    const bool exactPreBoundProvenanceIsIrrelevant =
        bound.priorDirectBoundedIndexRevalidation || postMergeNormalization ||
        exactPriorAfterRetryStateLimit || !inheritedBound.edges.empty();
    // If the ordinary resolver exhausted maxStates before reaching the index's
    // pre-bound definition, the value's earlier provenance is irrelevant to a
    // new automatic table only when the local slice later proves that this
    // exact register is guarded and consumed unchanged by the indexed load.
    // If the one permitted maxStates retry also exhausts, the same local proof
    // may ignore pre-bound provenance only for an exact prior automatic table.
    // The guard-to-load slice and every table field/raw entry are still
    // revalidated below; no other retry budget or failure is accepted.
    const bool boundedIndexAfterStateLimit =
        requireStableBoundIndexLineage && !input.priorAutomaticTable;
    if ((requireCompatibleBoundIndexPaths ||
         (requireStableBoundIndexLineage && !boundedIndexAfterStateLimit)) &&
        !exactPreBoundProvenanceIsIrrelevant) {
      auto boundIndex = resolver.Resolve(bound.indexRegister, bound.compareAddress);
      auto freshDefinition = FindFreshBoundIndexDefinition(
          decoded, cfg, input.limits, bound.indexRegister, bound.compareAddress);
      const bool freshLoadedIndex = ContainsFreshBoundIndexLoad(decoded, boundIndex.expression);
      const bool freshLocalIndex =
          freshDefinition.valid && (input.priorAutomaticTable || !requireStableBoundIndexLineage);
      if (boundIndex.limitHit && !freshLocalIndex) {
        recovery.limitHit = true;
        reject("bound_index_resolution_limit");
        continue;
      }
      if ((boundIndex.incompleteCaseEntryPath || !boundIndex.expression || boundIndex.ambiguous) &&
          !freshLocalIndex && !(requireCompatibleBoundIndexPaths && freshLoadedIndex)) {
        reject("bound_index_lineage_ambiguous");
        continue;
      }
      if (!freshLocalIndex) {
        auto lineage = ValidateLocalBoundIndexLineage(
            decoded, cfg, input.limits, boundIndex.expression, requireStableBoundIndexLineage);
        recovery.limitHit = recovery.limitHit || lineage.limitHit;
        if (!lineage.valid) {
          reject("bound_index_lineage:" + lineage.rejection);
          continue;
        }
      }
      if (freshLocalIndex)
        freshBoundEvidence = std::move(freshDefinition.evidence);
    }
    if (postMergeNormalization) {
      freshBoundEvidence.push_back(
          Evidence(*postMergeNormalization, "local_bounded_slice_post_merge_index_normalization"));
    }

    LocalBoundedSliceTracer tracer(decoded, cfg, input.limits, bound, boundEvidence,
                                   inheritedBound.edges);
    if (!tracer.valid()) {
      reject("guard_has_no_unique_case_path");
      continue;
    }
    auto target = tracer.Trace(static_cast<uint8_t>(mtctr.XFX.RS()), mtctr.address);
    recovery.limitHit = recovery.limitHit || target.limitHit;
    if (!target.expression) {
      reject((target.limitHit ? "target_trace_limit:" : "target_trace_unresolved:") +
             target.rejection);
      continue;
    }

    const std::string indexKey = ExprKey(MakeSymbolicDefinition(bound.compareAddress));
    const Expr* primaryLoad = FindPrimaryLoad(target.expression, indexKey);
    if (!primaryLoad ||
        (primaryLoad->width != 1 && primaryLoad->width != 2 && primaryLoad->width != 4)) {
      reject("supported_primary_load_not_found:target=" + ExprKey(target.expression) +
             ":index=" + indexKey + ":trace=" + target.rejection);
      continue;
    }
    const auto* loadInstruction = decoded.get(primaryLoad->origin);
    if (!loadInstruction ||
        (loadInstruction->opcode != Opcode::lbzx && loadInstruction->opcode != Opcode::lhzx &&
         loadInstruction->opcode != Opcode::lwzx)) {
      reject("primary_load_opcode_unsupported");
      continue;
    }
    recovery.applicable = true;

    JumpTable table;
    table.bctrAddress = input.site;
    table.ownerAddress = input.ownerAddress;
    table.indexRegister = bound.indexRegister;
    table.boundValue = bound.value;
    table.caseCount = bound.caseCount;
    table.boundInclusive = bound.inclusive;
    table.boundSemantics = bound.inclusive ? "unsigned_index <= bound" : "unsigned_index < bound";
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
    table.confidence =
        !inheritedBound.edges.empty()       ? "validated_inherited_bound_from_upstream_switch"
        : equivalentBoundIndexRecomputation ? "validated_equivalent_bound_index_recomputation"
        : input.priorAutomaticTable
            ? (bound.priorExactRevalidation
                   ? "validated_exact_prior_bound_family_local_bounded_slice"
                   : "validated_exact_prior_local_bounded_slice")
        : freshTransformedBoundedIndex
            ? "validated_local_bounded_transformed_index"
            : (boundedIndexAfterStateLimit ? "validated_local_bounded_slice_after_state_limit"
                                           : "validated_local_bounded_slice");
    table.evidence = instructionEvidence;
    table.evidence.insert(table.evidence.end(), target.evidence.begin(), target.evidence.end());
    table.evidence.insert(table.evidence.end(), freshBoundEvidence.begin(),
                          freshBoundEvidence.end());
    for (uint32_t source : inheritedBound.sourceDispatches) {
      if (const auto* dispatch = decoded.get(source)) {
        table.evidence.push_back(Evidence(*dispatch, "inherited_bound_source_dispatch"));
      }
    }
    if (const auto* compare = decoded.get(bound.compareAddress)) {
      table.evidence.push_back(Evidence(
          *compare, !inheritedBound.edges.empty() ? "inherited_bound_source_compare"
                    : bound.priorDirectBoundedIndexRevalidation
                        ? "local_bounded_slice_prior_direct_compare"
                        : (bound.priorExactRevalidation
                               ? "local_bounded_slice_prior_exact_compare"
                               : (equivalentBoundIndexRecomputation
                                      ? "local_bounded_slice_equivalent_recomputation_compare"
                                      : (boundedIndexAfterStateLimit
                                             ? "local_bounded_slice_state_limit_compare"
                                             : "local_bounded_slice_compare")))));
    }
    if (const auto* guard = decoded.get(bound.guardAddress)) {
      table.evidence.push_back(Evidence(
          *guard,
          !inheritedBound.edges.empty() ? "inherited_bound_source_guard"
          : bound.priorDirectBoundedIndexRevalidation
              ? "local_bounded_slice_prior_direct_guard"
              : (bound.priorExactRevalidation
                     ? "local_bounded_slice_prior_exact_guard"
                     : (equivalentBoundIndexRecomputation
                            ? "local_bounded_slice_equivalent_recomputation_guard"
                            : (boundedIndexAfterStateLimit ? "local_bounded_slice_state_limit_guard"
                                                           : "local_bounded_slice_guard")))));
    }
    for (const auto& equivalent : boundEvidence) {
      if (equivalent.compareAddress == bound.compareAddress ||
          !EquivalentBoundCasePathStart(decoded, bound, equivalent)) {
        continue;
      }
      if (const auto* compare = decoded.get(equivalent.compareAddress)) {
        table.evidence.push_back(
            Evidence(*compare, "local_bounded_slice_equivalent_bound_compare"));
      }
      if (const auto* guard = decoded.get(equivalent.guardAddress)) {
        table.evidence.push_back(Evidence(*guard, "local_bounded_slice_equivalent_bound_guard"));
      }
    }
    table.evidence.push_back(Evidence(*loadInstruction, "local_bounded_slice_table_load"));

    if (primaryLoad->width < 4 && table.anchorAddress == 0) {
      recovery.failure = JumpTableFailure::UnsupportedRelativeForm;
      reject("relative_table_anchor_not_constant");
      continue;
    }

    uint32_t previousStorage = 0;
    uint32_t storageStride = 0;
    JumpTableFailure targetFailure = JumpTableFailure::None;
    uint32_t failureIndex = 0;
    uint32_t failureStorage = 0;
    uint32_t failureTarget = 0;
    bool failureTargetDecoded = false;
    bool failureTargetInvalid = false;
    bool failureTargetInOwner = false;
    for (uint32_t index = 0; index < bound.caseCount; ++index) {
      auto evaluated = Evaluate(target.expression, indexKey, index, decoded);
      auto loadIt = evaluated.loads.find(primaryLoad->origin);
      if (!evaluated.ok || loadIt == evaluated.loads.end()) {
        targetFailure = JumpTableFailure::TargetOutOfRange;
        failureIndex = index;
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
          targetFailure = JumpTableFailure::UnsupportedRelativeForm;
          failureIndex = index;
          failureStorage = storage;
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
        targetFailure = JumpTableFailure::TargetUnaligned;
        failureIndex = index;
        failureStorage = storage;
        failureTarget = caseTarget;
        break;
      }
      const auto* targetInstruction = decoded.get(caseTarget);
      const bool targetInvalid = targetInstruction && isInvalid(*targetInstruction);
      const bool targetInOwner = TargetWithinValidatedOwner(input, caseTarget);
      if (!targetInstruction || targetInvalid || !targetInOwner) {
        targetFailure = JumpTableFailure::TargetOutOfRange;
        failureIndex = index;
        failureStorage = storage;
        failureTarget = caseTarget;
        failureTargetDecoded = targetInstruction != nullptr;
        failureTargetInvalid = targetInvalid;
        failureTargetInOwner = targetInOwner;
        break;
      }
      table.targets.push_back(caseTarget);
    }

    if (targetFailure != JumpTableFailure::None) {
      recovery.failure =
          table.targets.empty() ? targetFailure : JumpTableFailure::MixedValidityTargets;
      reject(std::string(JumpTableFailureName(recovery.failure)) + ":index=" +
             std::to_string(failureIndex) + ":storage=" + std::to_string(failureStorage) +
             ":target=" + std::to_string(failureTarget) +
             ":decoded=" + std::to_string(failureTargetDecoded) +
             ":invalid=" + std::to_string(failureTargetInvalid) +
             ":in_owner=" + std::to_string(failureTargetInOwner));
      continue;
    }
    const uint32_t stride = bound.caseCount > 1 ? table.rawEntries[1].storageAddress -
                                                      table.rawEntries[0].storageAddress
                                                : primaryLoad->width;
    table.storageEnd = table.tableAddress + (bound.caseCount - 1) * stride + primaryLoad->width;
    table.tableInExecutableSection = decoded.get(table.tableAddress) != nullptr;
    table.manualComparison = input.manualTable ? CompareManual(table, *input.manualTable)
                                               : JumpTableManualComparison::NewAutomaticTable;
    if (input.priorAutomaticTable &&
        !SameRecoveryTableSemantics(table, *input.priorAutomaticTable)) {
      recovery.priorMismatch = true;
      reject("prior_table_semantics_mismatch");
      continue;
    }
    candidates.push_back(std::move(table));
  }

  if (candidates.empty())
    return recovery;
  const auto& first = candidates.front();
  if (!std::all_of(candidates.begin() + 1, candidates.end(), [&](const auto& candidate) {
        return SameRecoveryTableSemantics(first, candidate);
      })) {
    recovery.failure = JumpTableFailure::AmbiguousBound;
    reject("multiple_incompatible_local_tables");
    return recovery;
  }
  recovery.failure = JumpTableFailure::None;
  recovery.table = std::move(candidates.front());
  return recovery;
}

bool IsFreshTransformedBoundedIndexCandidate(
    DecodedBinary& decoded, const LocalCfg& cfg, const JumpTableRecoveryInput& input,
    const ResolveResult& target, std::span<const JumpTableBoundCandidateEvidence> boundEvidence,
    bool* limitHit) {
  constexpr const char* kAmbiguousIndexKey = "?";
  if (!target.ambiguous || target.limitHit || target.incompleteCaseEntryPath ||
      !target.expression || CountUnknownLeaves(target.expression) != 1) {
    return false;
  }

  const Expr* primaryLoad = FindPrimaryLoad(target.expression, kAmbiguousIndexKey);
  if (!primaryLoad || CountUnknownLeaves(primaryLoad->lhs) != 1 ||
      (primaryLoad->width != 1 && primaryLoad->width != 2 && primaryLoad->width != 4)) {
    return false;
  }
  const auto* loadInstruction = decoded.get(primaryLoad->origin);
  if (!loadInstruction ||
      (loadInstruction->opcode != Opcode::lbzx && loadInstruction->opcode != Opcode::lhzx &&
       loadInstruction->opcode != Opcode::lwzx)) {
    return false;
  }

  bool cycleLimit = false;
  if (cfg.IsInCycle(input.site, input.limits, &cycleLimit) ||
      cfg.IsInCycle(loadInstruction->address, input.limits, &cycleLimit)) {
    return false;
  }
  if (cycleLimit) {
    if (limitHit)
      *limitHit = true;
    return false;
  }

  const uint8_t loadIndexRegister = static_cast<uint8_t>(loadInstruction->X.RB);
  return std::any_of(boundEvidence.begin(), boundEvidence.end(), [&](const auto& bound) {
    return bound.finiteDenseDomain && !bound.signedCompare && bound.dominatesDispatch &&
           bound.guardAddress != 0 && bound.caseCount != 0 &&
           bound.caseCount <= input.limits.maxEntries && bound.indexRegister != loadIndexRegister;
  });
}

JumpTableDiagnosticProbe RunDiagnosticProbe(
    DecodedBinary& decoded, const JumpTableRecoveryInput& input, const ResolveResult& target,
    const std::vector<JumpTableBoundCandidateEvidence>& boundEvidence,
    const std::vector<JumpTableInstructionEvidence>& instructionEvidence) {
  JumpTableDiagnosticProbe probe;
  probe.attempted = true;
  probe.assumptions.push_back("derived_only_from_site_symbolic_slice");

  if (!target.expression || !ContainsLoad(target.expression)) {
    probe.rejections.push_back("target_expression_has_no_table_like_load");
    return probe;
  }
  if (CountUnknownLeaves(target.expression) != 1) {
    probe.rejections.push_back("target_expression_does_not_have_one_bounded_unknown_index");
    return probe;
  }

  constexpr const char* kDiagnosticIndexKey = "?";
  const Expr* primaryLoad = FindPrimaryLoad(target.expression, kDiagnosticIndexKey);
  if (!primaryLoad ||
      (primaryLoad->width != 1 && primaryLoad->width != 2 && primaryLoad->width != 4)) {
    probe.rejections.push_back("unsupported_or_unidentified_element_load");
    return probe;
  }
  const auto* loadInstruction = decoded.get(primaryLoad->origin);
  if (!loadInstruction ||
      (loadInstruction->opcode != Opcode::lbzx && loadInstruction->opcode != Opcode::lhzx &&
       loadInstruction->opcode != Opcode::lwzx)) {
    probe.rejections.push_back("primary_load_is_not_a_supported_indexed_load");
    return probe;
  }
  const uint8_t loadIndexRegister = static_cast<uint8_t>(loadInstruction->X.RB);

  std::map<std::string, const JumpTableBoundCandidateEvidence*> matchingBounds;
  for (const auto& bound : boundEvidence) {
    if (!bound.finiteDenseDomain || bound.indexRegister != loadIndexRegister)
      continue;
    const std::string key = std::to_string(bound.value) + ':' + std::to_string(bound.caseCount) +
                            ':' + std::to_string(bound.inclusive) + ':' +
                            std::to_string(bound.defaultTarget) + ':' +
                            std::to_string(bound.defaultIsReturn);
    auto existing = matchingBounds.find(key);
    if (existing == matchingBounds.end() ||
        existing->second->compareAddress < bound.compareAddress) {
      matchingBounds[key] = &bound;
    }
  }
  if (matchingBounds.size() != 1) {
    probe.rejections.push_back(matchingBounds.empty()
                                   ? "no_dominating_unsigned_bound_for_load_index"
                                   : "multiple_incompatible_bounds_for_load_index");
    return probe;
  }
  const auto& bound = *matchingBounds.begin()->second;
  probe.assumptions.push_back("single_unknown_is_direct_index_register_r" +
                              std::to_string(loadIndexRegister));
  probe.assumptions.push_back("matching_dominating_unsigned_dense_bound");

  JumpTable table;
  table.bctrAddress = input.site;
  table.ownerAddress = input.ownerAddress;
  table.indexRegister = loadIndexRegister;
  table.boundValue = bound.value;
  table.caseCount = bound.caseCount;
  table.boundInclusive = bound.inclusive;
  table.boundSemantics = bound.inclusive ? "unsigned_index <= bound" : "unsigned_index < bound";
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
  table.confidence = "diagnostic_probe_only_validated_all_targets";
  table.evidence = instructionEvidence;

  if (primaryLoad->width < 4 && table.anchorAddress == 0) {
    probe.rejections.push_back("relative_table_has_no_constant_anchor");
    return probe;
  }

  uint32_t previousStorage = 0;
  uint32_t storageStride = 0;
  bool invalid = false;
  for (uint32_t index = 0; index < bound.caseCount; ++index) {
    auto evaluated = Evaluate(target.expression, kDiagnosticIndexKey, index, decoded);
    auto loadIt = evaluated.loads.find(primaryLoad->origin);
    if (!evaluated.ok || loadIt == evaluated.loads.end()) {
      probe.rejections.push_back("symbolic_table_hypothesis_did_not_evaluate");
      invalid = true;
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
        probe.rejections.push_back("table_storage_is_not_a_consistent_stride");
        invalid = true;
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
    ++probe.decodedEntries;
    const bool aligned = (caseTarget & 3) == 0;
    const auto* targetInstruction = aligned ? decoded.get(caseTarget) : nullptr;
    const bool executable = targetInstruction && !isInvalid(*targetInstruction) &&
                            TargetWithinValidatedOwner(input, caseTarget);
    if (aligned && executable) {
      ++probe.alignedExecutableTargets;
      table.targets.push_back(caseTarget);
      continue;
    }
    probe.mixedValidity = !table.targets.empty();
    probe.rejections.push_back(!aligned ? "target_unaligned" : "target_out_of_range");
    invalid = true;
    break;
  }

  if (invalid)
    return probe;

  const uint32_t stride =
      bound.caseCount > 1 ? table.rawEntries[1].storageAddress - table.rawEntries[0].storageAddress
                          : primaryLoad->width;
  table.storageEnd = table.tableAddress + (bound.caseCount - 1) * stride + primaryLoad->width;
  table.tableInExecutableSection = decoded.get(table.tableAddress) != nullptr;
  table.manualComparison = input.manualTable ? CompareManual(table, *input.manualTable)
                                             : JumpTableManualComparison::NewAutomaticTable;
  probe.hypothesisComplete = true;
  probe.allTargetsValid = true;
  probe.candidateTable = std::move(table);
  return probe;
}

struct DirectBoundedIndexRecovery {
  bool applicable = false;
  bool limitHit = false;
  JumpTableFailure failure = JumpTableFailure::None;
  std::optional<JumpTable> table;
};

DirectBoundedIndexRecovery RecoverDirectBoundedAmbiguousIndex(
    DecodedBinary& decoded, const LocalCfg& cfg, Resolver& resolver,
    const JumpTableRecoveryInput& input, const ResolveResult& target,
    const std::vector<JumpTableBoundCandidateEvidence>& boundEvidence,
    const std::vector<JumpTableInstructionEvidence>& instructionEvidence) {
  DirectBoundedIndexRecovery recovery;
  constexpr const char* kDirectIndexKey = "?";
  if (!target.ambiguous || target.limitHit || target.incompleteCaseEntryPath ||
      !target.expression || CountUnknownLeaves(target.expression) != 1) {
    return recovery;
  }

  const Expr* primaryLoad = FindPrimaryLoad(target.expression, kDirectIndexKey);
  if (!primaryLoad || CountUnknownLeaves(primaryLoad->lhs) != 1 ||
      (primaryLoad->width != 1 && primaryLoad->width != 2 && primaryLoad->width != 4)) {
    return recovery;
  }
  const auto* loadInstruction = decoded.get(primaryLoad->origin);
  if (!loadInstruction ||
      (loadInstruction->opcode != Opcode::lbzx && loadInstruction->opcode != Opcode::lhzx &&
       loadInstruction->opcode != Opcode::lwzx)) {
    return recovery;
  }

  const uint8_t baseRegister = static_cast<uint8_t>(loadInstruction->X.RA);
  const uint8_t indexRegister = static_cast<uint8_t>(loadInstruction->X.RB);
  if (baseRegister == indexRegister && baseRegister != 0)
    return recovery;

  bool cycleLimit = false;
  if (cfg.IsInCycle(input.site, input.limits, &cycleLimit) ||
      cfg.IsInCycle(loadInstruction->address, input.limits, &cycleLimit)) {
    recovery.limitHit = cycleLimit;
    return recovery;
  }
  if (cycleLimit) {
    recovery.limitHit = true;
    return recovery;
  }

  if (baseRegister != 0) {
    auto base = resolver.Resolve(baseRegister, loadInstruction->address);
    if (base.limitHit) {
      recovery.limitHit = true;
      return recovery;
    }
    if (base.ambiguous || base.incompleteCaseEntryPath || !EvaluateConstant(base.expression)) {
      return recovery;
    }
  }

  auto index = resolver.Resolve(indexRegister, loadInstruction->address);
  if (index.limitHit) {
    recovery.limitHit = true;
    return recovery;
  }
  if (!index.ambiguous || index.incompleteCaseEntryPath)
    return recovery;

  bool dominanceLimit = false;
  if (!cfg.Dominates(loadInstruction->address, input.site, input.limits, &dominanceLimit)) {
    recovery.limitHit = dominanceLimit;
    return recovery;
  }

  std::map<std::string, const JumpTableBoundCandidateEvidence*> matchingBounds;
  for (const auto& bound : boundEvidence) {
    if (!bound.finiteDenseDomain || bound.signedCompare || !bound.dominatesDispatch ||
        bound.indexRegister != indexRegister || bound.guardAddress == 0) {
      continue;
    }
    bool topologyLimit = false;
    if (!cfg.RegisterUnmodifiedOnEveryPath(bound.guardAddress, loadInstruction->address,
                                           indexRegister, input.limits, &topologyLimit)) {
      recovery.limitHit = recovery.limitHit || topologyLimit;
      continue;
    }
    const std::string key = std::to_string(bound.value) + ':' + std::to_string(bound.caseCount) +
                            ':' + std::to_string(bound.inclusive) + ':' +
                            std::to_string(bound.defaultTarget) + ':' +
                            std::to_string(bound.defaultIsReturn);
    auto existing = matchingBounds.find(key);
    if (existing == matchingBounds.end() ||
        existing->second->compareAddress < bound.compareAddress) {
      matchingBounds[key] = &bound;
    }
  }
  if (matchingBounds.size() != 1)
    return recovery;

  recovery.applicable = true;
  const auto& bound = *matchingBounds.begin()->second;
  JumpTable table;
  table.bctrAddress = input.site;
  table.ownerAddress = input.ownerAddress;
  table.indexRegister = indexRegister;
  table.boundValue = bound.value;
  table.caseCount = bound.caseCount;
  table.boundInclusive = bound.inclusive;
  table.boundSemantics = bound.inclusive ? "unsigned_index <= bound" : "unsigned_index < bound";
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
  table.confidence = "validated_direct_bounded_ambiguous_index";
  table.evidence = instructionEvidence;
  if (const auto* compare = decoded.get(bound.compareAddress))
    table.evidence.push_back(Evidence(*compare, "bounded_index_compare"));
  if (const auto* guard = decoded.get(bound.guardAddress))
    table.evidence.push_back(Evidence(*guard, "bounded_index_guard"));
  table.evidence.push_back(Evidence(*loadInstruction, "bounded_index_table_load"));

  if (primaryLoad->width < 4 && table.anchorAddress == 0) {
    recovery.failure = JumpTableFailure::UnsupportedRelativeForm;
    return recovery;
  }

  uint32_t previousStorage = 0;
  uint32_t storageStride = 0;
  JumpTableFailure targetFailure = JumpTableFailure::None;
  for (uint32_t tableIndex = 0; tableIndex < bound.caseCount; ++tableIndex) {
    auto evaluated = Evaluate(target.expression, kDirectIndexKey, tableIndex, decoded);
    auto loadIt = evaluated.loads.find(primaryLoad->origin);
    if (!evaluated.ok || loadIt == evaluated.loads.end()) {
      targetFailure = JumpTableFailure::TargetOutOfRange;
      break;
    }
    const uint32_t storage = loadIt->second.first;
    if (tableIndex == 0) {
      table.tableAddress = storage;
    } else {
      const uint32_t stride = storage - previousStorage;
      if (tableIndex == 1)
        storageStride = stride;
      if (stride != storageStride || stride == 0) {
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
      targetFailure = JumpTableFailure::TargetUnaligned;
      break;
    }
    const auto* targetInstruction = decoded.get(caseTarget);
    if (!targetInstruction || isInvalid(*targetInstruction) ||
        !TargetWithinValidatedOwner(input, caseTarget)) {
      targetFailure = JumpTableFailure::TargetOutOfRange;
      break;
    }
    table.targets.push_back(caseTarget);
  }

  if (targetFailure != JumpTableFailure::None) {
    table.conflicts.push_back(JumpTableFailureName(targetFailure));
    recovery.failure =
        table.targets.empty() ? targetFailure : JumpTableFailure::MixedValidityTargets;
    return recovery;
  }

  const uint32_t stride =
      bound.caseCount > 1 ? table.rawEntries[1].storageAddress - table.rawEntries[0].storageAddress
                          : primaryLoad->width;
  table.storageEnd = table.tableAddress + (bound.caseCount - 1) * stride + primaryLoad->width;
  table.tableInExecutableSection = decoded.get(table.tableAddress) != nullptr;
  table.manualComparison = input.manualTable ? CompareManual(table, *input.manualTable)
                                             : JumpTableManualComparison::NewAutomaticTable;
  recovery.table = std::move(table);
  return recovery;
}

const Expr* FindFirstLoad(const ExprPtr& expression) {
  if (!expression)
    return nullptr;
  if (expression->kind == ExprKind::Load)
    return expression.get();
  if (const Expr* load = FindFirstLoad(expression->lhs))
    return load;
  return FindFirstLoad(expression->rhs);
}

std::string FailureStage(const IndirectSiteAnalysis& analysis) {
  if (analysis.failures.empty())
    return "none";
  switch (analysis.failures.front()) {
    case JumpTableFailure::AmbiguousReachingDefinition:
    case JumpTableFailure::UnknownTableBase:
      return "target_reaching_definition";
    case JumpTableFailure::MissingBound:
    case JumpTableFailure::AmbiguousBound:
    case JumpTableFailure::UnknownIndex:
      return "bound_and_index_matching";
    case JumpTableFailure::UnsupportedRelativeForm:
    case JumpTableFailure::InvalidElementWidth:
      return "table_form_validation";
    case JumpTableFailure::TargetOutOfRange:
    case JumpTableFailure::TargetUnaligned:
    case JumpTableFailure::MixedValidityTargets:
      return "case_target_validation";
    case JumpTableFailure::AnalysisLimit:
      return "analysis_limit";
    case JumpTableFailure::NonSwitchIndirect:
    case JumpTableFailure::None:
      return "indirect_classification";
  }
  return "unknown";
}

std::string AlternativeShape(const std::string& alternative) {
  if (alternative.empty())
    return "empty";
  if (alternative[0] == 'c')
    return "constant";
  if (alternative[0] == 'p')
    return "loop_phi";
  if (alternative[0] == 'f')
    return "finite_phi";
  if (alternative[0] == 'l')
    return "load";
  if (alternative[0] == 's')
    return "shift";
  if (alternative[0] == 'a')
    return "add";
  if (alternative[0] == 'd')
    return "symbolic_definition";
  if (alternative[0] == 'r')
    return alternative.find('@') == std::string::npos ? "input_register" : "merge";
  if (alternative[0] == '?')
    return "unknown";
  return "other";
}

void FinalizeSiteDataflow(DecodedBinary& decoded, const LocalCfg& cfg,
                          const JumpTableRecoveryInput& input, const ResolveResult* target,
                          IndirectSiteAnalysis& analysis) {
  auto& dataflow = *analysis.dataflow;
  dataflow.failureStage = FailureStage(analysis);
  if (target) {
    dataflow.targetExpression = ExprKey(target->expression);
    dataflow.normalizedTargetExpression = ExprShape(target->expression);
  }
  for (const auto& alternative : dataflow.reachingDefinitionAlternatives)
    dataflow.normalizedReachingDefinitions.push_back(AlternativeShape(alternative));
  std::sort(dataflow.normalizedReachingDefinitions.begin(),
            dataflow.normalizedReachingDefinitions.end());
  dataflow.normalizedReachingDefinitions.erase(
      std::unique(dataflow.normalizedReachingDefinitions.begin(),
                  dataflow.normalizedReachingDefinitions.end()),
      dataflow.normalizedReachingDefinitions.end());

  const JumpTable* selected = analysis.selectedTable ? &*analysis.selectedTable : nullptr;
  const JumpTable* probed =
      dataflow.diagnosticProbe.candidateTable ? &*dataflow.diagnosticProbe.candidateTable : nullptr;
  const JumpTable* metadataTable = selected ? selected : probed;
  const Expr* primaryLoad = target ? FindFirstLoad(target->expression) : nullptr;
  if (primaryLoad) {
    std::set<uint8_t> inputRegisters;
    CollectInputRegisters(primaryLoad->lhs, inputRegisters);
    dataflow.tableLoadInputRegisters.assign(inputRegisters.begin(), inputRegisters.end());
  }
  if (metadataTable) {
    dataflow.indexRegister = metadataTable->indexRegister;
    dataflow.elementWidth = metadataTable->elementWidth;
    dataflow.elementSignedness = metadataTable->elementSigned ? "signed" : "unsigned";
    dataflow.targetScale = metadataTable->targetScale;
    dataflow.tableKindHypothesis = JumpTableKindName(metadataTable->kind);
    dataflow.tableBaseCandidates.push_back(metadataTable->tableAddress);
    if (metadataTable->anchorAddress)
      dataflow.anchorCandidates.push_back(metadataTable->anchorAddress);
  } else if (primaryLoad) {
    dataflow.elementWidth = primaryLoad->width;
    dataflow.elementSignedness =
        target && LoadIsSignExtended(target->expression, primaryLoad->origin) ? "signed"
                                                                              : "unsigned";
    dataflow.targetScale = target ? LoadTargetScale(target->expression, primaryLoad->origin) : 0;
    if (auto base = ConstantComponent(primaryLoad->lhs); base && *base != 0)
      dataflow.tableBaseCandidates.push_back(*base);
    if (target) {
      if (auto anchor = ConstantAnchor(target->expression); anchor && *anchor != 0)
        dataflow.anchorCandidates.push_back(*anchor);
    }
    const auto* loadInstruction = decoded.get(primaryLoad->origin);
    if (loadInstruction &&
        (loadInstruction->opcode == Opcode::lbzx || loadInstruction->opcode == Opcode::lhzx ||
         loadInstruction->opcode == Opcode::lwzx)) {
      dataflow.indexRegister = static_cast<uint8_t>(loadInstruction->X.RB);
    }
    dataflow.tableKindHypothesis =
        dataflow.elementWidth == 4 && dataflow.anchorCandidates.empty() && dataflow.targetScale <= 1
            ? "absolute_pointer"
            : (dataflow.elementWidth != 0 ? "relative_offset" : "unknown");
  }
  if (primaryLoad && target)
    CollectTransformChain(target->expression, primaryLoad->origin, dataflow.indexTransformChain);
  if (dataflow.tableBaseCandidates.empty())
    dataflow.tableBaseConstruction = "unknown_or_runtime";
  else
    dataflow.tableBaseConstruction = "constant_materialization";

  for (const auto& loop : analysis.loopEvidence) {
    dataflow.loopHeaders.push_back(loop.headerAddress);
    dataflow.loopCarriedRegisters.push_back(loop.registerIndex);
    for (uint32_t predecessor : loop.backedgeDefinitionAddresses)
      dataflow.backedges.push_back({predecessor, loop.headerAddress});
  }
  std::sort(dataflow.loopHeaders.begin(), dataflow.loopHeaders.end());
  dataflow.loopHeaders.erase(std::unique(dataflow.loopHeaders.begin(), dataflow.loopHeaders.end()),
                             dataflow.loopHeaders.end());
  std::sort(dataflow.loopCarriedRegisters.begin(), dataflow.loopCarriedRegisters.end());
  dataflow.loopCarriedRegisters.erase(
      std::unique(dataflow.loopCarriedRegisters.begin(), dataflow.loopCarriedRegisters.end()),
      dataflow.loopCarriedRegisters.end());
  dataflow.reachingDefinitionInScc = !analysis.loopEvidence.empty();
  const bool boundedDirectIndex =
      selected && selected->confidence == "validated_direct_bounded_ambiguous_index";
  const bool boundedIndexAfterStateLimit =
      selected && selected->confidence == "validated_local_bounded_slice_after_state_limit";
  const bool boundedTransformedIndex =
      selected && selected->confidence == "validated_local_bounded_transformed_index";
  const bool equivalentBoundIndexRecomputation =
      selected && selected->confidence == "validated_equivalent_bound_index_recomputation";
  const bool inheritedBoundFromUpstreamSwitch =
      selected && (selected->confidence == "validated_inherited_bound_from_upstream_switch" ||
                   selected->confidence == "validated_exact_prior_inherited_bound_case_edges");
  const bool finiteCfgDomain =
      selected && selected->confidence == "validated_finite_cfg_domain_all_targets";
  const bool interproceduralEntryDomain =
      selected && selected->confidence == "validated_interprocedural_entry_domain_all_targets";
  dataflow.mergeShape =
      boundedDirectIndex        ? "bounded_direct_index"
      : boundedTransformedIndex ? "bounded_transformed_index"
      : equivalentBoundIndexRecomputation
          ? "equivalent_bound_index_recomputation"
          : (interproceduralEntryDomain ? "interprocedural_entry_domain"
             : finiteCfgDomain ? "finite_cfg_domain"
                               : (inheritedBoundFromUpstreamSwitch ? "inherited_bound_case_edges"
                                  : boundedIndexAfterStateLimit
                                      ? "bounded_index_after_state_limit"
                                      : (!analysis.loopEvidence.empty()
                                             ? "finite_loop_phi"
                                             : (target && target->ambiguous ? "incompatible_phi"
                                                                            : "equivalent"))));

  bool cycleLimit = false;
  dataflow.sourceInScc = cfg.IsInCycle(input.site, input.limits, &cycleLimit);
  if (cycleLimit)
    dataflow.rejectionEvidence.push_back("scc_diagnostic_limit");

  FinalizeJumpTableSiteDisposition(analysis);
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

const char* JumpTableSwitchLikelihoodName(JumpTableSwitchLikelihood classification) {
  switch (classification) {
    case JumpTableSwitchLikelihood::ResolvedSwitch:
      return "resolved_switch";
    case JumpTableSwitchLikelihood::ConfirmedSwitchMiss:
      return "confirmed_switch_miss";
    case JumpTableSwitchLikelihood::ProbableSwitchMiss:
      return "probable_switch_miss";
    case JumpTableSwitchLikelihood::PlausibleSwitchCandidate:
      return "plausible_switch_candidate";
    case JumpTableSwitchLikelihood::VirtualOrCallbackDispatch:
      return "virtual_or_callback_dispatch";
    case JumpTableSwitchLikelihood::ComputedTailDispatch:
      return "computed_tail_dispatch";
    case JumpTableSwitchLikelihood::OpaqueNonTableDispatch:
      return "opaque_non_table_dispatch";
    case JumpTableSwitchLikelihood::InsufficientStaticEvidence:
      return "insufficient_static_evidence";
    case JumpTableSwitchLikelihood::RejectedFalsePositive:
      return "rejected_false_positive";
  }
  return "insufficient_static_evidence";
}

void FinalizeJumpTableSiteDisposition(IndirectSiteAnalysis& analysis) {
  if (!analysis.dataflow)
    return;

  auto& dataflow = *analysis.dataflow;
  dataflow.failureStage = FailureStage(analysis);
  const auto hasFailure = [&](JumpTableFailure failure) {
    return std::find(analysis.failures.begin(), analysis.failures.end(), failure) !=
           analysis.failures.end();
  };
  const bool finiteBound = std::any_of(
      dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(), [&](const auto& bound) {
        return bound.finiteDenseDomain && dataflow.indexRegister != 0xFF &&
               bound.indexRegister == dataflow.indexRegister;
      });

  if (analysis.selectedTable) {
    dataflow.switchLikelihood = JumpTableSwitchLikelihood::ResolvedSwitch;
  } else if (analysis.link) {
    dataflow.switchLikelihood = JumpTableSwitchLikelihood::VirtualOrCallbackDispatch;
  } else if (dataflow.diagnosticProbe.hypothesisComplete &&
             dataflow.diagnosticProbe.allTargetsValid) {
    dataflow.switchLikelihood = JumpTableSwitchLikelihood::ProbableSwitchMiss;
  } else if (hasFailure(JumpTableFailure::MixedValidityTargets) ||
             hasFailure(JumpTableFailure::TargetOutOfRange) ||
             hasFailure(JumpTableFailure::TargetUnaligned) ||
             dataflow.diagnosticProbe.mixedValidity) {
    dataflow.switchLikelihood = JumpTableSwitchLikelihood::RejectedFalsePositive;
  } else if (hasFailure(JumpTableFailure::AnalysisLimit)) {
    dataflow.switchLikelihood = JumpTableSwitchLikelihood::InsufficientStaticEvidence;
  } else if (!dataflow.entryRegisterDomains.empty()) {
    // An attempted whole-image entry-domain proof that did not produce a
    // selected table is explicitly incomplete evidence, not license to infer
    // a table length from runtime observations or executable pointer runs.
    dataflow.switchLikelihood = JumpTableSwitchLikelihood::InsufficientStaticEvidence;
  } else if (dataflow.elementWidth != 0 && finiteBound) {
    dataflow.switchLikelihood = JumpTableSwitchLikelihood::PlausibleSwitchCandidate;
  } else if (analysis.classification == IndirectSiteClassification::ComputedTailBctr) {
    dataflow.switchLikelihood = JumpTableSwitchLikelihood::ComputedTailDispatch;
  } else {
    dataflow.switchLikelihood = JumpTableSwitchLikelihood::OpaqueNonTableDispatch;
  }

  std::vector<std::string> rejectionEvidence;
  for (const auto& evidence : dataflow.rejectionEvidence) {
    if (evidence == "bound_census_limit" || evidence == "scc_diagnostic_limit" ||
        evidence == "equivalent_bound_recomputation_topology_limit" ||
        evidence.starts_with("ambiguous_bound_candidate:") ||
        evidence.starts_with("local_bounded_slice:") || evidence.starts_with("table_validation:")) {
      rejectionEvidence.push_back(evidence);
    }
  }
  for (auto failure : analysis.failures)
    rejectionEvidence.push_back(JumpTableFailureName(failure));
  rejectionEvidence.insert(rejectionEvidence.end(), dataflow.diagnosticProbe.rejections.begin(),
                           dataflow.diagnosticProbe.rejections.end());
  std::sort(rejectionEvidence.begin(), rejectionEvidence.end());
  rejectionEvidence.erase(std::unique(rejectionEvidence.begin(), rejectionEvidence.end()),
                          rejectionEvidence.end());
  dataflow.rejectionEvidence = std::move(rejectionEvidence);

  std::string boundShape = "none";
  bool sawUnmatchedFiniteBound = false;
  for (const auto& bound : dataflow.boundCandidates) {
    if (!bound.finiteDenseDomain)
      continue;
    if (dataflow.indexRegister != 0xFF && bound.indexRegister == dataflow.indexRegister) {
      if (bound.finiteCfgDomain) {
        boundShape = "finite_cfg_dense";
      } else if (bound.interproceduralEntryDomain) {
        boundShape = "interprocedural_entry_dense";
      } else {
        boundShape = bound.signedCompare ? "signed_" : "unsigned_";
        boundShape += bound.inclusive ? "le" : "lt";
      }
      break;
    }
    sawUnmatchedFiniteBound = true;
  }
  if (boundShape == "none" && sawUnmatchedFiniteBound)
    boundShape = "unmatched";
  std::string transformShape = "none";
  if (!dataflow.indexTransformChain.empty()) {
    transformShape.clear();
    for (const auto& transform : dataflow.indexTransformChain) {
      if (!transformShape.empty())
        transformShape += '>';
      transformShape += transform;
    }
  }
  std::vector<std::string> failureNames;
  for (auto failure : analysis.failures)
    failureNames.push_back(JumpTableFailureName(failure));
  std::sort(failureNames.begin(), failureNames.end());
  failureNames.erase(std::unique(failureNames.begin(), failureNames.end()), failureNames.end());
  std::string failureShape = "none";
  if (!failureNames.empty()) {
    failureShape.clear();
    for (const auto& failure : failureNames) {
      if (!failureShape.empty())
        failureShape += '+';
      failureShape += failure;
    }
  }
  const std::string loopShape = dataflow.reachingDefinitionInScc ? "loop_carried" : "acyclic";
  const std::string elementShape =
      dataflow.elementWidth == 0
          ? "unknown"
          : dataflow.elementSignedness +
                std::to_string(static_cast<uint32_t>(dataflow.elementWidth) * 8);
  dataflow.clusterId = "dispatch=" + dataflow.dispatchKind +
                       "|form=" + dataflow.tableKindHypothesis + "|element=" + elementShape +
                       "|scale=" + std::to_string(dataflow.targetScale) + "|bound=" + boundShape +
                       "|index=" + transformShape + "|cfg=" + loopShape +
                       "|merge=" + dataflow.mergeShape + "|base=" + dataflow.tableBaseConstruction +
                       "|slice=" + dataflow.normalizedTargetExpression +
                       "|stage=" + dataflow.failureStage + "|reason=" + failureShape;
}

JumpTableEntryCallsiteDomainEvidence AnalyzeDirectCallArgumentDomain(
    DecodedBinary& decoded, std::span<const Block> callerBlocks, uint32_t callerAddress,
    uint32_t callAddress, uint32_t expectedTarget, uint8_t registerIndex,
    const JumpTableRecoveryLimits& limits) {
  JumpTableEntryCallsiteDomainEvidence output;
  output.callerAddress = callerAddress;
  output.callAddress = callAddress;
  output.targetAddress = expectedTarget;
  output.registerIndex = registerIndex;

  const auto reject = [&](std::string reason) {
    if (std::find(output.rejections.begin(), output.rejections.end(), reason) ==
        output.rejections.end()) {
      output.rejections.push_back(std::move(reason));
    }
  };
  if (registerIndex >= 32) {
    reject("invalid_register");
    return output;
  }
  const auto* call = decoded.get(callAddress);
  if (!call || call->opcode != Opcode::bl || !call->branch_target ||
      *call->branch_target != expectedTarget) {
    reject("not_exact_relative_unconditional_direct_call");
    return output;
  }

  LocalCfg cfg(decoded, callerBlocks, callerAddress, callAddress);
  if (!cfg.contains(callerAddress) || !cfg.contains(callAddress)) {
    reject("callsite_not_reachable_in_preliminary_cfg");
    return output;
  }

  std::vector<JumpTableReachingDefinitionPathEvidence> paths;
  Resolver resolver(decoded, cfg, limits, nullptr, nullptr, &paths);
  auto value = resolver.Resolve(registerIndex, callAddress);
  if (resolver.maxStatesLimitHit()) {
    output.limitHit = true;
    output.exhaustedBudget = "max_states";
    output.budgetLimit = limits.maxStates;
    output.budgetObserved = resolver.visitedStates();
    reject("callsite_reaching_definition_limit");
    return output;
  }
  if (value.limitHit) {
    // Resolver sub-analyses can report a conservative limit without exposing
    // which internal traversal exhausted. Keep the failure structured, but do
    // not falsely attribute it to max_states or invent an observed count.
    output.limitHit = true;
    reject("callsite_reaching_definition_limit");
    return output;
  }
  if (value.ambiguous || !value.expression || IsUnknown(value.expression)) {
    reject("callsite_reaching_definition_ambiguous");
    return output;
  }

  // An exact immediate reaching the call is already a stronger finite-domain
  // proof than any surrounding upper-bound guard. Validate it before the
  // caller-wide bound census so a large unrelated prefix cannot hide a local
  // dominating constant behind maxBackwardInstructions exhaustion.
  if (value.expression->kind == ExprKind::Constant && value.expression->origin != 0) {
    bool dominanceLimit = false;
    if (!cfg.Dominates(value.expression->origin, callAddress, limits, &dominanceLimit)) {
      output.limitHit = dominanceLimit;
      reject(dominanceLimit ? "callsite_constant_dominance_limit"
                            : "callsite_constant_does_not_dominate");
      return output;
    }
    bool stabilityLimit = false;
    if (!cfg.RegisterValueAvailableOnEveryPath(value.expression->origin + 4, callAddress,
                                               registerIndex, limits, &stabilityLimit)) {
      output.limitHit = stabilityLimit;
      reject(stabilityLimit ? "callsite_constant_stability_limit"
                            : "callsite_register_modified_after_constant");
      return output;
    }
    output.definitionAddresses.push_back(value.expression->origin);
    output.finiteValues.push_back(value.expression->value);
    output.proofKind = "dominating_immediate_constant";
    output.complete = true;
    return output;
  }

  bool boundLimit = false;
  auto bounds = FindBounds(decoded, cfg, resolver, callAddress, limits, &boundLimit);
  if (boundLimit) {
    output.limitHit = true;
    reject("callsite_bound_analysis_limit");
    return output;
  }
  std::vector<BoundCandidate> matchingBounds;
  for (auto& bound : bounds) {
    if (bound.indexRegister == registerIndex &&
        ContainsExpression(value.expression, ExprKey(bound.indexExpression))) {
      matchingBounds.push_back(std::move(bound));
    }
  }
  if (!matchingBounds.empty()) {
    const auto equivalent = [&](const BoundCandidate& bound) {
      return bound.caseCount == matchingBounds.front().caseCount &&
             bound.value == matchingBounds.front().value &&
             bound.inclusive == matchingBounds.front().inclusive &&
             ExprKey(bound.indexExpression) == ExprKey(matchingBounds.front().indexExpression);
    };
    if (!std::all_of(matchingBounds.begin(), matchingBounds.end(), equivalent)) {
      reject("multiple_incompatible_callsite_bounds");
      return output;
    }
    const auto selected = std::max_element(
        matchingBounds.begin(), matchingBounds.end(),
        [](const auto& lhs, const auto& rhs) { return lhs.compareAddress < rhs.compareAddress; });
    bool stabilityLimit = false;
    if (!cfg.RegisterValueAvailableOnEveryPath(selected->compareAddress + 4, callAddress,
                                               registerIndex, limits, &stabilityLimit)) {
      output.limitHit = stabilityLimit;
      reject(stabilityLimit ? "callsite_guard_stability_limit"
                            : "callsite_register_modified_after_guard");
      return output;
    }
    output.compareAddress = selected->compareAddress;
    output.guardAddress = selected->guardAddress;
    output.proofKind = "unsigned_dominating_callsite_guard";
    output.finiteValues.resize(selected->caseCount);
    for (uint32_t index = 0; index < selected->caseCount; ++index)
      output.finiteValues[index] = index;
    output.complete = true;
    return output;
  }

  reject("no_exact_constant_or_unsigned_dominating_guard");
  return output;
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
    FinalizeJumpTableSiteDisposition(analysis);
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
  if (analysis.usesCtr && !analysis.link) {
    analysis.dataflow = std::make_shared<JumpTableSiteDataflowEvidence>();
    analysis.dataflow->dispatchKind = analysis.conditional ? "conditional_bctr" : "bctr";
  }

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

  LocalCfg cfg(decoded, input.preliminaryBlocks, input.ownerAddress, input.site,
               input.priorAutomaticTable, input.validatedOwnerTables);
  auto& dataflow = *analysis.dataflow;
  if (input.entryRegisterDomains) {
    std::vector<uint8_t> registers;
    registers.reserve(input.entryRegisterDomains->size());
    for (const auto& [reg, unused] : *input.entryRegisterDomains)
      registers.push_back(reg);
    std::sort(registers.begin(), registers.end());
    for (uint8_t reg : registers)
      dataflow.entryRegisterDomains.push_back(input.entryRegisterDomains->at(reg));
  }
  Resolver resolver(decoded, cfg, input.limits, input.priorAutomaticTable, stats,
                    &dataflow.reachingDefinitionPaths);
  for (const auto& block : input.preliminaryBlocks) {
    if (block.contains(input.site)) {
      dataflow.preliminaryBlockStart = block.base;
      dataflow.preliminaryBlockEnd = block.end();
      break;
    }
  }
  dataflow.predecessors = cfg.predecessors(input.site);
  dataflow.caseExpandedCfg = input.priorAutomaticTable != nullptr ||
                             (input.validatedOwnerTables && !input.validatedOwnerTables->empty());
  if (input.validatedOwnerTables) {
    for (const auto& [site, table] : *input.validatedOwnerTables) {
      if (site == input.site)
        continue;
      for (uint32_t target : table.targets)
        dataflow.caseExpansionEdges.push_back({site, target});
    }
  }
  if (input.priorAutomaticTable) {
    for (uint32_t target : input.priorAutomaticTable->targets)
      dataflow.caseExpansionEdges.push_back({input.site, target});
  }
  bool diagnosticLimitHit = false;
  dataflow.boundCandidates =
      CollectBoundEvidence(decoded, cfg, input.site, input.limits, &diagnosticLimitHit);
  for (auto& inherited : CollectInheritedBoundEvidence(decoded, cfg, input)) {
    const auto duplicate = std::find_if(
        dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(),
        [&](const auto& existing) {
          return existing.compareAddress == inherited.compareAddress &&
                 existing.guardAddress == inherited.guardAddress &&
                 existing.value == inherited.value && existing.caseCount == inherited.caseCount &&
                 existing.indexRegister == inherited.indexRegister &&
                 existing.inclusive == inherited.inclusive;
        });
    if (duplicate == dataflow.boundCandidates.end()) {
      dataflow.boundCandidates.push_back(std::move(inherited));
    } else if (!duplicate->finiteDenseDomain || !duplicate->inheritedCaseEdgeProof) {
      *duplicate = std::move(inherited);
    }
  }
  if (input.priorAutomaticTable) {
    bool priorBoundLimit = false;
    auto priorBounds = RecoverExactPriorBoundEvidence(decoded, cfg, input, &priorBoundLimit);
    for (const auto& priorBound : priorBounds) {
      auto existing = std::find_if(dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(),
                                   [&](const auto& candidate) {
                                     return candidate.compareAddress == priorBound.compareAddress &&
                                            candidate.guardAddress == priorBound.guardAddress &&
                                            candidate.value == priorBound.value &&
                                            candidate.caseCount == priorBound.caseCount &&
                                            candidate.indexRegister == priorBound.indexRegister &&
                                            candidate.inclusive == priorBound.inclusive;
                                   });
      if (existing == dataflow.boundCandidates.end()) {
        dataflow.boundCandidates.push_back(priorBound);
      } else if (priorBound.priorExactRevalidation) {
        // The exact initial automatic-table proof is authoritative for this
        // candidate. Equivalent repeated guards remain path evidence only.
        *existing = priorBound;
      }
    }
    std::sort(dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(),
              [](const auto& lhs, const auto& rhs) {
                if (lhs.compareAddress != rhs.compareAddress)
                  return lhs.compareAddress < rhs.compareAddress;
                return lhs.guardAddress < rhs.guardAddress;
              });
    if (priorBoundLimit)
      dataflow.rejectionEvidence.push_back("prior_bound_revalidation_limit");
  }
  std::sort(dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(),
            [](const auto& lhs, const auto& rhs) {
              if (lhs.compareAddress != rhs.compareAddress)
                return lhs.compareAddress < rhs.compareAddress;
              return lhs.guardAddress < rhs.guardAddress;
            });
  if (diagnosticLimitHit)
    dataflow.rejectionEvidence.push_back("bound_census_limit");
  std::optional<ResolveResult> resolvedTarget;
  std::vector<BoundCandidate> finiteCfgBounds;

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
    dataflow.ctrSourceRegister = static_cast<uint8_t>(mtctr->XFX.RS());
    resolvedTarget = resolver.Resolve(dataflow.ctrSourceRegister, mtctr->address);
    if (resolver.maxStatesLimitHit()) {
      dataflow.exhaustedBudgets.push_back(
          {"max_states", input.limits.maxStates, resolver.visitedStates()});
    }
    auto& target = *resolvedTarget;
    dataflow.targetExpression = ExprKey(target.expression);
    dataflow.reachingDefinitionAlternatives = target.alternatives;
    std::sort(dataflow.reachingDefinitionAlternatives.begin(),
              dataflow.reachingDefinitionAlternatives.end());
    dataflow.reachingDefinitionAlternatives.erase(
        std::unique(dataflow.reachingDefinitionAlternatives.begin(),
                    dataflow.reachingDefinitionAlternatives.end()),
        dataflow.reachingDefinitionAlternatives.end());
    CollectLoopEvidence(target.expression, analysis.loopEvidence);
    analysis.evidence.insert(analysis.evidence.end(), target.evidence.begin(),
                             target.evidence.end());
    bool finiteCfgLimitHit = false;
    finiteCfgBounds = FindFiniteCfgDomainBounds(decoded, cfg, input, target.expression,
                                                &dataflow.boundCandidates, &finiteCfgLimitHit);
    if (finiteCfgLimitHit) {
      dataflow.rejectionEvidence.push_back("finite_cfg_domain_limit");
      if (stats)
        stats->analysisLimitHit = true;
    }
    bool entryDomainLimitHit = false;
    auto entryDomainBounds = FindEntryRegisterDomainBounds(
        decoded, cfg, input, target.expression, &dataflow.boundCandidates, &entryDomainLimitHit);
    if (entryDomainLimitHit) {
      dataflow.rejectionEvidence.push_back("interprocedural_entry_domain_limit");
      if (stats)
        stats->analysisLimitHit = true;
    }
    std::sort(dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(),
              [](const auto& lhs, const auto& rhs) {
                if (lhs.compareAddress != rhs.compareAddress)
                  return lhs.compareAddress < rhs.compareAddress;
                if (lhs.guardAddress != rhs.guardAddress)
                  return lhs.guardAddress < rhs.guardAddress;
                return lhs.domainOriginAddress < rhs.domainOriginAddress;
              });
    // Preserve this structural diagnostic even when a later local fallback
    // rejects for a more specific reason (for example, an exact-prior table
    // mismatch). It describes the reaching-definition lifecycle and must not
    // be masked by fallback ordering.
    analysis.incompleteCaseEntryPaths = target.incompleteCaseEntryPath;
    LocalBoundedSliceRecovery localSlice;
    bool equivalentRecomputationLimit = false;
    const bool equivalentBoundIndexRecomputation =
        target.expression &&
        std::any_of(dataflow.boundCandidates.begin(), dataflow.boundCandidates.end(),
                    [&](const auto& bound) {
                      if (!bound.finiteDenseDomain || bound.signedCompare)
                        return false;
                      return FindEquivalentBoundIndexRecomputation(
                                 decoded, cfg, input.limits, bound, &equivalentRecomputationLimit)
                          .has_value();
                    });
    if (equivalentRecomputationLimit) {
      dataflow.rejectionEvidence.push_back("equivalent_bound_recomputation_topology_limit");
      if (stats)
        stats->analysisLimitHit = true;
    }
    bool freshTransformedIndexLimit = false;
    const bool freshTransformedBoundedIndex =
        !input.priorAutomaticTable &&
        (!input.validatedOwnerTables || input.validatedOwnerTables->empty()) &&
        IsFreshTransformedBoundedIndexCandidate(
            decoded, cfg, input, target, dataflow.boundCandidates, &freshTransformedIndexLimit);
    if (freshTransformedIndexLimit) {
      dataflow.rejectionEvidence.push_back("transformed_bounded_index_topology_limit");
      if (stats)
        stats->analysisLimitHit = true;
    }
    const bool allowLocalSlice =
        (target.limitHit && (!input.priorAutomaticTable || input.allowPriorLocalSliceRecovery)) ||
        (target.ambiguous &&
         (input.priorAutomaticTable ||
          (input.validatedOwnerTables && !input.validatedOwnerTables->empty()))) ||
        freshTransformedBoundedIndex || equivalentBoundIndexRecomputation;
    if (allowLocalSlice) {
      bool localSliceTopologyLimit = false;
      cfg.IsInCycle(input.site, input.limits, &localSliceTopologyLimit);
      if (localSliceTopologyLimit) {
        localSlice.limitHit = true;
        localSlice.rejections.push_back("cfg_topology_limit");
      } else {
        localSlice = RecoverLocalBoundedSlice(
            decoded, cfg, resolver, input, *mtctr, dataflow.boundCandidates, analysis.evidence,
            target.ambiguous &&
                (input.priorAutomaticTable ||
                 (input.validatedOwnerTables && !input.validatedOwnerTables->empty())) &&
                !target.limitHit && !equivalentBoundIndexRecomputation,
            target.limitHit, freshTransformedBoundedIndex, equivalentBoundIndexRecomputation);
      }
      for (const auto& rejection : localSlice.rejections) {
        dataflow.rejectionEvidence.push_back("local_bounded_slice:" + rejection);
      }
    }
    if (localSlice.table) {
      analysis.automaticTable = std::move(*localSlice.table);
      analysis.classification = IndirectSiteClassification::SwitchBctr;
      analysis.failures.clear();
      if (stats)
        ++stats->recoveredTables;
    } else if (localSlice.priorMismatch) {
      dataflow.rejectionEvidence.push_back("local_bounded_slice_prior_table_mismatch");
      AddFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition);
    } else if (!input.priorAutomaticTable && localSlice.applicable &&
               localSlice.failure != JumpTableFailure::None) {
      dataflow.rejectionEvidence.push_back("local_bounded_slice_target_validation_failed");
      AddFailure(analysis, localSlice.failure);
      analysis.classification = IndirectSiteClassification::ComputedTailBctr;
    } else if (localSlice.limitHit) {
      dataflow.rejectionEvidence.push_back("local_bounded_slice_limit");
      AddFailure(analysis, JumpTableFailure::AnalysisLimit);
      if (stats)
        stats->analysisLimitHit = true;
    } else if (target.limitHit) {
      AddFailure(analysis, JumpTableFailure::AnalysisLimit);
      analysis.incompleteCaseEntryPaths = target.incompleteCaseEntryPath;
      analysis.classification = IndirectSiteClassification::OpaqueIndirectTransfer;
      if (stats)
        stats->analysisLimitHit = true;
    } else if (target.ambiguous) {
      auto directBoundedIndex = RecoverDirectBoundedAmbiguousIndex(
          decoded, cfg, resolver, input, target, dataflow.boundCandidates, analysis.evidence);
      if (directBoundedIndex.table) {
        analysis.automaticTable = std::move(*directBoundedIndex.table);
        analysis.classification = IndirectSiteClassification::SwitchBctr;
        if (stats)
          ++stats->recoveredTables;
      } else if (directBoundedIndex.limitHit) {
        AddFailure(analysis, JumpTableFailure::AnalysisLimit);
        if (stats)
          stats->analysisLimitHit = true;
      } else if (directBoundedIndex.applicable &&
                 directBoundedIndex.failure != JumpTableFailure::None) {
        AddFailure(analysis, directBoundedIndex.failure);
      } else {
        AddFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition);
        analysis.incompleteCaseEntryPaths = target.incompleteCaseEntryPath;
      }
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
      // A complete CFG join is an independent finite-domain proof. Prefer an
      // ordinary dominating compare when one already matches the same target
      // slice; otherwise use the exact zero-based domain retained by the phi.
      if (matchingBounds.empty()) {
        for (auto& bound : finiteCfgBounds) {
          if (ContainsExpression(target.expression, ExprKey(bound.indexExpression)))
            matchingBounds.push_back(std::move(bound));
        }
      }
      if (matchingBounds.empty()) {
        for (auto& bound : entryDomainBounds) {
          if (ContainsExpression(target.expression, ExprKey(bound.indexExpression)))
            matchingBounds.push_back(std::move(bound));
        }
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
          AddFailure(analysis, bounds.empty() && finiteCfgBounds.empty()
                                   ? JumpTableFailure::MissingBound
                                   : JumpTableFailure::UnknownIndex);
        }
      } else if (matchingBounds.size() != 1) {
        for (const auto& bound : matchingBounds) {
          dataflow.rejectionEvidence.push_back(
              "ambiguous_bound_candidate:compare=" + std::to_string(bound.compareAddress) +
              ":guard=" + std::to_string(bound.guardAddress) + ":index=" +
              ExprKey(bound.indexExpression) + ":cases=" + std::to_string(bound.caseCount));
        }
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
              bound.interproceduralEntryDomain ? "interprocedural_entry_domain_zero_based_dense"
              : bound.finiteCfgDomain
                  ? "finite_cfg_domain_zero_based_dense"
                  : (bound.inclusive ? "unsigned_index <= bound" : "unsigned_index < bound");
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
          table.confidence = bound.interproceduralEntryDomain
                                 ? "validated_interprocedural_entry_domain_all_targets"
                             : bound.finiteCfgDomain ? "validated_finite_cfg_domain_all_targets"
                                                     : "validated_bound_and_all_targets";
          table.evidence = analysis.evidence;
          table.evidence.insert(table.evidence.end(), bound.evidence.begin(), bound.evidence.end());

          if (primaryLoad->width < 4 && table.anchorAddress == 0) {
            AddFailure(analysis, JumpTableFailure::UnsupportedRelativeForm);
          }

          bool invalid = !analysis.failures.empty();
          JumpTableFailure targetFailure = JumpTableFailure::None;
          uint32_t failureIndex = 0;
          uint32_t failureStorage = 0;
          uint32_t failureTarget = 0;
          bool failureTargetDecoded = false;
          bool failureTargetInvalid = false;
          bool failureTargetInRegion = false;
          uint32_t previousStorage = 0;
          uint32_t storageStride = 0;
          for (uint32_t index = 0; index < bound.caseCount && !invalid; ++index) {
            auto evaluated = Evaluate(target.expression, indexKey, index, decoded);
            auto loadIt = evaluated.loads.find(primaryLoad->origin);
            if (!evaluated.ok || loadIt == evaluated.loads.end()) {
              invalid = true;
              targetFailure = JumpTableFailure::TargetOutOfRange;
              failureIndex = index;
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
                failureIndex = index;
                failureStorage = storage;
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
              failureIndex = index;
              failureStorage = storage;
              failureTarget = caseTarget;
              break;
            }
            const auto* targetInstruction = decoded.get(caseTarget);
            const bool targetInvalid = targetInstruction && isInvalid(*targetInstruction);
            const bool targetInRegion = TargetWithinValidatedOwner(input, caseTarget);
            if (!targetInstruction || targetInvalid || !targetInRegion) {
              invalid = true;
              targetFailure = JumpTableFailure::TargetOutOfRange;
              failureIndex = index;
              failureStorage = storage;
              failureTarget = caseTarget;
              failureTargetDecoded = targetInstruction != nullptr;
              failureTargetInvalid = targetInvalid;
              failureTargetInRegion = targetInRegion;
              break;
            }
            table.targets.push_back(caseTarget);
          }

          if (invalid) {
            table.conflicts.push_back(JumpTableFailureName(targetFailure));
            dataflow.rejectionEvidence.push_back(
                "table_validation:index=" + std::to_string(failureIndex) + ":storage=" +
                std::to_string(failureStorage) + ":target=" + std::to_string(failureTarget) +
                ":decoded=" + std::to_string(failureTargetDecoded) +
                ":invalid=" + std::to_string(failureTargetInvalid) +
                ":in_region=" + std::to_string(failureTargetInRegion) +
                ":reason=" + JumpTableFailureName(targetFailure));
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
  if (!analysis.selectedTable && resolvedTarget) {
    dataflow.diagnosticProbe = RunDiagnosticProbe(decoded, input, *resolvedTarget,
                                                  dataflow.boundCandidates, analysis.evidence);
  }
  FinalizeSiteDataflow(decoded, cfg, input, resolvedTarget ? &*resolvedTarget : nullptr, analysis);
  if (cfg.topologyLimitHit()) {
    dataflow.exhaustedBudgets.push_back(
        {"max_cfg_topology_nodes", input.limits.maxCfgTopologyNodes, cfg.topologyNodeCount()});
  }
  return finish();
}

IndirectSiteAnalysis AnalyzeIndirectSiteWithPriorLimitRetry(DecodedBinary& decoded,
                                                            const JumpTableRecoveryInput& input,
                                                            JumpTableRecoveryStats* stats) {
  // Preserve the established per-site result first. Other validated switch
  // edges are a targeted second proof for a newly exposed downstream site;
  // they must not perturb revalidation of an already selected table.
  JumpTableRecoveryInput initialInput = input;
  initialInput.validatedOwnerTables = nullptr;
  auto analysis = AnalyzeIndirectSite(decoded, initialInput, stats);

  const bool tableLikeUnresolved =
      !analysis.selectedTable && analysis.dataflow &&
      std::any_of(analysis.failures.begin(), analysis.failures.end(), [](auto failure) {
        return failure == JumpTableFailure::AnalysisLimit ||
               failure == JumpTableFailure::AmbiguousReachingDefinition ||
               failure == JumpTableFailure::MissingBound ||
               failure == JumpTableFailure::UnknownIndex;
      });
  if (tableLikeUnresolved && input.validatedOwnerTables && !input.validatedOwnerTables->empty()) {
    auto expanded = AnalyzeIndirectSite(decoded, input, stats);
    const bool recoveredAutomatic = expanded.selectedTable && expanded.automaticTable &&
                                    expanded.selectedTable->origin == JumpTableOrigin::Automatic;
    const bool exactPriorMatch =
        !input.priorAutomaticTable ||
        (recoveredAutomatic &&
         SameRecoveryTableSemantics(*expanded.selectedTable, *input.priorAutomaticTable) &&
         SameRecoveryTableSemantics(*expanded.automaticTable, *input.priorAutomaticTable));
    const bool accepted = recoveredAutomatic && exactPriorMatch;
    if (stats) {
      // Both attempts contribute real elapsed and decode work, but they still
      // describe one site and one final disposition.
      if (stats->indirectSites > 0)
        --stats->indirectSites;
      if (accepted) {
        if (stats->unresolvedSites > 0)
          --stats->unresolvedSites;
      } else if (expanded.selectedTable) {
        if (stats->recoveredTables > 0)
          --stats->recoveredTables;
      } else if (stats->unresolvedSites > 0) {
        --stats->unresolvedSites;
      }
    }
    if (accepted) {
      if (input.priorAutomaticTable) {
        expanded.automaticTable->confidence = "validated_exact_prior_inherited_bound_case_edges";
        expanded.selectedTable->confidence = "validated_exact_prior_inherited_bound_case_edges";
      }
      return expanded;
    }
    if (analysis.dataflow) {
      std::string retryFailures;
      for (auto failure : expanded.failures) {
        if (!retryFailures.empty())
          retryFailures += '+';
        retryFailures += JumpTableFailureName(failure);
      }
      analysis.dataflow->rejectionEvidence.push_back(
          "validated_owner_table_edge_retry:" +
          (retryFailures.empty() ? std::string("no_selected_table") : retryFailures));
      if (expanded.dataflow) {
        for (const auto& rejection : expanded.dataflow->rejectionEvidence) {
          analysis.dataflow->rejectionEvidence.push_back("validated_owner_table_edge_retry:" +
                                                         rejection);
        }
      }
    }
  }
  if (analysis.selectedTable || !input.priorAutomaticTable || analysis.failures.size() != 1 ||
      analysis.failures.front() != JumpTableFailure::AnalysisLimit) {
    return analysis;
  }
  if (analysis.dataflow &&
      std::any_of(analysis.dataflow->exhaustedBudgets.begin(),
                  analysis.dataflow->exhaustedBudgets.end(),
                  [](const auto& exhaustion) { return exhaustion.budget != "max_states"; })) {
    // The bounded retry is specifically for resolver-state growth after case
    // expansion. A distinct exhausted budget must never be masked by raising
    // maxStates, because that retry cannot address the recorded limit.
    return analysis;
  }

  JumpTableRecoveryInput retryInput = input;
  const uint64_t grownStates =
      std::max<uint64_t>(static_cast<uint64_t>(input.limits.maxStates) + 1,
                         static_cast<uint64_t>(input.limits.maxStates) * 32);
  retryInput.limits.maxStates = static_cast<uint32_t>(std::min<uint64_t>(grownStates, 1000000));
  retryInput.allowPriorLocalSliceRecovery = true;
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
      SameRecoveryTableSemantics(*retry.selectedTable, *input.priorAutomaticTable) &&
      SameRecoveryTableSemantics(*retry.automaticTable, *input.priorAutomaticTable);
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
  if (retry.selectedTable->confidence != "validated_exact_prior_local_bounded_slice") {
    retry.automaticTable->confidence = "validated_after_expanded_cfg_limit_retry";
    retry.selectedTable->confidence = "validated_after_expanded_cfg_limit_retry";
  }
  return retry;
}

}  // namespace rex::codegen
