/**
 * @file        rex/codegen/function_types.h
 * @brief       Types and structures used by FunctionNode and FunctionGraph
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#pragma once

#include <bitset>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include <rex/types.h>

namespace rex::codegen::ppc {
struct Instruction;
}  // namespace rex::codegen::ppc

namespace rex::runtime {
class ExportResolver;
}  // namespace rex::runtime

namespace rex::codegen {

// Forward declarations
class FunctionGraph;
class FunctionNode;
class BinaryView;
struct RecompilerConfig;

/// Lightweight context passed to FunctionNode::emitCpp() and BuilderContext.
/// Non-owning references -- caller must ensure lifetimes.
struct EmitContext {
  const BinaryView& binary;
  const RecompilerConfig& config;
  const FunctionGraph& graph;
  uint32_t entryPoint = 0;                      ///< For "xstart" naming
  runtime::ExportResolver* resolver = nullptr;  ///< For import ordinal resolution (nullable)

  /// Every function name emitted as a call. The writer turns this into the
  /// per-file declaration header, so a missed name is a compile error.
  std::unordered_set<std::string>* referenced = nullptr;

  void reference(std::string_view name) const {
    if (referenced)
      referenced->emplace(name);
  }
};

//=============================================================================
// Authority Levels
//=============================================================================
// Determines boundary mutability and merge eligibility.
// Only GAP_FILL can be absorbed during vacancy merging.
// All others represent immutable entry points.
enum class FunctionAuthority : uint8_t {
  GAP_FILL = 0,    // Speculative - found in unclaimed gap, CAN be absorbed
  DISCOVERED = 1,  // Found via bl/bcl - immutable entry point
  VTABLE = 2,      // Found in vtable - immutable entry point
  HELPER = 3,      // Save/restore helpers - fixed, overlaps allowed
  PDATA = 4,       // From .pdata - entry fixed, can extend
  CONFIG = 5,      // User config - exact boundaries, immutable
  IMPORT = 6,      // Import thunk - external function, immutable
};

//=============================================================================
// Target Classification (for code generation)
//=============================================================================
enum class TargetKind {
  InternalLabel,  // Target inside caller's function (PIC pattern)
  Function,       // Target is a function entry point
  Import,         // Target is an import
  Unknown,        // Target not recognized
};

const char* AuthorityName(FunctionAuthority auth);

//=============================================================================
// Function State (3-state machine)
//=============================================================================
enum class FunctionState : uint8_t {
  kRegistered,  // Entry point known, blocks/instructions not yet assigned
  kDiscovered,  // Blocks and instructions assigned, may have unresolved branches
  kSealed,      // All branches resolved, ready for code generation
};

// Legacy aliases for compatibility during migration
constexpr FunctionState PENDING = FunctionState::kRegistered;  // Will be removed
constexpr FunctionState SEALED = FunctionState::kSealed;       // Will be removed

//=============================================================================
// Exception Handling - SEH (Structured Exception Handling)
//=============================================================================

struct SehScope {
  uint32_t tryStart;  // [+0] Start of __try block
  uint32_t tryEnd;    // [+4] End of __try block
  uint32_t handler;   // [+8] Handler function (__finally or __except body)
  uint32_t filter;    // [+C] Filter expression (0 for __finally, address for __except)
};

struct SehExceptionInfo {
  uint32_t handlerThunk;    // e.g. __C_specific_handler thunk address
  uint32_t scopeTableAddr;  // Pointer to scope table in .rdata
  std::vector<SehScope> scopes;
  uint32_t frameSize = 0;      // Stack frame size for r12 setup during unwind
  uint32_t restoreHelper = 0;  // __restgprlr_N address to call on unwind
};

//=============================================================================
// Exception Handling - C++ EH (FuncInfo with magic 0x19930522)
//=============================================================================

constexpr uint32_t CXX_EH_MAGIC = 0x19930522;

struct CxxUnwindEntry {
  int32_t toState;  // Previous state (-1 = terminal)
  uint32_t action;  // Cleanup/destructor function address
};

struct CxxIPStateEntry {
  uint32_t ip;    // Code address where state changes
  int32_t state;  // State number at this IP
};

struct CxxCatchHandler {
  uint32_t adjectives;           // Catch type flags
  uint32_t typeDescriptor;       // Pointer to type descriptor (RTTI)
  int32_t catchObjDisplacement;  // Displacement of catch object
  uint32_t handlerAddress;       // Catch handler function address
};

struct CxxTryBlock {
  int32_t tryLow;     // Lowest state in try
  int32_t tryHigh;    // Highest state in try
  int32_t catchHigh;  // Highest state in catch
  std::vector<CxxCatchHandler> handlers;
};

struct CxxExceptionInfo {
  uint32_t handlerThunk;  // Frame handler function
  uint32_t funcInfoAddr;  // Address of FuncInfo in .rdata
  uint32_t maxState;      // Number of unwind states
  std::vector<CxxUnwindEntry> unwindMap;
  std::vector<CxxTryBlock> tryBlocks;
  std::vector<CxxIPStateEntry> ipToStateMap;
};

//=============================================================================
// Combined Exception Info (variant of SEH or C++ EH)
//=============================================================================

struct ExceptionInfo {
  std::variant<std::monostate, SehExceptionInfo, CxxExceptionInfo> data;

  bool hasInfo() const { return !std::holds_alternative<std::monostate>(data); }
  bool isSeh() const { return std::holds_alternative<SehExceptionInfo>(data); }
  bool isCxx() const { return std::holds_alternative<CxxExceptionInfo>(data); }

  const SehExceptionInfo* asSeh() const { return std::get_if<SehExceptionInfo>(&data); }
  const CxxExceptionInfo* asCxx() const { return std::get_if<CxxExceptionInfo>(&data); }

  uint32_t handlerThunk() const {
    if (auto* seh = asSeh())
      return seh->handlerThunk;
    if (auto* cxx = asCxx())
      return cxx->handlerThunk;
    return 0;
  }
};

//=============================================================================
// Call Target - Resolved destination of a call/jump
//=============================================================================
struct CallTarget {
  struct ToFunction {
    FunctionNode* node;
  };
  struct ToImport {
    uint32_t address;
    std::string name;
  };
  struct Unresolved {
    uint32_t address;
  };

  std::variant<ToFunction, ToImport, Unresolved> value;

  bool isResolved() const { return !std::holds_alternative<Unresolved>(value); }
  bool isFunction() const { return std::holds_alternative<ToFunction>(value); }
  bool isImport() const { return std::holds_alternative<ToImport>(value); }

  FunctionNode* asFunction() const {
    if (auto* f = std::get_if<ToFunction>(&value))
      return f->node;
    return nullptr;
  }

  static CallTarget function(FunctionNode* fn) { return {ToFunction{fn}}; }
  static CallTarget import(uint32_t addr, std::string name) {
    return {ToImport{addr, std::move(name)}};
  }
  static CallTarget unresolved(uint32_t addr) { return {Unresolved{addr}}; }
};

//=============================================================================
// Call Edge - A call site within a function
//=============================================================================

struct CallEdge {
  uint32_t site;      // Address of the bl/b instruction
  CallTarget target;  // Resolved or unresolved target
};

//=============================================================================
// Basic Block
//=============================================================================

struct Block {
  uint32_t base;
  uint32_t size;

  uint32_t end() const { return base + size; }
  bool contains(uint32_t addr) const { return addr >= base && addr < end(); }
};

//=============================================================================
// Jump Table
//=============================================================================

enum class IndirectSiteClassification : uint8_t {
  SwitchBctr,
  ComputedTailBctr,
  VirtualOrCallbackBctrl,
  IndirectTailBctrlOrBctr,
  OrdinaryBlrReturn,
  NonstandardBclr,
  OpaqueIndirectTransfer,
};

enum class JumpTableFailure : uint8_t {
  None,
  MissingBound,
  AmbiguousBound,
  UnknownTableBase,
  UnknownIndex,
  AmbiguousReachingDefinition,
  UnsupportedRelativeForm,
  InvalidElementWidth,
  TargetOutOfRange,
  TargetUnaligned,
  MixedValidityTargets,
  AnalysisLimit,
  NonSwitchIndirect,
};

enum class JumpTableKind : uint8_t {
  Unknown,
  AbsolutePointer,
  RelativeOffset,
};

enum class JumpTableOrigin : uint8_t {
  Automatic,
  Manual,
};

enum class JumpTableSwitchLikelihood : uint8_t {
  ResolvedSwitch,
  ConfirmedSwitchMiss,
  ProbableSwitchMiss,
  PlausibleSwitchCandidate,
  VirtualOrCallbackDispatch,
  ComputedTailDispatch,
  OpaqueNonTableDispatch,
  InsufficientStaticEvidence,
  RejectedFalsePositive,
};

enum class JumpTableManualComparison : uint8_t {
  None,
  ExactEquivalent,
  AutomaticSuperset,
  AutomaticSubset,
  ConflictingTargets,
  ConflictingBounds,
  UnsupportedManualForm,
  NewAutomaticTable,
};

const char* IndirectSiteClassificationName(IndirectSiteClassification classification);
const char* JumpTableFailureName(JumpTableFailure failure);
const char* JumpTableKindName(JumpTableKind kind);
const char* JumpTableOriginName(JumpTableOrigin origin);
const char* JumpTableManualComparisonName(JumpTableManualComparison comparison);
const char* JumpTableSwitchLikelihoodName(JumpTableSwitchLikelihood classification);

struct JumpTableRawEntry {
  uint32_t storageAddress = 0;
  uint32_t rawValue = 0;
  uint32_t target = 0;

  bool operator==(const JumpTableRawEntry&) const = default;
};

struct JumpTableInstructionEvidence {
  uint32_t address = 0;
  uint32_t rawInstruction = 0;
  std::string role;
  std::string instruction;
};

struct JumpTable {
  uint32_t bctrAddress = 0;       // Address of bctr instruction
  uint32_t tableAddress = 0;      // Address of jump table data
  uint8_t indexRegister = 0xFF;   // Register holding unscaled switch index
  std::vector<uint32_t> targets;  // Resolved case targets (internal labels)

  // Recovery evidence. Manual tables need only the compatibility fields above;
  // automatic tables fill the complete model before they can affect ownership.
  JumpTableKind kind = JumpTableKind::Unknown;
  JumpTableOrigin origin = JumpTableOrigin::Automatic;
  JumpTableManualComparison manualComparison = JumpTableManualComparison::None;
  uint32_t ownerAddress = 0;
  uint32_t storageEnd = 0;
  uint32_t boundValue = 0;
  // False when boundValue describes only a finite storage extent. Consumers
  // must not turn that value into a runtime index-domain proof.
  bool boundValueIsFiniteIndexDomain = true;
  uint32_t caseCount = 0;
  uint32_t defaultTarget = 0;
  uint32_t anchorAddress = 0;
  uint32_t targetScale = 1;
  uint8_t elementWidth = 0;
  bool elementSigned = false;
  bool boundInclusive = false;
  bool defaultIsReturn = false;
  bool tableInExecutableSection = false;
  std::string boundSemantics;
  std::string confidence;
  std::vector<JumpTableRawEntry> rawEntries;
  std::vector<JumpTableInstructionEvidence> evidence;
  std::vector<std::string> conflicts;
};

struct JumpTableBudgetExhaustionEvidence {
  std::string budget;
  uint32_t limit = 0;
  uint32_t observed = 0;
};

struct JumpTableLimitRetryEvidence {
  std::string exhaustedBudget;
  uint32_t initialBudgetValue = 0;
  uint32_t retryBudgetValue = 0;
  std::vector<JumpTableFailure> initialFailures;
  std::vector<JumpTableFailure> retryFailures;
  std::vector<JumpTableBudgetExhaustionEvidence> initialExhaustedBudgets;
  std::vector<JumpTableBudgetExhaustionEvidence> retryExhaustedBudgets;
  bool exactPriorTableMatch = false;
  bool accepted = false;
};

struct JumpTableLoopEvidence {
  uint8_t registerIndex = 0xFF;
  uint32_t headerAddress = 0;
  std::vector<uint32_t> entryDefinitionAddresses;
  std::vector<uint32_t> backedgeDefinitionAddresses;
  std::vector<uint32_t> entryValues;
  std::vector<uint32_t> backedgeValues;
  std::vector<uint32_t> finiteValues;
  bool identityBackedge = false;
  bool finiteEntryDomain = false;
  bool converged = false;
};

struct JumpTableCfgEdgeEvidence {
  uint32_t source = 0;
  uint32_t target = 0;

  bool operator==(const JumpTableCfgEdgeEvidence&) const = default;
};

// A finite argument-domain proof at one direct callsite. This is deliberately
// separate from callable-entry discovery: it constrains a register value at an
// already trusted function entry and never makes an address callable.
struct JumpTableEntryCallsiteDomainEvidence {
  uint32_t callerAddress = 0;
  uint32_t callAddress = 0;
  uint32_t targetAddress = 0;
  uint32_t compareAddress = 0;
  uint32_t guardAddress = 0;
  uint8_t registerIndex = 0xFF;
  std::vector<uint32_t> definitionAddresses;
  std::vector<uint32_t> finiteValues;
  // The caller CFG supplied to the proof may include only ordinary entry
  // reachability or additional edges from independently validated local jump
  // tables. This provenance never makes a target callable and never replaces
  // the complete inbound-reference/domain checks below.
  std::string callerCfgKind;
  std::vector<uint32_t> callerCfgJumpTableSites;
  bool reachableOnlyAfterCaseExpansion = false;
  std::string proofKind;
  std::vector<std::string> rejections;
  std::string exhaustedBudget;
  uint32_t budgetLimit = 0;
  uint32_t budgetObserved = 0;
  bool complete = false;
  bool limitHit = false;
};

// Whole-image evidence that every supported static inbound reference to an
// existing trusted entry is accounted for and supplies a finite register
// domain. A production switch may consume this only after the union is proven
// dense and the register is preserved from entry to dispatch.
struct JumpTableEntryRegisterDomainEvidence {
  uint32_t entryAddress = 0;
  uint8_t registerIndex = 0xFF;
  std::vector<uint32_t> finiteValues;
  std::vector<uint32_t> directCallSites;
  std::vector<uint32_t> rejectedReferenceSites;
  std::vector<std::string> referenceRejections;
  std::vector<JumpTableEntryCallsiteDomainEvidence> callsites;
  bool allReferencesDirectCalls = false;
  bool finiteDenseDomain = false;
  std::string rejection;
};

using JumpTableEntryRegisterDomainMap =
    std::unordered_map<uint8_t, JumpTableEntryRegisterDomainEvidence>;
using JumpTableEntryRegisterDomainsBySite =
    std::unordered_map<uint32_t, JumpTableEntryRegisterDomainMap>;

struct JumpTableBoundCandidateEvidence {
  uint32_t compareAddress = 0;
  uint32_t guardAddress = 0;
  uint32_t domainOriginAddress = 0;
  uint32_t value = 0;
  uint32_t caseCount = 0;
  uint32_t defaultTarget = 0;
  uint8_t indexRegister = 0xFF;
  bool inclusive = false;
  bool signedCompare = false;
  bool defaultIsReturn = false;
  bool dominatesDispatch = false;
  bool finiteDenseDomain = false;
  bool priorExactRevalidation = false;
  bool priorDirectBoundedIndexRevalidation = false;
  bool inheritedCaseEdgeProof = false;
  // Exact finite values carried by validated upstream switch edges into this
  // downstream dispatch. This is control-flow evidence, not runtime-derived
  // table-length evidence and never makes a case target callable.
  bool inheritedFiniteCaseDomain = false;
  bool finiteCfgDomain = false;
  bool interproceduralEntryDomain = false;
  // A static table-extent proof, deliberately distinct from a runtime index
  // domain. For the supported compiler idiom the absolute word table starts
  // immediately after a non-fallthrough bctr and ends exactly at its earliest
  // validated case block. This never claims that an observed runtime edge or
  // the first invalid word bounds the table.
  bool selfDelimitedInlineTableExtent = false;
  uint32_t tableStorageStart = 0;
  uint32_t tableStorageEnd = 0;
  bool inlineBoundaryCfgVerified = false;
  uint32_t inlineBoundaryBlockStart = 0;
  uint32_t inlineBoundaryBlockEnd = 0;
  uint32_t inlineBoundaryTerminator = 0;
  // A report-only self-delimited candidate may be used once to expose its
  // own case blocks. Recovery is authoritative only when one of those case
  // blocks has an ordinary CFG path back to the dispatch and reanalysis
  // reproduces the complete candidate exactly. This proves state-machine
  // topology; it deliberately does not prove a finite runtime index domain.
  bool inlineCaseLoopCfgVerified = false;
  uint32_t inlineCaseLoopTarget = 0;
  uint32_t inlineCaseLoopHeader = 0;
  std::vector<uint32_t> finiteValues;
  std::vector<uint32_t> normalizedFiniteValues;
  std::vector<JumpTableCfgEdgeEvidence> inheritedCaseEdges;
  uint32_t stackSpillAddress = 0;
  uint32_t stackReloadAddress = 0;
  int32_t stackSlotOffset = 0;
  uint8_t stackSlotWidth = 0;
  std::string rejection;
};

struct JumpTableReachingDefinitionPathEvidence {
  uint8_t registerIndex = 0xFF;
  uint32_t mergeAddress = 0;
  uint32_t predecessor = 0;
  uint32_t loopHeader = 0;
  bool backedge = false;
  bool limitHit = false;
  std::string expression;
  std::string normalizedExpression;
  std::string disposition;
};

struct JumpTableDiagnosticProbe {
  bool attempted = false;
  bool reportOnly = true;
  bool hypothesisComplete = false;
  bool allTargetsValid = false;
  bool mixedValidity = false;
  uint32_t decodedEntries = 0;
  uint32_t alignedExecutableTargets = 0;
  std::vector<std::string> assumptions;
  std::vector<std::string> rejections;
  std::optional<JumpTable> candidateTable;
};

struct JumpTableSiteDataflowEvidence {
  uint32_t preliminaryBlockStart = 0;
  uint32_t preliminaryBlockEnd = 0;
  std::vector<uint32_t> predecessors;
  bool caseExpandedCfg = false;
  std::vector<JumpTableCfgEdgeEvidence> caseExpansionEdges;
  bool sourceInScc = false;
  bool reachingDefinitionInScc = false;
  std::vector<uint32_t> loopHeaders;
  std::vector<JumpTableCfgEdgeEvidence> backedges;
  std::vector<uint8_t> loopCarriedRegisters;
  uint8_t ctrSourceRegister = 0xFF;
  std::string targetExpression;
  std::string normalizedTargetExpression;
  std::vector<std::string> reachingDefinitionAlternatives;
  std::vector<std::string> normalizedReachingDefinitions;
  std::vector<JumpTableReachingDefinitionPathEvidence> reachingDefinitionPaths;
  std::vector<uint32_t> tableBaseCandidates;
  std::vector<uint32_t> anchorCandidates;
  uint8_t indexRegister = 0xFF;
  // ABI input registers that occur in the primary table load's address
  // expression. This is distinct from indexRegister, which may be the PPC
  // load's already-scaled RB scratch register.
  std::vector<uint8_t> tableLoadInputRegisters;
  std::vector<std::string> indexTransformChain;
  uint8_t elementWidth = 0;
  std::string elementSignedness = "unknown";
  uint32_t targetScale = 0;
  std::vector<JumpTableBoundCandidateEvidence> boundCandidates;
  std::vector<JumpTableEntryRegisterDomainEvidence> entryRegisterDomains;
  std::string tableKindHypothesis = "unknown";
  std::string tableBaseConstruction = "unknown";
  std::string mergeShape = "unknown";
  std::string failureStage = "none";
  std::string dispatchKind = "other";
  std::string clusterId;
  JumpTableSwitchLikelihood switchLikelihood =
      JumpTableSwitchLikelihood::InsufficientStaticEvidence;
  std::vector<std::string> rejectionEvidence;
  std::vector<JumpTableBudgetExhaustionEvidence> exhaustedBudgets;
  JumpTableDiagnosticProbe diagnosticProbe;
};

struct IndirectSiteAnalysis {
  uint32_t site = 0;
  uint32_t ownerAddress = 0;
  bool link = false;
  bool conditional = false;
  bool usesCtr = false;
  IndirectSiteClassification classification = IndirectSiteClassification::OpaqueIndirectTransfer;
  std::vector<JumpTableFailure> failures;
  std::vector<JumpTableInstructionEvidence> evidence;
  std::optional<JumpTable> automaticTable;
  std::optional<JumpTable> selectedTable;
  std::optional<JumpTableLimitRetryEvidence> limitRetry;
  std::vector<JumpTableLoopEvidence> loopEvidence;
  // Whole-image census evidence is only needed for non-link CTR transfers.
  // Keep it out of the hot, frequently moved record for ordinary returns and
  // share it across the graph-to-report copy made by entrypoint closure.
  std::shared_ptr<JumpTableSiteDataflowEvidence> dataflow;
  bool incompleteCaseEntryPaths = false;
};

struct JumpTableRecoveryLimits {
  uint32_t maxBackwardInstructions = 96;
  uint32_t maxPredecessors = 64;
  uint32_t maxStates = 128;
  uint32_t maxCfgTopologyNodes = 65536;
  uint32_t maxEntries = 4096;
  uint32_t maxFixpointIterations = 16;
};

struct JumpTableRecoveryStats {
  uint64_t elapsedMicroseconds = 0;
  uint64_t preliminaryCfgMicroseconds = 0;
  uint64_t caseExpansionCfgMicroseconds = 0;
  uint64_t indirectSiteClassificationMicroseconds = 0;
  uint64_t fixpointOverheadMicroseconds = 0;
  uint64_t functionFixpointMicroseconds = 0;
  uint64_t decodedInstructions = 0;
  uint32_t fixpointIterations = 0;
  uint32_t indirectSites = 0;
  uint32_t recoveredTables = 0;
  uint32_t manualTables = 0;
  uint32_t unresolvedSites = 0;
  bool analysisLimitHit = false;
};

//=============================================================================
// Function Analysis (computed at seal time)
//=============================================================================

struct FunctionAnalysis {
  // CSR requirements (denormal handling)
  enum class CsrRequirement : uint8_t { None, Fpu, Vmx };

  // Special register usage
  bool usesCtr = false;
  bool usesXer = false;
  bool usesCr = false;
  bool usesFpscr = false;

  // CSR state needed
  CsrRequirement csrRequirement = CsrRequirement::None;
};

//=============================================================================
// Unresolved Jump - Internal jump awaiting resolution
//=============================================================================

struct UnresolvedJump {
  uint32_t site;       // Address of the branch instruction
  uint32_t target;     // Target address
  bool isCall;         // true = bl (call), false = b (tail call)
  bool isConditional;  // true = bc/beq/bne/etc, false = b
};

//=============================================================================
// Code Buffer - Holds executable code for a section
//=============================================================================
// The graph owns code buffers so recompilation doesn't need module access.
// Each buffer corresponds to one executable section.

struct CodeBuffer {
  std::vector<uint8_t> data;
  uint32_t baseAddress = 0;

  uint32_t size() const { return static_cast<uint32_t>(data.size()); }
  uint32_t endAddress() const { return baseAddress + size(); }

  bool contains(uint32_t addr) const { return addr >= baseAddress && addr < endAddress(); }

  const uint8_t* translate(uint32_t addr) const {
    if (!contains(addr))
      return nullptr;
    return data.data() + (addr - baseAddress);
  }
};

}  // namespace rex::codegen
