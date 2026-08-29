/**
 * @file        rex/codegen/entrypoint_closure.h
 * @brief       Report-only static code-pointer and entrypoint closure analysis
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rex/codegen/binary_view.h>
#include <rex/result.h>

namespace rex::codegen {

class CodegenContext;

inline constexpr uint32_t kEntrypointClosureSchemaVersion = 2;
inline constexpr std::string_view kEntrypointClosureAnalyzerVersion = "1.1.0";
inline constexpr std::string_view kExecutableMemoryFingerprintAlgorithm =
    "fable2-executable-memory-sha256-v1";

enum class EntrypointEvidenceKind : uint8_t {
  XexEntrypoint,
  PeExport,
  TlsCallback,
  PdataFunction,
  PdataException,
  DirectBranchLink,
  InterFunctionTailBranch,
  RelocationBackedPointer,
  ReadonlyCodePointer,
  WritableCodePointer,
  PointerTableRun,
  RttiVtable,
  CallbackTable,
  CodeMaterializationXref,
  ExistingManifest,
  ManualVerified,
  FaultWalkerVerified,
  AbiHelper,
  RexglueDiscovered,
  ReservedGhidraImport,
  ReservedJumpTableRecovery,
  ReservedXeniaTrace,
  ReservedRuntimeBulkImport,
};

enum class EntrypointClassification : uint8_t {
  ConfirmedExistingFunction,
  StrongNewFunction,
  ProbableNewFunction,
  CallableMidFunctionEntry,
  JumpTableCase,
  ExceptionLandingPad,
  AmbiguousCodePointer,
  RejectedNonCode,
  RejectedOverlap,
  RejectedOutOfRange,
};

enum class EntrypointConfidence : uint8_t {
  Confirmed,
  Strong,
  Probable,
  Review,
  Rejected,
};

const char* EntrypointEvidenceKindName(EntrypointEvidenceKind kind);
const char* EntrypointClassificationName(EntrypointClassification classification);
const char* EntrypointConfidenceName(EntrypointConfidence confidence);

struct EntrypointAddressRange {
  uint32_t start = 0;
  uint32_t end = 0;

  uint32_t size() const { return end - start; }
  bool contains(uint32_t address) const { return address >= start && address < end; }
  bool overlaps(const EntrypointAddressRange& other) const {
    return start < other.end && other.start < end;
  }
};

struct EntrypointEvidence {
  EntrypointEvidenceKind kind = EntrypointEvidenceKind::ReadonlyCodePointer;
  uint32_t targetAddress = 0;
  std::optional<uint32_t> sourceAddress;
  std::optional<uint32_t> storageAddress;
  std::string sourceSection;
  std::string provenance;
  std::map<std::string, std::string> attributes;
};

struct EntrypointBasicBlock {
  EntrypointAddressRange range;
  uint32_t ownerAddress = 0;
  std::string termination;
};

struct EntrypointDirectEdge {
  uint32_t site = 0;
  uint32_t source = 0;
  uint32_t target = 0;
  std::string kind;
};

struct EntrypointIndirectSite {
  uint32_t site = 0;
  uint32_t ownerAddress = 0;
  bool link = false;
  std::string kind;
};

struct EntrypointFunctionSeed {
  EntrypointAddressRange range;
  std::string authority;
  std::vector<std::string> boundaryProvenance;
  bool trusted = false;
  bool preliminary = false;
  bool manifest = false;
  bool exceptionFunction = false;
  std::vector<EntrypointAddressRange> blocks;
  std::vector<EntrypointDirectEdge> directEdges;
  std::set<uint32_t> labels;
  std::set<uint32_t> jumpTableTargets;
  std::set<uint32_t> exceptionEntries;
};

struct EntrypointManualEvidence {
  uint32_t address = 0;
  uint32_t size = 0;
  std::vector<EntrypointEvidenceKind> kinds;
  std::string provenance;
};

struct EntrypointFixtureExpectation {
  uint32_t address = 0;
  uint32_t size = 0;
  std::string verifiedClassification;
};

struct EntrypointClosureLimits {
  uint32_t maxIterations = 12;
  uint32_t maxCandidates = 100000;
  uint32_t maxInstructionsPerCandidate = 4096;
  uint32_t maxTraversalDepth = 256;
  uint32_t maxPointerRunEntries = 4096;
  uint32_t materializationWindow = 8;
};

struct EntrypointImageIdentity {
  std::string identityMethod;
  std::string baseXexSha256;
  std::string titleUpdateSha256;
  std::string patchedImageSha256;
  std::string executableMemoryFingerprintAlgorithm;
  std::string executableMemoryFingerprint;
  uint32_t imageBase = 0;
  uint32_t imageSize = 0;
  uint32_t entryPoint = 0;
  uint32_t titleId = 0;
  uint32_t mediaId = 0;
  std::string version;
  uint32_t peTimeDateStamp = 0;
};

struct EntrypointSectionRecord {
  std::string name;
  EntrypointAddressRange range;
  std::string sha256;
  bool executable = false;
  bool readable = false;
  bool writable = false;
};

struct EntrypointCandidate {
  uint32_t address = 0;
  std::optional<EntrypointAddressRange> proposedRange;
  EntrypointClassification classification = EntrypointClassification::AmbiguousCodePointer;
  EntrypointConfidence confidence = EntrypointConfidence::Review;
  std::string knownRangeRelationship;
  std::string decodedInstruction;
  std::string boundaryProvenance;
  std::vector<EntrypointEvidence> evidence;
  std::vector<EntrypointBasicBlock> basicBlocks;
  std::vector<EntrypointDirectEdge> directEdges;
  std::vector<EntrypointIndirectSite> indirectSites;
  std::vector<std::string> conflicts;
  std::vector<std::string> rejectionReasons;
  bool completeTraversal = false;
  bool hitInstructionLimit = false;
  bool hitDepthLimit = false;
};

struct EntrypointFixpointIteration {
  uint32_t iteration = 0;
  uint32_t candidatesBefore = 0;
  uint32_t candidatesAfter = 0;
  uint32_t newDirectCallTargets = 0;
  uint32_t newTailBranchTargets = 0;
  uint32_t newEvidenceRecords = 0;
  uint32_t classificationsChanged = 0;
};

struct EntrypointLimitDiagnostic {
  std::string limit;
  uint64_t configured = 0;
  uint64_t observed = 0;
  std::optional<uint32_t> address;
  std::string detail;
};

struct EntrypointFixtureResult {
  EntrypointFixtureExpectation expected;
  bool present = false;
  bool rangeMatches = false;
  bool independentlyRediscovered = false;
  std::vector<EntrypointEvidenceKind> independentEvidence;
  std::vector<uint32_t> storageAddresses;
  std::vector<uint32_t> materializationSites;
  std::string result;
};

struct EntrypointClosureCounts {
  uint32_t trustedRanges = 0;
  uint32_t preliminaryRanges = 0;
  uint32_t candidates = 0;
  uint32_t strongNewFunctions = 0;
  uint32_t probableNewFunctions = 0;
  uint32_t ambiguousCandidates = 0;
  uint32_t rejectedCandidates = 0;
  uint32_t pointerStorageSites = 0;
  uint32_t pointerRuns = 0;
  uint32_t relocationStorageSites = 0;
  uint32_t peExports = 0;
  uint32_t tlsCallbacks = 0;
  uint32_t indirectSites = 0;
  uint32_t candidateOverlapPairs = 0;
};

struct EntrypointClosureReport {
  uint32_t schemaVersion = kEntrypointClosureSchemaVersion;
  std::string analyzerVersion = std::string(kEntrypointClosureAnalyzerVersion);
  EntrypointImageIdentity image;
  EntrypointClosureLimits limits;
  std::vector<EntrypointSectionRecord> sections;
  std::vector<EntrypointFunctionSeed> functionRanges;
  std::vector<EntrypointDirectEdge> directEdges;
  std::vector<EntrypointIndirectSite> indirectSites;
  std::vector<EntrypointCandidate> candidates;
  std::vector<EntrypointFixpointIteration> fixpointIterations;
  std::vector<EntrypointLimitDiagnostic> limitDiagnostics;
  std::vector<EntrypointFixtureResult> fixtureResults;
  EntrypointClosureCounts counts;
  bool fixpointReached = false;
  bool manifestMutationAttempted = false;
};

struct EntrypointClosureInput {
  EntrypointImageIdentity image;
  EntrypointClosureLimits limits;
  std::vector<EntrypointFunctionSeed> functionSeeds;
  std::vector<EntrypointManualEvidence> manualEvidence;
  std::vector<EntrypointFixtureExpectation> fixtures;
  std::set<uint32_t> relocationStorageAddresses;
  std::vector<std::pair<uint32_t, std::string>> peExports;
  std::vector<uint32_t> tlsCallbacks;
  std::vector<EntrypointLimitDiagnostic> producerDiagnostics;
};

struct EntrypointClosureRunMetadata {
  uint64_t elapsedMilliseconds = 0;
  uint64_t peakWorkingSetBytes = 0;
  std::string commandLine;
};

EntrypointClosureReport AnalyzeEntrypointClosure(const BinaryView& binary,
                                                 EntrypointClosureInput input);

/// Reuse the production CodegenContext decoder cache after Analyze() has run.
EntrypointClosureReport AnalyzeEntrypointClosure(const CodegenContext& context,
                                                 EntrypointClosureInput input);

Result<void> WriteEntrypointClosureReports(const EntrypointClosureReport& report,
                                           const EntrypointClosureRunMetadata& runMetadata,
                                           const std::filesystem::path& outputDirectory,
                                           bool writeReviewToml = true);

/// Stable authoritative JSON, excluding volatile run metadata.
std::string SerializeEntrypointClosureJson(const EntrypointClosureReport& report);

}  // namespace rex::codegen
