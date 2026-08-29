#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <rex/codegen/binary_view.h>
#include <rex/codegen/entrypoint_closure.h>

namespace fs = std::filesystem;

namespace {

using namespace rex::codegen;

constexpr uint32_t kTextBase = 0x10000000;
constexpr uint32_t kReadOnlyBase = 0x20000000;
constexpr uint32_t kWritableBase = 0x20000100;

void StoreBe32(std::vector<uint8_t>& bytes, uint32_t offset, uint32_t value) {
  REQUIRE(offset + 4 <= bytes.size());
  bytes[offset + 0] = static_cast<uint8_t>(value >> 24);
  bytes[offset + 1] = static_cast<uint8_t>(value >> 16);
  bytes[offset + 2] = static_cast<uint8_t>(value >> 8);
  bytes[offset + 3] = static_cast<uint8_t>(value);
}

uint32_t Branch(uint32_t site, uint32_t target, bool link = false) {
  int32_t displacement = static_cast<int32_t>(target - site);
  return 0x48000000u | (static_cast<uint32_t>(displacement) & 0x03FFFFFCu) | (link ? 1u : 0u);
}

struct SyntheticImage {
  std::vector<uint8_t> text = std::vector<uint8_t>(0x100);
  std::vector<uint8_t> readOnly = std::vector<uint8_t>(0x100);
  std::vector<uint8_t> writable = std::vector<uint8_t>(0x100);

  BinaryView view(uint32_t entryPoint = 0) const {
    const std::array sections{
        BinarySectionInput{.name = ".text",
                           .baseAddress = kTextBase,
                           .data = text,
                           .executable = true,
                           .readable = true,
                           .writable = false},
        BinarySectionInput{.name = ".rdata",
                           .baseAddress = kReadOnlyBase,
                           .data = readOnly,
                           .executable = false,
                           .readable = true,
                           .writable = false},
        BinarySectionInput{.name = ".data",
                           .baseAddress = kWritableBase,
                           .data = writable,
                           .executable = false,
                           .readable = true,
                           .writable = true},
    };
    return BinaryView::fromSections(kTextBase, 0x10000200, entryPoint, sections);
  }
};

const EntrypointCandidate& Candidate(const EntrypointClosureReport& report, uint32_t address) {
  auto found =
      std::find_if(report.candidates.begin(), report.candidates.end(),
                   [address](const auto& candidate) { return candidate.address == address; });
  REQUIRE(found != report.candidates.end());
  return *found;
}

bool HasEvidence(const EntrypointCandidate& candidate, EntrypointEvidenceKind kind) {
  return std::any_of(candidate.evidence.begin(), candidate.evidence.end(),
                     [kind](const auto& evidence) { return evidence.kind == kind; });
}

EntrypointClosureInput DefaultInput() {
  EntrypointClosureInput input;
  input.image.identityMethod = "synthetic test image";
  input.image.patchedImageSha256 = std::string(64, 'A');
  input.image.imageBase = kTextBase;
  input.image.imageSize = 0x10000200;
  return input;
}

}  // namespace

TEST_CASE("entrypoint closure retains an uncorroborated big-endian singleton as ambiguous",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  StoreBe32(image.text, 0x40, 0x38600000);  // li r3, 0
  StoreBe32(image.text, 0x44, 0x4E800020);  // blr
  StoreBe32(image.readOnly, 0x00, kTextBase + 0x40);

  auto report = AnalyzeEntrypointClosure(image.view(), DefaultInput());
  const auto& candidate = Candidate(report, kTextBase + 0x40);
  CHECK(candidate.classification == EntrypointClassification::AmbiguousCodePointer);
  REQUIRE(candidate.proposedRange);
  CHECK(candidate.proposedRange->size() == 8);
  CHECK(HasEvidence(candidate, EntrypointEvidenceKind::ReadonlyCodePointer));
  CHECK(candidate.completeTraversal);
}

TEST_CASE("entrypoint closure records relocations, pointer runs and writable pointers",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  StoreBe32(image.text, 0x00, 0x3D802000);  // lis r12, 0x2000
  StoreBe32(image.text, 0x04, 0x618C0100);  // ori r12, r12, 0x100
  StoreBe32(image.text, 0x08, 0x4E800020);
  for (uint32_t offset : {0x40u, 0x48u, 0x50u}) {
    StoreBe32(image.text, offset, 0x38600000);
    StoreBe32(image.text, offset + 4, 0x4E800020);
  }
  StoreBe32(image.writable, 0x00, kTextBase + 0x40);
  StoreBe32(image.writable, 0x04, kTextBase + 0x48);
  StoreBe32(image.writable, 0x08, kTextBase + 0x50);
  auto input = DefaultInput();
  input.relocationStorageAddresses.insert(kWritableBase);

  auto report = AnalyzeEntrypointClosure(image.view(), std::move(input));
  const auto& candidate = Candidate(report, kTextBase + 0x40);
  CHECK(candidate.classification == EntrypointClassification::StrongNewFunction);
  CHECK(HasEvidence(candidate, EntrypointEvidenceKind::WritableCodePointer));
  CHECK(HasEvidence(candidate, EntrypointEvidenceKind::RelocationBackedPointer));
  CHECK(HasEvidence(candidate, EntrypointEvidenceKind::PointerTableRun));
  CHECK(HasEvidence(candidate, EntrypointEvidenceKind::CallbackTable));
  CHECK(std::any_of(candidate.evidence.begin(), candidate.evidence.end(), [](const auto& evidence) {
    return evidence.sourceAddress == kTextBase && evidence.storageAddress == kWritableBase &&
           evidence.provenance == "bounded PPC xref to pointer storage/table";
  }));
  CHECK(report.counts.pointerRuns == 1);
}

TEST_CASE("entrypoint closure requires a code xref before calling a pointer run a callback table",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  for (uint32_t offset : {0x40u, 0x48u}) {
    StoreBe32(image.text, offset, 0x38600000);
    StoreBe32(image.text, offset + 4, 0x4E800020);
  }
  StoreBe32(image.readOnly, 0x00, kTextBase + 0x40);
  StoreBe32(image.readOnly, 0x04, kTextBase + 0x48);

  auto report = AnalyzeEntrypointClosure(image.view(), DefaultInput());
  const auto& candidate = Candidate(report, kTextBase + 0x40);
  CHECK(candidate.classification == EntrypointClassification::ProbableNewFunction);
  CHECK(HasEvidence(candidate, EntrypointEvidenceKind::PointerTableRun));
  CHECK_FALSE(HasEvidence(candidate, EntrypointEvidenceKind::CallbackTable));
}

TEST_CASE("entrypoint closure records conflicts between proposed candidate ranges",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  StoreBe32(image.text, 0x40, 0x60000000);
  StoreBe32(image.text, 0x44, 0x60000000);
  StoreBe32(image.text, 0x48, 0x60000000);
  StoreBe32(image.text, 0x4C, 0x4E800020);
  StoreBe32(image.readOnly, 0x00, kTextBase + 0x40);
  StoreBe32(image.readOnly, 0x04, kTextBase + 0x48);

  auto report = AnalyzeEntrypointClosure(image.view(), DefaultInput());
  const auto& outer = Candidate(report, kTextBase + 0x40);
  const auto& inner = Candidate(report, kTextBase + 0x48);
  CHECK(report.counts.candidateOverlapPairs == 1);
  CHECK(outer.conflicts.size() == 1);
  CHECK(inner.conflicts.size() == 1);
}

TEST_CASE("entrypoint closure recognizes PPC high-low address materialization",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  StoreBe32(image.text, 0x00, 0x3D801000);  // lis r12, 0x1000
  StoreBe32(image.text, 0x04, 0x618C0040);  // ori r12, r12, 0x40
  StoreBe32(image.text, 0x08, 0x4E800020);  // blr
  StoreBe32(image.text, 0x40, 0x38600000);
  StoreBe32(image.text, 0x44, 0x4E800020);

  auto report = AnalyzeEntrypointClosure(image.view(), DefaultInput());
  const auto& candidate = Candidate(report, kTextBase + 0x40);
  CHECK(HasEvidence(candidate, EntrypointEvidenceKind::CodeMaterializationXref));
  CHECK(candidate.classification == EntrypointClassification::ProbableNewFunction);
}

TEST_CASE("entrypoint closure excludes PE metadata from generic pointer scanning",
          "[codegen][entrypoint-closure]") {
  std::vector<uint8_t> text(0x40);
  std::vector<uint8_t> pdata(0x20);
  StoreBe32(text, 0x20, 0x4E800020);
  StoreBe32(pdata, 0x00, kTextBase + 0x20);
  const std::array sections{
      BinarySectionInput{.name = ".text",
                         .baseAddress = kTextBase,
                         .data = text,
                         .executable = true,
                         .readable = true},
      BinarySectionInput{
          .name = ".pdata", .baseAddress = kReadOnlyBase, .data = pdata, .readable = true},
  };
  auto view = BinaryView::fromSections(kTextBase, 0x10000020, 0, sections);
  auto report = AnalyzeEntrypointClosure(view, DefaultInput());
  CHECK(report.candidates.empty());
  CHECK(report.counts.pointerStorageSites == 0);
}

TEST_CASE("entrypoint closure reaches a direct-call fixpoint", "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  StoreBe32(image.text, 0x40, Branch(kTextBase + 0x40, kTextBase + 0x60, true));
  StoreBe32(image.text, 0x44, 0x4E800020);
  StoreBe32(image.text, 0x60, 0x38600000);
  StoreBe32(image.text, 0x64, 0x4E800020);
  StoreBe32(image.readOnly, 0x00, kTextBase + 0x40);

  auto report = AnalyzeEntrypointClosure(image.view(), DefaultInput());
  const auto& discovered = Candidate(report, kTextBase + 0x60);
  CHECK(HasEvidence(discovered, EntrypointEvidenceKind::DirectBranchLink));
  CHECK(discovered.classification == EntrypointClassification::StrongNewFunction);
  CHECK(report.fixpointReached);
  CHECK(report.fixpointIterations.size() >= 2);
}

TEST_CASE("entrypoint closure reclassifies an existing pointer candidate after call evidence",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  StoreBe32(image.text, 0x40, Branch(kTextBase + 0x40, kTextBase + 0x60, true));
  StoreBe32(image.text, 0x44, 0x4E800020);
  StoreBe32(image.text, 0x60, 0x38600000);
  StoreBe32(image.text, 0x64, 0x4E800020);
  StoreBe32(image.readOnly, 0x00, kTextBase + 0x40);
  StoreBe32(image.readOnly, 0x08, kTextBase + 0x60);

  auto report = AnalyzeEntrypointClosure(image.view(), DefaultInput());
  const auto& discovered = Candidate(report, kTextBase + 0x60);
  CHECK(discovered.classification == EntrypointClassification::StrongNewFunction);
  CHECK(report.fixpointReached);
  CHECK(std::any_of(report.fixpointIterations.begin(), report.fixpointIterations.end(),
                    [](const auto& iteration) { return iteration.newEvidenceRecords != 0; }));
}

TEST_CASE("entrypoint closure treats image entry, exports and TLS callbacks as reliable seeds",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  for (uint32_t offset : {0x10u, 0x20u, 0x30u})
    StoreBe32(image.text, offset, 0x4E800020);
  auto input = DefaultInput();
  input.image.entryPoint = kTextBase + 0x10;
  input.peExports.emplace_back(kTextBase + 0x20, "SyntheticExport");
  input.tlsCallbacks.push_back(kTextBase + 0x30);

  auto report = AnalyzeEntrypointClosure(image.view(kTextBase + 0x10), std::move(input));
  CHECK(Candidate(report, kTextBase + 0x10).classification ==
        EntrypointClassification::StrongNewFunction);
  CHECK(HasEvidence(Candidate(report, kTextBase + 0x10), EntrypointEvidenceKind::XexEntrypoint));
  CHECK(HasEvidence(Candidate(report, kTextBase + 0x20), EntrypointEvidenceKind::PeExport));
  CHECK(HasEvidence(Candidate(report, kTextBase + 0x30), EntrypointEvidenceKind::TlsCallback));
}

TEST_CASE("entrypoint closure distinguishes owned internal entry kinds",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  for (uint32_t offset = 0x20; offset < 0x50; offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop
  StoreBe32(image.text, 0x4C, 0x4E800020);
  StoreBe32(image.readOnly, 0x00, kTextBase + 0x20);
  StoreBe32(image.readOnly, 0x04, kTextBase + 0x24);
  StoreBe32(image.readOnly, 0x08, kTextBase + 0x28);
  StoreBe32(image.readOnly, 0x0C, kTextBase + 0x30);
  StoreBe32(image.readOnly, 0x10, kTextBase + 0x34);

  auto input = DefaultInput();
  input.functionSeeds.push_back({.range = {.start = kTextBase + 0x20, .end = kTextBase + 0x50},
                                 .authority = "PDATA",
                                 .trusted = true,
                                 .blocks = {{.start = kTextBase + 0x20, .end = kTextBase + 0x28},
                                            {.start = kTextBase + 0x28, .end = kTextBase + 0x50}},
                                 .labels = {kTextBase + 0x28, kTextBase + 0x30},
                                 .jumpTableTargets = {kTextBase + 0x30},
                                 .exceptionEntries = {kTextBase + 0x34}});

  auto report = AnalyzeEntrypointClosure(image.view(), std::move(input));
  CHECK(Candidate(report, kTextBase + 0x28).classification ==
        EntrypointClassification::CallableMidFunctionEntry);
  CHECK(Candidate(report, kTextBase + 0x30).classification ==
        EntrypointClassification::JumpTableCase);
  CHECK(Candidate(report, kTextBase + 0x34).classification ==
        EntrypointClassification::ExceptionLandingPad);
  CHECK(Candidate(report, kTextBase + 0x24).classification ==
        EntrypointClassification::RejectedOverlap);
}

TEST_CASE("entrypoint closure rejects invalid, out-of-range and overlapping candidates",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  StoreBe32(image.text, 0x40, 0x00000000);  // invalid
  StoreBe32(image.text, 0x60, Branch(kTextBase + 0x60, kTextBase + 0x6C));
  StoreBe32(image.text, 0x64, 0x4E800020);
  StoreBe32(image.text, 0x68, 0x4E800020);
  StoreBe32(image.text, 0x6C, 0x4E800020);
  StoreBe32(image.text, 0x70, 0x4E800020);
  auto input = DefaultInput();
  input.manualEvidence = {
      {.address = kTextBase + 0x40,
       .size = 4,
       .kinds = {EntrypointEvidenceKind::ManualVerified},
       .provenance = "synthetic invalid"},
      {.address = 0x30000000,
       .size = 4,
       .kinds = {EntrypointEvidenceKind::ManualVerified},
       .provenance = "synthetic out of range"},
      {.address = kTextBase + 0x60,
       .size = 0x0C,
       .kinds = {EntrypointEvidenceKind::ManualVerified},
       .provenance = "synthetic overlap"},
  };
  input.functionSeeds.push_back({.range = {.start = kTextBase + 0x68, .end = kTextBase + 0x74},
                                 .authority = "PDATA",
                                 .trusted = true,
                                 .blocks = {{.start = kTextBase + 0x68, .end = kTextBase + 0x74}}});

  auto report = AnalyzeEntrypointClosure(image.view(), std::move(input));
  CHECK(Candidate(report, kTextBase + 0x40).classification ==
        EntrypointClassification::RejectedNonCode);
  CHECK(Candidate(report, 0x30000000).classification ==
        EntrypointClassification::RejectedOutOfRange);
  CHECK(Candidate(report, kTextBase + 0x60).classification ==
        EntrypointClassification::RejectedOverlap);
}

TEST_CASE("entrypoint closure output is deterministic and reports safety limits",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  StoreBe32(image.text, 0x40, 0x60000000);
  StoreBe32(image.text, 0x44, 0x60000000);
  StoreBe32(image.text, 0x48, 0x60000000);
  StoreBe32(image.text, 0x4C, 0x4E800020);
  StoreBe32(image.readOnly, 0x00, kTextBase + 0x40);
  auto input = DefaultInput();
  input.limits.maxInstructionsPerCandidate = 2;

  const auto first = AnalyzeEntrypointClosure(image.view(), input);
  const auto second = AnalyzeEntrypointClosure(image.view(), input);
  CHECK(SerializeEntrypointClosureJson(first) == SerializeEntrypointClosureJson(second));
  CHECK_FALSE(first.limitDiagnostics.empty());
  CHECK(Candidate(first, kTextBase + 0x40).hitInstructionLimit);
}

TEST_CASE("entrypoint closure reports deterministic candidate truncation",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  for (uint32_t offset : {0x10u, 0x20u, 0x30u})
    StoreBe32(image.text, offset, 0x4E800020);
  auto input = DefaultInput();
  input.limits.maxCandidates = 2;
  input.manualEvidence = {
      {.address = kTextBase + 0x10,
       .size = 4,
       .kinds = {EntrypointEvidenceKind::ManualVerified},
       .provenance = "candidate one"},
      {.address = kTextBase + 0x20,
       .size = 4,
       .kinds = {EntrypointEvidenceKind::ManualVerified},
       .provenance = "candidate two"},
      {.address = kTextBase + 0x30,
       .size = 4,
       .kinds = {EntrypointEvidenceKind::ManualVerified},
       .provenance = "candidate three"},
  };

  auto report = AnalyzeEntrypointClosure(image.view(), std::move(input));
  CHECK(report.candidates.size() == 2);
  CHECK(report.candidates[0].address == kTextBase + 0x10);
  CHECK(report.candidates[1].address == kTextBase + 0x20);
  REQUIRE_FALSE(report.limitDiagnostics.empty());
  CHECK(report.limitDiagnostics[0].limit == "max_candidates");
}

TEST_CASE("entrypoint closure reports never mutate an unrelated manifest",
          "[codegen][entrypoint-closure]") {
  SyntheticImage image;
  StoreBe32(image.text, 0x40, 0x4E800020);
  StoreBe32(image.readOnly, 0x00, kTextBase + 0x40);
  auto report = AnalyzeEntrypointClosure(image.view(), DefaultInput());

  const fs::path directory = fs::temp_directory_path() / "rexglue-entrypoint-closure-report-test";
  fs::create_directories(directory);
  const fs::path manifest = directory / "synthetic_manifest.toml";
  const std::string sentinel = "[entrypoint.functions]\n";
  {
    std::ofstream output(manifest, std::ios::binary);
    output << sentinel;
  }
  auto result = WriteEntrypointClosureReports(report, {}, directory / "analysis");
  REQUIRE(result);
  {
    std::ifstream input(manifest, std::ios::binary);
    std::string after((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    CHECK(after == sentinel);
  }
  CHECK(fs::exists(directory / "analysis" / "entrypoint-closure.json"));
  fs::remove_all(directory);
}
