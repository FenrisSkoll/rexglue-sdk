#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <unordered_set>
#include <vector>

#include <rex/codegen/binary_view.h>
#include <rex/codegen/jump_table_recovery.h>
#include <rex/codegen/function_scanner.h>

#include "codegen/decoded_binary.h"

namespace {

using namespace rex::codegen;

constexpr uint32_t kTextBase = 0x10000000;
constexpr uint32_t kTableBase = 0x20000000;

void StoreBe32(std::vector<uint8_t>& bytes, uint32_t offset, uint32_t value) {
  REQUIRE(offset + 4 <= bytes.size());
  bytes[offset] = static_cast<uint8_t>(value >> 24);
  bytes[offset + 1] = static_cast<uint8_t>(value >> 16);
  bytes[offset + 2] = static_cast<uint8_t>(value >> 8);
  bytes[offset + 3] = static_cast<uint8_t>(value);
}

uint32_t Bc(uint32_t site, uint32_t target, uint8_t bo, uint8_t bi) {
  const int32_t displacement = static_cast<int32_t>(target - site);
  return 0x40000000u | (static_cast<uint32_t>(bo) << 21) | (static_cast<uint32_t>(bi) << 16) |
         (static_cast<uint32_t>(displacement) & 0x0000FFFCu);
}

uint32_t B(uint32_t site, uint32_t target) {
  const int32_t displacement = static_cast<int32_t>(target - site);
  return 0x48000000u | (static_cast<uint32_t>(displacement) & 0x03FFFFFCu);
}

uint32_t Addi(uint8_t rt, uint8_t ra, int16_t immediate) {
  return 0x38000000u | (static_cast<uint32_t>(rt) << 21) | (static_cast<uint32_t>(ra) << 16) |
         static_cast<uint16_t>(immediate);
}

uint32_t Rlwinm(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t mb, uint8_t me) {
  return 0x54000000u | (static_cast<uint32_t>(rs) << 21) | (static_cast<uint32_t>(ra) << 16) |
         (static_cast<uint32_t>(sh) << 11) | (static_cast<uint32_t>(mb) << 6) |
         (static_cast<uint32_t>(me) << 1);
}

uint32_t Srawi(uint8_t ra, uint8_t rs, uint8_t sh) {
  return 0x7C000670u | (static_cast<uint32_t>(rs) << 21) | (static_cast<uint32_t>(ra) << 16) |
         (static_cast<uint32_t>(sh) << 11);
}

uint32_t Lwzx(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C00002Eu | (static_cast<uint32_t>(rt) << 21) | (static_cast<uint32_t>(ra) << 16) |
         (static_cast<uint32_t>(rb) << 11);
}

uint32_t Lbzx(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C0000AEu | (static_cast<uint32_t>(rt) << 21) | (static_cast<uint32_t>(ra) << 16) |
         (static_cast<uint32_t>(rb) << 11);
}

uint32_t Lhzx(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C00022Eu | (static_cast<uint32_t>(rt) << 21) | (static_cast<uint32_t>(ra) << 16) |
         (static_cast<uint32_t>(rb) << 11);
}

uint32_t Ldx(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C00002Au | (static_cast<uint32_t>(rt) << 21) | (static_cast<uint32_t>(ra) << 16) |
         (static_cast<uint32_t>(rb) << 11);
}

uint32_t Add(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C000214u | (static_cast<uint32_t>(rt) << 21) | (static_cast<uint32_t>(ra) << 16) |
         (static_cast<uint32_t>(rb) << 11);
}

uint32_t Extsb(uint8_t ra, uint8_t rs) {
  return 0x7C000774u | (static_cast<uint32_t>(rs) << 21) | (static_cast<uint32_t>(ra) << 16);
}

uint32_t Extsh(uint8_t ra, uint8_t rs) {
  return 0x7C000734u | (static_cast<uint32_t>(rs) << 21) | (static_cast<uint32_t>(ra) << 16);
}

uint32_t Mr(uint8_t ra, uint8_t rs) {
  return 0x7C000378u | (static_cast<uint32_t>(rs) << 21) | (static_cast<uint32_t>(ra) << 16) |
         (static_cast<uint32_t>(rs) << 11);
}

uint32_t Bclr(uint8_t bo, uint8_t bi, bool link = false) {
  return 0x4C000020u | (static_cast<uint32_t>(bo) << 21) | (static_cast<uint32_t>(bi) << 16) |
         (link ? 1u : 0u);
}

uint32_t Mtctr(uint8_t rs) {
  return 0x7C0903A6u | (static_cast<uint32_t>(rs) << 21);
}

struct AbsoluteSwitch {
  std::vector<uint8_t> text = std::vector<uint8_t>(0x100, 0);
  std::vector<uint8_t> table = std::vector<uint8_t>(0x40, 0);

  AbsoluteSwitch() {
    for (uint32_t offset = 0; offset < text.size(); offset += 4)
      StoreBe32(text, offset, 0x60000000);  // nop, keep one executable region

    StoreBe32(text, 0x00, 0x28030002);                                  // cmplwi r3, 2
    StoreBe32(text, 0x04, Bc(kTextBase + 4, kTextBase + 0x30, 12, 1));  // bgt default
    StoreBe32(text, 0x08, 0x3C802000);                                  // lis r4, 0x2000
    StoreBe32(text, 0x0C, Rlwinm(3, 3, 2, 0, 29));                      // slwi r3, r3, 2
    StoreBe32(text, 0x10, Lwzx(5, 4, 3));
    StoreBe32(text, 0x14, Mtctr(5));
    StoreBe32(text, 0x18, 0x4E800420);  // bctr
    StoreBe32(text, 0x30, 0x4E800020);  // default: blr
    StoreBe32(text, 0x40, 0x4E800020);
    StoreBe32(text, 0x50, 0x4E800020);
    StoreBe32(text, 0x60, 0x4E800020);
    StoreBe32(table, 0x00, kTextBase + 0x40);
    StoreBe32(table, 0x04, kTextBase + 0x50);
    StoreBe32(table, 0x08, kTextBase + 0x60);
  }

  BinaryView view() const {
    const std::array sections{
        BinarySectionInput{.name = ".text",
                           .baseAddress = kTextBase,
                           .data = text,
                           .executable = true,
                           .readable = true},
        BinarySectionInput{
            .name = ".rdata", .baseAddress = kTableBase, .data = table, .readable = true},
    };
    return BinaryView::fromSections(kTextBase, 0x10000100, kTextBase, sections);
  }
};

IndirectSiteAnalysis Analyze(AbsoluteSwitch& image, uint32_t site = kTextBase + 0x18,
                             const JumpTable* manual = nullptr, JumpTableRecoveryLimits limits = {},
                             uint32_t blockSize = 0x80) {
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block block{kTextBase, blockSize};
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  JumpTableRecoveryInput input;
  input.site = site;
  input.ownerAddress = kTextBase;
  input.preliminaryBlocks = std::span<const Block>(&block, 1);
  input.containingRegion = region;
  input.manualTable = manual;
  input.limits = limits;
  return AnalyzeIndirectSite(decoded, input);
}

struct RelativeSwitch {
  std::vector<uint8_t> text = std::vector<uint8_t>(0x100, 0);
  std::vector<uint8_t> table = std::vector<uint8_t>(0x80, 0);
  uint32_t site = kTextBase + 0x28;

  RelativeSwitch(bool halfword = false, bool conditionalReturn = false) {
    for (uint32_t offset = 0; offset < text.size(); offset += 4)
      StoreBe32(text, offset, 0x60000000);
    StoreBe32(text, 0x00, conditionalReturn ? 0x28030003 : 0x28030002);
    if (conditionalReturn) {
      StoreBe32(text, 0x04, Bclr(4, 0));  // bgelr: return unless index < 3
    } else {
      StoreBe32(text, 0x04, Bc(kTextBase + 4, kTextBase + 0x34, 12, 1));
    }
    StoreBe32(text, 0x08, 0x3C802000);  // lis r4, table@h
    StoreBe32(text, 0x0C, 0x60840020);  // ori r4, r4, table@l
    if (halfword) {
      StoreBe32(text, 0x10, Rlwinm(3, 3, 1, 0, 30));
      StoreBe32(text, 0x14, Lhzx(5, 4, 3));
      StoreBe32(text, 0x18, Extsh(5, 5));
    } else {
      StoreBe32(text, 0x10, Lbzx(5, 4, 3));
      StoreBe32(text, 0x14, Extsb(5, 5));
      StoreBe32(text, 0x18, Rlwinm(5, 5, 2, 0, 29));
    }
    StoreBe32(text, 0x1C, 0x3CC01000);  // lis r6, text anchor
    StoreBe32(text, 0x20, Add(5, 6, 5));
    StoreBe32(text, 0x24, Mtctr(5));
    StoreBe32(text, 0x28, 0x4E800420);
    StoreBe32(text, 0x34, 0x4E800020);
    StoreBe32(text, 0x40, 0x4E800020);
    StoreBe32(text, 0x50, 0x4E800020);
    StoreBe32(text, 0x60, 0x4E800020);
    if (halfword) {
      StoreBe32(table, 0x20, 0x00400050);
      table[0x24] = 0x00;
      table[0x25] = 0x60;
    } else {
      table[0x20] = 0x10;
      table[0x21] = 0x14;
      table[0x22] = 0x18;
    }
  }

  BinaryView view() const {
    const std::array sections{
        BinarySectionInput{.name = ".text",
                           .baseAddress = kTextBase,
                           .data = text,
                           .executable = true,
                           .readable = true},
        BinarySectionInput{
            .name = ".rdata", .baseAddress = kTableBase, .data = table, .readable = true},
    };
    return BinaryView::fromSections(kTextBase, 0x10000100, kTextBase, sections);
  }
};

IndirectSiteAnalysis Analyze(RelativeSwitch& image) {
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block block{kTextBase, 0x80};
  JumpTableRecoveryInput input;
  input.site = image.site;
  input.ownerAddress = kTextBase;
  input.preliminaryBlocks = std::span<const Block>(&block, 1);
  input.containingRegion = decoded.regionContaining(kTextBase);
  return AnalyzeIndirectSite(decoded, input);
}

bool HasFailure(const IndirectSiteAnalysis& analysis, JumpTableFailure failure) {
  return std::find(analysis.failures.begin(), analysis.failures.end(), failure) !=
         analysis.failures.end();
}

std::string FailureNames(const IndirectSiteAnalysis& analysis) {
  std::string result;
  for (auto failure : analysis.failures) {
    if (!result.empty())
      result += ',';
    result += JumpTableFailureName(failure);
  }
  return result;
}

}  // namespace

TEST_CASE("jump-table recovery validates a bounded absolute Xenon switch",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  auto analysis = Analyze(image);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.classification == IndirectSiteClassification::SwitchBctr);
  CHECK(analysis.selectedTable->kind == JumpTableKind::AbsolutePointer);
  CHECK(analysis.selectedTable->tableAddress == kTableBase);
  CHECK(analysis.selectedTable->storageEnd == kTableBase + 12);
  CHECK(analysis.selectedTable->caseCount == 3);
  CHECK(analysis.selectedTable->boundValue == 2);
  CHECK(analysis.selectedTable->boundInclusive);
  CHECK(analysis.selectedTable->defaultTarget == kTextBase + 0x30);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
  CHECK(analysis.selectedTable->manualComparison == JumpTableManualComparison::NewAutomaticTable);
  REQUIRE_FALSE(analysis.evidence.empty());
  CHECK(analysis.evidence.front().rawInstruction == 0x4E800420);
}

TEST_CASE("jump-table recovery rejects a mixed-validity table as a whole",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.table, 0x08, kTextBase + 0x61);
  auto analysis = Analyze(image);
  CHECK_FALSE(analysis.selectedTable);
  CHECK(HasFailure(analysis, JumpTableFailure::MixedValidityTargets));
}

TEST_CASE("manual jump tables remain authoritative and are compared with automation",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  JumpTable manual;
  manual.bctrAddress = kTextBase + 0x18;
  manual.tableAddress = kTableBase;
  manual.targets = {kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60};
  auto analysis = Analyze(image, kTextBase + 0x18, &manual);
  REQUIRE(analysis.automaticTable);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->origin == JumpTableOrigin::Manual);
  CHECK(analysis.selectedTable->manualComparison == JumpTableManualComparison::ExactEquivalent);
}

TEST_CASE("manual comparison distinguishes bounds, target order and set containment",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  JumpTable manual;
  manual.bctrAddress = kTextBase + 0x18;
  manual.tableAddress = kTableBase;
  manual.targets = {kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60};
  manual.caseCount = 4;
  CHECK(Analyze(image, kTextBase + 0x18, &manual).selectedTable->manualComparison ==
        JumpTableManualComparison::ConflictingBounds);

  manual.caseCount = 0;
  manual.targets = {kTextBase + 0x50, kTextBase + 0x40, kTextBase + 0x60};
  CHECK(Analyze(image, kTextBase + 0x18, &manual).selectedTable->manualComparison ==
        JumpTableManualComparison::ConflictingTargets);

  manual.targets = {kTextBase + 0x40, kTextBase + 0x50};
  CHECK(Analyze(image, kTextBase + 0x18, &manual).selectedTable->manualComparison ==
        JumpTableManualComparison::AutomaticSuperset);

  manual.targets = {kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60, kTextBase + 0x70};
  CHECK(Analyze(image, kTextBase + 0x18, &manual).selectedTable->manualComparison ==
        JumpTableManualComparison::AutomaticSubset);
}

TEST_CASE("indirect-site classification excludes calls and returns from switches",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x18, 0x4E800421);  // bctrl
  auto callback = Analyze(image);
  CHECK(callback.classification == IndirectSiteClassification::VirtualOrCallbackBctrl);
  CHECK(HasFailure(callback, JumpTableFailure::NonSwitchIndirect));

  StoreBe32(image.text, 0x18, 0x4E800020);  // blr
  auto returning = Analyze(image);
  CHECK(returning.classification == IndirectSiteClassification::OrdinaryBlrReturn);
  CHECK(HasFailure(returning, JumpTableFailure::NonSwitchIndirect));
}

TEST_CASE("jump-table recovery reports a missing dominating bound", "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, 0x60000000);  // remove cmplwi
  StoreBe32(image.text, 0x04, 0x60000000);  // remove guard
  auto analysis = Analyze(image);
  CHECK_FALSE(analysis.selectedTable);
  CHECK(HasFailure(analysis, JumpTableFailure::MissingBound));
}

TEST_CASE("jump-table recovery reports unknown index and ambiguous bounds",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, 0x28070002);  // bound uses unrelated r7
  auto unknown = Analyze(image);
  CHECK_FALSE(unknown.selectedTable);
  CHECK(HasFailure(unknown, JumpTableFailure::UnknownIndex));

  image = AbsoluteSwitch{};
  StoreBe32(image.text, 0x00, 0x28030004);
  StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x30, 12, 1));
  StoreBe32(image.text, 0x08, 0x28030002);
  StoreBe32(image.text, 0x0C, Bc(kTextBase + 0x0C, kTextBase + 0x30, 12, 1));
  StoreBe32(image.text, 0x10, 0x3C802000);
  StoreBe32(image.text, 0x14, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x18, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x1C, Mtctr(5));
  StoreBe32(image.text, 0x20, 0x4E800420);
  auto ambiguous = Analyze(image, kTextBase + 0x20);
  CHECK_FALSE(ambiguous.selectedTable);
  CHECK(HasFailure(ambiguous, JumpTableFailure::AmbiguousBound));
}

TEST_CASE("jump-table recovery selects the bound on a normalized local index",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, 0x28030005);  // outer cmplwi r3, 5
  StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x34, 12, 1));
  StoreBe32(image.text, 0x08, Addi(3, 3, -3));
  StoreBe32(image.text, 0x0C, 0x28030002);  // normalized cmplwi r3, 2
  StoreBe32(image.text, 0x10, Bc(kTextBase + 0x10, kTextBase + 0x34, 12, 1));
  StoreBe32(image.text, 0x14, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x18, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x1C, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x20, Mtctr(5));
  StoreBe32(image.text, 0x24, 0x4E800420);  // bctr

  auto analysis = Analyze(image, kTextBase + 0x24);
  REQUIRE(analysis.selectedTable);
  CHECK_FALSE(HasFailure(analysis, JumpTableFailure::AmbiguousBound));
  CHECK(analysis.selectedTable->boundValue == 2);
  CHECK(analysis.selectedTable->caseCount == 3);
}

TEST_CASE("jump-table recovery coalesces exact-equivalent dominating bounds",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x34, 12, 1));
  StoreBe32(image.text, 0x08, 0x28030002);  // equivalent repeated guard
  StoreBe32(image.text, 0x0C, Bc(kTextBase + 0x0C, kTextBase + 0x34, 12, 1));
  StoreBe32(image.text, 0x10, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x14, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x18, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x1C, Mtctr(5));
  StoreBe32(image.text, 0x20, 0x4E800420);  // bctr

  auto analysis = Analyze(image, kTextBase + 0x20);
  REQUIRE(analysis.selectedTable);
  CHECK_FALSE(HasFailure(analysis, JumpTableFailure::AmbiguousBound));
  CHECK(analysis.selectedTable->caseCount == 3);
}

TEST_CASE("jump-table recovery reports target validation failures without accepting prefixes",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.table, 0x00, 0x30000000);
  auto outside = Analyze(image);
  INFO(FailureNames(outside));
  CHECK(HasFailure(outside, JumpTableFailure::TargetOutOfRange));
  CHECK_FALSE(outside.selectedTable);

  image = AbsoluteSwitch{};
  StoreBe32(image.table, 0x00, kTextBase + 0x41);
  auto unaligned = Analyze(image);
  INFO(FailureNames(unaligned));
  CHECK(HasFailure(unaligned, JumpTableFailure::TargetUnaligned));
  CHECK_FALSE(unaligned.selectedTable);
}

TEST_CASE("jump-table recovery reports unknown bases and invalid element widths",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x10, Add(5, 4, 3));
  auto noLoad = Analyze(image);
  CHECK(HasFailure(noLoad, JumpTableFailure::UnknownTableBase));

  image = AbsoluteSwitch{};
  CHECK(ppc::decode_instruction(kTextBase + 0x10, Ldx(5, 4, 3)).opcode == ppc::Opcode::ldx);
  StoreBe32(image.text, 0x10, Ldx(5, 4, 3));
  auto invalidWidth = Analyze(image);
  INFO(FailureNames(invalidWidth));
  CHECK(HasFailure(invalidWidth, JumpTableFailure::InvalidElementWidth));
}

TEST_CASE("jump-table recovery refuses byte offsets without a relative anchor",
          "[codegen][jump-table]") {
  RelativeSwitch image;
  StoreBe32(image.text, 0x1C, Mr(5, 5));
  auto analysis = Analyze(image);
  CHECK_FALSE(analysis.selectedTable);
  CHECK(HasFailure(analysis, JumpTableFailure::UnsupportedRelativeForm));
}

TEST_CASE("jump-table recovery follows register copies between bound and indexed load",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x0C, Mr(7, 3));
  StoreBe32(image.text, 0x10, Rlwinm(7, 7, 2, 0, 29));
  StoreBe32(image.text, 0x14, Lwzx(5, 4, 7));
  StoreBe32(image.text, 0x18, Mtctr(5));
  StoreBe32(image.text, 0x1C, 0x4E800420);
  auto analysis = Analyze(image, kTextBase + 0x1C);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->targets.size() == 3);
}

TEST_CASE("jump-table recovery matches equivalent index reloads by memory lineage",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, 0x80610020);  // lwz r3, 0x20(r1)
  StoreBe32(image.text, 0x04, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x08, Bc(kTextBase + 0x08, kTextBase + 0x30, 12, 1));
  StoreBe32(image.text, 0x0C, 0x3C802000);
  StoreBe32(image.text, 0x10, 0x80E10020);  // lwz r7, 0x20(r1)
  StoreBe32(image.text, 0x14, Rlwinm(7, 7, 2, 0, 29));
  StoreBe32(image.text, 0x18, Lwzx(5, 4, 7));
  StoreBe32(image.text, 0x1C, Mtctr(5));
  StoreBe32(image.text, 0x20, 0x4E800420);
  auto analysis = Analyze(image, kTextBase + 0x20);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->targets.size() == 3);
}

TEST_CASE("jump-table recovery preserves a bounded index defined by srawi",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x0C, 12, 2));
  StoreBe32(image.text, 0x04, 0x38600000);  // li r3, 0
  StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x10));
  StoreBe32(image.text, 0x0C, 0x38600020);  // li r3, 32
  StoreBe32(image.text, 0x10, Srawi(3, 3, 4));
  StoreBe32(image.text, 0x14, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x18, Bc(kTextBase + 0x18, kTextBase + 0x50, 12, 1));
  StoreBe32(image.text, 0x1C, Mr(7, 3));
  StoreBe32(image.text, 0x20, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x24, Rlwinm(7, 7, 2, 0, 29));
  StoreBe32(image.text, 0x28, Lwzx(5, 4, 7));
  StoreBe32(image.text, 0x2C, Mtctr(5));
  StoreBe32(image.text, 0x30, 0x60000000);  // nop
  StoreBe32(image.text, 0x34, 0x4E800420);  // bctr
  StoreBe32(image.text, 0x50, B(kTextBase + 0x50, kTextBase + 0x10));

  JumpTableRecoveryLimits limits;
  limits.maxStates = 16;
  auto analysis = Analyze(image, kTextBase + 0x34, nullptr, limits);
  CHECK_FALSE(HasFailure(analysis, JumpTableFailure::AnalysisLimit));
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->caseCount == 3);
  CHECK(analysis.selectedTable->tableAddress == kTableBase);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
  CHECK(std::any_of(analysis.selectedTable->evidence.begin(),
                    analysis.selectedTable->evidence.end(), [](const auto& evidence) {
                      return evidence.address == kTextBase + 0x10 &&
                             evidence.role == "reaching_definition";
                    }));
}

TEST_CASE("jump-table recovery accepts a delayed guard with preserved condition state",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  image.text.resize(0x200);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop
  StoreBe32(image.text, 0x00, 0x28030002);      // cmplwi r3, 2
  StoreBe32(image.text, 0x04, 0x100B61CB);      // stvx128 v64, r11, r12 (not Rc)
  StoreBe32(image.text, 0x08, 0x90C40000);      // stw r6, 0(r4)
  StoreBe32(image.text, 0x0C, 0x80E40004);      // lwz r7, 4(r4)
  StoreBe32(image.text, 0x10, 0x90E40004);      // stw r7, 4(r4)
  StoreBe32(image.text, 0x14, 0x81040008);      // lwz r8, 8(r4)
  StoreBe32(image.text, 0x18, 0x91040008);      // stw r8, 8(r4)
  StoreBe32(image.text, 0x1C, Bc(kTextBase + 0x1C, kTextBase + 0x1F0, 12, 1));
  StoreBe32(image.text, 0x150, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x154, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x158, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x15C, Mtctr(5));
  StoreBe32(image.text, 0x160, 0x4E800420);  // bctr
  StoreBe32(image.text, 0x180, 0x4E800020);  // blr
  StoreBe32(image.text, 0x190, 0x4E800020);  // blr
  StoreBe32(image.text, 0x1A0, 0x4E800020);  // blr
  StoreBe32(image.text, 0x1F0, 0x4E800020);  // default: blr
  StoreBe32(image.table, 0x00, kTextBase + 0x180);
  StoreBe32(image.table, 0x04, kTextBase + 0x190);
  StoreBe32(image.table, 0x08, kTextBase + 0x1A0);

  JumpTableRecoveryLimits truncatedLimits;
  truncatedLimits.maxBackwardInstructions = 64;
  auto truncated = Analyze(image, kTextBase + 0x160, nullptr, truncatedLimits, 0x200);
  CHECK_FALSE(truncated.selectedTable);
  CHECK(HasFailure(truncated, JumpTableFailure::AnalysisLimit));

  auto analysis = Analyze(image, kTextBase + 0x160, nullptr, {}, 0x200);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->caseCount == 3);
  CHECK(analysis.selectedTable->defaultTarget == kTextBase + 0x1F0);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x180, kTextBase + 0x190, kTextBase + 0x1A0});
}

TEST_CASE("case-expanded CFG limit retry requires an exact previously validated table",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  image.text.resize(0x200);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop
  StoreBe32(image.text, 0x00, 0x28030002);      // cmplwi r3, 2
  StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x1F0, 12, 1));
  StoreBe32(image.text, 0x150, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x154, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x158, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x15C, Mtctr(5));
  StoreBe32(image.text, 0x160, 0x4E800420);  // bctr
  StoreBe32(image.text, 0x180, 0x4E800020);
  StoreBe32(image.text, 0x190, 0x4E800020);
  StoreBe32(image.text, 0x1A0, 0x4E800020);
  StoreBe32(image.text, 0x1F0, 0x4E800020);  // default: blr
  StoreBe32(image.table, 0x00, kTextBase + 0x180);
  StoreBe32(image.table, 0x04, kTextBase + 0x190);
  StoreBe32(image.table, 0x08, kTextBase + 0x1A0);

  auto prior = Analyze(image, kTextBase + 0x160, nullptr, {}, 0x200);
  REQUIRE(prior.selectedTable);

  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block expandedBlock{kTextBase, 0x200};
  JumpTableRecoveryLimits truncatedLimits;
  truncatedLimits.maxBackwardInstructions = 64;
  JumpTableRecoveryInput input{
      .site = kTextBase + 0x160,
      .ownerAddress = kTextBase,
      .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
      .containingRegion = decoded.regionContaining(kTextBase),
      .priorAutomaticTable = &*prior.selectedTable,
      .limits = truncatedLimits,
  };

  auto truncated = AnalyzeIndirectSite(decoded, input);
  REQUIRE_FALSE(truncated.selectedTable);
  REQUIRE(HasFailure(truncated, JumpTableFailure::AnalysisLimit));

  JumpTableRecoveryStats acceptedStats;
  auto accepted = AnalyzeIndirectSiteWithPriorLimitRetry(decoded, input, &acceptedStats);
  REQUIRE(accepted.selectedTable);
  CHECK(accepted.selectedTable->targets == prior.selectedTable->targets);
  CHECK(accepted.selectedTable->rawEntries.size() == prior.selectedTable->rawEntries.size());
  CHECK(accepted.selectedTable->confidence == "validated_after_expanded_cfg_limit_retry");
  CHECK(acceptedStats.indirectSites == 1);
  CHECK(acceptedStats.recoveredTables == 1);
  CHECK(acceptedStats.unresolvedSites == 0);

  JumpTable mismatchedPrior = *prior.selectedTable;
  mismatchedPrior.rawEntries[0].target += 4;
  input.priorAutomaticTable = &mismatchedPrior;
  JumpTableRecoveryStats rejectedStats;
  auto rejected = AnalyzeIndirectSiteWithPriorLimitRetry(decoded, input, &rejectedStats);
  CHECK_FALSE(rejected.selectedTable);
  CHECK(HasFailure(rejected, JumpTableFailure::AnalysisLimit));
  CHECK(rejectedStats.indirectSites == 1);
  CHECK(rejectedStats.recoveredTables == 0);
  CHECK(rejectedStats.unresolvedSites == 1);
}

TEST_CASE("jump-table recovery uses an exact transformed index despite ambiguous live-ins",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x0C, 12, 2));
  StoreBe32(image.text, 0x04, 0x38600000);  // li r3, 0
  StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x10));
  StoreBe32(image.text, 0x0C, 0x38600002);               // li r3, 2
  StoreBe32(image.text, 0x10, Rlwinm(8, 3, 31, 1, 31));  // local transformed index
  StoreBe32(image.text, 0x14, 0x28080002);               // cmplwi r8, 2
  StoreBe32(image.text, 0x18, Bc(kTextBase + 0x18, kTextBase + 0x30, 12, 1));
  StoreBe32(image.text, 0x1C, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x20, Rlwinm(8, 8, 2, 0, 29));
  StoreBe32(image.text, 0x24, Lwzx(5, 4, 8));
  StoreBe32(image.text, 0x28, Mtctr(5));
  StoreBe32(image.text, 0x2C, 0x4E800420);  // bctr

  auto analysis = Analyze(image, kTextBase + 0x2C);
  REQUIRE(analysis.selectedTable);
  CHECK_FALSE(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
  CHECK(analysis.selectedTable->caseCount == 3);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
}

TEST_CASE("jump-table recovery reports ambiguous CFG reaching definitions",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x10, 12, 2));
  StoreBe32(image.text, 0x04, 0x3C802000);  // path A table base
  StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x14));
  StoreBe32(image.text, 0x10, 0x3C802001);  // path B conflicting table base
  StoreBe32(image.text, 0x14, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x18, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x1C, Mtctr(5));
  StoreBe32(image.text, 0x20, 0x4E800420);
  auto analysis = Analyze(image, kTextBase + 0x20);
  CHECK_FALSE(analysis.selectedTable);
  CHECK(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
}

TEST_CASE("jump-table recovery decodes signed byte relative offsets and scaling",
          "[codegen][jump-table]") {
  RelativeSwitch image;
  auto analysis = Analyze(image);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->kind == JumpTableKind::RelativeOffset);
  CHECK(analysis.selectedTable->elementWidth == 1);
  CHECK(analysis.selectedTable->elementSigned);
  CHECK(analysis.selectedTable->targetScale == 4);
  CHECK(analysis.selectedTable->anchorAddress == kTextBase);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
}

TEST_CASE("jump-table recovery folds a nested lis/addi relative anchor", "[codegen][jump-table]") {
  RelativeSwitch image;
  StoreBe32(image.text, 0x04, Bc(kTextBase + 4, kTextBase + 0x38, 12, 1));
  StoreBe32(image.text, 0x1C, 0x3CC01000);  // lis r6, anchor@ha
  StoreBe32(image.text, 0x20, 0x38C60040);  // addi r6, r6, anchor@l
  StoreBe32(image.text, 0x24, Add(5, 6, 5));
  StoreBe32(image.text, 0x28, Mtctr(5));
  StoreBe32(image.text, 0x2C, 0x4E800420);
  StoreBe32(image.text, 0x38, 0x4E800020);
  image.site = kTextBase + 0x2C;
  image.table[0x20] = 0;
  image.table[0x21] = 4;
  image.table[0x22] = 8;
  auto analysis = Analyze(image);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->anchorAddress == kTextBase + 0x40);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
}

TEST_CASE("jump-table recovery decodes signed halfword relative offsets", "[codegen][jump-table]") {
  RelativeSwitch image(true);
  auto analysis = Analyze(image);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->elementWidth == 2);
  CHECK(analysis.selectedTable->elementSigned);
  CHECK(analysis.selectedTable->targetScale == 1);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
}

TEST_CASE("jump-table recovery accepts compare plus conditional-return default",
          "[codegen][jump-table]") {
  RelativeSwitch image(true, true);
  auto analysis = Analyze(image);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->caseCount == 3);
  CHECK_FALSE(analysis.selectedTable->boundInclusive);
  CHECK(analysis.selectedTable->defaultIsReturn);
  CHECK(analysis.selectedTable->defaultTarget == 0);
}

TEST_CASE("jump-table recovery evaluates two-level relative tables", "[codegen][jump-table]") {
  RelativeSwitch image;
  StoreBe32(image.text, 0x08, 0x3C802000);
  StoreBe32(image.text, 0x0C, 0x60840000);
  StoreBe32(image.text, 0x10, Lbzx(5, 4, 3));
  StoreBe32(image.text, 0x14, 0x3CC02000);
  StoreBe32(image.text, 0x18, 0x60C60020);
  StoreBe32(image.text, 0x1C, Lhzx(5, 6, 5));
  StoreBe32(image.text, 0x20, 0x3CC01000);
  StoreBe32(image.text, 0x24, Add(5, 6, 5));
  StoreBe32(image.text, 0x28, Mtctr(5));
  StoreBe32(image.text, 0x2C, 0x4E800420);
  image.site = kTextBase + 0x2C;
  image.table[0] = 0;
  image.table[1] = 2;
  image.table[2] = 4;
  image.table[0x20] = 0;
  image.table[0x21] = 0x40;
  image.table[0x22] = 0;
  image.table[0x23] = 0x50;
  image.table[0x24] = 0;
  image.table[0x25] = 0x60;
  auto analysis = Analyze(image);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->tableAddress == kTableBase);
  CHECK(analysis.selectedTable->elementWidth == 1);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
}

TEST_CASE("jump-table recovery accepts inline executable table storage", "[codegen][jump-table]") {
  AbsoluteSwitch image;
  std::vector<uint8_t> text(0x140);
  for (uint32_t offset = 0; offset < text.size(); offset += 4)
    StoreBe32(text, offset, 0x60000000);
  std::copy(image.text.begin(), image.text.end(), text.begin());
  StoreBe32(text, 0x08, 0x3C801000);
  StoreBe32(text, 0x0C, 0x60840080);
  StoreBe32(text, 0x10, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(text, 0x14, Lwzx(5, 4, 3));
  StoreBe32(text, 0x18, Mtctr(5));
  StoreBe32(text, 0x1C, 0x4E800420);
  StoreBe32(text, 0x80, kTextBase + 0x40);
  StoreBe32(text, 0x84, kTextBase + 0x50);
  StoreBe32(text, 0x88, kTextBase + 0x60);
  const std::array sections{BinarySectionInput{.name = ".text",
                                               .baseAddress = kTextBase,
                                               .data = text,
                                               .executable = true,
                                               .readable = true}};
  auto view = BinaryView::fromSections(kTextBase, 0x140, kTextBase, sections);
  DecodedBinary decoded(view);
  decoded.decode();
  const Block block{kTextBase, 0x70};
  JumpTableRecoveryInput input{.site = kTextBase + 0x1C,
                               .ownerAddress = kTextBase,
                               .preliminaryBlocks = std::span<const Block>(&block, 1),
                               .containingRegion = decoded.regionContaining(kTextBase),
                               .limits = {}};
  auto analysis = AnalyzeIndirectSite(decoded, input);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.selectedTable->tableAddress == kTextBase + 0x80);
  CHECK(analysis.selectedTable->tableInExecutableSection);
}

TEST_CASE("jump-table recovery preserves overlapping and shared table storage",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x80, 0x28030001);  // cmplwi r3, 1
  StoreBe32(image.text, 0x84, Bc(kTextBase + 0x84, kTextBase + 0xB0, 12, 1));
  StoreBe32(image.text, 0x88, 0x3C802000);
  StoreBe32(image.text, 0x8C, 0x60840004);  // start at the second shared entry
  StoreBe32(image.text, 0x90, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x94, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x98, Mtctr(5));
  StoreBe32(image.text, 0x9C, 0x4E800420);
  StoreBe32(image.text, 0xB0, 0x4E800020);

  auto first = Analyze(image);
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block secondBlock{kTextBase + 0x80, 0x34};
  JumpTableRecoveryInput input{.site = kTextBase + 0x9C,
                               .ownerAddress = kTextBase + 0x80,
                               .preliminaryBlocks = std::span<const Block>(&secondBlock, 1),
                               .containingRegion = decoded.regionContaining(kTextBase + 0x80),
                               .limits = {}};
  auto second = AnalyzeIndirectSite(decoded, input);
  REQUIRE(first.selectedTable);
  REQUIRE(second.selectedTable);
  CHECK(first.selectedTable->tableAddress == kTableBase);
  CHECK(second.selectedTable->tableAddress == kTableBase + 4);
  CHECK(first.selectedTable->storageEnd > second.selectedTable->tableAddress);
  CHECK(second.selectedTable->targets == std::vector<uint32_t>{kTextBase + 0x50, kTextBase + 0x60});
}

TEST_CASE("jump-table recovery reports an analysis safety limit", "[codegen][jump-table]") {
  AbsoluteSwitch image;
  JumpTableRecoveryLimits limits;
  limits.maxStates = 2;
  auto analysis = Analyze(image, kTextBase + 0x18, nullptr, limits);
  CHECK_FALSE(analysis.selectedTable);
  CHECK(HasFailure(analysis, JumpTableFailure::AnalysisLimit));
}

TEST_CASE("jump-table recovery accepts an exact local addi index after ambiguous live-ins",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x0C, 4, 2));
  StoreBe32(image.text, 0x04, Addi(6, 0, 7));
  StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x10));
  StoreBe32(image.text, 0x0C, Addi(6, 0, 9));
  StoreBe32(image.text, 0x10, Addi(3, 6, -1));
  StoreBe32(image.text, 0x14, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x18, Bc(kTextBase + 0x18, kTextBase + 0x34, 12, 1));
  StoreBe32(image.text, 0x1C, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x20, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x24, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x28, Mtctr(5));
  StoreBe32(image.text, 0x2C, 0x4E800420);  // bctr

  auto analysis = Analyze(image, kTextBase + 0x2C);
  REQUIRE(analysis.selectedTable);
  CHECK_FALSE(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
  CHECK(analysis.selectedTable->indexRegister == 3);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
}

TEST_CASE("jump-table recovery accepts an exact local loaded index after ambiguous bases",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x0C, 4, 2));
  StoreBe32(image.text, 0x04, Addi(6, 0, 7));
  StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x10));
  StoreBe32(image.text, 0x0C, Addi(6, 0, 9));
  StoreBe32(image.text, 0x10, 0x88660000);  // lbz r3, 0(r6)
  StoreBe32(image.text, 0x14, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x18, Bc(kTextBase + 0x18, kTextBase + 0x34, 12, 1));
  StoreBe32(image.text, 0x1C, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x20, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x24, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x28, Mtctr(5));
  StoreBe32(image.text, 0x2C, 0x4E800420);  // bctr

  auto analysis = Analyze(image, kTextBase + 0x2C);
  REQUIRE(analysis.selectedTable);
  CHECK_FALSE(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
  CHECK(analysis.selectedTable->indexRegister == 3);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
}

TEST_CASE("local index fallbacks preserve incomplete prior-case paths",
          "[codegen][jump-table]") {
  auto analyze = [](bool loadedIndex) {
    AbsoluteSwitch image;
    StoreBe32(image.text, 0x00, Addi(6, 0, 7));
    StoreBe32(image.text, 0x04, B(kTextBase + 0x04, kTextBase + 0x14));
    StoreBe32(image.text, 0x10, B(kTextBase + 0x10, kTextBase + 0x14));
    StoreBe32(image.text, 0x14,
              loadedIndex ? 0x88660000 : Addi(3, 6, -1));  // lbz/addi r3, ...r6
    StoreBe32(image.text, 0x18, 0x28030002);                // cmplwi r3, 2
    StoreBe32(image.text, 0x1C, Bc(kTextBase + 0x1C, kTextBase + 0x38, 12, 1));
    StoreBe32(image.text, 0x20, 0x3C802000);  // lis r4, table@h
    StoreBe32(image.text, 0x24, Rlwinm(3, 3, 2, 0, 29));
    StoreBe32(image.text, 0x28, Lwzx(5, 4, 3));
    StoreBe32(image.text, 0x2C, Mtctr(5));
    StoreBe32(image.text, 0x30, 0x4E800420);  // bctr

    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const std::array blocks{Block{kTextBase, 0x08}, Block{kTextBase + 0x10, 0x04},
                            Block{kTextBase + 0x14, 0x20}};
    JumpTable prior;
    prior.origin = JumpTableOrigin::Automatic;
    prior.targets = {kTextBase + 0x10};
    JumpTableRecoveryInput input{.site = kTextBase + 0x30,
                                 .ownerAddress = kTextBase,
                                 .preliminaryBlocks = blocks,
                                 .containingRegion = decoded.regionContaining(kTextBase),
                                 .priorAutomaticTable = &prior,
                                 .limits = {}};
    return AnalyzeIndirectSite(decoded, input);
  };

  for (bool loadedIndex : {false, true}) {
    auto analysis = analyze(loadedIndex);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.incompleteCaseEntryPaths);
    CHECK(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
  }
}

TEST_CASE("jump-table recovery does not equate different local index definitions",
          "[codegen][jump-table]") {
  SECTION("addi") {
    AbsoluteSwitch image;
    StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x0C, 4, 2));
    StoreBe32(image.text, 0x04, Addi(6, 0, 7));
    StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x10));
    StoreBe32(image.text, 0x0C, Addi(6, 0, 9));
    StoreBe32(image.text, 0x10, Addi(3, 6, -1));
    StoreBe32(image.text, 0x14, 0x28030002);  // cmplwi r3, 2
    StoreBe32(image.text, 0x18, Bc(kTextBase + 0x18, kTextBase + 0x38, 12, 1));
    StoreBe32(image.text, 0x1C, Addi(7, 6, -2));  // different local transform
    StoreBe32(image.text, 0x20, 0x3C802000);      // lis r4, table@h
    StoreBe32(image.text, 0x24, Rlwinm(7, 7, 2, 0, 29));
    StoreBe32(image.text, 0x28, Lwzx(5, 4, 7));
    StoreBe32(image.text, 0x2C, Mtctr(5));
    StoreBe32(image.text, 0x30, 0x4E800420);  // bctr

    auto analysis = Analyze(image, kTextBase + 0x30);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::UnknownIndex));
  }

  SECTION("load") {
    AbsoluteSwitch image;
    StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x0C, 4, 2));
    StoreBe32(image.text, 0x04, Addi(6, 0, 7));
    StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x10));
    StoreBe32(image.text, 0x0C, Addi(6, 0, 9));
    StoreBe32(image.text, 0x10, 0x88660000);  // lbz r3, 0(r6)
    StoreBe32(image.text, 0x14, 0x28030002);  // cmplwi r3, 2
    StoreBe32(image.text, 0x18, Bc(kTextBase + 0x18, kTextBase + 0x38, 12, 1));
    StoreBe32(image.text, 0x1C, 0x88E60001);  // different local load address
    StoreBe32(image.text, 0x20, 0x3C802000);  // lis r4, table@h
    StoreBe32(image.text, 0x24, Rlwinm(7, 7, 2, 0, 29));
    StoreBe32(image.text, 0x28, Lwzx(5, 4, 7));
    StoreBe32(image.text, 0x2C, Mtctr(5));
    StoreBe32(image.text, 0x30, 0x4E800420);  // bctr

    auto analysis = Analyze(image, kTextBase + 0x30);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::UnknownIndex));
  }
}

TEST_CASE("block discovery expands recovered switch cases before final boundaries",
          "[codegen][jump-table][integration]") {
  AbsoluteSwitch image;
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const std::unordered_set<uint32_t> functions{kTextBase};

  auto result = discoverBlocks(decoded, kTextBase, *region, functions, 0x1C);
  REQUIRE(result.jumpTables.size() == 1);
  CHECK(result.jumpTableRecovery.fixpointIterations == 2);
  CHECK(result.jumpTableRecovery.recoveredTables == 1);
  CHECK(result.labels.contains(kTextBase + 0x40));
  CHECK(result.labels.contains(kTextBase + 0x50));
  CHECK(result.labels.contains(kTextBase + 0x60));
  CHECK(std::any_of(result.blocks.begin(), result.blocks.end(),
                    [](const Block& block) { return block.contains(kTextBase + 0x60); }));
}

TEST_CASE("case expansion exposes and recovers another indirect site at fixpoint",
          "[codegen][jump-table][integration]") {
  AbsoluteSwitch image;
  StoreBe32(image.table, 0x00, kTextBase + 0x40);
  StoreBe32(image.table, 0x04, kTextBase + 0x70);
  StoreBe32(image.table, 0x08, kTextBase + 0x78);
  StoreBe32(image.table, 0x10, kTextBase + 0x90);
  StoreBe32(image.table, 0x14, kTextBase + 0xA0);
  StoreBe32(image.text, 0x40, 0x28080001);  // cmplwi r8, 1
  StoreBe32(image.text, 0x44, Bc(kTextBase + 0x44, kTextBase + 0x78, 12, 1));
  StoreBe32(image.text, 0x48, 0x3D202000);  // lis r9, 0x2000
  StoreBe32(image.text, 0x4C, 0x61290010);  // ori r9, r9, 0x10
  StoreBe32(image.text, 0x50, Rlwinm(8, 8, 2, 0, 29));
  StoreBe32(image.text, 0x54, Lwzx(10, 9, 8));
  StoreBe32(image.text, 0x58, Mtctr(10));
  StoreBe32(image.text, 0x5C, 0x4E800420);
  StoreBe32(image.text, 0x70, 0x4E800020);
  StoreBe32(image.text, 0x78, 0x4E800020);
  StoreBe32(image.text, 0x90, 0x4E800020);
  StoreBe32(image.text, 0xA0, 0x4E800020);

  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const std::unordered_set<uint32_t> functions{kTextBase};
  auto result = discoverBlocks(decoded, kTextBase, *region, functions, 0x1C);
  CHECK(result.jumpTableRecovery.fixpointIterations == 3);
  CHECK(result.jumpTableRecovery.recoveredTables == 2);
  CHECK(result.jumpTables.size() == 2);
  CHECK(result.labels.contains(kTextBase + 0x90));
  CHECK(result.labels.contains(kTextBase + 0xA0));
}

TEST_CASE("case expansion preserves a switch with an equivalent guarded loop",
          "[codegen][jump-table][integration]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, 0x80660000);  // lwz r3, 0(r6)
  StoreBe32(image.text, 0x04, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x08, Bc(kTextBase + 0x08, kTextBase + 0x30, 12, 1));
  StoreBe32(image.text, 0x0C, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x10, Mr(7, 3));
  StoreBe32(image.text, 0x14, Rlwinm(7, 7, 2, 0, 29));
  StoreBe32(image.text, 0x18, Lwzx(5, 4, 7));
  StoreBe32(image.text, 0x1C, Mtctr(5));
  StoreBe32(image.text, 0x20, 0x4E800420);  // bctr
  StoreBe32(image.text, 0x40, 0x80660000);  // lwz r3, 0(r6)
  StoreBe32(image.text, 0x44, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x48, Bc(kTextBase + 0x48, kTextBase + 0x30, 12, 1));
  StoreBe32(image.text, 0x4C, B(kTextBase + 0x4C, kTextBase + 0x0C));

  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const std::unordered_set<uint32_t> functions{kTextBase};
  auto result = discoverBlocks(decoded, kTextBase, *region, functions, 0x80);
  auto dispatch = std::find_if(result.indirectSites.begin(), result.indirectSites.end(),
                               [](const auto& site) { return site.site == kTextBase + 0x20; });
  REQUIRE(dispatch != result.indirectSites.end());
  CHECK_FALSE(HasFailure(*dispatch, JumpTableFailure::AmbiguousReachingDefinition));
  CHECK_FALSE(HasFailure(*dispatch, JumpTableFailure::AmbiguousBound));
  CHECK_FALSE(HasFailure(*dispatch, JumpTableFailure::MissingBound));
  REQUIRE(result.jumpTables.size() == 1);
  CHECK(result.jumpTableRecovery.fixpointIterations == 2);
  CHECK(result.jumpTableRecovery.recoveredTables == 1);
  CHECK(result.jumpTables[0].targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
}

TEST_CASE("independent callable evidence keeps a case as a separate function entry",
          "[codegen][jump-table][integration]") {
  AbsoluteSwitch image;
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const std::unordered_set<uint32_t> functions{kTextBase, kTextBase + 0x50};
  auto result = discoverBlocks(decoded, kTextBase, *region, functions, 0x1C);
  REQUIRE(result.jumpTables.size() == 1);
  CHECK(std::find(result.jumpTables[0].targets.begin(), result.jumpTables[0].targets.end(),
                  kTextBase + 0x50) != result.jumpTables[0].targets.end());
  CHECK_FALSE(std::any_of(result.blocks.begin(), result.blocks.end(),
                          [](const Block& block) { return block.contains(kTextBase + 0x50); }));
}

TEST_CASE("a table invalidated by expanded CFG is quarantined instead of oscillating",
          "[codegen][jump-table][integration]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x40, 0x38A00000);  // li r5, 0: conflict with table load
  StoreBe32(image.text, 0x44, B(kTextBase + 0x44, kTextBase + 0x14));
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const std::unordered_set<uint32_t> functions{kTextBase};
  auto result = discoverBlocks(decoded, kTextBase, *region, functions, 0x1C);
  CHECK(result.jumpTables.empty());
  auto dispatch = std::find_if(result.indirectSites.begin(), result.indirectSites.end(),
                               [](const auto& site) { return site.site == kTextBase + 0x18; });
  REQUIRE(dispatch != result.indirectSites.end());
  CHECK_FALSE(dispatch->selectedTable);
  CHECK(HasFailure(*dispatch, JumpTableFailure::AmbiguousReachingDefinition));
  CHECK_FALSE(result.jumpTableRecovery.analysisLimitHit);
}
