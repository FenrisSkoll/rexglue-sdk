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
  return 0x40000000u | (static_cast<uint32_t>(bo) << 21) |
         (static_cast<uint32_t>(bi) << 16) |
         (static_cast<uint32_t>(displacement) & 0x0000FFFCu);
}

uint32_t Rlwinm(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t mb, uint8_t me) {
  return 0x54000000u | (static_cast<uint32_t>(rs) << 21) |
         (static_cast<uint32_t>(ra) << 16) | (static_cast<uint32_t>(sh) << 11) |
         (static_cast<uint32_t>(mb) << 6) | (static_cast<uint32_t>(me) << 1);
}

uint32_t Lwzx(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C00002Eu | (static_cast<uint32_t>(rt) << 21) |
         (static_cast<uint32_t>(ra) << 16) | (static_cast<uint32_t>(rb) << 11);
}

uint32_t Lbzx(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C0000AEu | (static_cast<uint32_t>(rt) << 21) |
         (static_cast<uint32_t>(ra) << 16) | (static_cast<uint32_t>(rb) << 11);
}

uint32_t Lhzx(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C00022Eu | (static_cast<uint32_t>(rt) << 21) |
         (static_cast<uint32_t>(ra) << 16) | (static_cast<uint32_t>(rb) << 11);
}

uint32_t Add(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C000214u | (static_cast<uint32_t>(rt) << 21) |
         (static_cast<uint32_t>(ra) << 16) | (static_cast<uint32_t>(rb) << 11);
}

uint32_t Extsb(uint8_t ra, uint8_t rs) {
  return 0x7C000774u | (static_cast<uint32_t>(rs) << 21) |
         (static_cast<uint32_t>(ra) << 16);
}

uint32_t Extsh(uint8_t ra, uint8_t rs) {
  return 0x7C000734u | (static_cast<uint32_t>(rs) << 21) |
         (static_cast<uint32_t>(ra) << 16);
}

uint32_t Mr(uint8_t ra, uint8_t rs) {
  return 0x7C000378u | (static_cast<uint32_t>(rs) << 21) |
         (static_cast<uint32_t>(ra) << 16) | (static_cast<uint32_t>(rs) << 11);
}

uint32_t Bclr(uint8_t bo, uint8_t bi, bool link = false) {
  return 0x4C000020u | (static_cast<uint32_t>(bo) << 21) |
         (static_cast<uint32_t>(bi) << 16) | (link ? 1u : 0u);
}

uint32_t Mtctr(uint8_t rs) { return 0x7C0903A6u | (static_cast<uint32_t>(rs) << 21); }

struct AbsoluteSwitch {
  std::vector<uint8_t> text = std::vector<uint8_t>(0x100, 0);
  std::vector<uint8_t> table = std::vector<uint8_t>(0x40, 0);

  AbsoluteSwitch() {
    for (uint32_t offset = 0; offset < text.size(); offset += 4)
      StoreBe32(text, offset, 0x60000000);  // nop, keep one executable region

    StoreBe32(text, 0x00, 0x28030002);  // cmplwi r3, 2
    StoreBe32(text, 0x04, Bc(kTextBase + 4, kTextBase + 0x30, 12, 1));  // bgt default
    StoreBe32(text, 0x08, 0x3C802000);  // lis r4, 0x2000
    StoreBe32(text, 0x0C, Rlwinm(3, 3, 2, 0, 29));  // slwi r3, r3, 2
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
        BinarySectionInput{.name = ".rdata",
                           .baseAddress = kTableBase,
                           .data = table,
                           .readable = true},
    };
    return BinaryView::fromSections(kTextBase, 0x10000100, kTextBase, sections);
  }
};

IndirectSiteAnalysis Analyze(AbsoluteSwitch& image, uint32_t site = kTextBase + 0x18,
                             const JumpTable* manual = nullptr,
                             JumpTableRecoveryLimits limits = {}) {
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block block{kTextBase, 0x80};
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
        BinarySectionInput{.name = ".rdata",
                           .baseAddress = kTableBase,
                           .data = table,
                           .readable = true},
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
  CHECK(analysis.selectedTable->manualComparison ==
        JumpTableManualComparison::NewAutomaticTable);
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
  CHECK(analysis.selectedTable->manualComparison ==
        JumpTableManualComparison::ExactEquivalent);
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

TEST_CASE("jump-table recovery decodes signed halfword relative offsets",
          "[codegen][jump-table]") {
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

TEST_CASE("jump-table recovery reports an analysis safety limit", "[codegen][jump-table]") {
  AbsoluteSwitch image;
  JumpTableRecoveryLimits limits;
  limits.maxStates = 2;
  auto analysis = Analyze(image, kTextBase + 0x18, nullptr, limits);
  CHECK_FALSE(analysis.selectedTable);
  CHECK(HasFailure(analysis, JumpTableFailure::AnalysisLimit));
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
