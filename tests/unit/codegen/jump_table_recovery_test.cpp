#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <rex/codegen/binary_view.h>
#include <rex/codegen/codegen_context.h>
#include <rex/codegen/config.h>
#include <rex/codegen/jump_table_recovery.h>
#include <rex/codegen/function_scanner.h>
#include <rex/codegen/phases.h>

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

void StoreBe16(std::vector<uint8_t>& bytes, uint32_t offset, uint16_t value) {
  REQUIRE(offset + 2 <= bytes.size());
  bytes[offset] = static_cast<uint8_t>(value >> 8);
  bytes[offset + 1] = static_cast<uint8_t>(value);
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

uint32_t Bl(uint32_t site, uint32_t target) {
  return B(site, target) | 1u;
}

uint32_t Addi(uint8_t rt, uint8_t ra, int16_t immediate) {
  return 0x38000000u | (static_cast<uint32_t>(rt) << 21) | (static_cast<uint32_t>(ra) << 16) |
         static_cast<uint16_t>(immediate);
}

uint32_t Lwz(uint8_t rt, uint8_t ra, int16_t displacement) {
  return 0x80000000u | (static_cast<uint32_t>(rt) << 21) | (static_cast<uint32_t>(ra) << 16) |
         static_cast<uint16_t>(displacement);
}

uint32_t Stw(uint8_t rs, uint8_t ra, int16_t displacement) {
  return 0x90000000u | (static_cast<uint32_t>(rs) << 21) | (static_cast<uint32_t>(ra) << 16) |
         static_cast<uint16_t>(displacement);
}

uint32_t Rlwinm(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t mb, uint8_t me) {
  return 0x54000000u | (static_cast<uint32_t>(rs) << 21) | (static_cast<uint32_t>(ra) << 16) |
         (static_cast<uint32_t>(sh) << 11) | (static_cast<uint32_t>(mb) << 6) |
         (static_cast<uint32_t>(me) << 1);
}

uint32_t Rlwimi(uint8_t ra, uint8_t rs, uint8_t sh, uint8_t mb, uint8_t me) {
  return 0x50000000u | (static_cast<uint32_t>(rs) << 21) | (static_cast<uint32_t>(ra) << 16) |
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

uint32_t Lhax(uint8_t rt, uint8_t ra, uint8_t rb) {
  return 0x7C0002AEu | (static_cast<uint32_t>(rt) << 21) | (static_cast<uint32_t>(ra) << 16) |
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

struct InlineAbsoluteSwitch {
  std::vector<uint8_t> text = std::vector<uint8_t>(0x180, 0);
  uint32_t site = kTextBase + 0x2C;
  uint32_t tableBase = kTextBase + 0x30;
  uint32_t ownerEnd = kTextBase + 0x140;
  std::vector<uint32_t> expectedTargets{
      kTextBase + 0x5C, kTextBase + 0x80, kTextBase + 0x90, kTextBase + 0xA0,
      kTextBase + 0xA0, kTextBase + 0x70, kTextBase + 0xA0, kTextBase + 0xA0,
      kTextBase + 0xA0, kTextBase + 0xA0, kTextBase + 0x64,
  };

  InlineAbsoluteSwitch() {
    for (uint32_t offset = 0; offset < text.size(); offset += 4)
      StoreBe32(text, offset, 0x60000000);  // nop

    // Match the structural form at TU1 0x82B951A4. The record-derived value
    // is deliberately not statically enumerable; the table extent is instead
    // proven by its exact inline layout without using a runtime target.
    StoreBe32(text, 0x00, Rlwinm(11, 20, 1, 0, 30));
    StoreBe32(text, 0x04, Add(11, 20, 11));
    StoreBe32(text, 0x08, Rlwinm(11, 11, 2, 0, 29));
    StoreBe32(text, 0x0C, Add(8, 11, 19));
    StoreBe32(text, 0x10, Lwzx(11, 11, 19));
    StoreBe32(text, 0x14, Addi(9, 11, -1));
    StoreBe32(text, 0x18, 0x3D801000);  // lis r12, text@h
    StoreBe32(text, 0x1C, Addi(12, 12, 0x30));
    StoreBe32(text, 0x20, Rlwinm(0, 9, 2, 0, 29));
    StoreBe32(text, 0x24, Lwzx(0, 12, 0));
    StoreBe32(text, 0x28, Mtctr(0));
    StoreBe32(text, 0x2C, 0x4E800420);  // bctr, with no fallthrough edge

    for (uint32_t index = 0; index < expectedTargets.size(); ++index)
      StoreBe32(text, 0x30 + index * 4, expectedTargets[index]);
    for (uint32_t target : std::set<uint32_t>(expectedTargets.begin(), expectedTargets.end()))
      StoreBe32(text, target - kTextBase, 0x4E800020);  // case block
  }

  BinaryView view() const {
    const std::array sections{BinarySectionInput{
        .name = ".text",
        .baseAddress = kTextBase,
        .data = text,
        .executable = true,
        .readable = true,
    }};
    return BinaryView::fromSections(kTextBase, kTextBase + text.size(), kTextBase, sections);
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

bool SameValidatedTable(const JumpTable& lhs, const JumpTable& rhs) {
  if (lhs.rawEntries.size() != rhs.rawEntries.size() || lhs.evidence.size() != rhs.evidence.size())
    return false;
  for (size_t index = 0; index < lhs.rawEntries.size(); ++index) {
    if (lhs.rawEntries[index].storageAddress != rhs.rawEntries[index].storageAddress ||
        lhs.rawEntries[index].rawValue != rhs.rawEntries[index].rawValue ||
        lhs.rawEntries[index].target != rhs.rawEntries[index].target) {
      return false;
    }
  }
  for (size_t index = 0; index < lhs.evidence.size(); ++index) {
    if (lhs.evidence[index].address != rhs.evidence[index].address ||
        lhs.evidence[index].rawInstruction != rhs.evidence[index].rawInstruction ||
        lhs.evidence[index].role != rhs.evidence[index].role ||
        lhs.evidence[index].instruction != rhs.evidence[index].instruction) {
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

constexpr uint32_t kLoopHeader = kTextBase + 0x10;
constexpr uint32_t kLoopSite = kTextBase + 0x3C;

AbsoluteSwitch LoopStateSwitch() {
  AbsoluteSwitch image;
  std::fill(image.text.begin(), image.text.end(), 0);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  StoreBe32(image.text, 0x00, Addi(21, 0, 0));  // entry state: li r21, 0
  // The state is preserved through a separate input-scanning loop before it
  // enters the dispatch loop. This nested identity phi is the compiler shape
  // that the fixture is intended to preserve.
  StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kLoopHeader, 4, 2));
  StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x04));
  StoreBe32(image.text, 0x0C, 0x4E800020);  // disconnected padding does not enter header
  StoreBe32(image.text, 0x10, Mr(11, 21));  // copy loop state to table index
  StoreBe32(image.text, 0x14, 0x280B0002);  // cmplwi r11, 2
  StoreBe32(image.text, 0x18, Bc(kTextBase + 0x18, kTextBase + 0x70, 12, 1));
  StoreBe32(image.text, 0x1C, 0x3D802000);              // lis r12, table@h
  StoreBe32(image.text, 0x20, Lbzx(0, 12, 11));         // unsigned byte offset
  StoreBe32(image.text, 0x24, Mr(7, 0));                // copy loaded element
  StoreBe32(image.text, 0x28, Rlwinm(7, 7, 2, 0, 29));  // scale by four
  StoreBe32(image.text, 0x2C, 0x3D801000);              // lis r12, anchor@h
  StoreBe32(image.text, 0x30, Add(12, 12, 7));
  StoreBe32(image.text, 0x34, Mr(8, 12));  // copy resolved target before CTR setup
  StoreBe32(image.text, 0x38, Mtctr(8));
  StoreBe32(image.text, 0x3C, 0x4E800420);  // bctr; case 0 is exactly dispatch + 4

  StoreBe32(image.text, 0x40, Addi(21, 0, 1));  // case 0 -> state 1
  StoreBe32(image.text, 0x44, B(kTextBase + 0x44, kLoopHeader));
  StoreBe32(image.text, 0x50, Addi(21, 0, 2));  // case 1 -> state 2
  StoreBe32(image.text, 0x54, B(kTextBase + 0x54, kLoopHeader));
  StoreBe32(image.text, 0x60, Addi(21, 0, 0));  // case 2 -> state 0
  StoreBe32(image.text, 0x64, B(kTextBase + 0x64, kLoopHeader));
  StoreBe32(image.text, 0x6C, 0x4E800020);  // disconnected padding does not enter default
  StoreBe32(image.text, 0x70, B(kTextBase + 0x70, kLoopHeader));  // identity backedge

  image.table[0] = 0x10;
  image.table[1] = 0x14;
  image.table[2] = 0x18;
  return image;
}

AbsoluteSwitch LargeLoopStateSwitch() {
  auto image = LoopStateSwitch();
  const size_t originalSize = image.text.size();
  image.text.resize(0x920);
  for (uint32_t offset = static_cast<uint32_t>(originalSize); offset < image.text.size();
       offset += 4) {
    StoreBe32(image.text, offset, 0x60000000);  // nop
  }
  // Keep the same validated table and state recurrence, but make one case's
  // backedge traverse more nodes than the resolver-state budget. The former
  // repeated reachability walk incorrectly used maxStates for CFG topology
  // and reported ambiguous_reaching_definition on this lifecycle.
  StoreBe32(image.text, 0x40, B(kTextBase + 0x40, kTextBase + 0x100));
  StoreBe32(image.text, 0x44, 0x4E800020);
  StoreBe32(image.text, 0x900, Addi(21, 0, 1));
  StoreBe32(image.text, 0x904, B(kTextBase + 0x904, kLoopHeader));
  StoreBe32(image.text, 0x908, 0x4E800020);
  return image;
}

AbsoluteSwitch GuardedLoopStateSwitch() {
  auto image = LoopStateSwitch();
  for (uint32_t offset = 0x40; offset < 0xA0; offset += 4)
    StoreBe32(image.text, offset, 0x60000000);

  // Seed r11 once, preserve it through a separate input loop, then carry r11
  // itself around the dispatch loop (the TU1 compiler shape).
  StoreBe32(image.text, 0x04, Mr(11, 21));
  StoreBe32(image.text, 0x08, Bc(kTextBase + 0x08, kLoopHeader, 4, 2));
  StoreBe32(image.text, 0x0C, B(kTextBase + 0x0C, kTextBase + 0x08));
  StoreBe32(image.text, 0x10, 0x60000000);

  // Preserve the bounded dispatch but move its default to a join which sees
  // both the current loop state and a finite case assignment.
  StoreBe32(image.text, 0x18, Bc(kTextBase + 0x18, kTextBase + 0x90, 12, 1));

  // Case 0: two finite definitions converge before the backedge.
  StoreBe32(image.text, 0x40, Bc(kTextBase + 0x40, kTextBase + 0x50, 4, 2));
  StoreBe32(image.text, 0x44, Addi(11, 0, 1));
  StoreBe32(image.text, 0x48, B(kTextBase + 0x48, kTextBase + 0x58));
  StoreBe32(image.text, 0x50, Addi(11, 0, 2));
  StoreBe32(image.text, 0x54, B(kTextBase + 0x54, kTextBase + 0x58));
  StoreBe32(image.text, 0x58, B(kTextBase + 0x58, kLoopHeader));

  // Case 1: direct finite assignment.
  StoreBe32(image.text, 0x70, Addi(11, 0, 0));
  StoreBe32(image.text, 0x74, B(kTextBase + 0x74, kLoopHeader));

  // Case 2 joins the static default path. The join is identity-or-finite;
  // the following guard sends only the identity path back to the header.
  StoreBe32(image.text, 0x80, Addi(11, 0, 2));
  StoreBe32(image.text, 0x84, B(kTextBase + 0x84, kTextBase + 0x90));
  StoreBe32(image.text, 0x8C, 0x4E800020);
  StoreBe32(image.text, 0x90, 0x2F0B0002);  // cmpwi cr6,r11,2
  StoreBe32(image.text, 0x94, Bc(kTextBase + 0x94, kLoopHeader, 4, 2));
  StoreBe32(image.text, 0x98, 0x4E800020);

  image.table[0] = 0x10;  // 0x10000040
  image.table[1] = 0x1C;  // 0x10000070
  image.table[2] = 0x20;  // 0x10000080
  return image;
}

AbsoluteSwitch DirectBoundedAmbiguousIndexSwitch() {
  AbsoluteSwitch image;
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  // Two path-dependent loads provide the state byte. The exact current r3
  // value is nevertheless bounded after the merge and consumed unchanged by
  // the table load; its earlier provenance is irrelevant to table semantics.
  StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x0C, 4, 2));
  StoreBe32(image.text, 0x04, 0x88660000);  // lbz r3, 0(r6)
  StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x10));
  StoreBe32(image.text, 0x0C, 0x88670001);  // lbz r3, 1(r7)
  StoreBe32(image.text, 0x10, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x14, Bc(kTextBase + 0x14, kTextBase + 0x60, 12, 1));
  StoreBe32(image.text, 0x1C, 0x3C802000);              // lis r4, table@h
  StoreBe32(image.text, 0x20, Lbzx(5, 4, 3));           // unsigned byte offset
  StoreBe32(image.text, 0x24, Rlwinm(5, 5, 2, 0, 29));  // scale by four
  StoreBe32(image.text, 0x28, 0x3CC01000);              // lis r6, anchor@h
  StoreBe32(image.text, 0x2C, Add(5, 6, 5));
  StoreBe32(image.text, 0x30, Mtctr(5));
  StoreBe32(image.text, 0x34, 0x4E800420);  // bctr
  StoreBe32(image.text, 0x40, 0x4E800020);
  StoreBe32(image.text, 0x50, 0x4E800020);
  StoreBe32(image.text, 0x60, 0x4E800020);
  image.table[0] = 0x10;
  image.table[1] = 0x14;
  image.table[2] = 0x18;
  return image;
}

AbsoluteSwitch TransformedBoundedAmbiguousIndexSwitch() {
  AbsoluteSwitch image;
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  // Two path-dependent loads provide the state. The merged state register is
  // range-checked, then scaled into a separate temporary for an unsigned
  // halfword relative table, matching the compiler family used by large
  // state-machine switches.
  StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x0C, 4, 2));
  StoreBe32(image.text, 0x04, 0x88660000);  // lbz r3, 0(r6)
  StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x10));
  StoreBe32(image.text, 0x0C, 0x88670001);  // lbz r3, 1(r7)
  StoreBe32(image.text, 0x10, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x14, Bc(kTextBase + 0x14, kTextBase + 0x70, 12, 1));
  StoreBe32(image.text, 0x1C, 0x3D802000);              // lis r12, table@h
  StoreBe32(image.text, 0x20, Rlwinm(0, 3, 1, 0, 30));  // scale index by two
  StoreBe32(image.text, 0x24, Lhzx(0, 12, 0));          // unsigned halfword offset
  StoreBe32(image.text, 0x28, 0x3D801000);              // lis r12, anchor@h
  StoreBe32(image.text, 0x2C, Add(12, 12, 0));
  StoreBe32(image.text, 0x30, Mtctr(12));
  StoreBe32(image.text, 0x34, 0x4E800420);  // bctr
  StoreBe32(image.text, 0x40, 0x4E800020);
  StoreBe32(image.text, 0x50, 0x4E800020);
  StoreBe32(image.text, 0x60, 0x4E800020);
  StoreBe32(image.text, 0x70, 0x4E800020);
  StoreBe16(image.table, 0x00, 0x40);
  StoreBe16(image.table, 0x02, 0x50);
  StoreBe16(image.table, 0x04, 0x60);
  return image;
}

AbsoluteSwitch RecomputedLoopIndexSwitch() {
  AbsoluteSwitch image;
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  StoreBe32(image.text, 0x00, Addi(28, 0, 1));    // li r28, 1
  StoreBe32(image.text, 0x04, Addi(11, 28, -1));  // bounded index definition
  StoreBe32(image.text, 0x08, 0x280B0003);        // cmplwi r11, 3
  StoreBe32(image.text, 0x0C, Bc(kTextBase + 0x0C, kTextBase + 0xB0, 12, 1));  // bgt default
  StoreBe32(image.text, 0x14, Addi(11, 28, -1));  // exact case-path recomputation
  StoreBe32(image.text, 0x18, 0x3D802000);        // lis r12, table@h
  StoreBe32(image.text, 0x1C, Rlwinm(0, 11, 2, 0, 29));
  StoreBe32(image.text, 0x20, Lwzx(0, 12, 0));
  StoreBe32(image.text, 0x24, Mtctr(0));
  StoreBe32(image.text, 0x28, 0x4E800420);  // bctr

  StoreBe32(image.text, 0x40, B(kTextBase + 0x40, kTextBase + 0x90));
  StoreBe32(image.text, 0x50, B(kTextBase + 0x50, kTextBase + 0x90));
  StoreBe32(image.text, 0x60, B(kTextBase + 0x60, kTextBase + 0x90));
  StoreBe32(image.text, 0x70, B(kTextBase + 0x70, kTextBase + 0x90));
  StoreBe32(image.text, 0x90, Addi(28, 28, 1));
  StoreBe32(image.text, 0x94, Addi(11, 28, -1));
  StoreBe32(image.text, 0x98, 0x2C0B0004);                                     // cmpwi r11, 4
  StoreBe32(image.text, 0x9C, Bc(kTextBase + 0x9C, kTextBase + 0x04, 12, 0));  // blt loop
  StoreBe32(image.text, 0xA0, 0x4E800020);
  StoreBe32(image.text, 0xB0, 0x4E800020);
  StoreBe32(image.table, 0x00, kTextBase + 0x40);
  StoreBe32(image.table, 0x04, kTextBase + 0x50);
  StoreBe32(image.table, 0x08, kTextBase + 0x60);
  StoreBe32(image.table, 0x0C, kTextBase + 0x70);
  return image;
}

AbsoluteSwitch CaseEdgeInvariantLoopStateSwitch() {
  auto image = GuardedLoopStateSwitch();
  StoreBe32(image.text, 0x00, Addi(27, 0, 1));  // loop-invariant case input
  StoreBe32(image.text, 0x04, Addi(11, 0, 0));  // entry state
  StoreBe32(image.text, 0x40, Mr(11, 27));      // case 0 consumes the invariant
  StoreBe32(image.text, 0x44, B(kTextBase + 0x44, kLoopHeader));
  StoreBe32(image.text, 0x48, 0x4E800020);
  StoreBe32(image.text, 0x50, 0x4E800020);
  StoreBe32(image.text, 0x54, 0x4E800020);
  StoreBe32(image.text, 0x58, 0x4E800020);
  StoreBe32(image.text, 0x6C, 0x4E800020);
  StoreBe32(image.text, 0x7C, 0x4E800020);
  return image;
}

AbsoluteSwitch RepeatedBoundGuardSwitch() {
  AbsoluteSwitch image;
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  // Entry and backedge compute the same switch index from different loads.
  // Each path proves the same finite domain immediately before converging on
  // the table slice; their out-of-range defaults intentionally differ.
  StoreBe32(image.text, 0x00, 0x81660000);  // lwz r11, 0(r6)
  StoreBe32(image.text, 0x04, 0x280B0003);  // cmplwi r11, 3
  StoreBe32(image.text, 0x08, Bc(kTextBase + 0x08, kTextBase + 0x90, 12, 1));
  StoreBe32(image.text, 0x0C, 0x3D802000);  // lis r12, table@h
  StoreBe32(image.text, 0x10, Rlwinm(0, 11, 2, 0, 29));
  StoreBe32(image.text, 0x14, Lwzx(0, 12, 0));
  StoreBe32(image.text, 0x18, Mtctr(0));
  StoreBe32(image.text, 0x1C, 0x4E800420);  // bctr

  StoreBe32(image.text, 0x40, 0x81660004);  // lwz r11, 4(r6)
  StoreBe32(image.text, 0x44, 0x280B0003);  // cmplwi r11, 3
  StoreBe32(image.text, 0x48, Bc(kTextBase + 0x48, kTextBase + 0x0C, 4, 1));
  StoreBe32(image.text, 0x4C, B(kTextBase + 0x4C, kTextBase + 0x80));
  StoreBe32(image.text, 0x50, 0x4E800020);
  StoreBe32(image.text, 0x60, 0x4E800020);
  StoreBe32(image.text, 0x70, 0x4E800020);
  StoreBe32(image.text, 0x80, 0x4E800020);  // repeated-guard default
  StoreBe32(image.text, 0x90, 0x4E800020);  // entry-guard default

  StoreBe32(image.table, 0x00, kTextBase + 0x40);
  StoreBe32(image.table, 0x04, kTextBase + 0x50);
  StoreBe32(image.table, 0x08, kTextBase + 0x60);
  StoreBe32(image.table, 0x0C, kTextBase + 0x70);
  return image;
}

AbsoluteSwitch FiniteCfgDomainSwitch() {
  AbsoluteSwitch image;
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  // Four complete predecessor paths assign the entire finite index domain.
  // There is intentionally no compare-based upper bound: the CFG join itself
  // is the proof that the copied table index is exactly one of 0, 1, 2, 3.
  StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x10, 12, 2));
  StoreBe32(image.text, 0x04, Addi(10, 0, 0));
  StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x30));
  StoreBe32(image.text, 0x10, Bc(kTextBase + 0x10, kTextBase + 0x20, 12, 2));
  StoreBe32(image.text, 0x14, Addi(10, 0, 1));
  StoreBe32(image.text, 0x18, B(kTextBase + 0x18, kTextBase + 0x30));
  StoreBe32(image.text, 0x20, Bc(kTextBase + 0x20, kTextBase + 0x2C, 12, 2));
  StoreBe32(image.text, 0x24, Addi(10, 0, 2));
  StoreBe32(image.text, 0x28, B(kTextBase + 0x28, kTextBase + 0x30));
  StoreBe32(image.text, 0x2C, Addi(10, 0, 3));
  StoreBe32(image.text, 0x30, 0x3D802000);  // lis r12, table@h
  StoreBe32(image.text, 0x34, Mr(11, 10));  // preserve a register copy
  StoreBe32(image.text, 0x38, Rlwinm(0, 11, 2, 0, 29));
  StoreBe32(image.text, 0x3C, Lwzx(0, 12, 0));
  StoreBe32(image.text, 0x40, Mtctr(0));
  StoreBe32(image.text, 0x44, 0x4E800420);  // bctr
  StoreBe32(image.text, 0x60, 0x4E800020);
  StoreBe32(image.text, 0x70, 0x4E800020);
  StoreBe32(image.text, 0x80, 0x4E800020);
  StoreBe32(image.text, 0x90, 0x4E800020);
  StoreBe32(image.table, 0x00, kTextBase + 0x60);
  StoreBe32(image.table, 0x04, kTextBase + 0x70);
  StoreBe32(image.table, 0x08, kTextBase + 0x80);
  StoreBe32(image.table, 0x0C, kTextBase + 0x90);
  return image;
}

constexpr uint32_t kEntryDomainSite = kTextBase + 0x10;

AbsoluteSwitch EntryDomainSwitch() {
  AbsoluteSwitch image;
  image.text.resize(0x200);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  // The owner deliberately has no local compare. Its absolute table index is
  // the incoming r7 value, mirroring the missing-bound compiler form without
  // using any private executable bytes.
  StoreBe32(image.text, 0x00, 0x3D802000);              // lis r12, table@h
  StoreBe32(image.text, 0x04, Rlwinm(0, 7, 2, 0, 29));  // slwi r0, r7, 2
  StoreBe32(image.text, 0x08, Lwzx(0, 12, 0));
  StoreBe32(image.text, 0x0C, Mtctr(0));
  StoreBe32(image.text, 0x10, 0x4E800420);  // bctr
  for (uint32_t index = 0; index < 8; ++index) {
    const uint32_t target = kTextBase + 0x20 + index * 0x10;
    StoreBe32(image.text, target - kTextBase, 0x4E800020);
    StoreBe32(image.table, index * 4, target);
  }

  StoreBe32(image.text, 0xC0, Addi(7, 0, 6));
  StoreBe32(image.text, 0xC4, Bl(kTextBase + 0xC4, kTextBase));
  StoreBe32(image.text, 0xC8, 0x4E800020);
  StoreBe32(image.text, 0xD0, Addi(7, 0, 3));
  StoreBe32(image.text, 0xD4, Bl(kTextBase + 0xD4, kTextBase));
  StoreBe32(image.text, 0xD8, 0x4E800020);
  StoreBe32(image.text, 0xE0, Addi(7, 0, 4));
  StoreBe32(image.text, 0xE4, Bl(kTextBase + 0xE4, kTextBase));
  StoreBe32(image.text, 0xE8, 0x4E800020);
  StoreBe32(image.text, 0xF0, Lwzx(7, 3, 4));
  StoreBe32(image.text, 0xF4, 0x28070007);  // cmplwi r7, 7
  StoreBe32(image.text, 0xF8, Bc(kTextBase + 0xF8, kTextBase + 0x108, 12, 1));
  StoreBe32(image.text, 0xFC, Bl(kTextBase + 0xFC, kTextBase));
  StoreBe32(image.text, 0x100, 0x4E800020);
  StoreBe32(image.text, 0x108, 0x4E800020);
  return image;
}

JumpTableEntryRegisterDomainEvidence ProveEntryDomain(DecodedBinary& decoded) {
  JumpTableEntryRegisterDomainEvidence domain;
  domain.entryAddress = kTextBase;
  domain.registerIndex = 7;
  const std::array callsites{
      std::pair{Block{kTextBase + 0xC0, 0x0C}, kTextBase + 0xC4},
      std::pair{Block{kTextBase + 0xD0, 0x0C}, kTextBase + 0xD4},
      std::pair{Block{kTextBase + 0xE0, 0x0C}, kTextBase + 0xE4},
      std::pair{Block{kTextBase + 0xF0, 0x1C}, kTextBase + 0xFC},
  };
  std::set<uint32_t> values;
  for (const auto& [block, callAddress] : callsites) {
    auto callsite = AnalyzeDirectCallArgumentDomain(decoded, std::span<const Block>(&block, 1),
                                                    block.base, callAddress, kTextBase, 7);
    domain.directCallSites.push_back(callAddress);
    values.insert(callsite.finiteValues.begin(), callsite.finiteValues.end());
    domain.callsites.push_back(std::move(callsite));
  }
  domain.finiteValues.assign(values.begin(), values.end());
  domain.allReferencesDirectCalls = true;
  domain.finiteDenseDomain = std::all_of(domain.callsites.begin(), domain.callsites.end(),
                                         [](const auto& callsite) { return callsite.complete; }) &&
                             domain.finiteValues.size() == 8;
  return domain;
}

CodegenContext MakeEntryDomainContext(const AbsoluteSwitch& image) {
  const std::array sections{
      BinarySectionInput{.name = ".text",
                         .baseAddress = kTextBase,
                         .data = image.text,
                         .executable = true,
                         .readable = true},
      BinarySectionInput{
          .name = ".rdata", .baseAddress = kTableBase, .data = image.table, .readable = true},
  };
  RecompilerConfig config;
  auto ctx = CodegenContext::Create(
      BinaryView::fromSections(kTextBase, 0x10000200, kTextBase + 0x1F0, sections),
      std::move(config));
  ctx.initDecoded();
  ctx.scan.codeRegions.assign(ctx.decoded().codeRegions().begin(),
                              ctx.decoded().codeRegions().end());

  ctx.graph.addFunction(kTextBase, 4, FunctionAuthority::DISCOVERED, true);
  const std::array callers{
      std::pair{kTextBase + 0xC0, 0x0Cu},
      std::pair{kTextBase + 0xD0, 0x0Cu},
      std::pair{kTextBase + 0xE0, 0x0Cu},
      std::pair{kTextBase + 0xF0, 0x1Cu},
  };
  for (const auto& [address, size] : callers) {
    ctx.graph.addFunction(address, size, FunctionAuthority::PDATA, true);
    ctx.scan.pdataSizes.emplace(address, size);
  }
  return ctx;
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

TEST_CASE("jump-table recovery validates a complete finite CFG index domain",
          "[codegen][jump-table][finite-domain]") {
  auto image = FiniteCfgDomainSwitch();
  auto analysis = Analyze(image, kTextBase + 0x44, nullptr, {}, 0xA0);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.failures.empty());
  CHECK(analysis.selectedTable->indexRegister == 10);
  CHECK(analysis.selectedTable->boundValue == 3);
  CHECK(analysis.selectedTable->caseCount == 4);
  CHECK(analysis.selectedTable->boundInclusive);
  CHECK(analysis.selectedTable->boundSemantics == "finite_cfg_domain_zero_based_dense");
  CHECK(analysis.selectedTable->confidence == "validated_finite_cfg_domain_all_targets");
  CHECK(analysis.selectedTable->targets == std::vector<uint32_t>{kTextBase + 0x60, kTextBase + 0x70,
                                                                 kTextBase + 0x80,
                                                                 kTextBase + 0x90});
  REQUIRE(analysis.dataflow);
  const auto domain = std::find_if(analysis.dataflow->boundCandidates.begin(),
                                   analysis.dataflow->boundCandidates.end(),
                                   [](const auto& candidate) { return candidate.finiteCfgDomain; });
  REQUIRE(domain != analysis.dataflow->boundCandidates.end());
  CHECK(domain->domainOriginAddress == kTextBase + 0x30);
  CHECK(domain->indexRegister == 10);
  CHECK(domain->finiteValues == std::vector<uint32_t>{0, 1, 2, 3});
  CHECK(domain->finiteDenseDomain);
  CHECK(domain->dominatesDispatch);
  CHECK(domain->rejection.empty());
  CHECK(analysis.dataflow->mergeShape == "finite_cfg_domain");
}

TEST_CASE("finite CFG index domains retain conservative rejection controls",
          "[codegen][jump-table][finite-domain]") {
  SECTION("non-dense values are not remapped into a partial table") {
    auto image = FiniteCfgDomainSwitch();
    StoreBe32(image.text, 0x2C, Addi(10, 0, 4));
    auto analysis = Analyze(image, kTextBase + 0x44, nullptr, {}, 0xA0);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::MissingBound));
    REQUIRE(analysis.dataflow);
    const auto domain = std::find_if(
        analysis.dataflow->boundCandidates.begin(), analysis.dataflow->boundCandidates.end(),
        [](const auto& candidate) { return candidate.finiteCfgDomain; });
    REQUIRE(domain != analysis.dataflow->boundCandidates.end());
    CHECK_FALSE(domain->finiteDenseDomain);
    CHECK(domain->finiteValues == std::vector<uint32_t>{0, 1, 2, 4});
    CHECK(domain->rejection == "finite_cfg_domain_not_dense_zero_based");
  }

  SECTION("an incompatible predecessor remains an ambiguous reaching definition") {
    auto image = FiniteCfgDomainSwitch();
    StoreBe32(image.text, 0x2C, Mr(10, 3));
    auto analysis = Analyze(image, kTextBase + 0x44, nullptr, {}, 0xA0);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
  }

  SECTION("the source register must still contain the finite value at dispatch") {
    auto image = FiniteCfgDomainSwitch();
    StoreBe32(image.text, 0x38, Addi(10, 0, 7));
    StoreBe32(image.text, 0x3C, Rlwinm(0, 11, 2, 0, 29));
    StoreBe32(image.text, 0x40, Lwzx(0, 12, 0));
    StoreBe32(image.text, 0x44, Mtctr(0));
    StoreBe32(image.text, 0x48, 0x4E800420);
    auto analysis = Analyze(image, kTextBase + 0x48, nullptr, {}, 0xA0);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::MissingBound));
    REQUIRE(analysis.dataflow);
    CHECK(std::any_of(analysis.dataflow->boundCandidates.begin(),
                      analysis.dataflow->boundCandidates.end(), [](const auto& candidate) {
                        return candidate.finiteCfgDomain && !candidate.finiteDenseDomain &&
                               candidate.rejection ==
                                   "finite_cfg_domain_register_not_available_at_dispatch";
                      }));
  }

  SECTION("mixed-validity targets reject the complete table") {
    auto image = FiniteCfgDomainSwitch();
    StoreBe32(image.table, 0x0C, kTextBase + 0x91);
    auto analysis = Analyze(image, kTextBase + 0x44, nullptr, {}, 0xA0);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::MixedValidityTargets));
  }

  SECTION("a bounded analysis limit cannot be treated as a finite-domain proof") {
    auto image = FiniteCfgDomainSwitch();
    JumpTableRecoveryLimits limits;
    limits.maxStates = 1;
    auto analysis = Analyze(image, kTextBase + 0x44, nullptr, limits, 0xA0);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::AnalysisLimit));
  }
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

TEST_CASE("self-delimiting inline absolute tables require an exact static extent",
          "[codegen][jump-table][inline-table-extent]") {
  const auto analyze = [](InlineAbsoluteSwitch& image,
                          const std::unordered_set<uint32_t>* callableEntries = nullptr,
                          JumpTableRecoveryLimits limits = {}) {
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block preliminary{kTextBase, image.tableBase - kTextBase};
    JumpTableRecoveryInput input{
        .site = image.site,
        .ownerAddress = kTextBase,
        .trustedOwnerEnd = image.ownerEnd,
        .preliminaryBlocks = std::span<const Block>(&preliminary, 1),
        .containingRegion = decoded.regionContaining(kTextBase),
        .independentlyCallableEntries = callableEntries,
        .limits = limits,
    };
    return AnalyzeIndirectSite(decoded, input);
  };

  SECTION("a record-derived index uses the finite inline storage boundary") {
    InlineAbsoluteSwitch image;
    auto analysis = analyze(image);
    REQUIRE(analysis.selectedTable);
    CHECK(analysis.failures.empty());
    CHECK(analysis.classification == IndirectSiteClassification::SwitchBctr);
    CHECK(analysis.selectedTable->bctrAddress == image.site);
    CHECK(analysis.selectedTable->tableAddress == image.tableBase);
    CHECK(analysis.selectedTable->storageEnd == kTextBase + 0x5C);
    CHECK(analysis.selectedTable->caseCount == 11);
    CHECK(analysis.selectedTable->indexRegister == 9);
    CHECK(analysis.selectedTable->kind == JumpTableKind::AbsolutePointer);
    CHECK(analysis.selectedTable->elementWidth == 4);
    CHECK_FALSE(analysis.selectedTable->elementSigned);
    CHECK(analysis.selectedTable->boundSemantics ==
          "self_delimiting_inline_absolute_table_extent");
    CHECK(analysis.selectedTable->confidence ==
          "validated_self_delimiting_inline_absolute_table_all_targets");
    CHECK(analysis.selectedTable->targets == image.expectedTargets);
    REQUIRE(analysis.selectedTable->rawEntries.size() == image.expectedTargets.size());
    for (uint32_t index = 0; index < image.expectedTargets.size(); ++index) {
      const JumpTableRawEntry expectedEntry{image.tableBase + index * 4,
                                            image.expectedTargets[index],
                                            image.expectedTargets[index]};
      CHECK(analysis.selectedTable->rawEntries[index] == expectedEntry);
    }
    REQUIRE(analysis.dataflow);
    const auto extent = std::find_if(
        analysis.dataflow->boundCandidates.begin(), analysis.dataflow->boundCandidates.end(),
        [](const auto& bound) { return bound.selfDelimitedInlineTableExtent; });
    REQUIRE(extent != analysis.dataflow->boundCandidates.end());
    CHECK_FALSE(extent->finiteDenseDomain);
    CHECK(extent->tableStorageStart == image.tableBase);
    CHECK(extent->tableStorageEnd == kTextBase + 0x5C);
    CHECK(extent->caseCount == 11);

    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const auto* region = decoded.regionContaining(kTextBase);
    REQUIRE(region != nullptr);
    const std::unordered_set<uint32_t> functions{kTextBase, image.ownerEnd};
    auto discovered = discoverBlocks(decoded, kTextBase, *region, functions,
                                     image.ownerEnd - kTextBase);
    REQUIRE(discovered.jumpTables.size() == 1);
    CHECK(discovered.jumpTables.front().bctrAddress == image.site);
    CHECK(discovered.jumpTables.front().targets == image.expectedTargets);
    CHECK_FALSE(discovered.labels.contains(image.tableBase));
    for (uint32_t target : image.expectedTargets)
      CHECK(discovered.labels.contains(target));
  }

  SECTION("the table must start at the non-fallthrough instruction boundary") {
    InlineAbsoluteSwitch image;
    StoreBe32(image.text, 0x1C, Addi(12, 12, 0x34));
    auto analysis = analyze(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::MissingBound});
  }

  SECTION("a gap before the earliest case is not a self-delimiting extent") {
    InlineAbsoluteSwitch image;
    StoreBe32(image.text, 0x30, kTextBase + 0x80);
    auto analysis = analyze(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::MissingBound});
    REQUIRE(analysis.dataflow);
    CHECK(std::find(analysis.dataflow->rejectionEvidence.begin(),
                    analysis.dataflow->rejectionEvidence.end(),
                    "self_delimiting_inline_table:inline_table_target_outside_exact_owner:index=11") !=
          analysis.dataflow->rejectionEvidence.end());
  }

  SECTION("an altered raw entry is rejected rather than accepting a prefix") {
    InlineAbsoluteSwitch image;
    StoreBe32(image.text, 0x34, kTextBase + 0x81);
    auto analysis = analyze(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::MissingBound});
    REQUIRE(analysis.dataflow);
    CHECK(std::find(analysis.dataflow->rejectionEvidence.begin(),
                    analysis.dataflow->rejectionEvidence.end(),
                    "self_delimiting_inline_table:inline_table_target_unaligned:index=1") !=
          analysis.dataflow->rejectionEvidence.end());
  }

  SECTION("fewer than three entries remain insufficient evidence") {
    InlineAbsoluteSwitch image;
    StoreBe32(image.text, 0x30, kTextBase + 0x38);
    StoreBe32(image.text, 0x34, kTextBase + 0x38);
    StoreBe32(image.text, 0x38, 0x4E800020);
    auto analysis = analyze(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::MissingBound});
  }

  SECTION("the logical index must survive until generated dispatch") {
    InlineAbsoluteSwitch image;
    StoreBe32(image.text, 0x24, Lwzx(9, 12, 0));
    StoreBe32(image.text, 0x28, Mtctr(9));
    auto analysis = analyze(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::MissingBound});
  }

  SECTION("an independently callable target is not converted into an owner case") {
    InlineAbsoluteSwitch image;
    const std::unordered_set<uint32_t> callableEntries{kTextBase + 0x80};
    auto analysis = analyze(image, &callableEntries);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::MissingBound});
  }

  SECTION("incompatible index definitions remain ambiguous despite the storage shape") {
    InlineAbsoluteSwitch image;
    StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x10, 4, 2));
    StoreBe32(image.text, 0x04, Mr(9, 3));
    StoreBe32(image.text, 0x08, B(kTextBase + 0x08, kTextBase + 0x18));
    StoreBe32(image.text, 0x10, Mr(9, 4));
    StoreBe32(image.text, 0x14, B(kTextBase + 0x14, kTextBase + 0x18));
    auto analysis = analyze(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
    REQUIRE(analysis.dataflow);
    const auto extent = std::find_if(
        analysis.dataflow->boundCandidates.begin(), analysis.dataflow->boundCandidates.end(),
        [](const auto& bound) { return bound.selfDelimitedInlineTableExtent; });
    REQUIRE(extent != analysis.dataflow->boundCandidates.end());
    CHECK_FALSE(extent->finiteDenseDomain);
  }

  SECTION("entry-count safety exhaustion is reported without widening the budget") {
    InlineAbsoluteSwitch image;
    JumpTableRecoveryLimits limits;
    limits.maxEntries = 10;
    auto analysis = analyze(image, nullptr, limits);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::MissingBound});
    REQUIRE(analysis.dataflow);
    CHECK(std::find_if(analysis.dataflow->exhaustedBudgets.begin(),
                       analysis.dataflow->exhaustedBudgets.end(), [](const auto& budget) {
                         return budget.budget == "max_entries" && budget.limit == 10 &&
                                budget.observed == 10;
                       }) != analysis.dataflow->exhaustedBudgets.end());
  }

  SECTION("a linked callback remains excluded from switch recovery") {
    InlineAbsoluteSwitch image;
    StoreBe32(image.text, 0x2C, 0x4E800421);  // bctrl
    auto analysis = analyze(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.classification == IndirectSiteClassification::VirtualOrCallbackBctrl);
    CHECK(HasFailure(analysis, JumpTableFailure::NonSwitchIndirect));
  }
}

TEST_CASE("whole-image direct-call domains recover an otherwise unbounded entry switch",
          "[codegen][jump-table][entry-domain]") {
  auto image = EntryDomainSwitch();
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const Block ownerBlock{kTextBase, 0x14};

  JumpTableRecoveryInput input;
  input.site = kEntryDomainSite;
  input.ownerAddress = kTextBase;
  input.trustedOwnerEnd = kTextBase + 0xA0;
  input.preliminaryBlocks = std::span<const Block>(&ownerBlock, 1);
  input.containingRegion = region;
  auto initial = AnalyzeIndirectSite(decoded, input);
  REQUIRE_FALSE(initial.selectedTable);
  CHECK(initial.failures == std::vector{JumpTableFailure::MissingBound});
  REQUIRE(initial.dataflow);
  CHECK(initial.dataflow->indexRegister == 0);
  CHECK(initial.dataflow->tableLoadInputRegisters == std::vector<uint8_t>{7});

  auto domain = ProveEntryDomain(decoded);
  REQUIRE(domain.callsites.size() == 4);
  CHECK(domain.callsites[0].proofKind == "dominating_immediate_constant");
  CHECK(domain.callsites[0].finiteValues == std::vector<uint32_t>{6});
  CHECK(domain.callsites[1].finiteValues == std::vector<uint32_t>{3});
  CHECK(domain.callsites[2].finiteValues == std::vector<uint32_t>{4});
  CHECK(domain.callsites[3].proofKind == "unsigned_dominating_callsite_guard");
  CHECK(domain.callsites[3].compareAddress == kTextBase + 0xF4);
  CHECK(domain.callsites[3].guardAddress == kTextBase + 0xF8);
  CHECK(domain.callsites[3].finiteValues == std::vector<uint32_t>{0, 1, 2, 3, 4, 5, 6, 7});
  REQUIRE(domain.allReferencesDirectCalls);
  REQUIRE(domain.finiteDenseDomain);
  CHECK(domain.finiteValues == std::vector<uint32_t>{0, 1, 2, 3, 4, 5, 6, 7});

  JumpTableEntryRegisterDomainMap domains;
  domains.emplace(7, domain);
  input.entryRegisterDomains = &domains;
  auto recovered = AnalyzeIndirectSite(decoded, input);
  REQUIRE(recovered.selectedTable);
  CHECK(recovered.failures.empty());
  CHECK(recovered.selectedTable->caseCount == 8);
  CHECK(recovered.selectedTable->tableAddress == kTableBase);
  CHECK(recovered.selectedTable->storageEnd == kTableBase + 0x20);
  CHECK(recovered.selectedTable->boundSemantics == "interprocedural_entry_domain_zero_based_dense");
  CHECK(recovered.selectedTable->confidence ==
        "validated_interprocedural_entry_domain_all_targets");
  CHECK(std::find(recovered.selectedTable->targets.begin(), recovered.selectedTable->targets.end(),
                  kTextBase + 0x80) != recovered.selectedTable->targets.end());
  REQUIRE(recovered.dataflow);
  CHECK(recovered.dataflow->indexRegister == 7);
  CHECK(recovered.dataflow->tableLoadInputRegisters == std::vector<uint8_t>{7});
  REQUIRE(recovered.dataflow->entryRegisterDomains.size() == 1);
  CHECK(recovered.dataflow->entryRegisterDomains.front().directCallSites == domain.directCallSites);
  const auto bound = std::find_if(
      recovered.dataflow->boundCandidates.begin(), recovered.dataflow->boundCandidates.end(),
      [](const auto& candidate) { return candidate.interproceduralEntryDomain; });
  REQUIRE(bound != recovered.dataflow->boundCandidates.end());
  CHECK(bound->finiteDenseDomain);
  CHECK(bound->finiteValues == domain.finiteValues);
  CHECK(recovered.dataflow->mergeShape == "interprocedural_entry_domain");
  CHECK(recovered.dataflow->switchLikelihood == JumpTableSwitchLikelihood::ResolvedSwitch);

  const std::unordered_set<uint32_t> functions{kTextBase};
  JumpTableEntryRegisterDomainsBySite domainsBySite;
  domainsBySite.emplace(kEntryDomainSite, domains);
  auto integrated =
      discoverBlocks(decoded, kTextBase, *region, functions, 0xA0, nullptr, &domainsBySite);
  REQUIRE(integrated.jumpTables.size() == 1);
  CHECK(integrated.jumpTables.front().caseCount == 8);
  CHECK(integrated.labels.contains(kTextBase + 0x80));
  CHECK(std::any_of(integrated.blocks.begin(), integrated.blocks.end(),
                    [](const Block& block) { return block.contains(kTextBase + 0x80); }));
  CHECK(functions.size() == 1);
  CHECK_FALSE(functions.contains(kTextBase + 0x80));
}

TEST_CASE("exact local call arguments survive unrelated caller-wide bound exhaustion",
          "[codegen][jump-table][entry-domain]") {
  auto image = EntryDomainSwitch();
  image.text.resize(0x400);
  for (uint32_t offset = 0x200; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  constexpr uint32_t kCaller = kTextBase + 0x200;
  constexpr uint32_t kDefinition = kTextBase + 0x3F4;
  constexpr uint32_t kCall = kTextBase + 0x3F8;
  StoreBe32(image.text, kDefinition - kTextBase, Addi(7, 0, 4));
  StoreBe32(image.text, kCall - kTextBase, Bl(kCall, kTextBase));
  StoreBe32(image.text, kCall + 4 - kTextBase, 0x4E800020);  // blr

  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block caller{kCaller, 0x200};

  SECTION("the exact adjacent immediate is accepted before the unrelated scan limit") {
    auto callsite = AnalyzeDirectCallArgumentDomain(decoded, std::span<const Block>(&caller, 1),
                                                    kCaller, kCall, kTextBase, 7);
    CHECK_FALSE(callsite.limitHit);
    CHECK(callsite.rejections.empty());
    REQUIRE(callsite.complete);
    CHECK(callsite.proofKind == "dominating_immediate_constant");
    CHECK(callsite.definitionAddresses == std::vector<uint32_t>{kDefinition});
    CHECK(callsite.finiteValues == std::vector<uint32_t>{4});
  }

  SECTION("a later incompatible write cannot borrow the earlier immediate") {
    StoreBe32(image.text, kDefinition - 4 - kTextBase, Addi(7, 0, 4));
    StoreBe32(image.text, kDefinition - kTextBase, Mr(7, 3));
    auto alteredView = image.view();
    DecodedBinary alteredDecoded(alteredView);
    alteredDecoded.decode();
    auto callsite = AnalyzeDirectCallArgumentDomain(
        alteredDecoded, std::span<const Block>(&caller, 1), kCaller, kCall, kTextBase, 7);
    CHECK_FALSE(callsite.complete);
    CHECK(callsite.finiteValues.empty());
    CHECK(callsite.proofKind.empty());
  }
}

TEST_CASE("discover phase requires a complete static inbound-reference census for entry domains",
          "[codegen][jump-table][entry-domain][discover]") {
  SECTION("four independently finite callsites recover the exact eight-case table") {
    auto image = EntryDomainSwitch();
    auto ctx = MakeEntryDomainContext(image);
    REQUIRE(phases::Discover(ctx));

    const auto* owner = ctx.graph.getFunction(kTextBase);
    REQUIRE(owner != nullptr);
    REQUIRE(owner->jumpTables().size() == 1);
    const auto& table = owner->jumpTables().front();
    CHECK(table.bctrAddress == kEntryDomainSite);
    CHECK(table.caseCount == 8);
    CHECK(table.storageEnd == kTableBase + 0x20);
    CHECK(table.indexRegister == 7);
    CHECK(table.boundSemantics == "interprocedural_entry_domain_zero_based_dense");
    CHECK(table.confidence == "validated_interprocedural_entry_domain_all_targets");
    CHECK(std::find(table.targets.begin(), table.targets.end(), kTextBase + 0x80) !=
          table.targets.end());
    CHECK(owner->containsAddress(kTextBase + 0x80));
    CHECK_FALSE(ctx.graph.isEntryPoint(kTextBase + 0x80));

    const auto site =
        std::find_if(owner->indirectSites().begin(), owner->indirectSites().end(),
                     [](const auto& analysis) { return analysis.site == kEntryDomainSite; });
    REQUIRE(site != owner->indirectSites().end());
    REQUIRE(site->selectedTable);
    REQUIRE(site->dataflow);
    REQUIRE(site->dataflow->entryRegisterDomains.size() == 1);
    const auto& domain = site->dataflow->entryRegisterDomains.front();
    CHECK(domain.allReferencesDirectCalls);
    CHECK(domain.finiteDenseDomain);
    CHECK(domain.directCallSites == std::vector<uint32_t>{kTextBase + 0xC4, kTextBase + 0xD4,
                                                          kTextBase + 0xE4, kTextBase + 0xFC});
    CHECK(domain.finiteValues == std::vector<uint32_t>{0, 1, 2, 3, 4, 5, 6, 7});
  }

  SECTION("one static address escape rejects recovery despite the same finite callsites") {
    auto image = EntryDomainSwitch();
    StoreBe32(image.table, 0x30, kTextBase);
    auto ctx = MakeEntryDomainContext(image);
    REQUIRE(phases::Discover(ctx));

    const auto* owner = ctx.graph.getFunction(kTextBase);
    REQUIRE(owner != nullptr);
    CHECK(owner->jumpTables().empty());
    const auto site =
        std::find_if(owner->indirectSites().begin(), owner->indirectSites().end(),
                     [](const auto& analysis) { return analysis.site == kEntryDomainSite; });
    REQUIRE(site != owner->indirectSites().end());
    CHECK_FALSE(site->selectedTable);
    REQUIRE(site->dataflow);
    REQUIRE(site->dataflow->entryRegisterDomains.size() == 1);
    const auto& domain = site->dataflow->entryRegisterDomains.front();
    CHECK_FALSE(domain.allReferencesDirectCalls);
    CHECK_FALSE(domain.finiteDenseDomain);
    CHECK(domain.rejection == "entry_has_non_call_or_address_escape_reference");
    CHECK(domain.rejectedReferenceSites == std::vector<uint32_t>{kTableBase + 0x30});
    CHECK(domain.referenceRejections ==
          std::vector<std::string>{"aligned_static_code_pointer_reference"});
    CHECK(site->dataflow->switchLikelihood ==
          JumpTableSwitchLikelihood::InsufficientStaticEvidence);
  }

  SECTION("non-call references remain visible when there are no direct callers") {
    auto image = EntryDomainSwitch();
    StoreBe32(image.text, 0xC4, 0x4E800020);
    StoreBe32(image.text, 0xD4, 0x4E800020);
    StoreBe32(image.text, 0xE4, 0x4E800020);
    StoreBe32(image.text, 0xFC, 0x4E800020);
    StoreBe32(image.table, 0x30, kTextBase);
    auto ctx = MakeEntryDomainContext(image);
    REQUIRE(phases::Discover(ctx));

    const auto* owner = ctx.graph.getFunction(kTextBase);
    REQUIRE(owner != nullptr);
    CHECK(owner->jumpTables().empty());
    const auto site =
        std::find_if(owner->indirectSites().begin(), owner->indirectSites().end(),
                     [](const auto& analysis) { return analysis.site == kEntryDomainSite; });
    REQUIRE(site != owner->indirectSites().end());
    REQUIRE(site->dataflow);
    REQUIRE(site->dataflow->entryRegisterDomains.size() == 1);
    const auto& domain = site->dataflow->entryRegisterDomains.front();
    CHECK(domain.directCallSites.empty());
    CHECK(domain.rejection == "entry_has_only_non_call_or_address_escape_references");
    CHECK(domain.rejectedReferenceSites == std::vector<uint32_t>{kTableBase + 0x30});
    CHECK(domain.referenceRejections ==
          std::vector<std::string>{"aligned_static_code_pointer_reference"});
  }
}

TEST_CASE("entry-domain recovery rejects incomplete or altered evidence",
          "[codegen][jump-table][entry-domain]") {
  auto analyzeWithDomain = [](AbsoluteSwitch& image, JumpTableEntryRegisterDomainEvidence domain,
                              uint32_t site = kEntryDomainSite, uint32_t blockSize = 0x14) {
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block ownerBlock{kTextBase, blockSize};
    JumpTableEntryRegisterDomainMap domains;
    domains.emplace(7, std::move(domain));
    JumpTableRecoveryInput input;
    input.site = site;
    input.ownerAddress = kTextBase;
    input.trustedOwnerEnd = kTextBase + 0xA0;
    input.preliminaryBlocks = std::span<const Block>(&ownerBlock, 1);
    input.containingRegion = decoded.regionContaining(kTextBase);
    input.entryRegisterDomains = &domains;
    return AnalyzeIndirectSite(decoded, input);
  };

  SECTION("a runtime edge cannot replace complete inbound-reference evidence") {
    auto image = EntryDomainSwitch();
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    auto domain = ProveEntryDomain(decoded);
    domain.allReferencesDirectCalls = false;
    domain.finiteDenseDomain = false;
    domain.rejectedReferenceSites.push_back(kTextBase + 0x180);
    domain.referenceRejections.push_back("aligned_static_code_pointer_reference");
    domain.rejection = "entry_has_non_call_or_address_escape_reference";
    auto rejected = analyzeWithDomain(image, std::move(domain));
    CHECK_FALSE(rejected.selectedTable);
    CHECK(HasFailure(rejected, JumpTableFailure::MissingBound));
    REQUIRE(rejected.dataflow);
    CHECK(rejected.dataflow->switchLikelihood ==
          JumpTableSwitchLikelihood::InsufficientStaticEvidence);
  }

  SECTION("a sparse entry domain is not expanded into an inferred table length") {
    auto image = EntryDomainSwitch();
    JumpTableEntryRegisterDomainEvidence domain;
    domain.entryAddress = kTextBase;
    domain.registerIndex = 7;
    domain.allReferencesDirectCalls = true;
    domain.finiteDenseDomain = false;
    domain.finiteValues = {0, 2};
    domain.rejection = "entry_domain_not_dense_zero_based";
    auto rejected = analyzeWithDomain(image, std::move(domain));
    CHECK_FALSE(rejected.selectedTable);
    CHECK(HasFailure(rejected, JumpTableFailure::MissingBound));
  }

  SECTION("direct references remain distinct from incomplete callsite domains") {
    auto image = EntryDomainSwitch();
    JumpTableEntryRegisterDomainEvidence domain;
    domain.entryAddress = kTextBase;
    domain.registerIndex = 7;
    domain.allReferencesDirectCalls = true;
    domain.finiteDenseDomain = false;
    domain.rejection = "one_or_more_callsite_domains_incomplete";
    JumpTableEntryCallsiteDomainEvidence callsite;
    callsite.callAddress = kTextBase + 0xC4;
    callsite.targetAddress = kTextBase;
    callsite.registerIndex = 7;
    callsite.rejections = {"no_exact_constant_or_unsigned_dominating_guard"};
    domain.callsites.push_back(std::move(callsite));
    auto rejected = analyzeWithDomain(image, std::move(domain));
    CHECK_FALSE(rejected.selectedTable);
    CHECK(HasFailure(rejected, JumpTableFailure::MissingBound));
    REQUIRE(rejected.dataflow);
    CHECK(rejected.dataflow->switchLikelihood ==
          JumpTableSwitchLikelihood::InsufficientStaticEvidence);
  }

  SECTION("the owner must preserve the proven entry register") {
    auto image = EntryDomainSwitch();
    StoreBe32(image.text, 0x00, 0x3D802000);  // lis r12, table@h
    StoreBe32(image.text, 0x04, Mr(7, 3));    // incompatible owner write
    StoreBe32(image.text, 0x08, Rlwinm(0, 7, 2, 0, 29));
    StoreBe32(image.text, 0x0C, Lwzx(0, 12, 0));
    StoreBe32(image.text, 0x10, Mtctr(0));
    StoreBe32(image.text, 0x14, 0x4E800420);
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    auto domain = ProveEntryDomain(decoded);
    auto rejected = analyzeWithDomain(image, std::move(domain), kTextBase + 0x14, 0x18);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(HasFailure(rejected, JumpTableFailure::MissingBound));
    REQUIRE(rejected.dataflow);
    const auto evidence = std::find_if(
        rejected.dataflow->boundCandidates.begin(), rejected.dataflow->boundCandidates.end(),
        [](const auto& candidate) { return candidate.interproceduralEntryDomain; });
    REQUIRE(evidence != rejected.dataflow->boundCandidates.end());
    CHECK(evidence->rejection == "entry_domain_register_modified_before_dispatch");
  }

  SECTION("the entry register must be the exact element-scaled table index") {
    auto image = EntryDomainSwitch();
    StoreBe32(image.text, 0x04, Rlwinm(0, 7, 1, 0, 30));  // scale by two, not word width
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    auto domain = ProveEntryDomain(decoded);
    auto rejected = analyzeWithDomain(image, std::move(domain));
    CHECK_FALSE(rejected.selectedTable);
    CHECK(HasFailure(rejected, JumpTableFailure::MissingBound));
    REQUIRE(rejected.dataflow);
    const auto evidence = std::find_if(
        rejected.dataflow->boundCandidates.begin(), rejected.dataflow->boundCandidates.end(),
        [](const auto& candidate) { return candidate.interproceduralEntryDomain; });
    REQUIRE(evidence != rejected.dataflow->boundCandidates.end());
    CHECK(evidence->rejection == "entry_domain_register_not_exact_scaled_table_index");
  }

  SECTION("an altered raw entry invalidates the whole table") {
    auto image = EntryDomainSwitch();
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    auto domain = ProveEntryDomain(decoded);
    StoreBe32(image.table, 7 * 4, kTextBase + 0x23);  // unaligned final target
    auto rejected = analyzeWithDomain(image, std::move(domain));
    CHECK_FALSE(rejected.selectedTable);
    CHECK(HasFailure(rejected, JumpTableFailure::MixedValidityTargets));
  }

  SECTION("one observed direct call without a finite argument proof remains incomplete") {
    auto image = EntryDomainSwitch();
    StoreBe32(image.text, 0xF4, Bl(kTextBase + 0xF4, kTextBase));
    StoreBe32(image.text, 0xF8, 0x4E800020);
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block block{kTextBase + 0xF0, 0x0C};
    auto callsite = AnalyzeDirectCallArgumentDomain(decoded, std::span<const Block>(&block, 1),
                                                    block.base, kTextBase + 0xF4, kTextBase, 7);
    CHECK_FALSE(callsite.complete);
    CHECK(callsite.finiteValues.empty());
    CHECK(std::find(callsite.rejections.begin(), callsite.rejections.end(),
                    "no_exact_constant_or_unsigned_dominating_guard") != callsite.rejections.end());
  }

  SECTION("a signed callsite guard does not prove a zero-based unsigned domain") {
    auto image = EntryDomainSwitch();
    StoreBe32(image.text, 0xF4, 0x2C070007);  // cmpwi r7, 7
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block block{kTextBase + 0xF0, 0x1C};
    auto callsite = AnalyzeDirectCallArgumentDomain(decoded, std::span<const Block>(&block, 1),
                                                    block.base, kTextBase + 0xFC, kTextBase, 7);
    CHECK_FALSE(callsite.complete);
    CHECK(callsite.finiteValues.empty());
  }

  SECTION("the exhausted callsite budget is reported without widening another limit") {
    auto image = EntryDomainSwitch();
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block block{kTextBase + 0xF0, 0x1C};
    JumpTableRecoveryLimits limits;
    limits.maxStates = 1;
    auto callsite =
        AnalyzeDirectCallArgumentDomain(decoded, std::span<const Block>(&block, 1), block.base,
                                        kTextBase + 0xFC, kTextBase, 7, limits);
    CHECK_FALSE(callsite.complete);
    REQUIRE(callsite.limitHit);
    CHECK(callsite.exhaustedBudget == "max_states");
    CHECK(callsite.budgetLimit == 1);
    CHECK(callsite.budgetObserved > callsite.budgetLimit);
    CHECK(callsite.rejections == std::vector<std::string>{"callsite_reaching_definition_limit"});
  }
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

TEST_CASE("signed upper bounds cannot compete with an exact unsigned switch bound",
          "[codegen][jump-table][bound-disambiguation]") {
  AbsoluteSwitch image;
  StoreBe32(image.text, 0x00, 0x2C030004);  // cmpwi r3, 4: negatives remain possible
  StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x30, 12, 1));
  StoreBe32(image.text, 0x08, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x0C, Bc(kTextBase + 0x0C, kTextBase + 0x30, 12, 1));
  StoreBe32(image.text, 0x10, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x14, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x18, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x1C, Mtctr(5));
  StoreBe32(image.text, 0x20, 0x4E800420);  // bctr

  auto recovered = Analyze(image, kTextBase + 0x20);
  INFO("failures=" << FailureNames(recovered));
  REQUIRE(recovered.selectedTable);
  CHECK(recovered.failures.empty());
  CHECK(recovered.selectedTable->caseCount == 3);
  CHECK(recovered.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
  REQUIRE(recovered.dataflow);
  const auto signedBound = std::find_if(
      recovered.dataflow->boundCandidates.begin(), recovered.dataflow->boundCandidates.end(),
      [](const auto& bound) { return bound.compareAddress == kTextBase; });
  REQUIRE(signedBound != recovered.dataflow->boundCandidates.end());
  CHECK(signedBound->signedCompare);
  CHECK_FALSE(signedBound->finiteDenseDomain);
  CHECK(signedBound->rejection == "signed_upper_bound_does_not_exclude_negative_indices");

  SECTION("a signed upper bound alone does not establish a finite switch domain") {
    StoreBe32(image.text, 0x08, 0x60000000);  // remove unsigned compare
    StoreBe32(image.text, 0x0C, 0x60000000);  // remove unsigned guard
    auto rejected = Analyze(image, kTextBase + 0x20);
    CHECK_FALSE(rejected.selectedTable);
  }
}

TEST_CASE("dominance is not inferred when a bounded CFG search exhausts",
          "[codegen][jump-table][bound-disambiguation]") {
  AbsoluteSwitch image;
  image.text.resize(0xC00);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // long linear owner

  constexpr uint32_t kBypassOffset = 0x900;
  constexpr uint32_t kExactOffset = 0x920;
  constexpr uint32_t kSiteOffset = 0x938;
  StoreBe32(image.text, 0x8F0, 0x806E0000);  // lwz r3, 0(r14)
  StoreBe32(image.text, kBypassOffset,
            Bc(kTextBase + kBypassOffset, kTextBase + kExactOffset, 12, 2));
  StoreBe32(image.text, 0x904, 0x28030004);  // non-dominating cmplwi r3, 4
  StoreBe32(image.text, 0x908, Bc(kTextBase + 0x908, kTextBase + 0xA60, 12, 1));
  StoreBe32(image.text, 0x90C, B(kTextBase + 0x90C, kTextBase + kExactOffset));
  StoreBe32(image.text, kExactOffset, 0x28030002);  // exact cmplwi r3, 2
  StoreBe32(image.text, 0x924, Bc(kTextBase + 0x924, kTextBase + 0xA60, 12, 1));
  StoreBe32(image.text, 0x928, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x92C, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x930, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x934, Mtctr(5));
  StoreBe32(image.text, kSiteOffset, 0x4E800420);  // bctr
  StoreBe32(image.text, 0xA60, 0x4E800020);        // default
  StoreBe32(image.text, 0xA80, 0x4E800020);
  StoreBe32(image.text, 0xA90, 0x4E800020);
  StoreBe32(image.text, 0xAA0, 0x4E800020);
  StoreBe32(image.table, 0x00, kTextBase + 0xA80);
  StoreBe32(image.table, 0x04, kTextBase + 0xA90);
  StoreBe32(image.table, 0x08, kTextBase + 0xAA0);

  JumpTableRecoveryLimits limits;
  limits.maxStates = 512;
  auto recovered = Analyze(image, kTextBase + kSiteOffset, nullptr, limits, 0xAB0);
  INFO("failures=" << FailureNames(recovered));
  REQUIRE(recovered.selectedTable);
  CHECK(recovered.failures.empty());
  CHECK(recovered.selectedTable->caseCount == 3);
  CHECK(recovered.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0xA80, kTextBase + 0xA90, kTextBase + 0xAA0});
  REQUIRE(recovered.dataflow);
  const auto bypassedBound = std::find_if(
      recovered.dataflow->boundCandidates.begin(), recovered.dataflow->boundCandidates.end(),
      [](const auto& bound) { return bound.compareAddress == kTextBase + 0x904; });
  REQUIRE(bypassedBound != recovered.dataflow->boundCandidates.end());
  CHECK_FALSE(bypassedBound->dominatesDispatch);
  CHECK(bypassedBound->rejection == "compare_does_not_dominate_dispatch");
  CHECK(std::find(recovered.dataflow->rejectionEvidence.begin(),
                  recovered.dataflow->rejectionEvidence.end(),
                  "bound_census_limit") != recovered.dataflow->rejectionEvidence.end());
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
  image.text.resize(0x500);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop
  constexpr uint32_t kSwitch = kTextBase + 0x400;
  constexpr uint32_t kSite = kSwitch + 0x18;
  StoreBe32(image.text, 0x400, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0x404, Bc(kSwitch + 0x04, kSwitch + 0x30, 12, 1));
  StoreBe32(image.text, 0x408, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x40C, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0x410, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0x414, Mtctr(5));
  StoreBe32(image.text, 0x418, 0x4E800420);  // bctr
  StoreBe32(image.text, 0x430, 0x4E800020);  // default: blr

  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block preliminaryBlock{kSwitch, 0x80};
  JumpTableRecoveryInput preliminaryInput{
      .site = kSite,
      .ownerAddress = kSwitch,
      .preliminaryBlocks = std::span<const Block>(&preliminaryBlock, 1),
      .containingRegion = decoded.regionContaining(kSwitch),
      .limits = {},
  };
  auto prior = AnalyzeIndirectSite(decoded, preliminaryInput);
  REQUIRE(prior.selectedTable);
  REQUIRE(prior.failures.empty());

  // Case targets 0x40/0x50/0x60 enter the newly expanded block. Its long,
  // definition-preserving fallthrough rejoins the original switch at 0x400.
  const std::array expandedBlocks{Block{kTextBase + 0x40, 0x3C0}, preliminaryBlock};
  JumpTableRecoveryLimits truncatedLimits;
  truncatedLimits.maxStates = 64;
  JumpTableRecoveryInput input{
      .site = kSite,
      .ownerAddress = kSwitch,
      .preliminaryBlocks = expandedBlocks,
      .containingRegion = decoded.regionContaining(kSwitch),
      .priorAutomaticTable = &*prior.selectedTable,
      .limits = truncatedLimits,
  };

  auto truncated = AnalyzeIndirectSite(decoded, input);
  REQUIRE_FALSE(truncated.selectedTable);
  CHECK(truncated.failures == std::vector{JumpTableFailure::AnalysisLimit});

  JumpTableRecoveryInput directRetryInput = input;
  directRetryInput.limits.maxStates = truncatedLimits.maxStates * 32;
  auto directRetry = AnalyzeIndirectSite(decoded, directRetryInput);
  REQUIRE(directRetry.selectedTable);
  CHECK(directRetry.failures.empty());
  CHECK(SameValidatedTable(*directRetry.selectedTable, *prior.selectedTable));
  CHECK(directRetryInput.limits.maxBackwardInstructions == input.limits.maxBackwardInstructions);
  CHECK(directRetryInput.limits.maxPredecessors == input.limits.maxPredecessors);
  CHECK(directRetryInput.limits.maxCfgTopologyNodes == input.limits.maxCfgTopologyNodes);
  CHECK(directRetryInput.limits.maxEntries == input.limits.maxEntries);

  JumpTableRecoveryStats acceptedStats;
  auto accepted = AnalyzeIndirectSiteWithPriorLimitRetry(decoded, input, &acceptedStats);
  REQUIRE(accepted.selectedTable);
  CHECK(SameValidatedTable(*accepted.selectedTable, *prior.selectedTable));
  CHECK(accepted.selectedTable->confidence == "validated_after_expanded_cfg_limit_retry");
  REQUIRE(accepted.limitRetry);
  CHECK(accepted.limitRetry->exhaustedBudget == "max_states");
  CHECK(accepted.limitRetry->initialBudgetValue == 64);
  CHECK(accepted.limitRetry->retryBudgetValue == 2048);
  CHECK(accepted.limitRetry->initialFailures == std::vector{JumpTableFailure::AnalysisLimit});
  CHECK(accepted.limitRetry->retryFailures.empty());
  CHECK(accepted.limitRetry->exactPriorTableMatch);
  CHECK(accepted.limitRetry->accepted);
  CHECK(acceptedStats.indirectSites == 1);
  CHECK(acceptedStats.recoveredTables == 1);
  CHECK(acceptedStats.unresolvedSites == 0);

  JumpTable mismatchedPrior = *prior.selectedTable;
  mismatchedPrior.rawEntries[0].target += 4;
  input.priorAutomaticTable = &mismatchedPrior;
  JumpTableRecoveryStats rejectedStats;
  auto rejected = AnalyzeIndirectSiteWithPriorLimitRetry(decoded, input, &rejectedStats);
  CHECK_FALSE(rejected.selectedTable);
  CHECK(rejected.failures == std::vector{JumpTableFailure::AnalysisLimit});
  REQUIRE(rejected.limitRetry);
  CHECK(rejected.limitRetry->exhaustedBudget == "max_states");
  CHECK(rejected.limitRetry->initialFailures == std::vector{JumpTableFailure::AnalysisLimit});
  CHECK(rejected.limitRetry->retryFailures.empty());
  CHECK_FALSE(rejected.limitRetry->exactPriorTableMatch);
  CHECK_FALSE(rejected.limitRetry->accepted);
  CHECK(rejectedStats.indirectSites == 1);
  CHECK(rejectedStats.recoveredTables == 0);
  CHECK(rejectedStats.unresolvedSites == 1);

  JumpTable rawMismatchedPrior = *prior.selectedTable;
  rawMismatchedPrior.rawEntries[0].rawValue ^= 1;
  input.priorAutomaticTable = &rawMismatchedPrior;
  JumpTableRecoveryStats rawRejectedStats;
  auto rawRejected = AnalyzeIndirectSiteWithPriorLimitRetry(decoded, input, &rawRejectedStats);
  CHECK_FALSE(rawRejected.selectedTable);
  CHECK(rawRejected.failures == std::vector{JumpTableFailure::AnalysisLimit});
  REQUIRE(rawRejected.limitRetry);
  CHECK(rawRejected.limitRetry->exhaustedBudget == "max_states");
  CHECK(rawRejected.limitRetry->initialFailures == std::vector{JumpTableFailure::AnalysisLimit});
  CHECK(rawRejected.limitRetry->retryFailures.empty());
  CHECK_FALSE(rawRejected.limitRetry->exactPriorTableMatch);
  CHECK_FALSE(rawRejected.limitRetry->accepted);
  CHECK(rawRejectedStats.indirectSites == 1);
  CHECK(rawRejectedStats.recoveredTables == 0);
  CHECK(rawRejectedStats.unresolvedSites == 1);
}

TEST_CASE("an exact prior local slice survives repeated max_states exhaustion",
          "[codegen][jump-table][limit-retry][local-slice]") {
  AbsoluteSwitch image;
  image.text.resize(0xC00);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  constexpr uint32_t kSwitch = kTextBase + 0xB00;
  constexpr uint32_t kSite = kSwitch + 0x18;
  StoreBe32(image.text, 0xB00, 0x28030002);  // cmplwi r3, 2
  StoreBe32(image.text, 0xB04, Bc(kSwitch + 0x04, kSwitch + 0x30, 12, 1));
  StoreBe32(image.text, 0xB08, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0xB0C, Rlwinm(3, 3, 2, 0, 29));
  StoreBe32(image.text, 0xB10, Lwzx(5, 4, 3));
  StoreBe32(image.text, 0xB14, Mtctr(5));
  StoreBe32(image.text, 0xB18, 0x4E800420);  // bctr
  StoreBe32(image.text, 0xB30, 0x4E800020);  // default: blr

  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block preliminaryBlock{kSwitch, 0x80};
  JumpTableRecoveryInput preliminaryInput{
      .site = kSite,
      .ownerAddress = kSwitch,
      .preliminaryBlocks = std::span<const Block>(&preliminaryBlock, 1),
      .containingRegion = decoded.regionContaining(kSwitch),
      .limits = {},
  };
  auto prior = AnalyzeIndirectSite(decoded, preliminaryInput);
  REQUIRE(prior.selectedTable);
  REQUIRE(prior.failures.empty());

  const std::array expandedBlocks{Block{kTextBase + 0x40, 0xAC0}, preliminaryBlock};
  JumpTableRecoveryLimits constrainedLimits;
  constrainedLimits.maxStates = 16;
  JumpTableRecoveryInput input{
      .site = kSite,
      .ownerAddress = kSwitch,
      .preliminaryBlocks = expandedBlocks,
      .containingRegion = decoded.regionContaining(kSwitch),
      .priorAutomaticTable = &*prior.selectedTable,
      .limits = constrainedLimits,
  };

  auto initial = AnalyzeIndirectSite(decoded, input);
  CHECK_FALSE(initial.selectedTable);
  CHECK(initial.failures == std::vector{JumpTableFailure::AnalysisLimit});
  REQUIRE(initial.dataflow);
  REQUIRE(initial.dataflow->exhaustedBudgets.size() == 1);
  CHECK(initial.dataflow->exhaustedBudgets.front().budget == "max_states");
  CHECK(initial.dataflow->exhaustedBudgets.front().limit == 16);

  auto accepted = AnalyzeIndirectSiteWithPriorLimitRetry(decoded, input);
  REQUIRE(accepted.selectedTable);
  CHECK(accepted.failures.empty());
  CHECK(accepted.selectedTable->targets == prior.selectedTable->targets);
  CHECK(accepted.selectedTable->rawEntries == prior.selectedTable->rawEntries);
  REQUIRE(accepted.limitRetry);
  CHECK(accepted.limitRetry->exhaustedBudget == "max_states");
  CHECK(accepted.limitRetry->initialBudgetValue == 16);
  CHECK(accepted.limitRetry->retryBudgetValue == 512);
  CHECK(accepted.limitRetry->initialFailures == std::vector{JumpTableFailure::AnalysisLimit});
  CHECK(accepted.limitRetry->retryFailures.empty());
  CHECK(accepted.limitRetry->exactPriorTableMatch);
  CHECK(accepted.limitRetry->accepted);
  REQUIRE(accepted.dataflow);
  CHECK(std::any_of(accepted.dataflow->exhaustedBudgets.begin(),
                    accepted.dataflow->exhaustedBudgets.end(), [](const auto& exhausted) {
                      return exhausted.budget == "max_states" && exhausted.limit == 512 &&
                             exhausted.observed > exhausted.limit;
                    }));

  JumpTable alteredPrior = *prior.selectedTable;
  alteredPrior.rawEntries[0].rawValue ^= 1;
  input.priorAutomaticTable = &alteredPrior;
  auto rejected = AnalyzeIndirectSiteWithPriorLimitRetry(decoded, input);
  CHECK_FALSE(rejected.selectedTable);
  REQUIRE(rejected.limitRetry);
  CHECK_FALSE(rejected.limitRetry->exactPriorTableMatch);
  CHECK_FALSE(rejected.limitRetry->accepted);
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

TEST_CASE("direct bounded table index abstracts only path-dependent pre-bound provenance",
          "[codegen][jump-table][bounded-index]") {
  auto image = DirectBoundedAmbiguousIndexSwitch();
  auto analysis = Analyze(image, kTextBase + 0x34);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.failures.empty());
  CHECK(analysis.selectedTable->confidence == "validated_direct_bounded_ambiguous_index");
  CHECK(analysis.selectedTable->kind == JumpTableKind::RelativeOffset);
  CHECK(analysis.selectedTable->elementWidth == 1);
  CHECK_FALSE(analysis.selectedTable->elementSigned);
  CHECK(analysis.selectedTable->targetScale == 4);
  CHECK(analysis.selectedTable->indexRegister == 3);
  CHECK(analysis.selectedTable->tableAddress == kTableBase);
  CHECK(analysis.selectedTable->storageEnd == kTableBase + 3);
  CHECK(analysis.selectedTable->anchorAddress == kTextBase);
  CHECK(analysis.selectedTable->rawEntries.size() == 3);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
  REQUIRE(analysis.dataflow);
  CHECK(analysis.dataflow->mergeShape == "bounded_direct_index");
  CHECK_FALSE(analysis.dataflow->diagnosticProbe.attempted);
  CHECK(std::any_of(analysis.selectedTable->evidence.begin(),
                    analysis.selectedTable->evidence.end(),
                    [](const auto& evidence) { return evidence.role == "bounded_index_compare"; }));

  SECTION("a resolver limit after an exact finite guard does not require pre-bound provenance") {
    JumpTableRecoveryLimits limits;
    limits.maxStates = 9;
    auto limited = Analyze(image, kTextBase + 0x34, nullptr, limits);
    INFO("failures=" << FailureNames(limited));
    REQUIRE(limited.selectedTable);
    CHECK(limited.failures.empty());
    CHECK(limited.selectedTable->confidence == "validated_local_bounded_slice_after_state_limit");
    CHECK(limited.selectedTable->targets == analysis.selectedTable->targets);
    CHECK(limited.selectedTable->rawEntries == analysis.selectedTable->rawEntries);
    CHECK(std::any_of(limited.selectedTable->evidence.begin(),
                      limited.selectedTable->evidence.end(), [](const auto& evidence) {
                        return evidence.role == "local_bounded_slice_state_limit_compare";
                      }));
    REQUIRE(limited.dataflow);
    CHECK(limited.dataflow->mergeShape == "bounded_index_after_state_limit");
    REQUIRE(limited.dataflow->exhaustedBudgets.size() == 1);
    CHECK(limited.dataflow->exhaustedBudgets.front().budget == "max_states");
    CHECK(limited.dataflow->exhaustedBudgets.front().limit == 9);
    CHECK(limited.dataflow->exhaustedBudgets.front().observed > 1);
  }

  SECTION("the state-limit fallback rejects an unrelated index overwrite after the guard") {
    auto redefined = DirectBoundedAmbiguousIndexSwitch();
    StoreBe32(redefined.text, 0x18, Addi(3, 0, 1));
    JumpTableRecoveryLimits limits;
    limits.maxStates = 9;
    auto rejected = Analyze(redefined, kTextBase + 0x34, nullptr, limits);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(rejected.failures == std::vector{JumpTableFailure::AnalysisLimit});
    REQUIRE(rejected.dataflow);
    CHECK_FALSE(rejected.dataflow->rejectionEvidence.empty());
  }

  SECTION("exact initial proof survives a guarded case-edge loop") {
    auto looped = DirectBoundedAmbiguousIndexSwitch();
    StoreBe32(looped.text, 0x40, B(kTextBase + 0x40, kTextBase + 0x10));
    auto loopedView = looped.view();
    DecodedBinary loopedDecoded(loopedView);
    loopedDecoded.decode();
    const Block expandedBlock{kTextBase, 0x80};
    JumpTableRecoveryInput initialInput{
        .site = kTextBase + 0x34,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = loopedDecoded.regionContaining(kTextBase),
        .limits = {},
    };
    auto initial = AnalyzeIndirectSite(loopedDecoded, initialInput);
    REQUIRE(initial.selectedTable);
    CHECK(initial.selectedTable->confidence == "validated_direct_bounded_ambiguous_index");
    JumpTableRecoveryInput expandedInput = initialInput;
    expandedInput.priorAutomaticTable = &*initial.selectedTable;
    auto expanded = AnalyzeIndirectSite(loopedDecoded, expandedInput);
    REQUIRE(expanded.selectedTable);
    CHECK(expanded.selectedTable->targets ==
          std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
    CHECK(expanded.selectedTable->rawEntries == initial.selectedTable->rawEntries);
    CHECK(expanded.selectedTable->confidence ==
          "validated_exact_prior_bound_family_local_bounded_slice");
  }

  SECTION("a case-edge loop that bypasses the bound is rejected") {
    auto unguarded = DirectBoundedAmbiguousIndexSwitch();
    StoreBe32(unguarded.text, 0x40, B(kTextBase + 0x40, kTextBase + 0x1C));
    auto unguardedView = unguarded.view();
    DecodedBinary unguardedDecoded(unguardedView);
    unguardedDecoded.decode();
    const Block expandedBlock{kTextBase, 0x80};
    JumpTableRecoveryInput initialInput{
        .site = kTextBase + 0x34,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = unguardedDecoded.regionContaining(kTextBase),
        .limits = {},
    };
    auto initial = AnalyzeIndirectSite(unguardedDecoded, initialInput);
    REQUIRE(initial.selectedTable);
    JumpTableRecoveryInput expandedInput = initialInput;
    expandedInput.priorAutomaticTable = &*initial.selectedTable;
    auto expanded = AnalyzeIndirectSite(unguardedDecoded, expandedInput);
    CHECK_FALSE(expanded.selectedTable);
    CHECK(HasFailure(expanded, JumpTableFailure::AmbiguousReachingDefinition));
  }

  SECTION("an intervening index write is not abstracted") {
    auto redefined = DirectBoundedAmbiguousIndexSwitch();
    StoreBe32(redefined.text, 0x18, Addi(3, 3, 0));
    auto rejected = Analyze(redefined, kTextBase + 0x34);
    CHECK_FALSE(rejected.selectedTable);
  }

  SECTION("a bound on an unrelated register is not borrowed") {
    auto unrelated = DirectBoundedAmbiguousIndexSwitch();
    StoreBe32(unrelated.text, 0x10, 0x28080002);  // cmplwi r8, 2
    auto rejected = Analyze(unrelated, kTextBase + 0x34);
    CHECK_FALSE(rejected.selectedTable);
  }

  SECTION("mixed-validity raw entries reject the entire table") {
    auto mixed = DirectBoundedAmbiguousIndexSwitch();
    mixed.table[2] = 0x80;  // anchor + 0x200 is outside the executable fixture
    auto rejected = Analyze(mixed, kTextBase + 0x34);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(rejected.failures == std::vector{JumpTableFailure::MixedValidityTargets});
  }
}

TEST_CASE("a finite guard may feed a separately scaled halfword table index",
          "[codegen][jump-table][bounded-index][transformed-index]") {
  auto image = TransformedBoundedAmbiguousIndexSwitch();
  auto analysis = Analyze(image, kTextBase + 0x34);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.failures.empty());
  CHECK(analysis.selectedTable->confidence == "validated_local_bounded_transformed_index");
  CHECK(analysis.selectedTable->kind == JumpTableKind::RelativeOffset);
  CHECK(analysis.selectedTable->elementWidth == 2);
  CHECK_FALSE(analysis.selectedTable->elementSigned);
  CHECK(analysis.selectedTable->targetScale == 1);
  CHECK(analysis.selectedTable->indexRegister == 3);
  CHECK(analysis.selectedTable->caseCount == 3);
  CHECK(analysis.selectedTable->tableAddress == kTableBase);
  CHECK(analysis.selectedTable->storageEnd == kTableBase + 6);
  CHECK(analysis.selectedTable->anchorAddress == kTextBase);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
  REQUIRE(analysis.dataflow);
  CHECK(analysis.dataflow->mergeShape == "bounded_transformed_index");
  CHECK(std::any_of(
      analysis.selectedTable->evidence.begin(), analysis.selectedTable->evidence.end(),
      [](const auto& evidence) { return evidence.role == "local_bounded_slice_definition"; }));

  SECTION("an exact transformed table survives case-expanded input ambiguity") {
    auto looped = TransformedBoundedAmbiguousIndexSwitch();
    StoreBe32(looped.text, 0x40, B(kTextBase + 0x40, kTextBase));
    auto view = looped.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block preliminaryBlock{kTextBase, 0x38};
    JumpTableRecoveryInput preliminaryInput{
        .site = kTextBase + 0x34,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&preliminaryBlock, 1),
        .containingRegion = decoded.regionContaining(kTextBase),
        .limits = {},
    };
    auto preliminary = AnalyzeIndirectSite(decoded, preliminaryInput);
    REQUIRE(preliminary.selectedTable);
    CHECK(preliminary.selectedTable->confidence == "validated_local_bounded_transformed_index");

    const Block expandedBlock{kTextBase, 0x80};
    JumpTableRecoveryInput expandedInput{
        .site = kTextBase + 0x34,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = decoded.regionContaining(kTextBase),
        .priorAutomaticTable = &*preliminary.selectedTable,
        .limits = {},
    };
    auto expanded = AnalyzeIndirectSite(decoded, expandedInput);
    REQUIRE(expanded.selectedTable);
    CHECK(expanded.failures.empty());
    CHECK(expanded.selectedTable->targets == preliminary.selectedTable->targets);
    CHECK(expanded.selectedTable->rawEntries == preliminary.selectedTable->rawEntries);
    CHECK(expanded.selectedTable->confidence ==
          "validated_exact_prior_bound_family_local_bounded_slice");
  }

  SECTION("a transformed case edge that bypasses the bound is rejected") {
    auto bypassed = TransformedBoundedAmbiguousIndexSwitch();
    StoreBe32(bypassed.text, 0x40, B(kTextBase + 0x40, kTextBase + 0x1C));
    auto view = bypassed.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block preliminaryBlock{kTextBase, 0x38};
    JumpTableRecoveryInput preliminaryInput{
        .site = kTextBase + 0x34,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&preliminaryBlock, 1),
        .containingRegion = decoded.regionContaining(kTextBase),
        .limits = {},
    };
    auto preliminary = AnalyzeIndirectSite(decoded, preliminaryInput);
    REQUIRE(preliminary.selectedTable);

    const Block expandedBlock{kTextBase, 0x80};
    JumpTableRecoveryInput expandedInput{
        .site = kTextBase + 0x34,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = decoded.regionContaining(kTextBase),
        .priorAutomaticTable = &*preliminary.selectedTable,
        .limits = {},
    };
    auto rejected = AnalyzeIndirectSite(decoded, expandedInput);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(HasFailure(rejected, JumpTableFailure::AmbiguousReachingDefinition));
  }

  SECTION("altered prior raw entries cannot retain a transformed table") {
    auto looped = TransformedBoundedAmbiguousIndexSwitch();
    StoreBe32(looped.text, 0x40, B(kTextBase + 0x40, kTextBase));
    auto view = looped.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block preliminaryBlock{kTextBase, 0x38};
    JumpTableRecoveryInput preliminaryInput{
        .site = kTextBase + 0x34,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&preliminaryBlock, 1),
        .containingRegion = decoded.regionContaining(kTextBase),
        .limits = {},
    };
    auto preliminary = AnalyzeIndirectSite(decoded, preliminaryInput);
    REQUIRE(preliminary.selectedTable);
    JumpTable alteredPrior = *preliminary.selectedTable;
    alteredPrior.rawEntries[0].rawValue ^= 1;

    const Block expandedBlock{kTextBase, 0x80};
    JumpTableRecoveryInput expandedInput{
        .site = kTextBase + 0x34,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = decoded.regionContaining(kTextBase),
        .priorAutomaticTable = &alteredPrior,
        .limits = {},
    };
    auto rejected = AnalyzeIndirectSite(decoded, expandedInput);
    CHECK_FALSE(rejected.selectedTable);
    REQUIRE(rejected.dataflow);
    CHECK(std::any_of(rejected.dataflow->rejectionEvidence.begin(),
                      rejected.dataflow->rejectionEvidence.end(), [](const auto& evidence) {
                        return evidence.find("prior_table_semantics_mismatch") != std::string::npos;
                      }));
  }

  SECTION("a transformed index still requires a finite bound or domain") {
    auto unbounded = TransformedBoundedAmbiguousIndexSwitch();
    StoreBe32(unbounded.text, 0x10, 0x60000000);  // remove cmplwi
    auto rejected = Analyze(unbounded, kTextBase + 0x34);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(rejected.failures == std::vector{JumpTableFailure::AmbiguousReachingDefinition});
  }

  SECTION("the bounded state must feed the scaled index") {
    auto unrelated = TransformedBoundedAmbiguousIndexSwitch();
    StoreBe32(unrelated.text, 0x20, Rlwinm(0, 8, 1, 0, 30));
    auto rejected = Analyze(unrelated, kTextBase + 0x34);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(rejected.failures == std::vector{JumpTableFailure::MissingBound});
  }

  SECTION("the bounded state cannot be overwritten after the guard") {
    auto overwritten = TransformedBoundedAmbiguousIndexSwitch();
    StoreBe32(overwritten.text, 0x18, Addi(3, 0, 1));
    auto rejected = Analyze(overwritten, kTextBase + 0x34);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(rejected.failures == std::vector{JumpTableFailure::MissingBound});
  }

  SECTION("a non-scaling rotate-mask is not accepted as the index transform") {
    auto incompatible = TransformedBoundedAmbiguousIndexSwitch();
    StoreBe32(incompatible.text, 0x20, Rlwinm(0, 3, 1, 4, 30));
    auto rejected = Analyze(incompatible, kTextBase + 0x34);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(rejected.failures == std::vector{JumpTableFailure::MissingBound});
  }

  SECTION("mixed-validity transformed tables are rejected whole") {
    auto mixed = TransformedBoundedAmbiguousIndexSwitch();
    StoreBe16(mixed.table, 0x04, 0x200);
    auto rejected = Analyze(mixed, kTextBase + 0x34);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(rejected.failures == std::vector{JumpTableFailure::MixedValidityTargets});
  }
}

TEST_CASE("a scheduled lhax does not hide a switch guard before max_states exhaustion",
          "[codegen][jump-table][bounded-index][opcode-coverage]") {
  AbsoluteSwitch image;
  image.text.resize(0x300);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  // The bound and table slice are local and exact, while the index provenance
  // is deliberately farther away than the focused resolver budget. The
  // scheduler may place an unrelated signed indexed load between cmplwi and
  // its guard; that instruction must be decoded as a non-CR-writing lhax, not
  // treated as an unknown barrier.
  StoreBe32(image.text, 0x00, 0x81660000);   // lwz r11, 0(r6)
  StoreBe32(image.text, 0x200, 0x280B0002);  // cmplwi r11, 2
  StoreBe32(image.text, 0x204, Lhax(29, 30, 9));
  StoreBe32(image.text, 0x218, Bc(kTextBase + 0x218, kTextBase + 0x280, 12, 1));  // bgt default
  StoreBe32(image.text, 0x21C, 0x3D802000);  // lis r12, table@h
  StoreBe32(image.text, 0x220, Lbzx(0, 12, 11));
  StoreBe32(image.text, 0x224, Rlwinm(0, 0, 2, 0, 29));
  StoreBe32(image.text, 0x228, 0x3D801000);  // lis r12, anchor@h
  StoreBe32(image.text, 0x22C, Add(12, 12, 0));
  StoreBe32(image.text, 0x230, Mtctr(12));
  StoreBe32(image.text, 0x234, 0x60000000);  // scheduled nop
  StoreBe32(image.text, 0x238, 0x4E800420);  // bctr
  StoreBe32(image.text, 0x250, 0x4E800020);
  StoreBe32(image.text, 0x260, 0x4E800020);
  StoreBe32(image.text, 0x270, 0x4E800020);
  StoreBe32(image.text, 0x280, 0x4E800020);
  image.table[0] = 0x94;
  image.table[1] = 0x98;
  image.table[2] = 0x9C;

  JumpTableRecoveryLimits limits;
  limits.maxStates = 32;
  auto analysis = Analyze(image, kTextBase + 0x238, nullptr, limits, 0x284);
  REQUIRE(analysis.selectedTable);
  CHECK(analysis.failures.empty());
  CHECK(analysis.selectedTable->kind == JumpTableKind::RelativeOffset);
  CHECK(analysis.selectedTable->elementWidth == 1);
  CHECK_FALSE(analysis.selectedTable->elementSigned);
  CHECK(analysis.selectedTable->targetScale == 4);
  CHECK(analysis.selectedTable->caseCount == 3);
  CHECK(analysis.selectedTable->tableAddress == kTableBase);
  CHECK(analysis.selectedTable->storageEnd == kTableBase + 3);
  CHECK(analysis.selectedTable->anchorAddress == kTextBase);
  CHECK(analysis.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x250, kTextBase + 0x260, kTextBase + 0x270});
  CHECK(analysis.selectedTable->confidence == "validated_local_bounded_slice_after_state_limit");
  REQUIRE(analysis.dataflow);
  CHECK(std::any_of(analysis.dataflow->boundCandidates.begin(),
                    analysis.dataflow->boundCandidates.end(), [](const auto& bound) {
                      return bound.compareAddress == kTextBase + 0x200 &&
                             bound.guardAddress == kTextBase + 0x218 && bound.finiteDenseDomain;
                    }));
  CHECK(std::any_of(analysis.dataflow->exhaustedBudgets.begin(),
                    analysis.dataflow->exhaustedBudgets.end(), [](const auto& budget) {
                      return budget.budget == "max_states" && budget.limit == 32 &&
                             budget.observed > budget.limit;
                    }));

  SECTION("a real intervening condition-register write is not crossed") {
    auto clobbered = image;
    StoreBe32(clobbered.text, 0x204, Rlwinm(29, 30, 0, 0, 31) | 1);  // record-form copy
    auto rejected = Analyze(clobbered, kTextBase + 0x238, nullptr, limits, 0x284);
    CHECK_FALSE(rejected.selectedTable);
    CHECK(rejected.failures == std::vector{JumpTableFailure::AnalysisLimit});
  }
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

TEST_CASE("local index fallbacks preserve incomplete prior-case paths", "[codegen][jump-table]") {
  auto analyze = [](bool loadedIndex) {
    AbsoluteSwitch image;
    StoreBe32(image.text, 0x00, Addi(6, 0, 7));
    StoreBe32(image.text, 0x04, B(kTextBase + 0x04, kTextBase + 0x14));
    StoreBe32(image.text, 0x10, B(kTextBase + 0x10, kTextBase + 0x14));
    StoreBe32(image.text, 0x14, loadedIndex ? 0x88660000 : Addi(3, 6, -1));  // lbz/addi r3, ...r6
    StoreBe32(image.text, 0x18, 0x28030002);                                 // cmplwi r3, 2
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

TEST_CASE("case-expanded CFG carries an upstream bounded index to a secondary table",
          "[codegen][jump-table][integration][inherited-bound]") {
  auto makeImage = [] {
    AbsoluteSwitch image;
    for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
      StoreBe32(image.text, offset, 0x60000000);  // nop

    StoreBe32(image.text, 0x00, 0x281C0002);  // cmplwi r28, 2
    StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x30, 12, 1));
    StoreBe32(image.text, 0x08, 0x3C802000);  // lis r4, table@h
    StoreBe32(image.text, 0x0C, Mr(7, 28));
    StoreBe32(image.text, 0x10, Rlwinm(7, 7, 2, 0, 29));
    StoreBe32(image.text, 0x14, Lwzx(5, 4, 7));
    StoreBe32(image.text, 0x18, Mtctr(5));
    StoreBe32(image.text, 0x1C, 0x4E800420);  // first bctr
    StoreBe32(image.text, 0x30, 0x4E800020);  // default
    StoreBe32(image.text, 0x40, Bc(kTextBase + 0x40, kTextBase + 0x40, 4, 2));
    StoreBe32(image.text, 0x44, B(kTextBase + 0x44, kTextBase + 0xA0));
    StoreBe32(image.text, 0x60, B(kTextBase + 0x60, kTextBase + 0xF0) | 1);  // bl, preserves r28
    StoreBe32(image.text, 0x64, B(kTextBase + 0x64, kTextBase + 0xA0));
    StoreBe32(image.text, 0x80, B(kTextBase + 0x80, kTextBase + 0xA0));

    // A second switch reuses nonvolatile r28 after every validated case edge.
    // It has no
    // new compare: the first switch's exact unsigned bound is still in force.
    StoreBe32(image.text, 0xA0, 0x3C802000);  // lis r4, table@h
    StoreBe32(image.text, 0xA4, 0x60840010);  // ori r4, r4, table2@l
    StoreBe32(image.text, 0xA8, Mr(8, 28));
    StoreBe32(image.text, 0xAC, Rlwinm(8, 8, 2, 0, 29));
    StoreBe32(image.text, 0xB0, Lwzx(5, 4, 8));
    StoreBe32(image.text, 0xB4, Mtctr(5));
    StoreBe32(image.text, 0xB8, 0x4E800420);  // second bctr
    StoreBe32(image.text, 0xC0, 0x4E800020);
    StoreBe32(image.text, 0xD0, 0x4E800020);
    StoreBe32(image.text, 0xE0, 0x4E800020);
    StoreBe32(image.text, 0xF0, 0x4E800020);  // call target

    StoreBe32(image.table, 0x00, kTextBase + 0x40);
    StoreBe32(image.table, 0x04, kTextBase + 0x60);
    StoreBe32(image.table, 0x08, kTextBase + 0x80);
    StoreBe32(image.table, 0x10, kTextBase + 0xC0);
    StoreBe32(image.table, 0x14, kTextBase + 0xD0);
    StoreBe32(image.table, 0x18, kTextBase + 0xE0);
    return image;
  };

  const auto analyze = [](AbsoluteSwitch& image) {
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const auto* region = decoded.regionContaining(kTextBase);
    REQUIRE(region != nullptr);
    const std::unordered_set<uint32_t> functions{kTextBase, kTextBase + 0xF0};
    return discoverBlocks(decoded, kTextBase, *region, functions, 0xF0);
  };

  auto image = makeImage();
  auto result = analyze(image);
  REQUIRE(result.jumpTables.size() == 2);
  const auto secondary =
      std::find_if(result.jumpTables.begin(), result.jumpTables.end(),
                   [](const auto& table) { return table.bctrAddress == kTextBase + 0xB8; });
  REQUIRE(secondary != result.jumpTables.end());
  CHECK(secondary->indexRegister == 28);
  CHECK(secondary->boundValue == 2);
  CHECK(secondary->caseCount == 3);
  CHECK(secondary->targets ==
        std::vector<uint32_t>{kTextBase + 0xC0, kTextBase + 0xD0, kTextBase + 0xE0});
  CHECK(secondary->confidence == "validated_inherited_bound_from_upstream_switch");
  CHECK(
      std::any_of(secondary->evidence.begin(), secondary->evidence.end(), [](const auto& evidence) {
        return evidence.address == kTextBase + 0x1C &&
               evidence.role == "inherited_bound_source_dispatch";
      }));
  const auto secondaryAnalysis =
      std::find_if(result.indirectSites.begin(), result.indirectSites.end(),
                   [](const auto& site) { return site.site == kTextBase + 0xB8; });
  REQUIRE(secondaryAnalysis != result.indirectSites.end());
  REQUIRE(secondaryAnalysis->selectedTable);
  CHECK(secondaryAnalysis->selectedTable->confidence ==
        "validated_exact_prior_inherited_bound_case_edges");
  REQUIRE(secondaryAnalysis->dataflow);
  CHECK(secondaryAnalysis->dataflow->mergeShape == "inherited_bound_case_edges");
  CHECK(std::any_of(secondaryAnalysis->dataflow->boundCandidates.begin(),
                    secondaryAnalysis->dataflow->boundCandidates.end(), [](const auto& bound) {
                      return bound.compareAddress == kTextBase && bound.inheritedCaseEdgeProof &&
                             !bound.dominatesDispatch && bound.finiteDenseDomain;
                    }));

  SECTION("a current local bound outranks a matching inherited domain") {
    auto localBound = makeImage();
    StoreBe32(localBound.text, 0xA0, 0x2B1C0002);  // cmplwi cr6, r28, 2
    StoreBe32(localBound.text, 0xA4, Bc(kTextBase + 0xA4, kTextBase + 0xF0, 12, 25));
    StoreBe32(localBound.text, 0xA8, 0x3C802000);  // lis r4, table@h
    StoreBe32(localBound.text, 0xAC, Mr(8, 28));
    StoreBe32(localBound.text, 0xB0, Rlwinm(8, 8, 2, 0, 29));
    StoreBe32(localBound.text, 0xB4, Lwzx(5, 4, 8));
    StoreBe32(localBound.text, 0xB8, Mtctr(5));
    StoreBe32(localBound.text, 0xBC, 0x4E800420);  // locally guarded second bctr

    auto locallyGuarded = analyze(localBound);
    const auto table = std::find_if(
        locallyGuarded.jumpTables.begin(), locallyGuarded.jumpTables.end(),
        [](const auto& candidate) { return candidate.bctrAddress == kTextBase + 0xBC; });
    REQUIRE(table != locallyGuarded.jumpTables.end());
    CHECK(table->boundSemantics == "unsigned_index <= bound");
    CHECK(table->defaultTarget == kTextBase + 0xF0);
    CHECK(table->defaultIsReturn == false);
  }

  SECTION("a case-path write invalidates the inherited domain") {
    auto modified = makeImage();
    StoreBe32(modified.text, 0x60, Addi(28, 0, 7));
    StoreBe32(modified.text, 0x64, B(kTextBase + 0x64, kTextBase + 0xA0));
    auto rejected = analyze(modified);
    CHECK(rejected.jumpTables.size() == 1);
    CHECK(std::none_of(rejected.jumpTables.begin(), rejected.jumpTables.end(),
                       [](const auto& table) { return table.bctrAddress == kTextBase + 0xB8; }));
  }

  SECTION("a linked call makes a volatile inherited index opaque") {
    auto volatileIndex = makeImage();
    StoreBe32(volatileIndex.text, 0x00, 0x28030002);  // cmplwi r3, 2
    StoreBe32(volatileIndex.text, 0x0C, Mr(7, 3));
    StoreBe32(volatileIndex.text, 0xA8, Mr(8, 3));
    auto rejected = analyze(volatileIndex);
    CHECK(rejected.jumpTables.size() == 1);
    CHECK(std::none_of(rejected.jumpTables.begin(), rejected.jumpTables.end(),
                       [](const auto& table) { return table.bctrAddress == kTextBase + 0xB8; }));
  }
}

TEST_CASE("validated case domains recover only finite downstream switch tables",
          "[codegen][jump-table][integration][inherited-case-domain]") {
  struct AnalysisSet {
    IndirectSiteAnalysis outer;
    IndirectSiteAnalysis initialInner;
    IndirectSiteAnalysis expandedInner;
  };

  const auto analyze = [](AbsoluteSwitch& image, uint32_t innerSite) {
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block block{kTextBase, 0xF0};
    const auto* region = decoded.regionContaining(kTextBase);
    REQUIRE(region != nullptr);

    JumpTableRecoveryInput outerInput{
        .site = kTextBase + 0x20,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&block, 1),
        .containingRegion = region,
        .limits = {},
    };
    auto outer = AnalyzeIndirectSite(decoded, outerInput);
    REQUIRE(outer.selectedTable);
    REQUIRE(outer.selectedTable->caseCount == 5);

    JumpTableRecoveryInput innerInput{
        .site = innerSite,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&block, 1),
        .containingRegion = region,
        .limits = {},
    };
    auto initialInner = AnalyzeIndirectSite(decoded, innerInput);

    const std::unordered_map<uint32_t, JumpTable> validatedTables{
        {outer.selectedTable->bctrAddress, *outer.selectedTable},
    };
    innerInput.validatedOwnerTables = &validatedTables;
    auto expandedInner = AnalyzeIndirectSiteWithPriorLimitRetry(decoded, innerInput);
    return AnalysisSet{std::move(outer), std::move(initialInner), std::move(expandedInner)};
  };

  const auto makeSpillReloadImage = [] {
    AbsoluteSwitch image;
    for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
      StoreBe32(image.text, offset, 0x60000000);  // nop

    // The first validated switch independently proves the finite r5 domain
    // 0..4. Values 0, 1, and 4 enter the downstream state; observing any one
    // runtime target would not prove this table length.
    StoreBe32(image.text, 0x00, Stw(5, 1, 0x20));
    StoreBe32(image.text, 0x04, 0x28050004);  // cmplwi r5, 4
    StoreBe32(image.text, 0x08, Bc(kTextBase + 0x08, kTextBase + 0x90, 12, 1));
    StoreBe32(image.text, 0x0C, 0x3C802000);  // lis r4, table@h
    StoreBe32(image.text, 0x10, 0x60840000);  // ori r4, r4, table@l
    StoreBe32(image.text, 0x14, Rlwinm(6, 5, 2, 0, 29));
    StoreBe32(image.text, 0x18, Lwzx(7, 4, 6));
    StoreBe32(image.text, 0x1C, Mtctr(7));
    StoreBe32(image.text, 0x20, 0x4E800420);  // outer bctr
    StoreBe32(image.text, 0x3C, 0x4E800020);  // no accidental fallthrough

    // A disjoint stack store must not obscure the exact r5 spill/reload.
    StoreBe32(image.text, 0x40, Stw(9, 1, 0x24));
    StoreBe32(image.text, 0x44, Lwz(10, 1, 0x20));
    StoreBe32(image.text, 0x48, 0x3C802000);  // lis r4, table@h
    StoreBe32(image.text, 0x4C, 0x60840020);  // ori r4, r4, table2@l
    StoreBe32(image.text, 0x50, Rlwinm(10, 10, 2, 0, 29));
    StoreBe32(image.text, 0x54, Lwzx(11, 4, 10));
    StoreBe32(image.text, 0x58, Mtctr(11));
    StoreBe32(image.text, 0x5C, 0x4E800420);  // inner bctr

    StoreBe32(image.text, 0x8C, 0x4E800020);
    for (uint32_t target : {0x90u, 0xA0u, 0xB0u, 0xC0u, 0xD0u, 0xE0u})
      StoreBe32(image.text, target, 0x4E800020);

    for (uint32_t index = 0; index < 5; ++index) {
      const uint32_t target =
          index == 0 || index == 1 || index == 4 ? kTextBase + 0x40 : kTextBase + 0x90;
      StoreBe32(image.table, index * 4, target);
      StoreBe32(image.table, 0x20 + index * 4, kTextBase + 0xA0 + index * 0x10);
    }
    return image;
  };

  SECTION("an exact stack spill/reload retains the upstream finite bound") {
    auto image = makeSpillReloadImage();
    auto result = analyze(image, kTextBase + 0x5C);

    REQUIRE(result.initialInner.failures.size() == 1);
    CHECK(result.initialInner.failures.front() == JumpTableFailure::MissingBound);
    REQUIRE(result.expandedInner.selectedTable);
    CHECK(result.expandedInner.selectedTable->indexRegister == 5);
    CHECK(result.expandedInner.selectedTable->boundValue == 4);
    CHECK(result.expandedInner.selectedTable->caseCount == 5);
    CHECK(result.expandedInner.selectedTable->targets ==
          std::vector<uint32_t>{kTextBase + 0xA0, kTextBase + 0xB0, kTextBase + 0xC0,
                                kTextBase + 0xD0, kTextBase + 0xE0});
    CHECK(result.expandedInner.selectedTable->confidence ==
          "validated_inherited_case_domain_all_targets");
    REQUIRE(result.expandedInner.dataflow);
    const auto spillDomain =
        std::find_if(result.expandedInner.dataflow->boundCandidates.begin(),
                     result.expandedInner.dataflow->boundCandidates.end(),
                     [](const auto& bound) { return bound.inheritedFiniteCaseDomain; });
    REQUIRE(spillDomain != result.expandedInner.dataflow->boundCandidates.end());
    CHECK(spillDomain->finiteValues == std::vector<uint32_t>{0, 1, 4});
    CHECK(spillDomain->normalizedFiniteValues == std::vector<uint32_t>{0, 1, 2, 3, 4});
    CHECK(spillDomain->stackSpillAddress == kTextBase);
    CHECK(spillDomain->stackReloadAddress == kTextBase + 0x44);
    CHECK(spillDomain->stackSlotOffset == 0x20);
    CHECK(spillDomain->stackSlotWidth == 4);
  }

  SECTION("an overlapping stack write rejects the spill lineage") {
    auto image = makeSpillReloadImage();
    StoreBe32(image.text, 0x40, Stw(9, 1, 0x20));
    auto result = analyze(image, kTextBase + 0x5C);
    CHECK_FALSE(result.expandedInner.selectedTable);
    CHECK(HasFailure(result.expandedInner, JumpTableFailure::MissingBound));
  }

  SECTION("a source-register change rejects the conservative spill lineage") {
    auto image = makeSpillReloadImage();
    StoreBe32(image.text, 0x40, Addi(5, 0, 2));
    auto result = analyze(image, kTextBase + 0x5C);
    CHECK_FALSE(result.expandedInner.selectedTable);
    CHECK(HasFailure(result.expandedInner, JumpTableFailure::MissingBound));
  }

  SECTION("an unproved direct predecessor rejects the inherited case domain") {
    auto image = makeSpillReloadImage();
    StoreBe32(image.text, 0x3C, B(kTextBase + 0x3C, kTextBase + 0x40));
    auto result = analyze(image, kTextBase + 0x5C);
    CHECK_FALSE(result.expandedInner.selectedTable);
    CHECK(HasFailure(result.expandedInner, JumpTableFailure::MissingBound));
  }

  const auto makeTransformedImage = [] {
    AbsoluteSwitch image;
    for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
      StoreBe32(image.text, offset, 0x60000000);  // nop

    StoreBe32(image.text, 0x00, 0x28050004);  // cmplwi r5, 4
    StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x90, 12, 1));
    StoreBe32(image.text, 0x08, 0x3C802000);  // lis r4, table@h
    StoreBe32(image.text, 0x0C, 0x60840000);  // ori r4, r4, table@l
    StoreBe32(image.text, 0x10, Rlwinm(6, 5, 2, 0, 29));
    StoreBe32(image.text, 0x14, Lwzx(7, 4, 6));
    StoreBe32(image.text, 0x18, Mtctr(7));
    StoreBe32(image.text, 0x1C, 0x60000000);
    StoreBe32(image.text, 0x20, 0x4E800420);  // outer bctr
    StoreBe32(image.text, 0x3C, 0x4E800020);  // no accidental fallthrough

    // Only exact outer cases 1..3 reach this block, so r10 = r5 - 1 has the
    // independently proven dense domain 0..2.
    StoreBe32(image.text, 0x40, Addi(10, 5, -1));
    StoreBe32(image.text, 0x44, 0x3C802000);  // lis r4, table@h
    StoreBe32(image.text, 0x48, 0x60840020);  // ori r4, r4, table2@l
    StoreBe32(image.text, 0x4C, Rlwinm(6, 10, 2, 0, 29));
    StoreBe32(image.text, 0x50, Lwzx(11, 4, 6));
    StoreBe32(image.text, 0x54, Mtctr(11));
    StoreBe32(image.text, 0x58, 0x4E800420);  // inner bctr

    StoreBe32(image.text, 0x8C, 0x4E800020);
    for (uint32_t target : {0x90u, 0xA0u, 0xB0u, 0xC0u})
      StoreBe32(image.text, target, 0x4E800020);

    for (uint32_t index = 0; index < 5; ++index) {
      const uint32_t target = index >= 1 && index <= 3 ? kTextBase + 0x40 : kTextBase + 0x90;
      StoreBe32(image.table, index * 4, target);
    }
    for (uint32_t index = 0; index < 3; ++index)
      StoreBe32(image.table, 0x20 + index * 4, kTextBase + 0xA0 + index * 0x10);
    return image;
  };

  SECTION("a transformed exact case domain becomes a dense zero-based table index") {
    auto image = makeTransformedImage();
    auto result = analyze(image, kTextBase + 0x58);

    REQUIRE(result.initialInner.failures.size() == 1);
    CHECK(result.initialInner.failures.front() == JumpTableFailure::MissingBound);
    REQUIRE(result.expandedInner.selectedTable);
    CHECK(result.expandedInner.selectedTable->indexRegister == 10);
    CHECK(result.expandedInner.selectedTable->boundValue == 2);
    CHECK(result.expandedInner.selectedTable->caseCount == 3);
    CHECK(result.expandedInner.selectedTable->targets ==
          std::vector<uint32_t>{kTextBase + 0xA0, kTextBase + 0xB0, kTextBase + 0xC0});
    CHECK(result.expandedInner.selectedTable->boundSemantics ==
          "inherited_case_domain_zero_based_dense");
    REQUIRE(result.expandedInner.dataflow);
    const auto transformedDomain =
        std::find_if(result.expandedInner.dataflow->boundCandidates.begin(),
                     result.expandedInner.dataflow->boundCandidates.end(),
                     [](const auto& bound) { return bound.inheritedFiniteCaseDomain; });
    REQUIRE(transformedDomain != result.expandedInner.dataflow->boundCandidates.end());
    CHECK(transformedDomain->finiteValues == std::vector<uint32_t>{1, 2, 3});
    CHECK(transformedDomain->normalizedFiniteValues == std::vector<uint32_t>{0, 1, 2});
    CHECK(transformedDomain->inheritedCaseEdges ==
          std::vector<JumpTableCfgEdgeEvidence>{{kTextBase + 0x20, kTextBase + 0x40}});
    CHECK(transformedDomain->stackSpillAddress == 0);
    CHECK(transformedDomain->stackReloadAddress == 0);
  }

  SECTION("a non-dense transformed case domain remains unresolved") {
    auto image = makeTransformedImage();
    StoreBe32(image.table, 0x08, kTextBase + 0x90);  // outer case 2 no longer reaches inner
    auto result = analyze(image, kTextBase + 0x58);
    CHECK_FALSE(result.expandedInner.selectedTable);
    CHECK(HasFailure(result.expandedInner, JumpTableFailure::MissingBound));
  }

  SECTION("mixed-validity transformed targets are rejected") {
    auto image = makeTransformedImage();
    StoreBe32(image.table, 0x24, kTextBase + 0xB2);
    auto result = analyze(image, kTextBase + 0x58);
    CHECK_FALSE(result.expandedInner.selectedTable);
    CHECK(HasFailure(result.expandedInner, JumpTableFailure::MissingBound));
    REQUIRE(result.expandedInner.dataflow);
    CHECK(std::find(result.expandedInner.dataflow->rejectionEvidence.begin(),
                    result.expandedInner.dataflow->rejectionEvidence.end(),
                    "validated_owner_table_edge_retry:mixed_validity_targets") !=
          result.expandedInner.dataflow->rejectionEvidence.end());
  }
}

TEST_CASE("case expansion removes a transient table when a new predecessor lacks domain proof",
          "[codegen][jump-table][integration][inherited-case-domain][fixpoint-retention]") {
  AbsoluteSwitch image;
  image.text.resize(0x180);
  image.table.resize(0x80);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  constexpr uint32_t kOuterSite = kTextBase + 0x1C;
  constexpr uint32_t kDownstreamBlock = kTextBase + 0x40;
  constexpr uint32_t kDownstreamSite = kTextBase + 0x58;
  constexpr uint32_t kLateSwitchBlock = kTextBase + 0x80;
  constexpr uint32_t kLateSwitchSite = kTextBase + 0xA0;
  constexpr uint32_t kDefault = kTextBase + 0xD0;

  // The first switch independently proves r5 in 0..4. Its cases 1..3 are the
  // initially complete predecessor set for the downstream r10 = r5 - 1 table.
  StoreBe32(image.text, 0x00, 0x28050004);  // cmplwi r5, 4
  StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kDefault, 12, 1));
  StoreBe32(image.text, 0x08, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x0C, 0x60840000);  // ori r4, r4, table@l
  StoreBe32(image.text, 0x10, Rlwinm(6, 5, 2, 0, 29));
  StoreBe32(image.text, 0x14, Lwzx(7, 4, 6));
  StoreBe32(image.text, 0x18, Mtctr(7));
  StoreBe32(image.text, 0x1C, 0x4E800420);  // outer bctr

  StoreBe32(image.text, 0x40, Addi(10, 5, -1));
  StoreBe32(image.text, 0x44, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x48, 0x60840020);  // ori r4, r4, table2@l
  StoreBe32(image.text, 0x4C, Rlwinm(6, 10, 2, 0, 29));
  StoreBe32(image.text, 0x50, Lwzx(11, 4, 6));
  StoreBe32(image.text, 0x54, Mtctr(11));
  StoreBe32(image.text, 0x58, 0x4E800420);  // downstream bctr

  // This separately bounded switch is discovered in the same iteration as
  // the downstream table. Its recovered case edge reaches the downstream
  // block only on the next CFG expansion, after r5 has been overwritten. That
  // new predecessor therefore cannot inherit the outer r5 domain.
  StoreBe32(image.text, 0x80, Addi(5, 0, 9));
  StoreBe32(image.text, 0x84, 0x298C0000);  // cmplwi cr3, r12, 0
  StoreBe32(image.text, 0x88, Bc(kTextBase + 0x88, kDefault, 12, 13));
  StoreBe32(image.text, 0x8C, 0x3C802000);  // lis r4, table@h
  StoreBe32(image.text, 0x90, 0x60840030);  // ori r4, r4, table3@l
  StoreBe32(image.text, 0x94, Rlwinm(13, 12, 2, 0, 29));
  StoreBe32(image.text, 0x98, Lwzx(14, 4, 13));
  StoreBe32(image.text, 0x9C, Mtctr(14));
  StoreBe32(image.text, 0xA0, 0x4E800420);  // late bctr

  StoreBe32(image.text, 0xD0, 0x4E800020);
  for (uint32_t target : {0x110u, 0x120u, 0x130u})
    StoreBe32(image.text, target, 0x4E800020);

  for (uint32_t index = 0; index < 5; ++index) {
    const uint32_t target = index >= 1 && index <= 3 ? kDownstreamBlock : kLateSwitchBlock;
    StoreBe32(image.table, index * 4, target);
  }
  for (uint32_t index = 0; index < 3; ++index)
    StoreBe32(image.table, 0x20 + index * 4, kTextBase + 0x110 + index * 0x10);
  StoreBe32(image.table, 0x30, kDownstreamBlock);

  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const std::array ownerBlocks{
      Block{kTextBase, 0x20},         Block{kDownstreamBlock, 0x1C},
      Block{kLateSwitchBlock, 0x24},  Block{kDefault, 0x04},
      Block{kTextBase + 0x110, 0x04}, Block{kTextBase + 0x120, 0x04},
      Block{kTextBase + 0x130, 0x04},
  };

  const auto analyzeSite = [&](uint32_t site,
                               const std::unordered_map<uint32_t, JumpTable>* validatedTables,
                               const JumpTable* prior = nullptr) {
    JumpTableRecoveryInput input{
        .site = site,
        .ownerAddress = kTextBase,
        .trustedOwnerEnd = kTextBase + 0x140,
        .preliminaryBlocks = ownerBlocks,
        .containingRegion = region,
        .validatedOwnerTables = validatedTables,
        .priorAutomaticTable = prior,
        .limits = {},
    };
    return AnalyzeIndirectSiteWithPriorLimitRetry(decoded, input);
  };

  auto outer = analyzeSite(kOuterSite, nullptr);
  REQUIRE(outer.selectedTable);
  auto late = analyzeSite(kLateSwitchSite, nullptr);
  REQUIRE(late.selectedTable);

  const std::unordered_map<uint32_t, JumpTable> initialValidatedTables{
      {kOuterSite, *outer.selectedTable},
  };
  auto transient = analyzeSite(kDownstreamSite, &initialValidatedTables);
  REQUIRE(transient.selectedTable);
  CHECK(transient.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x110, kTextBase + 0x120, kTextBase + 0x130});
  CHECK(transient.selectedTable->confidence == "validated_inherited_case_domain_all_targets");

  const std::unordered_map<uint32_t, JumpTable> expandedValidatedTables{
      {kOuterSite, *outer.selectedTable},
      {kDownstreamSite, *transient.selectedTable},
      {kLateSwitchSite, *late.selectedTable},
  };
  auto invalidated =
      analyzeSite(kDownstreamSite, &expandedValidatedTables, &*transient.selectedTable);
  CHECK_FALSE(invalidated.selectedTable);
  CHECK_FALSE(invalidated.automaticTable);
  CHECK((HasFailure(invalidated, JumpTableFailure::MissingBound) ||
         HasFailure(invalidated, JumpTableFailure::UnknownIndex)));

  const std::unordered_set<uint32_t> functions{kTextBase};
  auto result = discoverBlocks(decoded, kTextBase, *region, functions, 0x140);
  CHECK(result.jumpTableRecovery.fixpointIterations == 4);
  const auto finalSite =
      std::find_if(result.indirectSites.begin(), result.indirectSites.end(),
                   [](const auto& site) { return site.site == kDownstreamSite; });
  REQUIRE(finalSite != result.indirectSites.end());
  CHECK_FALSE(finalSite->selectedTable);
  CHECK_FALSE(finalSite->automaticTable);
  CHECK(std::none_of(result.jumpTables.begin(), result.jumpTables.end(),
                     [](const auto& table) { return table.bctrAddress == kDownstreamSite; }));
  CHECK_FALSE(result.labels.contains(kTextBase + 0x110));
  CHECK_FALSE(result.labels.contains(kTextBase + 0x120));
  CHECK_FALSE(result.labels.contains(kTextBase + 0x130));
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

TEST_CASE("equivalent repeated guards retain a bounded switch across a loop merge",
          "[codegen][jump-table][loop-state][local-slice]") {
  auto image = RepeatedBoundGuardSwitch();
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const std::unordered_set<uint32_t> functions{kTextBase};
  auto result = discoverBlocks(decoded, kTextBase, *region, functions, 0x94);

  REQUIRE(result.jumpTables.size() == 1);
  CHECK(result.jumpTables[0].targets == std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50,
                                                              kTextBase + 0x60, kTextBase + 0x70});
  const auto dispatch =
      std::find_if(result.indirectSites.begin(), result.indirectSites.end(),
                   [](const auto& site) { return site.site == kTextBase + 0x1C; });
  REQUIRE(dispatch != result.indirectSites.end());
  REQUIRE(dispatch->selectedTable);
  CHECK(dispatch->selectedTable->confidence ==
        "validated_exact_prior_bound_family_local_bounded_slice");
  CHECK(std::any_of(dispatch->selectedTable->evidence.begin(),
                    dispatch->selectedTable->evidence.end(), [](const auto& evidence) {
                      return evidence.address == kTextBase + 0x04 &&
                             evidence.role == "local_bounded_slice_prior_exact_compare";
                    }));
  CHECK(std::any_of(dispatch->selectedTable->evidence.begin(),
                    dispatch->selectedTable->evidence.end(), [](const auto& evidence) {
                      return evidence.address == kTextBase + 0x08 &&
                             evidence.role == "local_bounded_slice_prior_exact_guard";
                    }));
  CHECK(std::any_of(dispatch->selectedTable->evidence.begin(),
                    dispatch->selectedTable->evidence.end(), [](const auto& evidence) {
                      return evidence.address == kTextBase + 0x44 &&
                             evidence.role == "local_bounded_slice_equivalent_bound_compare";
                    }));
  REQUIRE(dispatch->dataflow);
  CHECK(std::any_of(dispatch->dataflow->boundCandidates.begin(),
                    dispatch->dataflow->boundCandidates.end(), [](const auto& bound) {
                      return bound.compareAddress == kTextBase + 0x04 &&
                             bound.guardAddress == kTextBase + 0x08 && bound.priorExactRevalidation;
                    }));
  CHECK(std::any_of(dispatch->dataflow->boundCandidates.begin(),
                    dispatch->dataflow->boundCandidates.end(), [](const auto& bound) {
                      return bound.compareAddress == kTextBase + 0x44 &&
                             bound.guardAddress == kTextBase + 0x48 && bound.value == 3 &&
                             !bound.dominatesDispatch;
                    }));

  SECTION("a different repeated bound is not merged") {
    auto incompatible = RepeatedBoundGuardSwitch();
    StoreBe32(incompatible.text, 0x44, 0x280B0004);  // cmplwi r11, 4
    auto incompatibleView = incompatible.view();
    DecodedBinary incompatibleDecoded(incompatibleView);
    incompatibleDecoded.decode();
    const auto* incompatibleRegion = incompatibleDecoded.regionContaining(kTextBase);
    REQUIRE(incompatibleRegion != nullptr);
    const std::array preliminaryBlocks{Block{kTextBase, 0x20}, Block{kTextBase + 0x90, 0x04}};
    JumpTableRecoveryInput preliminaryInput{
        .site = kTextBase + 0x1C,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = preliminaryBlocks,
        .containingRegion = incompatibleRegion,
        .limits = {},
    };
    auto preliminary = AnalyzeIndirectSite(incompatibleDecoded, preliminaryInput);
    REQUIRE(preliminary.selectedTable);
    const Block expandedBlock{kTextBase, 0x94};
    JumpTableRecoveryInput expandedInput{
        .site = kTextBase + 0x1C,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = incompatibleRegion,
        .priorAutomaticTable = &*preliminary.selectedTable,
        .limits = {},
    };
    auto expanded = AnalyzeIndirectSite(incompatibleDecoded, expandedInput);
    CHECK_FALSE(expanded.selectedTable);
    auto rejected =
        discoverBlocks(incompatibleDecoded, kTextBase, *incompatibleRegion, functions, 0x94);
    CHECK(rejected.jumpTables.empty());
    const auto rejectedDispatch =
        std::find_if(rejected.indirectSites.begin(), rejected.indirectSites.end(),
                     [](const auto& site) { return site.site == kTextBase + 0x1C; });
    REQUIRE(rejectedDispatch != rejected.indirectSites.end());
    CHECK_FALSE(rejectedDispatch->selectedTable);
    CHECK(HasFailure(*rejectedDispatch, JumpTableFailure::AmbiguousReachingDefinition));
  }

  SECTION("an unguarded backedge is not treated as finite") {
    auto unguarded = RepeatedBoundGuardSwitch();
    StoreBe32(unguarded.text, 0x44, 0x60000000);  // nop
    StoreBe32(unguarded.text, 0x48, B(kTextBase + 0x48, kTextBase + 0x0C));
    auto unguardedView = unguarded.view();
    DecodedBinary unguardedDecoded(unguardedView);
    unguardedDecoded.decode();
    const auto* unguardedRegion = unguardedDecoded.regionContaining(kTextBase);
    REQUIRE(unguardedRegion != nullptr);
    const std::array preliminaryBlocks{Block{kTextBase, 0x20}, Block{kTextBase + 0x90, 0x04}};
    JumpTableRecoveryInput preliminaryInput{
        .site = kTextBase + 0x1C,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = preliminaryBlocks,
        .containingRegion = unguardedRegion,
        .limits = {},
    };
    auto preliminary = AnalyzeIndirectSite(unguardedDecoded, preliminaryInput);
    REQUIRE(preliminary.selectedTable);
    const Block expandedBlock{kTextBase, 0x94};
    JumpTableRecoveryInput expandedInput{
        .site = kTextBase + 0x1C,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = unguardedRegion,
        .priorAutomaticTable = &*preliminary.selectedTable,
        .limits = {},
    };
    auto expanded = AnalyzeIndirectSite(unguardedDecoded, expandedInput);
    CHECK_FALSE(expanded.selectedTable);
    auto rejected = discoverBlocks(unguardedDecoded, kTextBase, *unguardedRegion, functions, 0x94);
    CHECK(rejected.jumpTables.empty());
  }
}

TEST_CASE("trusted owner fragments accept decoded rlwimi case entries only within the owner",
          "[codegen][jump-table][owner-fragment][decode]") {
  constexpr uint32_t kColdBase = kTextBase + 0x100;
  std::vector<uint8_t> hot(0x44, 0);
  std::vector<uint8_t> cold(0x08, 0);
  std::vector<uint8_t> table(0x04, 0);
  for (uint32_t offset = 0; offset < hot.size(); offset += 4)
    StoreBe32(hot, offset, 0x60000000);
  StoreBe32(hot, 0x00, 0x280B0000);  // cmplwi r11, 0
  StoreBe32(hot, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x30, 12, 1));
  StoreBe32(hot, 0x08, 0x3D802000);  // lis r12, table@h
  StoreBe32(hot, 0x0C, Rlwinm(0, 11, 2, 0, 29));
  StoreBe32(hot, 0x10, Lwzx(0, 12, 0));
  StoreBe32(hot, 0x14, Mtctr(0));
  StoreBe32(hot, 0x18, 0x4E800420);  // bctr
  StoreBe32(hot, 0x30, 0x4E800020);  // default: blr
  StoreBe32(cold, 0x00, Rlwimi(7, 8, 5, 9, 11));
  StoreBe32(cold, 0x04, 0x4E800020);  // blr
  StoreBe32(table, 0x00, kColdBase);

  const std::array sections{
      BinarySectionInput{.name = ".text.hot",
                         .baseAddress = kTextBase,
                         .data = hot,
                         .executable = true,
                         .readable = true},
      BinarySectionInput{.name = ".text.cold",
                         .baseAddress = kColdBase,
                         .data = cold,
                         .executable = true,
                         .readable = true},
      BinarySectionInput{
          .name = ".rdata", .baseAddress = kTableBase, .data = table, .readable = true},
  };
  auto view = BinaryView::fromSections(kTextBase, 0x10000200, kTextBase, sections);
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* hotRegion = decoded.regionContaining(kTextBase);
  REQUIRE(hotRegion != nullptr);
  const auto* coldInstruction = decoded.get(kColdBase);
  REQUIRE(coldInstruction != nullptr);
  CHECK(coldInstruction->opcode == ppc::Opcode::rlwimi);

  const std::array blocks{Block{kTextBase, 0x1C}, Block{kTextBase + 0x30, 0x04}};
  JumpTableRecoveryInput localInput{
      .site = kTextBase + 0x18,
      .ownerAddress = kTextBase,
      .preliminaryBlocks = blocks,
      .containingRegion = hotRegion,
      .limits = {},
  };
  auto outside = AnalyzeIndirectSite(decoded, localInput);
  CHECK_FALSE(outside.selectedTable);
  CHECK(HasFailure(outside, JumpTableFailure::TargetOutOfRange));

  localInput.trustedOwnerEnd = kColdBase + 0x08;
  auto recovered = AnalyzeIndirectSite(decoded, localInput);
  REQUIRE(recovered.selectedTable);
  CHECK(recovered.selectedTable->targets == std::vector<uint32_t>{kColdBase});

  const std::unordered_set<uint32_t> functions{kTextBase};
  auto integrated = discoverBlocks(decoded, kTextBase, *hotRegion, functions, 0x108);
  REQUIRE(integrated.jumpTables.size() == 1);
  CHECK(integrated.jumpTables[0].targets == std::vector<uint32_t>{kColdBase});
  CHECK(integrated.labels.contains(kColdBase));
  CHECK(std::any_of(integrated.blocks.begin(), integrated.blocks.end(),
                    [](const auto& block) { return block.contains(kColdBase); }));
}

TEST_CASE("a loop state may recompute the exact bounded index on the case path",
          "[codegen][jump-table][loop-state][recomputed-index]") {
  auto image = RecomputedLoopIndexSwitch();
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const std::unordered_set<uint32_t> functions{kTextBase};
  auto integrated = discoverBlocks(decoded, kTextBase, *region, functions, 0xB4);
  const auto dispatch =
      std::find_if(integrated.indirectSites.begin(), integrated.indirectSites.end(),
                   [](const auto& site) { return site.site == kTextBase + 0x28; });
  REQUIRE(dispatch != integrated.indirectSites.end());
  INFO("failures=" << FailureNames(*dispatch));
  REQUIRE(dispatch->selectedTable);
  CHECK(dispatch->failures.empty());
  CHECK(dispatch->selectedTable->confidence == "validated_equivalent_bound_index_recomputation");
  CHECK(dispatch->selectedTable->kind == JumpTableKind::AbsolutePointer);
  CHECK(dispatch->selectedTable->indexRegister == 11);
  CHECK(dispatch->selectedTable->caseCount == 4);
  CHECK(dispatch->selectedTable->tableAddress == kTableBase);
  CHECK(dispatch->selectedTable->storageEnd == kTableBase + 0x10);
  CHECK(dispatch->selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60,
                              kTextBase + 0x70});
  CHECK(dispatch->selectedTable->rawEntries ==
        std::vector<JumpTableRawEntry>{{kTableBase, kTextBase + 0x40, kTextBase + 0x40},
                                       {kTableBase + 4, kTextBase + 0x50, kTextBase + 0x50},
                                       {kTableBase + 8, kTextBase + 0x60, kTextBase + 0x60},
                                       {kTableBase + 12, kTextBase + 0x70, kTextBase + 0x70}});
  CHECK(std::any_of(dispatch->selectedTable->evidence.begin(),
                    dispatch->selectedTable->evidence.end(), [](const auto& evidence) {
                      return evidence.role == "local_bounded_slice_equivalent_index_recomputation";
                    }));
  CHECK(integrated.labels.contains(kTextBase + 0x40));
  CHECK(integrated.labels.contains(kTextBase + 0x50));
  CHECK(integrated.labels.contains(kTextBase + 0x60));
  CHECK(integrated.labels.contains(kTextBase + 0x70));

  SECTION("a different recomputation immediate is incompatible") {
    auto incompatible = RecomputedLoopIndexSwitch();
    StoreBe32(incompatible.text, 0x14, Addi(11, 28, -2));
    auto incompatibleView = incompatible.view();
    DecodedBinary incompatibleDecoded(incompatibleView);
    incompatibleDecoded.decode();
    const auto* incompatibleRegion = incompatibleDecoded.regionContaining(kTextBase);
    REQUIRE(incompatibleRegion != nullptr);
    auto rejected =
        discoverBlocks(incompatibleDecoded, kTextBase, *incompatibleRegion, functions, 0xB4);
    CHECK(rejected.jumpTables.empty());
  }

  SECTION("the recomputation source cannot change after the finite guard") {
    auto overwritten = RecomputedLoopIndexSwitch();
    StoreBe32(overwritten.text, 0x10, Addi(28, 28, 1));
    auto overwrittenView = overwritten.view();
    DecodedBinary overwrittenDecoded(overwrittenView);
    overwrittenDecoded.decode();
    const auto* overwrittenRegion = overwrittenDecoded.regionContaining(kTextBase);
    REQUIRE(overwrittenRegion != nullptr);
    auto rejected =
        discoverBlocks(overwrittenDecoded, kTextBase, *overwrittenRegion, functions, 0xB4);
    CHECK(rejected.jumpTables.empty());
  }
}

TEST_CASE("loop-carried byte state machine recovers through a finite loop phi",
          "[codegen][jump-table][loop-state]") {
  auto image = LoopStateSwitch();
  auto initial = Analyze(image, kLoopSite);
  INFO("failures=" << FailureNames(initial));
  REQUIRE(initial.selectedTable);
  CHECK(initial.failures.empty());
  CHECK(initial.selectedTable->origin == JumpTableOrigin::Automatic);
  CHECK(initial.selectedTable->kind == JumpTableKind::RelativeOffset);
  CHECK(initial.selectedTable->tableAddress == kTableBase);
  CHECK(initial.selectedTable->storageEnd == kTableBase + 3);
  CHECK(initial.selectedTable->elementWidth == 1);
  CHECK_FALSE(initial.selectedTable->elementSigned);
  CHECK(initial.selectedTable->targetScale == 4);
  CHECK(initial.selectedTable->anchorAddress == kTextBase);
  CHECK(initial.selectedTable->indexRegister == 11);
  CHECK(initial.selectedTable->boundValue == 2);
  CHECK(initial.selectedTable->caseCount == 3);
  CHECK(initial.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60});
  CHECK(initial.selectedTable->rawEntries ==
        std::vector<JumpTableRawEntry>{{kTableBase, 0x10, kTextBase + 0x40},
                                       {kTableBase + 1, 0x14, kTextBase + 0x50},
                                       {kTableBase + 2, 0x18, kTextBase + 0x60}});
  REQUIRE(initial.loopEvidence.size() == 2);
  const auto initialOuter =
      std::find_if(initial.loopEvidence.begin(), initial.loopEvidence.end(),
                   [](const auto& loop) { return loop.headerAddress == kLoopHeader; });
  const auto initialInner =
      std::find_if(initial.loopEvidence.begin(), initial.loopEvidence.end(),
                   [](const auto& loop) { return loop.headerAddress == kTextBase + 0x04; });
  REQUIRE(initialOuter != initial.loopEvidence.end());
  REQUIRE(initialInner != initial.loopEvidence.end());
  const auto& initialLoop = *initialOuter;
  CHECK(initialLoop.registerIndex == 21);
  CHECK(initialLoop.headerAddress == kLoopHeader);
  CHECK(initialLoop.finiteValues == std::vector<uint32_t>{0, 1, 2});
  CHECK(initialLoop.identityBackedge);
  CHECK(initialLoop.finiteEntryDomain);
  CHECK(initialLoop.converged);
  CHECK(initialInner->registerIndex == 21);
  CHECK(initialInner->entryDefinitionAddresses == std::vector<uint32_t>{kTextBase});
  CHECK(initialInner->backedgeDefinitionAddresses == std::vector<uint32_t>{kTextBase + 0x08});
  CHECK(initialInner->finiteValues == std::vector<uint32_t>{0});
  CHECK(initialInner->identityBackedge);
  CHECK(initialInner->converged);
  REQUIRE(initial.dataflow);
  CHECK_FALSE(initial.dataflow->caseExpandedCfg);
  CHECK_FALSE(initial.dataflow->sourceInScc);
  CHECK(initial.dataflow->mergeShape == "finite_loop_phi");
  CHECK(initial.dataflow->switchLikelihood == JumpTableSwitchLikelihood::ResolvedSwitch);

  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block expandedBlock{kTextBase, 0x80};
  JumpTableRecoveryInput expandedInput{
      .site = kLoopSite,
      .ownerAddress = kTextBase,
      .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
      .containingRegion = decoded.regionContaining(kTextBase),
      .priorAutomaticTable = &*initial.selectedTable,
      .limits = {},
  };
  auto expanded = AnalyzeIndirectSite(decoded, expandedInput);
  REQUIRE(expanded.selectedTable);
  CHECK(expanded.failures.empty());
  CHECK(expanded.selectedTable->targets == initial.selectedTable->targets);
  CHECK(expanded.selectedTable->rawEntries == initial.selectedTable->rawEntries);
  CHECK(expanded.selectedTable->tableAddress == initial.selectedTable->tableAddress);
  CHECK(expanded.selectedTable->storageEnd == initial.selectedTable->storageEnd);
  REQUIRE(expanded.dataflow);
  CHECK(expanded.dataflow->caseExpandedCfg);
  CHECK(expanded.dataflow->sourceInScc);
  CHECK(expanded.dataflow->caseExpansionEdges ==
        std::vector<JumpTableCfgEdgeEvidence>{{kLoopSite, kTextBase + 0x40},
                                              {kLoopSite, kTextBase + 0x50},
                                              {kLoopSite, kTextBase + 0x60}});
  REQUIRE(expanded.loopEvidence.size() == 2);
  const auto expandedOuter =
      std::find_if(expanded.loopEvidence.begin(), expanded.loopEvidence.end(),
                   [](const auto& loop) { return loop.headerAddress == kLoopHeader; });
  REQUIRE(expandedOuter != expanded.loopEvidence.end());
  const auto& expandedLoop = *expandedOuter;
  CHECK(expandedLoop.entryDefinitionAddresses ==
        std::vector<uint32_t>{kTextBase, kTextBase + 0x08});
  CHECK(expandedLoop.entryValues == std::vector<uint32_t>{0});
  CHECK(expandedLoop.backedgeDefinitionAddresses ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x50, kTextBase + 0x60,
                              kTextBase + 0x70});
  CHECK(expandedLoop.backedgeValues == std::vector<uint32_t>{0, 1, 2});

  const auto* region = decoded.regionContaining(kTextBase);
  REQUIRE(region != nullptr);
  const std::unordered_set<uint32_t> functions{kTextBase};
  auto result = discoverBlocks(decoded, kTextBase, *region, functions, 0x80);
  REQUIRE(result.jumpTables.size() == 1);
  CHECK(result.jumpTableRecovery.fixpointIterations == 2);
  CHECK(result.jumpTables.front().targets == initial.selectedTable->targets);
  for (uint32_t target : initial.selectedTable->targets) {
    CHECK(result.labels.contains(target));
    CHECK(std::any_of(result.blocks.begin(), result.blocks.end(),
                      [&](const Block& block) { return block.contains(target); }));
    CHECK_FALSE(functions.contains(target));
  }
}

TEST_CASE("loop-carried recovery uses bounded SCC topology beyond the resolver-state limit",
          "[codegen][jump-table][loop-state]") {
  auto image = LargeLoopStateSwitch();
  auto initial = Analyze(image, kLoopSite);
  INFO("initial failures=" << FailureNames(initial));
  REQUIRE(initial.selectedTable);
  REQUIRE(initial.failures.empty());

  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const Block expandedBlock{kTextBase, 0x920};
  JumpTableRecoveryLimits limits;
  limits.maxStates = 64;
  JumpTableRecoveryInput input{
      .site = kLoopSite,
      .ownerAddress = kTextBase,
      .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
      .containingRegion = decoded.regionContaining(kTextBase),
      .priorAutomaticTable = &*initial.selectedTable,
      .limits = limits,
  };
  auto expanded = AnalyzeIndirectSite(decoded, input);
  INFO("failures=" << FailureNames(expanded));
  REQUIRE(expanded.selectedTable);
  CHECK(expanded.failures.empty());
  CHECK(expanded.selectedTable->targets == initial.selectedTable->targets);
  CHECK(expanded.selectedTable->rawEntries == initial.selectedTable->rawEntries);
  CHECK(expanded.selectedTable->tableAddress == initial.selectedTable->tableAddress);
  CHECK(expanded.selectedTable->storageEnd == initial.selectedTable->storageEnd);
  CHECK(expanded.selectedTable->kind == initial.selectedTable->kind);
  CHECK(expanded.selectedTable->elementWidth == initial.selectedTable->elementWidth);
  CHECK(expanded.selectedTable->elementSigned == initial.selectedTable->elementSigned);
  CHECK(expanded.selectedTable->anchorAddress == initial.selectedTable->anchorAddress);
  CHECK(expanded.selectedTable->targetScale == initial.selectedTable->targetScale);
  CHECK(expanded.selectedTable->boundValue == initial.selectedTable->boundValue);
  CHECK(expanded.selectedTable->caseCount == initial.selectedTable->caseCount);
  REQUIRE(expanded.dataflow);
  CHECK(expanded.dataflow->caseExpandedCfg);
  CHECK(expanded.dataflow->sourceInScc);
  CHECK(expanded.dataflow->exhaustedBudgets.empty());
  REQUIRE(expanded.loopEvidence.size() == 2);
  const auto outer =
      std::find_if(expanded.loopEvidence.begin(), expanded.loopEvidence.end(),
                   [](const auto& loop) { return loop.headerAddress == kLoopHeader; });
  REQUIRE(outer != expanded.loopEvidence.end());
  CHECK(std::find(outer->backedgeDefinitionAddresses.begin(),
                  outer->backedgeDefinitionAddresses.end(),
                  kTextBase + 0x900) != outer->backedgeDefinitionAddresses.end());
}

TEST_CASE("loop-carried recovery retains finite joins and guarded identity recurrences",
          "[codegen][jump-table][loop-state]") {
  auto image = GuardedLoopStateSwitch();
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const std::array preliminaryBlocks{Block{kTextBase, 0x40}, Block{kTextBase + 0x90, 0x0C}};
  JumpTableRecoveryInput preliminaryInput{
      .site = kLoopSite,
      .ownerAddress = kTextBase,
      .preliminaryBlocks = preliminaryBlocks,
      .containingRegion = decoded.regionContaining(kTextBase),
      .limits = {},
  };
  auto initial = AnalyzeIndirectSite(decoded, preliminaryInput);
  INFO("initial failures=" << FailureNames(initial));
  REQUIRE(initial.selectedTable);
  REQUIRE(initial.failures.empty());
  CHECK(initial.selectedTable->targets ==
        std::vector<uint32_t>{kTextBase + 0x40, kTextBase + 0x70, kTextBase + 0x80});

  const Block expandedBlock{kTextBase, 0xA0};
  JumpTableRecoveryInput input{
      .site = kLoopSite,
      .ownerAddress = kTextBase,
      .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
      .containingRegion = decoded.regionContaining(kTextBase),
      .priorAutomaticTable = &*initial.selectedTable,
      .limits = {},
  };
  auto expanded = AnalyzeIndirectSite(decoded, input);
  INFO("expanded failures=" << FailureNames(expanded));
  REQUIRE(expanded.selectedTable);
  CHECK(expanded.failures.empty());
  CHECK(expanded.selectedTable->targets == initial.selectedTable->targets);
  CHECK(expanded.selectedTable->rawEntries == initial.selectedTable->rawEntries);
  REQUIRE(expanded.dataflow);
  CHECK(expanded.dataflow->caseExpandedCfg);
  CHECK(expanded.dataflow->sourceInScc);
  const auto hasDisposition = [&](std::string_view disposition) {
    return std::any_of(expanded.dataflow->reachingDefinitionPaths.begin(),
                       expanded.dataflow->reachingDefinitionPaths.end(),
                       [&](const auto& path) { return path.disposition == disposition; });
  };
  CHECK(hasDisposition("finite_constant_join"));
  CHECK(hasDisposition("finite_identity_recurrence"));
  CHECK(hasDisposition("finite_phi_domain"));
  REQUIRE(expanded.loopEvidence.size() == 2);
  const auto outer =
      std::find_if(expanded.loopEvidence.begin(), expanded.loopEvidence.end(),
                   [](const auto& loop) { return loop.headerAddress == kLoopHeader; });
  REQUIRE(outer != expanded.loopEvidence.end());
  CHECK(outer->finiteValues == std::vector<uint32_t>{0, 1, 2});
  CHECK(outer->finiteEntryDomain);
  CHECK(outer->identityBackedge);
  CHECK(outer->converged);

  auto analyzeExpandedImage = [&](AbsoluteSwitch& candidate) {
    auto candidateView = candidate.view();
    DecodedBinary candidateDecoded(candidateView);
    candidateDecoded.decode();
    JumpTableRecoveryInput candidateInput{
        .site = kLoopSite,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = candidateDecoded.regionContaining(kTextBase),
        .priorAutomaticTable = &*initial.selectedTable,
        .limits = {},
    };
    return AnalyzeIndirectSite(candidateDecoded, candidateInput);
  };

  SECTION("equivalent finite definitions through multiple predecessors") {
    auto equivalent = GuardedLoopStateSwitch();
    StoreBe32(equivalent.text, 0x50, Addi(11, 0, 1));
    auto equivalentAnalysis = analyzeExpandedImage(equivalent);
    REQUIRE(equivalentAnalysis.selectedTable);
    CHECK(equivalentAnalysis.failures.empty());
  }

  SECTION("incompatible finite join input is rejected") {
    auto incompatible = GuardedLoopStateSwitch();
    StoreBe32(incompatible.text, 0x50, Mr(11, 3));
    auto incompatibleAnalysis = analyzeExpandedImage(incompatible);
    CHECK_FALSE(incompatibleAnalysis.selectedTable);
    CHECK(incompatibleAnalysis.failures ==
          std::vector{JumpTableFailure::AmbiguousReachingDefinition});
  }

  SECTION("transformed recurrence is rejected") {
    auto nonConverging = GuardedLoopStateSwitch();
    StoreBe32(nonConverging.text, 0x80, Addi(11, 11, 1));
    auto nonConvergingAnalysis = analyzeExpandedImage(nonConverging);
    CHECK_FALSE(nonConvergingAnalysis.selectedTable);
    CHECK(nonConvergingAnalysis.failures ==
          std::vector{JumpTableFailure::AmbiguousReachingDefinition});
  }
}

TEST_CASE("expanded switch edges retain loop-invariant definitions used by a case",
          "[codegen][jump-table][loop-state][case-edge]") {
  auto image = CaseEdgeInvariantLoopStateSwitch();
  auto view = image.view();
  DecodedBinary decoded(view);
  decoded.decode();
  const std::array preliminaryBlocks{Block{kTextBase, 0x40}, Block{kTextBase + 0x90, 0x0C}};
  JumpTableRecoveryInput preliminaryInput{
      .site = kLoopSite,
      .ownerAddress = kTextBase,
      .preliminaryBlocks = preliminaryBlocks,
      .containingRegion = decoded.regionContaining(kTextBase),
      .limits = {},
  };
  auto initial = AnalyzeIndirectSite(decoded, preliminaryInput);
  REQUIRE(initial.selectedTable);
  CHECK(initial.failures.empty());

  const Block expandedBlock{kTextBase, 0xA0};
  JumpTableRecoveryInput expandedInput{
      .site = kLoopSite,
      .ownerAddress = kTextBase,
      .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
      .containingRegion = decoded.regionContaining(kTextBase),
      .priorAutomaticTable = &*initial.selectedTable,
      .limits = {},
  };
  auto expanded = AnalyzeIndirectSite(decoded, expandedInput);
  REQUIRE(expanded.selectedTable);
  CHECK(expanded.failures.empty());
  CHECK(expanded.selectedTable->targets == initial.selectedTable->targets);
  CHECK(expanded.selectedTable->rawEntries == initial.selectedTable->rawEntries);
  CHECK(expanded.selectedTable->tableAddress == initial.selectedTable->tableAddress);
  CHECK(expanded.selectedTable->storageEnd == initial.selectedTable->storageEnd);
  REQUIRE(expanded.dataflow);
  CHECK(expanded.dataflow->caseExpandedCfg);
  CHECK(std::any_of(expanded.dataflow->reachingDefinitionPaths.begin(),
                    expanded.dataflow->reachingDefinitionPaths.end(), [](const auto& path) {
                      return path.registerIndex == 27 && path.normalizedExpression == "constant" &&
                             path.disposition == "case_edge_loop_invariant_constant";
                    }));
  const auto stateLoop = std::find_if(
      expanded.loopEvidence.begin(), expanded.loopEvidence.end(), [](const auto& loop) {
        return loop.registerIndex == 11 && loop.headerAddress == kLoopHeader;
      });
  REQUIRE(stateLoop != expanded.loopEvidence.end());
  CHECK(stateLoop->finiteValues == std::vector<uint32_t>{0, 1, 2});
  CHECK(stateLoop->converged);

  auto nonConverging = CaseEdgeInvariantLoopStateSwitch();
  StoreBe32(nonConverging.text, 0x70, Addi(27, 27, 1));
  auto nonConvergingView = nonConverging.view();
  DecodedBinary nonConvergingDecoded(nonConvergingView);
  nonConvergingDecoded.decode();
  JumpTableRecoveryInput nonConvergingInput{
      .site = kLoopSite,
      .ownerAddress = kTextBase,
      .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
      .containingRegion = nonConvergingDecoded.regionContaining(kTextBase),
      .priorAutomaticTable = &*initial.selectedTable,
      .limits = {},
  };
  auto rejected = AnalyzeIndirectSite(nonConvergingDecoded, nonConvergingInput);
  CHECK_FALSE(rejected.selectedTable);
  CHECK(rejected.failures == std::vector{JumpTableFailure::AmbiguousReachingDefinition});
}

TEST_CASE("loop-carried state recovery rejects incompatible recurrences and domains",
          "[codegen][jump-table][loop-state]") {
  auto baselineImage = LoopStateSwitch();
  auto baseline = Analyze(baselineImage, kLoopSite);
  REQUIRE(baseline.selectedTable);

  auto analyzeExpanded = [&](AbsoluteSwitch& image, JumpTableRecoveryLimits limits = {}) {
    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block expandedBlock{kTextBase, 0x80};
    JumpTableRecoveryInput input{
        .site = kLoopSite,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = decoded.regionContaining(kTextBase),
        .priorAutomaticTable = &*baseline.selectedTable,
        .limits = limits,
    };
    return AnalyzeIndirectSite(decoded, input);
  };

  SECTION("non-converging recurrence") {
    auto image = LoopStateSwitch();
    StoreBe32(image.text, 0x40, Addi(21, 21, 1));
    auto analysis = analyzeExpanded(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::AmbiguousReachingDefinition});
    CHECK(analysis.loopEvidence.empty());
    REQUIRE(analysis.dataflow);
    CHECK(analysis.dataflow->mergeShape == "incompatible_phi");
  }

  SECTION("incompatible backedge definition") {
    auto image = LoopStateSwitch();
    StoreBe32(image.text, 0x50, Mr(21, 3));
    auto analysis = analyzeExpanded(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::AmbiguousReachingDefinition});
  }

  SECTION("missing finite entry definition") {
    auto image = LoopStateSwitch();
    StoreBe32(image.text, 0x00, Mr(21, 3));
    auto analysis = analyzeExpanded(image);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::AmbiguousReachingDefinition});
  }

  SECTION("a complete finite loop domain substitutes for an explicit compare") {
    auto image = LoopStateSwitch();
    StoreBe32(image.text, 0x14, 0x60000000);  // remove cmplwi
    auto analysis = Analyze(image, kLoopSite);
    REQUIRE(analysis.selectedTable);
    CHECK(analysis.selectedTable->confidence == "validated_finite_cfg_domain_all_targets");
  }

  SECTION("missing finite bound and finite loop domain") {
    auto image = LoopStateSwitch();
    StoreBe32(image.text, 0x14, 0x60000000);  // remove cmplwi
    StoreBe32(image.text, 0x40, Mr(21, 3));   // non-finite backedge state
    auto analysis = Analyze(image, kLoopSite);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
  }

  SECTION("path-local compare does not dominate dispatch") {
    AbsoluteSwitch image;
    StoreBe32(image.text, 0x00, Bc(kTextBase, kTextBase + 0x0C, 4, 2));
    StoreBe32(image.text, 0x04, 0x28030002);  // compare exists on only one predecessor
    StoreBe32(image.text, 0x08, Bc(kTextBase + 0x08, kTextBase + 0x30, 12, 1));
    StoreBe32(image.text, 0x0C, 0x3C802000);
    StoreBe32(image.text, 0x10, Rlwinm(3, 3, 2, 0, 29));
    StoreBe32(image.text, 0x14, Lwzx(5, 4, 3));
    StoreBe32(image.text, 0x18, Mtctr(5));
    StoreBe32(image.text, 0x1C, 0x4E800420);
    auto analysis = Analyze(image, kTextBase + 0x1C);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::MissingBound});
    REQUIRE(analysis.dataflow);
    CHECK(std::any_of(analysis.dataflow->boundCandidates.begin(),
                      analysis.dataflow->boundCandidates.end(), [](const auto& bound) {
                        return !bound.dominatesDispatch &&
                               bound.rejection == "compare_does_not_dominate_dispatch";
                      }));
  }

  SECTION("loop analysis safety limit") {
    auto image = LoopStateSwitch();
    JumpTableRecoveryLimits limits;
    limits.maxStates = 1;
    auto analysis = analyzeExpanded(image, limits);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::AnalysisLimit));
  }

  SECTION("CFG topology safety limit is distinct and structured") {
    auto image = LoopStateSwitch();
    JumpTableRecoveryLimits limits;
    limits.maxCfgTopologyNodes = 8;
    const uint32_t originalStateBudget = limits.maxStates;
    auto analysis = analyzeExpanded(image, limits);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(analysis.failures == std::vector{JumpTableFailure::AnalysisLimit});
    REQUIRE(analysis.dataflow);
    REQUIRE(analysis.dataflow->exhaustedBudgets.size() == 1);
    CHECK(analysis.dataflow->exhaustedBudgets.front().budget == "max_cfg_topology_nodes");
    CHECK(analysis.dataflow->exhaustedBudgets.front().limit == 8);
    CHECK(analysis.dataflow->exhaustedBudgets.front().observed > 8);
    CHECK(limits.maxStates == originalStateBudget);

    auto view = image.view();
    DecodedBinary decoded(view);
    decoded.decode();
    const Block expandedBlock{kTextBase, 0x80};
    JumpTableRecoveryInput input{
        .site = kLoopSite,
        .ownerAddress = kTextBase,
        .preliminaryBlocks = std::span<const Block>(&expandedBlock, 1),
        .containingRegion = decoded.regionContaining(kTextBase),
        .priorAutomaticTable = &*baseline.selectedTable,
        .limits = limits,
    };
    auto retry = AnalyzeIndirectSiteWithPriorLimitRetry(decoded, input);
    CHECK_FALSE(retry.selectedTable);
    CHECK(retry.failures == std::vector{JumpTableFailure::AnalysisLimit});
    CHECK_FALSE(retry.limitRetry);
    REQUIRE(retry.dataflow);
    REQUIRE(retry.dataflow->exhaustedBudgets.size() == 1);
    CHECK(retry.dataflow->exhaustedBudgets.front().budget == "max_cfg_topology_nodes");
    CHECK(retry.dataflow->exhaustedBudgets.front().limit == 8);
    CHECK(input.limits.maxStates == originalStateBudget);
  }
}

TEST_CASE("jump-table recovery rejects path-dependent relative-table semantics",
          "[codegen][jump-table][loop-state]") {
  SECTION("different anchors") {
    AbsoluteSwitch image;
    StoreBe32(image.text, 0x00, 0x28030002);  // cmplwi r3, 2
    StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x70, 12, 1));
    StoreBe32(image.text, 0x08, 0x3C802000);  // lis r4, table@h
    StoreBe32(image.text, 0x0C, Lbzx(5, 4, 3));
    StoreBe32(image.text, 0x10, Rlwinm(5, 5, 2, 0, 29));
    StoreBe32(image.text, 0x14, Bc(kTextBase + 0x14, kTextBase + 0x24, 4, 2));
    StoreBe32(image.text, 0x18, 0x3CC01000);  // path A anchor
    StoreBe32(image.text, 0x1C, B(kTextBase + 0x1C, kTextBase + 0x28));
    StoreBe32(image.text, 0x24, 0x3CC01001);  // path B different anchor
    StoreBe32(image.text, 0x28, Add(5, 6, 5));
    StoreBe32(image.text, 0x2C, Mtctr(5));
    StoreBe32(image.text, 0x30, 0x4E800420);
    image.table[0] = 0x10;
    image.table[1] = 0x14;
    image.table[2] = 0x18;
    auto analysis = Analyze(image, kTextBase + 0x30);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
  }

  SECTION("different scales") {
    AbsoluteSwitch image;
    StoreBe32(image.text, 0x00, 0x28030002);
    StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x70, 12, 1));
    StoreBe32(image.text, 0x08, 0x3C802000);
    StoreBe32(image.text, 0x0C, Lbzx(5, 4, 3));
    StoreBe32(image.text, 0x10, Bc(kTextBase + 0x10, kTextBase + 0x20, 4, 2));
    StoreBe32(image.text, 0x14, Rlwinm(5, 5, 2, 0, 29));
    StoreBe32(image.text, 0x18, B(kTextBase + 0x18, kTextBase + 0x28));
    StoreBe32(image.text, 0x20, Rlwinm(5, 5, 1, 0, 30));
    StoreBe32(image.text, 0x28, 0x3CC01000);
    StoreBe32(image.text, 0x2C, Add(5, 6, 5));
    StoreBe32(image.text, 0x30, Mtctr(5));
    StoreBe32(image.text, 0x34, 0x4E800420);
    image.table[0] = 0x10;
    image.table[1] = 0x14;
    image.table[2] = 0x18;
    auto analysis = Analyze(image, kTextBase + 0x34);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
  }

  SECTION("signed and unsigned paths disagree") {
    AbsoluteSwitch image;
    StoreBe32(image.text, 0x00, 0x28030002);
    StoreBe32(image.text, 0x04, Bc(kTextBase + 0x04, kTextBase + 0x70, 12, 1));
    StoreBe32(image.text, 0x08, 0x3C802000);
    StoreBe32(image.text, 0x0C, Lbzx(5, 4, 3));
    StoreBe32(image.text, 0x10, Bc(kTextBase + 0x10, kTextBase + 0x20, 4, 2));
    StoreBe32(image.text, 0x14, Extsb(5, 5));
    StoreBe32(image.text, 0x18, B(kTextBase + 0x18, kTextBase + 0x24));
    StoreBe32(image.text, 0x20, Mr(5, 5));
    StoreBe32(image.text, 0x24, Rlwinm(5, 5, 2, 0, 29));
    StoreBe32(image.text, 0x28, 0x3CC01000);
    StoreBe32(image.text, 0x2C, Add(5, 6, 5));
    StoreBe32(image.text, 0x30, Mtctr(5));
    StoreBe32(image.text, 0x34, 0x4E800420);
    image.table[0] = 0x10;
    image.table[1] = 0x14;
    image.table[2] = 0x18;
    auto analysis = Analyze(image, kTextBase + 0x34);
    CHECK_FALSE(analysis.selectedTable);
    CHECK(HasFailure(analysis, JumpTableFailure::AmbiguousReachingDefinition));
  }
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

TEST_CASE("a guarded loaded index does not spend CFG states resolving its source base",
          "[codegen][jump-table]") {
  AbsoluteSwitch image;
  image.text.resize(0xC00);
  std::fill(image.text.begin(), image.text.end(), 0);
  for (uint32_t offset = 0; offset < image.text.size(); offset += 4)
    StoreBe32(image.text, offset, 0x60000000);  // nop

  constexpr uint32_t kSwitchOffset = 0xA00;
  constexpr uint32_t kSwitch = kTextBase + kSwitchOffset;
  constexpr uint32_t kSite = kSwitch + 0x34;
  StoreBe32(image.text, kSwitchOffset + 0x00, 0x82610020);  // lwz r19, 32(r1)
  StoreBe32(image.text, kSwitchOffset + 0x04, Addi(11, 19, -99));
  StoreBe32(image.text, kSwitchOffset + 0x08, 0x280B0018);  // cmplwi r11, 24
  StoreBe32(image.text, kSwitchOffset + 0x0C,
            Bc(kSwitch + 0x0C, kSwitch + 0x80, 12, 1));     // bgt default
  StoreBe32(image.text, kSwitchOffset + 0x10, 0x3D802000);  // lis r12, table@h
  StoreBe32(image.text, kSwitchOffset + 0x14, Addi(12, 12, 0));
  StoreBe32(image.text, kSwitchOffset + 0x18, Rlwinm(0, 11, 1, 0, 30));
  StoreBe32(image.text, kSwitchOffset + 0x1C, Lhzx(0, 12, 0));
  StoreBe32(image.text, kSwitchOffset + 0x20, 0x3D801000);  // lis r12, anchor@h
  StoreBe32(image.text, kSwitchOffset + 0x24, Addi(12, 12, 0));
  StoreBe32(image.text, kSwitchOffset + 0x28, Add(12, 12, 0));
  StoreBe32(image.text, kSwitchOffset + 0x2C, Mtctr(12));
  StoreBe32(image.text, kSwitchOffset + 0x30, 0x60000000);  // nop
  StoreBe32(image.text, kSwitchOffset + 0x34, 0x4E800420);  // bctr
  StoreBe32(image.text, kSwitchOffset + 0x80, 0x4E800020);  // default: blr
  StoreBe32(image.text, 0xB00, 0x4E800020);
  StoreBe32(image.text, 0xB10, 0x4E800020);
  StoreBe32(image.text, 0xB20, 0x4E800020);
  for (uint32_t index = 0; index < 25; ++index)
    StoreBe16(image.table, index * 2, static_cast<uint16_t>(0xB00 + (index % 3) * 0x10));

  JumpTableRecoveryLimits limits;
  limits.maxStates = 512;
  auto recovered = Analyze(image, kSite, nullptr, limits, 0xC00);
  REQUIRE(recovered.selectedTable);
  CHECK(recovered.failures.empty());
  CHECK(recovered.selectedTable->kind == JumpTableKind::RelativeOffset);
  CHECK(recovered.selectedTable->caseCount == 25);
  CHECK(recovered.selectedTable->tableAddress == kTableBase);
  CHECK(recovered.selectedTable->anchorAddress == kTextBase);

  // The address used to obtain the pre-bound value is not part of the table
  // proof. The exact normalized register is range-checked and consumed by the
  // table load, so an opaque object base is as safe as r1 here. Table base,
  // anchor, storage stride, raw entries, and every target are still validated.
  StoreBe32(image.text, kSwitchOffset + 0x00, 0x82620020);  // lwz r19, 32(r2)
  auto unknownBase = Analyze(image, kSite, nullptr, limits, 0xC00);
  REQUIRE(unknownBase.selectedTable);
  CHECK(unknownBase.failures.empty());
  CHECK(unknownBase.selectedTable->confidence == "validated_local_bounded_slice_after_state_limit");
  CHECK(unknownBase.selectedTable->targets == recovered.selectedTable->targets);
  CHECK(unknownBase.selectedTable->rawEntries == recovered.selectedTable->rawEntries);
  REQUIRE(unknownBase.dataflow);
  REQUIRE(unknownBase.dataflow->exhaustedBudgets.size() == 1);
  CHECK(unknownBase.dataflow->exhaustedBudgets.front().budget == "max_states");
  CHECK(unknownBase.dataflow->exhaustedBudgets.front().limit == 512);
  CHECK(unknownBase.dataflow->exhaustedBudgets.front().observed > 512);
}
