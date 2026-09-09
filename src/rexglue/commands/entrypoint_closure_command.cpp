/**
 * @file        rexglue/commands/entrypoint_closure_command.cpp
 * @brief       Report-only static entrypoint-closure command
 *
 * @copyright   Copyright (c) 2026 Tom Clay
 * @license     BSD 3-Clause License
 */

#include "entrypoint_closure_command.h"
#include "codegen_command.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <rex/codegen/codegen.h>
#include <rex/codegen/entrypoint_closure.h>
#include <rex/codegen/function_node.h>
#include <rex/codegen/manifest.h>
#include <rex/logging.h>
#include <rex/runtime.h>
#include <rex/system/kernel_state.h>
#include <rex/system/user_module.h>
#include <rex/system/xex_module.h>

#include "crypto/sha256.h"

#if defined(_WIN32)
#include <Windows.h>
#include <Psapi.h>
#elif defined(__unix__) || defined(__APPLE__)
#include <sys/resource.h>
#endif

namespace rexglue::cli {

namespace {

namespace fs = std::filesystem;
using Json = nlohmann::json;
using namespace rex::codegen;

struct EntrypointClosureArgs {
  std::string manifestPath;
  std::string provenancePath;
  std::string outputDirectory;
  EntrypointClosureLimits limits;
  bool noReviewToml = false;
};

struct ProvenanceConfig {
  std::string expectedBaseXexSha256;
  std::string expectedTitleUpdateSha256;
  std::string expectedPatchedImageSha256;
  std::string expectedExecutableMemoryFingerprintAlgorithm;
  std::string expectedExecutableMemoryFingerprint;
  std::optional<uint32_t> expectedImageBase;
  std::optional<uint32_t> expectedImageSize;
  std::optional<uint32_t> expectedTitleId;
  std::optional<uint32_t> expectedMediaId;
  std::optional<std::string> expectedVersion;
  std::vector<EntrypointManualEvidence> manualEvidence;
  std::vector<EntrypointFixtureExpectation> fixtures;
};

std::string Upper(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return value;
}

Result<std::string> HashFile(const fs::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return Err<std::string>(rex::ErrorCategory::IO,
                            fmt::format("Unable to read '{}'", path.string()));
  }
  sha256::SHA256 hash;
  std::array<char, 64 * 1024> buffer{};
  while (input) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    if (input.gcount() > 0)
      hash.add(buffer.data(), static_cast<size_t>(input.gcount()));
  }
  if (!input.eof()) {
    return Err<std::string>(rex::ErrorCategory::IO,
                            fmt::format("Failed while hashing '{}'", path.string()));
  }
  return rex::Ok(Upper(hash.getHash()));
}

std::string HashPatchedImage(const rex::runtime::XexModule& module) {
  const uint8_t* image = module.memory()->TranslateVirtual<const uint8_t*>(module.base_address());
  sha256::SHA256 hash;
  hash.add(image, module.image_size());
  return Upper(hash.getHash());
}

std::string HashSection(const SectionView& section) {
  sha256::SHA256 hash;
  if (section.size != 0)
    hash.add(section.data, section.size);
  return Upper(hash.getHash());
}

Result<std::string> ComputeExecutableMemoryFingerprint(const BinaryView& binary) {
  struct CanonicalSpan {
    uint64_t start = 0;
    uint64_t end = 0;
    uint8_t permissions = 0;
    std::vector<const SectionView*> sections;
  };

  std::vector<const SectionView*> executableSections;
  for (const auto& section : binary.sections()) {
    if (section.executable && section.size != 0)
      executableSections.push_back(&section);
  }
  std::sort(executableSections.begin(), executableSections.end(), [](const auto* a, const auto* b) {
    if (a->baseAddress != b->baseAddress)
      return a->baseAddress < b->baseAddress;
    return a->size < b->size;
  });

  std::vector<CanonicalSpan> spans;
  for (const auto* section : executableSections) {
    const uint64_t start = section->baseAddress;
    const uint64_t end = start + section->size;
    const uint8_t permissions = static_cast<uint8_t>(
        (section->readable ? 1 : 0) | (section->writable ? 2 : 0) | (section->executable ? 4 : 0));
    if (!spans.empty() && start < spans.back().end) {
      return Err<std::string>(
          rex::ErrorCategory::Validation,
          fmt::format("Executable sections overlap at 0x{:08X}", section->baseAddress));
    }
    if (!spans.empty() && start == spans.back().end && permissions == spans.back().permissions) {
      spans.back().end = end;
      spans.back().sections.push_back(section);
    } else {
      spans.push_back(
          {.start = start, .end = end, .permissions = permissions, .sections = {section}});
    }
  }

  sha256::SHA256 hash;
  constexpr std::string_view magic = "FABLE2_EXECUTABLE_MEMORY_V1";
  hash.add(magic.data(), magic.size());
  const uint8_t terminator = 0;
  hash.add(&terminator, sizeof(terminator));

  auto addBe32 = [&](uint32_t value) {
    const std::array<uint8_t, 4> bytes{
        static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
    hash.add(bytes.data(), bytes.size());
  };
  auto addBe64 = [&](uint64_t value) {
    const std::array<uint8_t, 8> bytes{
        static_cast<uint8_t>(value >> 56), static_cast<uint8_t>(value >> 48),
        static_cast<uint8_t>(value >> 40), static_cast<uint8_t>(value >> 32),
        static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8),  static_cast<uint8_t>(value)};
    hash.add(bytes.data(), bytes.size());
  };

  addBe32(static_cast<uint32_t>(spans.size()));
  for (const auto& span : spans) {
    addBe64(span.start);
    addBe64(span.end - span.start);
    hash.add(&span.permissions, sizeof(span.permissions));
    for (const auto* section : span.sections)
      hash.add(section->data, section->size);
  }
  return rex::Ok(Upper(hash.getHash()));
}

uint64_t PeakWorkingSetBytes() {
#if defined(_WIN32)
  PROCESS_MEMORY_COUNTERS counters{};
  counters.cb = sizeof(counters);
  if (GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters)))
    return counters.PeakWorkingSetSize;
  return 0;
#elif defined(__unix__) || defined(__APPLE__)
  rusage usage{};
  if (getrusage(RUSAGE_SELF, &usage) != 0)
    return 0;
#if defined(__APPLE__)
  return usage.ru_maxrss;
#else
  return static_cast<uint64_t>(usage.ru_maxrss) * 1024;
#endif
#else
  return 0;
#endif
}

Result<uint32_t> JsonAddress(const Json& value, std::string_view fieldName) {
  if (value.is_number_unsigned())
    return rex::Ok(value.get<uint32_t>());
  if (!value.is_string()) {
    return Err<uint32_t>(rex::ErrorCategory::Config,
                         fmt::format("{} must be an integer or address string", fieldName));
  }
  const std::string text = value.get<std::string>();
  try {
    size_t consumed = 0;
    unsigned long parsed = std::stoul(text, &consumed, 0);
    if (consumed != text.size() || parsed > UINT32_MAX)
      throw std::out_of_range("guest address");
    return rex::Ok(static_cast<uint32_t>(parsed));
  } catch (const std::exception&) {
    return Err<uint32_t>(rex::ErrorCategory::Config,
                         fmt::format("{} has invalid address '{}'", fieldName, text));
  }
}

std::optional<EntrypointEvidenceKind> ParseEvidenceKind(std::string_view name) {
  for (uint32_t raw = static_cast<uint32_t>(EntrypointEvidenceKind::XexEntrypoint);
       raw <= static_cast<uint32_t>(EntrypointEvidenceKind::ReservedRuntimeBulkImport); ++raw) {
    auto kind = static_cast<EntrypointEvidenceKind>(raw);
    if (name == EntrypointEvidenceKindName(kind))
      return kind;
  }
  return std::nullopt;
}

Result<ProvenanceConfig> LoadProvenance(const fs::path& path) {
  ProvenanceConfig result;
  if (path.empty())
    return rex::Ok(std::move(result));

  std::ifstream stream(path);
  if (!stream) {
    return Err<ProvenanceConfig>(
        rex::ErrorCategory::IO,
        fmt::format("Entrypoint-closure provenance file not found: {}", path.string()));
  }

  Json root;
  try {
    root = Json::parse(stream);
  } catch (const std::exception& error) {
    return Err<ProvenanceConfig>(
        rex::ErrorCategory::Config,
        fmt::format("Unable to parse provenance '{}': {}", path.string(), error.what()));
  }
  const uint32_t schemaVersion = root.value("schema_version", 0);
  if (schemaVersion < 1 || schemaVersion > 5) {
    return Err<ProvenanceConfig>(
        rex::ErrorCategory::Config,
        "Unsupported provenance schema_version (expected 1, 2, 3, 4 or 5)");
  }

  const auto& identity = root.value("expected_image_identity", Json::object());
  result.expectedBaseXexSha256 = Upper(identity.value("base_xex_sha256", ""));
  result.expectedTitleUpdateSha256 = Upper(identity.value("title_update_sha256", ""));
  result.expectedPatchedImageSha256 = Upper(identity.value("patched_image_sha256", ""));
  result.expectedExecutableMemoryFingerprintAlgorithm =
      identity.value("executable_memory_fingerprint_algorithm", "");
  result.expectedExecutableMemoryFingerprint =
      Upper(identity.value("executable_memory_fingerprint", ""));
  auto optionalAddress = [&](const char* name,
                             std::optional<uint32_t>& destination) -> Result<void> {
    if (!identity.contains(name))
      return rex::Ok();
    auto parsed = JsonAddress(identity.at(name), name);
    if (!parsed)
      return Err<void>(parsed.error());
    destination = *parsed;
    return rex::Ok();
  };
  if (auto parsed = optionalAddress("image_base", result.expectedImageBase); !parsed)
    return Err<ProvenanceConfig>(parsed.error());
  if (auto parsed = optionalAddress("image_size", result.expectedImageSize); !parsed)
    return Err<ProvenanceConfig>(parsed.error());
  if (auto parsed = optionalAddress("title_id", result.expectedTitleId); !parsed)
    return Err<ProvenanceConfig>(parsed.error());
  if (auto parsed = optionalAddress("media_id", result.expectedMediaId); !parsed)
    return Err<ProvenanceConfig>(parsed.error());
  if (identity.contains("version"))
    result.expectedVersion = identity.at("version").get<std::string>();

  for (const auto& item : root.value("manual_evidence", Json::array())) {
    auto address = JsonAddress(item.at("address"), "manual_evidence.address");
    auto size = JsonAddress(item.at("size"), "manual_evidence.size");
    if (!address)
      return Err<ProvenanceConfig>(address.error());
    if (!size)
      return Err<ProvenanceConfig>(size.error());
    EntrypointManualEvidence evidence{
        .address = *address,
        .size = *size,
        .provenance = item.value("provenance", path.generic_string()),
    };
    for (const auto& kindValue : item.value("evidence", Json::array())) {
      auto kind = ParseEvidenceKind(kindValue.get<std::string>());
      if (!kind) {
        return Err<ProvenanceConfig>(
            rex::ErrorCategory::Config,
            fmt::format("Unknown evidence kind '{}'", kindValue.get<std::string>()));
      }
      evidence.kinds.push_back(*kind);
    }
    result.manualEvidence.push_back(std::move(evidence));
  }

  for (const auto& item : root.value("acceptance_fixtures", Json::array())) {
    auto address = JsonAddress(item.at("address"), "acceptance_fixtures.address");
    auto size = JsonAddress(item.at("size"), "acceptance_fixtures.size");
    if (!address)
      return Err<ProvenanceConfig>(address.error());
    if (!size)
      return Err<ProvenanceConfig>(size.error());
    result.fixtures.push_back(
        {.address = *address,
         .size = *size,
         .verifiedClassification = item.at("verified_classification").get<std::string>()});
  }
  return rex::Ok(std::move(result));
}

std::vector<EntrypointFunctionSeed> BuildFunctionSeeds(
    const rex::codegen::CodegenContext& context) {
  std::vector<EntrypointFunctionSeed> seeds;
  seeds.reserve(context.graph.functionCount());
  for (const auto& [address, ownedNode] : context.graph.functions()) {
    const auto& node = *ownedNode;
    if (node.isImport() || !node.size())
      continue;
    EntrypointFunctionSeed seed{
        .range = {.start = address, .end = address + node.size()},
        .authority = AuthorityName(node.authority()),
        .trusted = node.authority() != FunctionAuthority::GAP_FILL,
        .preliminary = node.authority() == FunctionAuthority::GAP_FILL,
        .manifest = node.authority() == FunctionAuthority::CONFIG,
        .exceptionFunction = node.hasExceptionHandler(),
    };
    switch (node.authority()) {
      case FunctionAuthority::CONFIG:
        seed.boundaryProvenance.push_back("existing_manifest");
        break;
      case FunctionAuthority::PDATA:
        seed.boundaryProvenance.push_back("pdata_function");
        if (node.hasExceptionHandler())
          seed.boundaryProvenance.push_back("pdata_exception");
        break;
      case FunctionAuthority::VTABLE:
        seed.boundaryProvenance.push_back("rtti_vtable");
        break;
      case FunctionAuthority::HELPER:
        seed.boundaryProvenance.push_back("abi_helper");
        break;
      case FunctionAuthority::DISCOVERED:
        seed.boundaryProvenance.push_back("rexglue_discovered");
        break;
      case FunctionAuthority::GAP_FILL:
        seed.boundaryProvenance.push_back("rexglue_gap_fill_preliminary");
        break;
      case FunctionAuthority::IMPORT:
        break;
    }
    for (const auto& block : node.blocks())
      seed.blocks.push_back({.start = block.base, .end = block.end()});
    seed.labels = node.labels();
    for (const auto& table : node.jumpTables()) {
      seed.jumpTableTargets.insert(table.targets.begin(), table.targets.end());
    }
    auto appendEdges = [&](const std::vector<CallEdge>& edges, std::string_view kind) {
      for (const auto& edge : edges) {
        uint32_t target = 0;
        if (auto* function = edge.target.asFunction())
          target = function->base();
        else if (auto* unresolved = std::get_if<CallTarget::Unresolved>(&edge.target.value))
          target = unresolved->address;
        if (target) {
          seed.directEdges.push_back(
              {.site = edge.site, .source = address, .target = target, .kind = std::string(kind)});
        }
      }
    };
    appendEdges(node.calls(), "direct_branch_link");
    appendEdges(node.tailCalls(), "inter_function_tail_branch");
    for (const auto& unresolved : node.unresolvedJumps()) {
      seed.directEdges.push_back(
          {.site = unresolved.site,
           .source = address,
           .target = unresolved.target,
           .kind = unresolved.isCall ? "direct_branch_link" : "inter_function_tail_branch"});
    }

    if (const auto& info = node.exceptionInfo(); info && info->hasInfo()) {
      auto retainIfInternal = [&](uint32_t candidate) {
        if (seed.range.contains(candidate))
          seed.exceptionEntries.insert(candidate);
      };
      if (auto* seh = info->asSeh()) {
        for (const auto& scope : seh->scopes) {
          retainIfInternal(scope.handler);
          retainIfInternal(scope.filter);
        }
      } else if (auto* cxx = info->asCxx()) {
        for (const auto& ipState : cxx->ipToStateMap)
          retainIfInternal(ipState.ip);
        for (const auto& tryBlock : cxx->tryBlocks) {
          for (const auto& handler : tryBlock.handlers)
            retainIfInternal(handler.handlerAddress);
        }
      }
    }

    std::sort(seed.blocks.begin(), seed.blocks.end(), [](const auto& a, const auto& b) {
      if (a.start != b.start)
        return a.start < b.start;
      return a.end < b.end;
    });
    std::sort(seed.directEdges.begin(), seed.directEdges.end(), [](const auto& a, const auto& b) {
      if (a.site != b.site)
        return a.site < b.site;
      if (a.kind != b.kind)
        return a.kind < b.kind;
      return a.target < b.target;
    });
    std::sort(seed.boundaryProvenance.begin(), seed.boundaryProvenance.end());
    seeds.push_back(std::move(seed));
  }
  std::sort(seeds.begin(), seeds.end(), [](const auto& a, const auto& b) {
    if (a.range.start != b.range.start)
      return a.range.start < b.range.start;
    if (a.range.end != b.range.end)
      return a.range.end < b.range.end;
    return a.authority < b.authority;
  });
  return seeds;
}

std::optional<EntrypointAddressRange> BlockExtent(
    const std::vector<EntrypointAddressRange>& blocks) {
  if (blocks.empty())
    return std::nullopt;
  uint32_t start = blocks.front().start;
  uint32_t end = blocks.front().end;
  for (const auto& block : blocks) {
    start = std::min(start, block.start);
    end = std::max(end, block.end);
  }
  return EntrypointAddressRange{start, end};
}

EntrypointJumpTableRecovery BuildJumpTableRecovery(const CodegenContext& context) {
  EntrypointJumpTableRecovery report;
  report.limits = context.analysisState().jumpTableLimits;
  report.stats = context.analysisState().jumpTableRecovery;

  for (const auto& [owner, ownedNode] : context.graph.functions()) {
    const auto& node = *ownedNode;
    report.indirectSites.insert(report.indirectSites.end(), node.indirectSites().begin(),
                                node.indirectSites().end());
    if (node.jumpTables().empty())
      continue;

    JumpTableBoundaryEffect effect;
    effect.ownerAddress = owner;
    effect.ownerAuthority = AuthorityName(node.authority());
    effect.pdataAssociated = context.scan.pdataSizes.contains(owner);
    for (const auto& block : node.jumpTablePreliminaryBlocks())
      effect.preliminaryBlocks.push_back({block.base, block.end()});
    for (const auto& block : node.blocks())
      effect.finalBlocks.push_back({block.base, block.end()});
    std::sort(effect.preliminaryBlocks.begin(), effect.preliminaryBlocks.end(),
              [](const auto& lhs, const auto& rhs) { return lhs.start < rhs.start; });
    std::sort(effect.finalBlocks.begin(), effect.finalBlocks.end(),
              [](const auto& lhs, const auto& rhs) { return lhs.start < rhs.start; });
    effect.preliminaryExtent = BlockExtent(effect.preliminaryBlocks);
    effect.finalExtent = BlockExtent(effect.finalBlocks);
    effect.changed = effect.preliminaryBlocks != effect.finalBlocks;

    std::set<uint32_t> targets;
    std::set<uint32_t> callable;
    for (const auto& table : node.jumpTables()) {
      for (uint32_t target : table.targets) {
        targets.insert(target);
        if (target != owner && context.graph.isEntryPoint(target))
          callable.insert(target);
      }
    }
    effect.caseTargets.assign(targets.begin(), targets.end());
    effect.independentlyCallableCases.assign(callable.begin(), callable.end());
    report.boundaryEffects.push_back(std::move(effect));
  }

  std::sort(report.indirectSites.begin(), report.indirectSites.end(),
            [](const auto& lhs, const auto& rhs) {
              if (lhs.site != rhs.site)
                return lhs.site < rhs.site;
              return lhs.ownerAddress < rhs.ownerAddress;
            });
  std::sort(report.boundaryEffects.begin(), report.boundaryEffects.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.ownerAddress < rhs.ownerAddress; });
  report.stats.indirectSites = static_cast<uint32_t>(report.indirectSites.size());
  report.stats.recoveredTables = static_cast<uint32_t>(
      std::count_if(report.indirectSites.begin(), report.indirectSites.end(), [](const auto& site) {
        return site.selectedTable && site.selectedTable->origin == JumpTableOrigin::Automatic;
      }));
  report.stats.manualTables = static_cast<uint32_t>(
      std::count_if(report.indirectSites.begin(), report.indirectSites.end(), [](const auto& site) {
        return site.selectedTable && site.selectedTable->origin == JumpTableOrigin::Manual;
      }));
  report.stats.unresolvedSites = static_cast<uint32_t>(std::count_if(
      report.indirectSites.begin(), report.indirectSites.end(),
      [](const auto& site) { return site.usesCtr && !site.link && !site.selectedTable; }));
  return report;
}

Result<void> VerifyIdentity(const EntrypointImageIdentity& actual,
                            const ProvenanceConfig& expected) {
  auto compareString = [&](std::string_view field, const std::string& wanted,
                           const std::string& found) -> Result<void> {
    if (!wanted.empty() && Upper(wanted) != Upper(found)) {
      return Err<void>(rex::ErrorCategory::Validation,
                       fmt::format("Wrong image: {} expected {}, found {}", field, wanted, found));
    }
    return rex::Ok();
  };
  auto compareAddress = [&](std::string_view field, const std::optional<uint32_t>& wanted,
                            uint32_t found) -> Result<void> {
    if (wanted && *wanted != found) {
      return Err<void>(
          rex::ErrorCategory::Validation,
          fmt::format("Wrong image: {} expected 0x{:08X}, found 0x{:08X}", field, *wanted, found));
    }
    return rex::Ok();
  };
  if (auto result =
          compareString("base_xex_sha256", expected.expectedBaseXexSha256, actual.baseXexSha256);
      !result)
    return result;
  if (auto result = compareString("title_update_sha256", expected.expectedTitleUpdateSha256,
                                  actual.titleUpdateSha256);
      !result)
    return result;
  if (auto result = compareString("patched_image_sha256", expected.expectedPatchedImageSha256,
                                  actual.patchedImageSha256);
      !result)
    return result;
  if (!expected.expectedExecutableMemoryFingerprint.empty()) {
    if (expected.expectedExecutableMemoryFingerprintAlgorithm.empty()) {
      return Err<void>(rex::ErrorCategory::Config,
                       "Expected executable-memory fingerprint requires its algorithm");
    }
    if (expected.expectedExecutableMemoryFingerprintAlgorithm !=
        actual.executableMemoryFingerprintAlgorithm) {
      return Err<void>(
          rex::ErrorCategory::Validation,
          fmt::format("Wrong image: executable_memory_fingerprint_algorithm expected {}, found {}",
                      expected.expectedExecutableMemoryFingerprintAlgorithm,
                      actual.executableMemoryFingerprintAlgorithm));
    }
    if (auto result = compareString("executable_memory_fingerprint",
                                    expected.expectedExecutableMemoryFingerprint,
                                    actual.executableMemoryFingerprint);
        !result)
      return result;
  }
  if (auto result = compareAddress("image_base", expected.expectedImageBase, actual.imageBase);
      !result)
    return result;
  if (auto result = compareAddress("image_size", expected.expectedImageSize, actual.imageSize);
      !result)
    return result;
  if (auto result = compareAddress("title_id", expected.expectedTitleId, actual.titleId); !result)
    return result;
  if (auto result = compareAddress("media_id", expected.expectedMediaId, actual.mediaId); !result)
    return result;
  if (expected.expectedVersion && *expected.expectedVersion != actual.version) {
    return Err<void>(rex::ErrorCategory::Validation,
                     fmt::format("Wrong image: version expected {}, found {}",
                                 *expected.expectedVersion, actual.version));
  }
  return rex::Ok();
}

Result<void> RunEntrypointClosure(const EntrypointClosureArgs& args) {
  using Clock = std::chrono::steady_clock;
  const auto start = std::chrono::steady_clock::now();
  auto elapsedMicroseconds = [](Clock::time_point started) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started).count());
  };
  EntrypointClosureRunMetadata runMetadata;
  fs::path manifestPath = args.manifestPath;
  if (manifestPath.empty()) {
    auto discovered = DiscoverManifestInCwd();
    if (!discovered)
      return Err<void>(discovered.error());
    manifestPath = *discovered;
  }
  if (!ManifestConfig::IsManifest(manifestPath)) {
    return Err<void>(rex::ErrorCategory::Config,
                     fmt::format("{} is not a project manifest", manifestPath.string()));
  }
  manifestPath = fs::canonical(manifestPath);
  auto manifestHashBefore = HashFile(manifestPath);
  if (!manifestHashBefore)
    return Err<void>(manifestHashBefore.error());

  auto loadedManifest = ManifestConfig::Load(manifestPath);
  if (!loadedManifest)
    return Err<void>(rex::ErrorCategory::Config, "Failed to load project manifest");
  auto provenance = LoadProvenance(args.provenancePath);
  if (!provenance)
    return Err<void>(provenance.error());

  auto stageStarted = Clock::now();
  auto pipeline = CodegenPipeline::CreateEntrypoint(*loadedManifest);
  runMetadata.stageTimings.imageLoadMicroseconds = elapsedMicroseconds(stageStarted);
  if (!pipeline)
    return Err<void>(pipeline.error());

  auto executable = pipeline->runtime().kernel_state()->GetExecutableModule();
  if (!executable || !executable->xex_module())
    return Err<void>(rex::ErrorCategory::Format, "Loaded XEX module is unavailable");
  auto* module = executable->xex_module();

  stageStarted = Clock::now();
  fs::path xexPath = loadedManifest->manifestDir / loadedManifest->entrypoint.recompiler.filePath;
  xexPath = fs::canonical(xexPath);
  fs::path titleUpdatePath = xexPath;
  titleUpdatePath.replace_extension(".xexp");
  auto baseHash = HashFile(xexPath);
  if (!baseHash)
    return Err<void>(baseHash.error());
  std::string titleUpdateHash;
  if (fs::exists(titleUpdatePath)) {
    auto hash = HashFile(titleUpdatePath);
    if (!hash)
      return Err<void>(hash.error());
    titleUpdateHash = *hash;
  }

  auto executableMemoryFingerprint =
      ComputeExecutableMemoryFingerprint(pipeline->context().binary());
  if (!executableMemoryFingerprint)
    return Err<void>(executableMemoryFingerprint.error());

  EntrypointImageIdentity identity{
      .identityMethod =
          "SHA-256 of source XEX, sibling XEXP, contiguous loaded post-patch guest image and "
          "versioned executable-memory spans",
      .baseXexSha256 = *baseHash,
      .titleUpdateSha256 = titleUpdateHash,
      .patchedImageSha256 = HashPatchedImage(*module),
      .executableMemoryFingerprintAlgorithm = std::string(kExecutableMemoryFingerprintAlgorithm),
      .executableMemoryFingerprint = *executableMemoryFingerprint,
      .imageBase = module->base_address(),
      .imageSize = module->image_size(),
      .entryPoint = module->entry_point(),
      .peTimeDateStamp = module->pe_time_date_stamp(),
  };
  if (auto* execution = module->opt_execution_info()) {
    identity.titleId = execution->title_id;
    identity.mediaId = execution->media_id;
    auto version = execution->version();
    identity.version = fmt::format(
        "{}.{}.{}.{}", static_cast<uint32_t>(version.major), static_cast<uint32_t>(version.minor),
        static_cast<uint32_t>(version.build), static_cast<uint32_t>(version.qfe));
  }
  if (auto verified = VerifyIdentity(identity, *provenance); !verified)
    return verified;
  runMetadata.stageTimings.identityVerificationMicroseconds = elapsedMicroseconds(stageStarted);

  // Reject a wrong executable/update pair before the expensive graph pass.
  if (auto analysis = pipeline->RunAnalyze(); !analysis)
    return analysis;
  const auto& analysisTimings = pipeline->context().analysisState().stageTimings;
  const auto& jumpTimings = pipeline->context().analysisState().jumpTableRecovery;
  runMetadata.stageTimings.instructionDecodeMicroseconds = analysisTimings.decodeMicroseconds;
  runMetadata.stageTimings.registerMicroseconds = analysisTimings.registerMicroseconds;
  runMetadata.stageTimings.scanMicroseconds = analysisTimings.scanMicroseconds;
  runMetadata.stageTimings.discoverMicroseconds = analysisTimings.discoverMicroseconds;
  runMetadata.stageTimings.gapFillMicroseconds = analysisTimings.gapFillMicroseconds;
  runMetadata.stageTimings.finalOwnershipMicroseconds = analysisTimings.mergeMicroseconds;
  runMetadata.stageTimings.validateMicroseconds = analysisTimings.validateMicroseconds;
  runMetadata.stageTimings.preliminaryCfgMicroseconds = jumpTimings.preliminaryCfgMicroseconds;
  runMetadata.stageTimings.indirectSiteClassificationMicroseconds =
      jumpTimings.indirectSiteClassificationMicroseconds;
  runMetadata.stageTimings.jumpTableDataflowRecoveryMicroseconds = jumpTimings.elapsedMicroseconds;
  runMetadata.stageTimings.caseTargetCfgExpansionMicroseconds =
      jumpTimings.caseExpansionCfgMicroseconds;
  runMetadata.stageTimings.perFunctionFixpointMicroseconds =
      jumpTimings.functionFixpointMicroseconds;
  runMetadata.stageTimings.fixpointOverheadMicroseconds = jumpTimings.fixpointOverheadMicroseconds;

  stageStarted = Clock::now();
  EntrypointClosureInput input{
      .image = identity,
      .limits = args.limits,
      .manualEvidence = provenance->manualEvidence,
      .fixtures = provenance->fixtures,
  };
  input.functionSeeds = BuildFunctionSeeds(pipeline->context());
  runMetadata.stageTimings.functionSeedConstructionMicroseconds = elapsedMicroseconds(stageStarted);
  stageStarted = Clock::now();
  input.jumpTableRecovery = BuildJumpTableRecovery(pipeline->context());
  runMetadata.stageTimings.jumpTableReportConstructionMicroseconds =
      elapsedMicroseconds(stageStarted);
  input.relocationStorageAddresses.insert(module->relocation_storage_addresses().begin(),
                                          module->relocation_storage_addresses().end());
  for (const auto& item : module->binary_exports())
    input.peExports.emplace_back(item.address, item.name);
  input.tlsCallbacks.assign(module->tls_callbacks().begin(), module->tls_callbacks().end());
  if (const auto* relocSection = module->FindSectionByName(".reloc");
      relocSection && relocSection->virtual_size && input.relocationStorageAddresses.empty()) {
    input.producerDiagnostics.push_back(
        {.limit = "pe_base_relocation_parse",
         .configured = relocSection->virtual_size,
         .observed = 0,
         .address = relocSection->virtual_address,
         .detail = "relocation section has no structurally valid PE base-relocation blocks; "
                   "relocation-backed pointer evidence is unavailable"});
  }

  stageStarted = Clock::now();
  auto report = AnalyzeEntrypointClosure(pipeline->context(), std::move(input));
  runMetadata.stageTimings.closureAnalysisMicroseconds = elapsedMicroseconds(stageStarted);
  stageStarted = Clock::now();
  for (auto& section : report.sections) {
    const auto* binarySection = pipeline->context().binary().findSection(section.range.start);
    if (!binarySection || binarySection->baseAddress != section.range.start ||
        binarySection->end() != section.range.end) {
      return Err<void>(rex::ErrorCategory::Validation,
                       fmt::format("Unable to hash report section {} [0x{:08X},0x{:08X})",
                                   section.name, section.range.start, section.range.end));
    }
    section.sha256 = HashSection(*binarySection);
  }
  runMetadata.stageTimings.sectionHashingMicroseconds = elapsedMicroseconds(stageStarted);
  fs::path outputDirectory = args.outputDirectory;
  if (outputDirectory.empty()) {
    outputDirectory =
        loadedManifest->manifestDir / "out" / "analysis" / identity.patchedImageSha256;
  } else if (outputDirectory.is_relative()) {
    outputDirectory = fs::current_path() / outputDirectory;
  }

  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start);
  std::ostringstream commandLine;
  commandLine << "rexglue entrypoint-closure \"" << manifestPath.string() << "\"";
  if (!args.provenancePath.empty())
    commandLine << " --provenance \"" << args.provenancePath << "\"";
  if (!args.outputDirectory.empty())
    commandLine << " --output \"" << args.outputDirectory << "\"";
  runMetadata.elapsedMilliseconds = static_cast<uint64_t>(elapsed.count());
  runMetadata.peakWorkingSetBytes = PeakWorkingSetBytes();
  runMetadata.commandLine = commandLine.str();
  auto written =
      WriteEntrypointClosureReports(report, runMetadata, outputDirectory, !args.noReviewToml);
  if (!written)
    return written;

  auto manifestHashAfter = HashFile(manifestPath);
  if (!manifestHashAfter)
    return Err<void>(manifestHashAfter.error());
  if (*manifestHashBefore != *manifestHashAfter) {
    return Err<void>(rex::ErrorCategory::Validation,
                     "Report-only invariant failed: manifest content changed");
  }

  for (const auto& fixture : report.fixtureResults) {
    if (!fixture.independentlyRediscovered || !fixture.rangeMatches) {
      return Err<void>(
          rex::ErrorCategory::Validation,
          fmt::format("Acceptance fixture 0x{:08X} failed: {}. Reports were preserved in {}",
                      fixture.expected.address, fixture.result, outputDirectory.string()));
    }
  }
  if (!report.fixpointReached) {
    return Err<void>(rex::ErrorCategory::Validation,
                     fmt::format("Entrypoint closure exhausted a safety limit; inspect {}",
                                 outputDirectory.string()));
  }
  auto exhausted =
      std::find_if(report.limitDiagnostics.begin(), report.limitDiagnostics.end(),
                   [](const auto& diagnostic) { return diagnostic.limit.starts_with("max_"); });
  if (exhausted != report.limitDiagnostics.end()) {
    return Err<void>(
        rex::ErrorCategory::Validation,
        fmt::format("Entrypoint closure exhausted {} at {}; inspect {}", exhausted->limit,
                    exhausted->address ? fmt::format("0x{:08X}", *exhausted->address)
                                       : std::string("an unspecified address"),
                    outputDirectory.string()));
  }

  REXLOG_INFO("Entrypoint closure: {} candidates, {} strong, {} probable; reports: {}",
              report.counts.candidates, report.counts.strongNewFunctions,
              report.counts.probableNewFunctions, outputDirectory.string());
  return rex::Ok();
}

}  // namespace

void RegisterEntrypointClosure(CLI::App& parent, DeferredAction& pending) {
  auto args = std::make_shared<EntrypointClosureArgs>();
  auto* command =
      parent
          .add_subcommand("entrypoint-closure",
                          "Report-only static code-pointer and entrypoint closure analysis")
          ->fallthrough();
  command
      ->add_option("manifest", args->manifestPath,
                   "Project manifest TOML (auto-discovered in cwd if omitted)")
      ->type_name("PATH");
  command
      ->add_option("--provenance", args->provenancePath,
                   "Versioned JSON with expected image identity, manual evidence and fixtures")
      ->type_name("PATH");
  command
      ->add_option("--output", args->outputDirectory,
                   "Output directory (default: out/analysis/<patched-image-sha256>)")
      ->type_name("PATH");
  command->add_flag("--no-review-toml", args->noReviewToml,
                    "Do not emit the non-authoritative review TOML fragment");
  command->add_option("--max-iterations", args->limits.maxIterations,
                      "Maximum closure fixpoint iterations");
  command->add_option("--max-candidates", args->limits.maxCandidates,
                      "Maximum candidate entrypoints retained");
  command->add_option("--max-instructions", args->limits.maxInstructionsPerCandidate,
                      "Maximum decoded instructions per candidate");
  command->add_option("--max-depth", args->limits.maxTraversalDepth,
                      "Maximum CFG work-queue depth per candidate");
  command->add_option("--max-pointer-run", args->limits.maxPointerRunEntries,
                      "Maximum entries retained in one pointer run");
  command->add_option("--materialization-window", args->limits.materializationWindow,
                      "Instruction window after lis/addis for low-half materialization");
  command->callback([args, &pending]() {
    pending = [args]() -> Result<void> { return RunEntrypointClosure(*args); };
  });
}

}  // namespace rexglue::cli
