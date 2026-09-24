/**
 * @file        codegen/output_stamp.cpp
 * @brief       Input fingerprinting so unchanged modules skip codegen entirely
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <rex/codegen/output_stamp.h>

#include <fstream>
#include <algorithm>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <rex/hash.h>
#include <rex/filesystem.h>
#include <rex/system/xex_module.h>
#if REX_PLATFORM_WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "codegen_logging.h"
#include "file_io.h"

namespace rex::codegen {

std::vector<std::filesystem::path> CodegenImplementationPaths() {
#if REX_PLATFORM_WIN32
  // _get_wpgmptr in a DLL's static CRT may be uninitialized. Ask the loader.
  wchar_t executable[32768]{};
  wchar_t library[32768]{};
  // A function address may name a static core copy or an import thunk in the
  // EXE. Identify the loaded DLL by the actual CMake target filename (including
  // configuration postfix), then ask the loader for its full path.
  const auto runtimeName = std::filesystem::path(REXGLUE_RUNTIME_FILENAME).wstring();
  const auto module = GetModuleHandleW(runtimeName.c_str());
  if (!module || module == GetModuleHandleW(nullptr))
    return {};
  const auto exeSize = GetModuleFileNameW(nullptr, executable, 32768);
  const auto libSize = GetModuleFileNameW(module, library, 32768);
  if (!exeSize || exeSize >= 32768 || !libSize || libSize >= 32768)
    return {};
  return {executable, library};
#else
  Dl_info info{};
  auto executable = rex::filesystem::GetExecutablePath();
  if (executable.empty() ||
      !dladdr(reinterpret_cast<void*>(&rex::runtime::XexModule::GetSecurityInfo), &info) ||
      !info.dli_fname)
    return {};
  return {executable, std::filesystem::canonical(info.dli_fname)};
#endif
}

std::vector<std::filesystem::path> ExecutableInputPaths(const std::filesystem::path& binary) {
  auto resolved = std::filesystem::canonical(binary);
  auto patch = resolved;
  patch += "p";
  return {binary, resolved, patch};
}

/// Bump when the stamp layout changes.
constexpr int kStampVersion = 1;

std::optional<OutputStamp> OutputStamp::Load(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return std::nullopt;

  nlohmann::json doc = nlohmann::json::parse(in, nullptr, false);
  if (doc.is_discarded() || !doc.is_object()) {
    REXCODEGEN_WARN("Ignoring malformed codegen stamp: {}", path.string());
    return std::nullopt;
  }

  auto version = doc.find("version");
  if (version == doc.end() || !version->is_number_integer() || version->get<int>() != kStampVersion)
    return std::nullopt;

  OutputStamp stamp;
  if (auto it = doc.find("fingerprint"); it != doc.end() && it->is_string())
    stamp.fingerprint = it->get<std::string>();
  if (stamp.fingerprint.empty())
    return std::nullopt;

  if (auto it = doc.find("outputs"); it != doc.end() && it->is_array()) {
    for (const auto& entry : *it) {
      if (entry.is_string())
        stamp.outputs.push_back(entry.get<std::string>());
    }
  }
  return stamp;
}

std::string OutputStamp::Serialize() const {
  nlohmann::json doc;
  doc["version"] = kStampVersion;
  doc["fingerprint"] = fingerprint;
  doc["outputs"] = outputs;
  return doc.dump(2) + "\n";
}

std::string ComputeInputFingerprint(std::span<const std::filesystem::path> inputFiles,
                                    std::string_view sdkVersion,
                                    std::span<const std::string> flagValues) {
  std::string accumulator;
  accumulator += "sdk=";
  accumulator += sdkVersion;
  accumulator += '\n';

  for (const auto& flag : flagValues) {
    accumulator += "flag=";
    accumulator += flag;
    accumulator += '\n';
  }

  for (const auto& path : inputFiles) {
    // Content, not mtime: survives a checkout, a copy, or a bare touch.
    std::error_code ec;
    std::string digest = "<missing>";
    const bool exists = std::filesystem::exists(path, ec);
    if (ec)
      return {};
    if (exists) {
      digest = rex::hash_file(path);
      if (digest.empty()) {
        REXCODEGEN_WARN("Could not read {} for fingerprinting", path.string());
        return {};  // No reusable identity when an existing input cannot be hashed.
      }
    }
    accumulator += fmt::format("file={} {}\n", path.filename().string(), digest);
  }

  return rex::hash_bytes(accumulator);
}

namespace {

std::string EscapeDepfilePath(const std::filesystem::path& path) {
  std::string source = std::filesystem::absolute(path).generic_string();
  std::string escaped;
  escaped.reserve(source.size() + 8);
  for (char c : source) {
    if (c == ' ' || c == '#')
      escaped += '\\';
    if (c == '$')
      escaped += '$';
    escaped += c;
  }
  return escaped;
}

}  // namespace

std::vector<std::filesystem::path> ExistingInputDependencies(
    std::span<const std::filesystem::path> inputs) {
  std::vector<std::filesystem::path> dependencies;
  for (const auto& input : inputs) {
    auto dependency = std::filesystem::absolute(input);
    if (std::filesystem::exists(dependency))
      dependencies.push_back(std::move(dependency));
  }
  std::sort(dependencies.begin(), dependencies.end());
  dependencies.erase(std::unique(dependencies.begin(), dependencies.end()), dependencies.end());
  return dependencies;
}

bool WriteInputDependencies(const std::filesystem::path& path,
                            std::span<const std::filesystem::path> inputs) {
  std::string content =
      "# Generated codegen input existence watches.\n"
      "file(GLOB REXGLUE_CODEGEN_INPUTS CONFIGURE_DEPENDS LIST_DIRECTORIES false\n";
  for (const auto& input : inputs) {
    std::string pattern;
    for (const char c : std::filesystem::absolute(input).generic_string()) {
      if (c == '[' || c == ']' || c == '*' || c == '?')
        pattern += std::string("[") + c + "]";
      else
        pattern += c;
    }
    std::string delimiter = "=";
    while (pattern.find("]" + delimiter + "]") != std::string::npos)
      delimiter += '=';
    content += "  [" + delimiter + "[" + pattern + "]" + delimiter + "]\n";
  }
  content += ")\n";
  return WriteIfChanged(path, content) != WriteOutcome::Failed;
}

bool WriteDepfile(const std::filesystem::path& path, const std::filesystem::path& target,
                  std::span<const std::filesystem::path> inputs) {
  std::string out = EscapeDepfilePath(target);
  out += ':';
  for (const auto& input : inputs) {
    out += " \\\n  ";
    out += EscapeDepfilePath(input);
  }
  out += '\n';

  return WriteFileBytes(path, out);
}

bool OutputsAreUpToDate(const OutputStamp& stamp, std::string_view fingerprint,
                        const std::filesystem::path& outputDir) {
  if (fingerprint.empty())
    return false;
  if (stamp.fingerprint != fingerprint)
    return false;
  if (stamp.outputs.empty())
    return false;

  for (const auto& name : stamp.outputs) {
    std::error_code ec;
    if (!std::filesystem::exists(outputDir / name, ec))
      return false;
  }
  return true;
}

}  // namespace rex::codegen
