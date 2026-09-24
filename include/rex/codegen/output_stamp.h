/**
 * @file        rex/codegen/output_stamp.h
 * @brief       Input fingerprinting so unchanged modules skip codegen entirely
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#pragma once

#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rex::codegen {

inline constexpr std::string_view kStampFileName = "codegen.stamp";
inline constexpr std::string_view kBuildStampFileName = "codegen.build.stamp";
inline constexpr std::string_view kDepfileName = "codegen.d";

/// What a module's output was generated from, and what it produced.
struct OutputStamp {
  std::string fingerprint;
  std::vector<std::string> outputs;  ///< basenames, relative to the output directory

  /// nullopt when missing, unreadable, or malformed.
  static std::optional<OutputStamp> Load(const std::filesystem::path& path);

  std::string Serialize() const;
};

/// Hash everything that can change emitted output for one module. A missing
/// input contributes a "missing" marker, so a file appearing later still
/// changes the fingerprint. Tool implementation files must also be inputs;
/// the SDK version string alone is not an implementation identity.
std::string ComputeInputFingerprint(std::span<const std::filesystem::path> inputFiles,
                                    std::string_view sdkVersion,
                                    std::span<const std::string> flagValues);

/// Files consulted by the tool-mode XEX loader, including an absent optional
/// sibling patch. Matches UserModule::LoadFromFile's append-"p" lookup.
std::vector<std::filesystem::path> ExecutableInputPaths(const std::filesystem::path& binary);

/// Existing scheduling inputs; optional-file creation is watched by CMake globs.
std::vector<std::filesystem::path> ExistingInputDependencies(
    std::span<const std::filesystem::path> inputs);

/// Content-stable CMake existence watches; use REXGLUE_CODEGEN_INPUTS in DEPENDS.
bool WriteInputDependencies(const std::filesystem::path& path,
                            std::span<const std::filesystem::path> inputs);

/// Actual host executable and loaded runtime library, not an install-directory guess.
std::vector<std::filesystem::path> CodegenImplementationPaths();

bool OutputsAreUpToDate(const OutputStamp& stamp, std::string_view fingerprint,
                        const std::filesystem::path& outputDir);

/// Make-syntax dependency file. `target` must match the consuming build rule's
/// declared output byte for byte or the rule rejects the file.
bool WriteDepfile(const std::filesystem::path& path, const std::filesystem::path& target,
                  std::span<const std::filesystem::path> inputs);

}  // namespace rex::codegen
