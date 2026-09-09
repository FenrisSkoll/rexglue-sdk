/**
 * @file        codegen/codegen.cpp
 * @brief       Codegen pipeline implementation
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <fmt/format.h>

#include <rex/codegen/analyze.h>
#include <rex/codegen/codegen.h>
#include <rex/codegen/codegen_writer.h>
#include <rex/codegen/manifest.h>
#include <rex/kernel/init.h>
#include <rex/logging.h>
#include <rex/runtime.h>
#include <rex/system/kernel_state.h>
#include <rex/system/user_module.h>
#include <rex/system/xex_module.h>

#include <algorithm>

namespace rex::codegen {

CodegenPipeline::~CodegenPipeline() = default;
CodegenPipeline::CodegenPipeline(CodegenPipeline&&) noexcept = default;
CodegenPipeline& CodegenPipeline::operator=(CodegenPipeline&&) noexcept = default;

Result<CodegenPipeline> CodegenPipeline::Create(const std::filesystem::path& configPath) {
  CodegenPipeline pipeline;

  // Load config to get XEX path
  RecompilerConfig tempConfig;
  if (!tempConfig.Load(configPath.string())) {
    return Err<CodegenPipeline>(ErrorCategory::Config,
                                fmt::format("Failed to load config: {}", configPath.string()));
  }

  auto configDir = configPath.parent_path();

  std::filesystem::path xexPath = configDir / tempConfig.filePath;

  if (!std::filesystem::exists(xexPath)) {
    return Err<CodegenPipeline>(ErrorCategory::IO,
                                fmt::format("XEX file not found: {}", xexPath.string()));
  }
  xexPath = std::filesystem::canonical(xexPath);

  // Create Runtime
  auto xexDir = xexPath.parent_path();
  pipeline.runtime_ = std::make_unique<Runtime>(xexDir.string());
  auto status = pipeline.runtime_->Setup(rex::RuntimeConfig{
      .kernel_init = rex::kernel::InitializeKernel,
      .tool_mode = true,
  });
  if (status != X_STATUS_SUCCESS) {
    return Err<CodegenPipeline>(ErrorCategory::IO,
                                fmt::format("Failed to initialize Runtime: {:#x}", status));
  }

  // Create CodegenContext (AnalysisState is populated from binary there)
  auto ctxResult = CodegenContext::Create(configPath, *pipeline.runtime_);
  if (!ctxResult) {
    return Err<CodegenPipeline>(ctxResult.error());
  }
  pipeline.ctx_ = std::make_unique<CodegenContext>(std::move(*ctxResult));

  return Ok(std::move(pipeline));
}

Result<CodegenPipeline> CodegenPipeline::CreateEntrypoint(const ManifestConfig& manifest) {
  namespace fs = std::filesystem;

  CodegenPipeline pipeline;
  const auto& config = manifest.entrypoint.recompiler;
  fs::path xexPath = manifest.manifestDir / config.filePath;
  if (!fs::exists(xexPath)) {
    return Err<CodegenPipeline>(ErrorCategory::IO,
                                fmt::format("Entrypoint XEX not found: {}", xexPath.string()));
  }
  xexPath = fs::canonical(xexPath);

  fs::path gameRoot;
  if (manifest.gameRoot && !manifest.gameRoot->empty()) {
    fs::path configuredRoot = manifest.manifestDir / *manifest.gameRoot;
    if (!fs::exists(configuredRoot) || !fs::is_directory(configuredRoot)) {
      return Err<CodegenPipeline>(
          ErrorCategory::Validation,
          fmt::format("[project].game_root '{}' does not resolve to a directory",
                      configuredRoot.string()));
    }
    gameRoot = fs::canonical(configuredRoot);
  } else {
    gameRoot = fs::canonical(xexPath.parent_path());
  }

  fs::path relativeXex = fs::relative(xexPath, gameRoot);
  if (relativeXex.empty() || *relativeXex.begin() == "..") {
    return Err<CodegenPipeline>(ErrorCategory::Validation,
                                fmt::format("Entrypoint XEX '{}' resolves outside game root '{}'",
                                            xexPath.string(), gameRoot.string()));
  }

  pipeline.runtime_ = std::make_unique<Runtime>(gameRoot.string());
  auto status = pipeline.runtime_->Setup(rex::RuntimeConfig{
      .kernel_init = rex::kernel::InitializeKernel,
      .tool_mode = true,
  });
  if (status != X_STATUS_SUCCESS) {
    return Err<CodegenPipeline>(ErrorCategory::IO,
                                fmt::format("Failed to initialize Runtime: {:#x}", status));
  }

  std::string relativeXexString = relativeXex.string();
  std::replace(relativeXexString.begin(), relativeXexString.end(), '/', '\\');
  status = pipeline.runtime_->LoadXexImage("game:\\" + relativeXexString);
  if (status != X_STATUS_SUCCESS) {
    return Err<CodegenPipeline>(ErrorCategory::IO,
                                fmt::format("Failed to load entrypoint XEX: {:#x}", status));
  }

  auto executable = pipeline.runtime_->kernel_state()->GetExecutableModule();
  if (!executable || !executable->xex_module()) {
    return Err<CodegenPipeline>(ErrorCategory::Format,
                                "Runtime did not expose the loaded entrypoint XEX");
  }

  auto binary = BinaryView::fromModule(*executable->xex_module());
  auto context = CodegenContext::Create(std::move(binary), config);
  context.setResolver(pipeline.runtime_->export_resolver());
  context.setConfigDir(manifest.manifestDir);
  context.analysisState().format = "xex";
  context.analysisState().loadAddress = context.binary().baseAddress();
  context.analysisState().entryPoint = context.binary().entryPoint();
  context.analysisState().imageSize = context.binary().imageSize();
  context.setHasDllModules(!manifest.modules.empty());
  context.setDllModule(config.isDll.value_or(false));
  pipeline.ctx_ = std::make_unique<CodegenContext>(std::move(context));
  return Ok(std::move(pipeline));
}

Result<void> CodegenPipeline::Run(bool force) {
  auto result = RunAnalyze();
  if (!result)
    return result;
  return RunWrite(force);
}

Result<void> CodegenPipeline::RunAnalyze() {
  auto analyzeResult = Analyze(*ctx_);
  if (!analyzeResult) {
    REXLOG_ERROR("Analysis failed: {}", analyzeResult.error().message);
    return analyzeResult;
  }
  return Ok();
}

Result<void> CodegenPipeline::RunWrite(bool force) {
  CodegenWriter writer(*ctx_, runtime_.get());
  if (!writer.write(force))
    return Err(ErrorCategory::Validation, "Code generation failed.");
  return Ok();
}

}  // namespace rex::codegen
