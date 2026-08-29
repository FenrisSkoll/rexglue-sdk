/**
 * @file        rexglue/commands/entrypoint_closure_command.h
 * @brief       Report-only static entrypoint-closure command
 *
 * @copyright   Copyright (c) 2026 Tom Clay
 * @license     BSD 3-Clause License
 */

#pragma once

#include "../cli_utils.h"

namespace CLI {
class App;
}

namespace rexglue::cli {

void RegisterEntrypointClosure(CLI::App& parent, DeferredAction& pending);

}  // namespace rexglue::cli
