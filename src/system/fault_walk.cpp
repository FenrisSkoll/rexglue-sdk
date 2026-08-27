/**
 * @file        system/fault_walk.cpp
 * @brief       Experimental generated guest-function fault walker
 *
 * This is deliberately diagnostic-only. Recovery restores the complete
 * PPCContext checkpoint captured at guest-function entry and then applies a
 * synthetic return policy. Guest-memory writes are not transactional and are
 * not rolled back, so later observations may be corruption-induced.
 */

#include <rex/fault_walk.h>

#include <rex/logging.h>
#include <rex/platform.h>
#include <rex/platform/env.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fmt/format.h>

#if REX_PLATFORM_WIN32
#include <windows.h>
#endif

namespace rex::diagnostics {
namespace {

constexpr uint32_t kAccessViolation = 0xC0000005;
constexpr uint32_t kIntegerDivideByZero = 0xC0000094;
constexpr uint32_t kDefaultMaxUnique = 32;
constexpr uint64_t kDefaultMaxTotalSuppressions = 1'000'000;
constexpr uint64_t kDefaultMaxFunctionSuppressions = 250'000;
constexpr size_t kMaxReportedGuestStack = 16;
constexpr uint32_t kInvalidDepth = std::numeric_limits<uint32_t>::max();

enum class AccessType : uint8_t {
  NotApplicable,
  Read,
  Write,
  Execute,
  Unknown,
};

enum class FaultKind : uint8_t {
  HostException,
  InvalidUnregisteredFunction,
};

struct Configuration {
  uint32_t max_unique = kDefaultMaxUnique;
  uint64_t max_total_suppressions = kDefaultMaxTotalSuppressions;
  uint64_t max_function_suppressions = kDefaultMaxFunctionSuppressions;
  std::string report_path = "rexglue-fault-walk-report.json";
};

struct CapturedException {
  uint32_t code = 0;
  AccessType access_type = AccessType::NotApplicable;
  uintptr_t fault_address = 0;
  uintptr_t host_exception_address = 0;
  uintptr_t host_module_base = 0;
  PPCContext context{};
};

struct ThreadFrame {
  uint64_t cookie = 0;
  const FaultWalkFunctionDescriptor* descriptor = nullptr;
  bool force_normal = false;
  PPCContext checkpoint{};
  CapturedException exception{};
};

struct ThreadFrames {
  std::vector<ThreadFrame> storage;
  uint32_t depth = 0;
  uint64_t next_cookie = 1;
  std::unordered_map<uint32_t, uint32_t> setjmp_depths;

  ThreadFrames() { storage.reserve(64); }
};

struct FrameToken {
  uint32_t depth = kInvalidDepth;
  uint64_t cookie = 0;
};

struct FaultRecord {
  FaultKind kind = FaultKind::HostException;
  uint32_t sequence = 0;
  uint32_t guest_address = 0;
  std::string function_name;
  std::string source_file;
  uint32_t source_line = 0;
  uint32_t exception_code = 0;
  AccessType access_type = AccessType::NotApplicable;
  uintptr_t fault_address = 0;
  uintptr_t host_exception_address = 0;
  uintptr_t host_module_base = 0;
  uint64_t host_exception_rva = 0;
  uint64_t thread_id = 0;
  uint32_t previous_guest_function = 0;
  uint32_t last_indirect_target = 0;
  PPCContext fault_context{};
  FaultWalkPolicy policy = FaultWalkPolicy::ReturnR3Zero;
  bool poisoned = true;
  uint64_t fault_hits = 0;
  uint64_t suppressed_invocations = 0;
  std::string fingerprint;
  std::string original_fatal;
  std::vector<uint32_t> guest_call_stack;
};

struct ProcessState {
  std::atomic<bool> active{false};
  std::mutex mutex;
  Configuration config;
  std::once_flag initialize_once;
  std::vector<FaultRecord> faults;
  std::unordered_map<uint32_t, size_t> fault_indices;
  uint64_t total_fault_hits = 0;
  uint64_t total_suppressed_invocations = 0;
  bool summary_printed = false;
};

thread_local ThreadFrames tls_frames;

ProcessState& GetProcessState() {
  static ProcessState state;
  return state;
}

const char* PolicyName(FaultWalkPolicy policy) {
  switch (policy) {
    case FaultWalkPolicy::Normal:
      return "NORMAL";
    case FaultWalkPolicy::ReturnR3Zero:
      return "RETURN_R3_ZERO";
    case FaultWalkPolicy::ReturnR3One:
      return "RETURN_R3_ONE";
    case FaultWalkPolicy::Stop:
      return "STOP";
  }
  return "STOP";
}

const char* AccessTypeName(AccessType access_type) {
  switch (access_type) {
    case AccessType::Read:
      return "READ";
    case AccessType::Write:
      return "WRITE";
    case AccessType::Execute:
      return "EXECUTE";
    case AccessType::Unknown:
      return "UNKNOWN";
    case AccessType::NotApplicable:
      return "N/A";
  }
  return "UNKNOWN";
}

const char* AccessTypeJsonName(AccessType access_type) {
  switch (access_type) {
    case AccessType::Read:
      return "read";
    case AccessType::Write:
      return "write";
    case AccessType::Execute:
      return "execute";
    case AccessType::Unknown:
      return "unknown";
    case AccessType::NotApplicable:
      return "not_applicable";
  }
  return "unknown";
}

const char* FaultKindName(FaultKind kind) {
  switch (kind) {
    case FaultKind::HostException:
      return "host_exception";
    case FaultKind::InvalidUnregisteredFunction:
      return "invalid_unregistered_function";
  }
  return "host_exception";
}

uint64_t ParseUnsignedEnvironment(const char* name, uint64_t fallback) {
  const auto value = rex::platform::env::get(name);
  if (!value || value->empty()) {
    return fallback;
  }

  uint64_t parsed = 0;
  const std::string_view text(*value);
  const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || parsed == 0) {
    REXLOG_WARN("[FWT] Ignoring invalid {}='{}'", name, *value);
    return fallback;
  }
  return parsed;
}

std::string EscapeJson(std::string_view value) {
  std::string escaped;
  escaped.reserve(value.size() + 16);
  for (const unsigned char ch : value) {
    switch (ch) {
      case '\"':
        escaped += "\\\"";
        break;
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (ch < 0x20) {
          fmt::format_to(std::back_inserter(escaped), "\\u{:04X}", ch);
        } else {
          escaped.push_back(static_cast<char>(ch));
        }
        break;
    }
  }
  return escaped;
}

uint64_t CurrentThreadIdValue() {
#if REX_PLATFORM_WIN32
  return static_cast<uint64_t>(GetCurrentThreadId());
#else
  return static_cast<uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
#endif
}

bool IsReportMilestone(uint64_t count) {
  if (count <= 10) {
    return true;
  }
  uint64_t value = count;
  while (value > 1 && value % 10 == 0) {
    value /= 10;
  }
  return value == 1;
}

void WriteReportLocked(const ProcessState& state) {
  std::ofstream report(state.config.report_path, std::ios::out | std::ios::trunc);
  if (!report) {
    REXLOG_ERROR("[FWT] Unable to write JSON report '{}'", state.config.report_path);
    return;
  }

  uint32_t poisoned_count = 0;
  for (const auto& fault : state.faults) {
    poisoned_count += fault.poisoned ? 1u : 0u;
  }

  report << "{\n"
         << "  \"fault_walk\": true,\n"
         << "  \"warning\": \"PPCContext only was restored; guest memory writes before a "
            "suppressed fault remain visible\",\n"
         << "  \"unique_faults\": " << state.faults.size() << ",\n"
         << "  \"poisoned_functions\": " << poisoned_count << ",\n"
         << "  \"total_fault_hits\": " << state.total_fault_hits << ",\n"
         << "  \"total_suppressed_invocations\": " << state.total_suppressed_invocations << ",\n"
         << "  \"guardrails\": {\n"
         << "    \"max_unique_poisoned_functions\": " << state.config.max_unique << ",\n"
         << "    \"max_total_suppressed_invocations\": " << state.config.max_total_suppressions
         << ",\n"
         << "    \"max_suppressed_invocations_per_function\": "
         << state.config.max_function_suppressions << "\n"
         << "  },\n"
         << "  \"faults\": [\n";

  for (size_t index = 0; index < state.faults.size(); ++index) {
    const auto& fault = state.faults[index];
    const uint32_t caller = static_cast<uint32_t>(fault.fault_context.lr) - 4;
    report << "    {\n"
           << fmt::format("      \"sequence\": {},\n", fault.sequence)
           << fmt::format("      \"guest_function\": \"0x{:08X}\",\n", fault.guest_address);
    if (fault.function_name.empty()) {
      report << "      \"function_name\": null,\n"
             << "      \"source_file\": null,\n"
             << "      \"source_line\": null,\n";
    } else {
      report << "      \"function_name\": \"" << EscapeJson(fault.function_name) << "\",\n"
             << "      \"source_file\": \"" << EscapeJson(fault.source_file) << "\",\n"
             << fmt::format("      \"source_line\": {},\n", fault.source_line);
    }
    report << "      \"fault_kind\": \"" << FaultKindName(fault.kind) << "\",\n";
    if (fault.kind == FaultKind::HostException) {
      report << fmt::format("      \"exception_code\": \"0x{:08X}\",\n", fault.exception_code)
             << "      \"original_fatal\": null,\n";
    } else {
      report << "      \"exception_code\": null,\n"
             << "      \"original_fatal\": \"" << EscapeJson(fault.original_fatal) << "\",\n";
    }
    report << "      \"access_type\": \"" << AccessTypeJsonName(fault.access_type) << "\",\n"
           << fmt::format("      \"fault_address\": \"0x{:016X}\",\n", fault.fault_address)
           << fmt::format("      \"host_exception_address\": \"0x{:016X}\",\n",
                          fault.host_exception_address)
           << fmt::format("      \"host_module_rva\": \"0x{:X}\",\n", fault.host_exception_rva)
           << fmt::format("      \"thread_id\": {},\n", fault.thread_id)
           << fmt::format("      \"lr\": \"0x{:08X}\",\n",
                          static_cast<uint32_t>(fault.fault_context.lr))
           << fmt::format("      \"caller\": \"0x{:08X}\",\n", caller)
           << fmt::format("      \"ctr\": \"0x{:08X}\",\n", fault.fault_context.ctr.u32)
           << fmt::format("      \"previous_guest_function\": \"0x{:08X}\",\n",
                          fault.previous_guest_function)
           << fmt::format("      \"last_indirect_target\": \"0x{:08X}\",\n",
                          fault.last_indirect_target)
           << "      \"registers\": {\n"
           << fmt::format("        \"r1\": \"0x{:016X}\",\n", fault.fault_context.r1.u64)
           << fmt::format("        \"r2\": \"0x{:016X}\",\n", fault.fault_context.r2.u64)
           << fmt::format("        \"r3\": \"0x{:016X}\",\n", fault.fault_context.r3.u64)
           << fmt::format("        \"r4\": \"0x{:016X}\",\n", fault.fault_context.r4.u64)
           << fmt::format("        \"r5\": \"0x{:016X}\",\n", fault.fault_context.r5.u64)
           << fmt::format("        \"r6\": \"0x{:016X}\",\n", fault.fault_context.r6.u64)
           << fmt::format("        \"r7\": \"0x{:016X}\",\n", fault.fault_context.r7.u64)
           << fmt::format("        \"r8\": \"0x{:016X}\",\n", fault.fault_context.r8.u64)
           << fmt::format("        \"r9\": \"0x{:016X}\",\n", fault.fault_context.r9.u64)
           << fmt::format("        \"r10\": \"0x{:016X}\"\n", fault.fault_context.r10.u64)
           << "      },\n"
           << "      \"policy\": \"" << PolicyName(fault.policy) << "\",\n"
           << "      \"poisoned\": " << (fault.poisoned ? "true" : "false") << ",\n"
           << fmt::format("      \"fingerprint\": \"{}\",\n", fault.fingerprint)
           << fmt::format("      \"hits\": {},\n", fault.fault_hits)
           << fmt::format("      \"suppressed_invocations\": {},\n", fault.suppressed_invocations)
           << "      \"guest_call_stack\": [";
    for (size_t stack_index = 0; stack_index < fault.guest_call_stack.size(); ++stack_index) {
      if (stack_index != 0) {
        report << ", ";
      }
      report << fmt::format("\"0x{:08X}\"", fault.guest_call_stack[stack_index]);
    }
    report << "]\n"
           << "    }" << (index + 1 == state.faults.size() ? "\n" : ",\n");
  }

  report << "  ]\n}\n";
  report.flush();
}

void PrintSummaryLocked(ProcessState& state) {
  if (state.summary_printed) {
    return;
  }
  state.summary_printed = true;

  uint32_t poisoned_count = 0;
  for (const auto& fault : state.faults) {
    poisoned_count += fault.poisoned ? 1u : 0u;
  }

  REXLOG_CRITICAL("=== FABLE II FAULT WALK SUMMARY ===");
  REXLOG_CRITICAL("Unique faulted guest functions: {}", state.faults.size());
  REXLOG_CRITICAL("Automatically poisoned guest functions: {}", poisoned_count);
  REXLOG_CRITICAL("Total suppressed invocations: {}", state.total_suppressed_invocations);
  for (const auto& fault : state.faults) {
    if (fault.kind == FaultKind::HostException) {
      REXLOG_CRITICAL("#{:03} 0x{:08X} {:08X} {}", fault.sequence, fault.guest_address,
                      fault.exception_code, AccessTypeName(fault.access_type));
    } else {
      REXLOG_CRITICAL("#{:03} 0x{:08X} INVALID_UNREGISTERED_FUNCTION", fault.sequence,
                      fault.guest_address);
    }
    REXLOG_CRITICAL("     policy={} faults={} suppressed={} poisoned={}", PolicyName(fault.policy),
                    fault.fault_hits, fault.suppressed_invocations, fault.poisoned);
  }
  REXLOG_CRITICAL("FAULT-WALK RESULTS ARE NOT CORRECTNESS RESULTS.");
  REXLOG_CRITICAL("ACCUMULATED GUEST MEMORY SIDE EFFECTS MAY MAKE LATER FAULTS SECONDARY.");
  if (auto logger = rex::GetLogger()) {
    logger->flush();
  }
}

void AtExitReport() {
  auto& state = GetProcessState();
  std::lock_guard lock(state.mutex);
  WriteReportLocked(state);
  PrintSummaryLocked(state);
}

void InitializeState() {
  auto& state = GetProcessState();
  std::call_once(state.initialize_once, [&state]() {
    const uint64_t max_unique =
        ParseUnsignedEnvironment("REXGLUE_FAULT_WALK_MAX_UNIQUE", kDefaultMaxUnique);
    state.config.max_unique =
        static_cast<uint32_t>(std::min<uint64_t>(max_unique, std::numeric_limits<uint32_t>::max()));
    state.config.max_total_suppressions = ParseUnsignedEnvironment(
        "REXGLUE_FAULT_WALK_MAX_TOTAL_SUPPRESSIONS", kDefaultMaxTotalSuppressions);
    state.config.max_function_suppressions = ParseUnsignedEnvironment(
        "REXGLUE_FAULT_WALK_MAX_FUNCTION_SUPPRESSIONS", kDefaultMaxFunctionSuppressions);
    if (const auto report_path = rex::platform::env::get("REXGLUE_FAULT_WALK_REPORT");
        report_path && !report_path->empty()) {
      state.config.report_path = *report_path;
    }
    std::atexit(AtExitReport);
    REXLOG_CRITICAL("[FWT] EXPERIMENTAL FAULT WALKING IS ENABLED");
    REXLOG_CRITICAL(
        "[FWT] WARNING: Fault-walk execution restores PPCContext only. Guest memory writes "
        "performed before a suppressed fault remain visible.");
    REXLOG_CRITICAL("[FWT] Later discovered faults may therefore be secondary/corruption-induced.");
    REXLOG_CRITICAL(
        "[FWT] guardrails: max_unique={} max_total_suppressions={} "
        "max_function_suppressions={} report='{}'",
        state.config.max_unique, state.config.max_total_suppressions,
        state.config.max_function_suppressions, state.config.report_path);
  });
  state.active.store(true, std::memory_order_release);
}

ThreadFrame* GetThreadFrame(FrameToken token) {
  if (token.depth >= tls_frames.depth || token.depth >= tls_frames.storage.size()) {
    return nullptr;
  }
  auto& frame = tls_frames.storage[token.depth];
  return frame.cookie == token.cookie ? &frame : nullptr;
}

FrameToken EnterFrame(PPCContext& ctx, const FaultWalkFunctionDescriptor& descriptor,
                      bool force_normal = false) {
  const uint32_t depth = tls_frames.depth;
  if (depth == tls_frames.storage.size()) {
    tls_frames.storage.emplace_back();
  }
  auto& frame = tls_frames.storage[depth];
  frame.cookie = tls_frames.next_cookie++;
  frame.descriptor = &descriptor;
  frame.force_normal = force_normal;
  std::memcpy(&frame.checkpoint, &ctx, sizeof(PPCContext));
  frame.exception = {};
  ++tls_frames.depth;
  return {depth, frame.cookie};
}

void LeaveFrame(FrameToken token) {
  if (tls_frames.depth == 0) {
    return;
  }
  if (token.depth + 1 != tls_frames.depth) {
    REXLOG_ERROR("[FWT] TLS guest-function stack mismatch: token_depth={} current_depth={}",
                 token.depth, tls_frames.depth);
    tls_frames.depth = std::min<uint32_t>(token.depth, tls_frames.depth);
    return;
  }
  --tls_frames.depth;
}

bool MustPreserveExceptionSemantics() {
  for (uint32_t index = 0; index < tls_frames.depth; ++index) {
    const auto& frame = tls_frames.storage[index];
    const auto* descriptor = frame.descriptor;
    if (frame.force_normal || (descriptor && descriptor->has_guest_exception_handlers)) {
      return true;
    }
  }
  return false;
}

void ApplyPolicy(PPCContext& ctx, FaultWalkPolicy policy) {
  switch (policy) {
    case FaultWalkPolicy::ReturnR3Zero:
      ctx.r3.u64 = 0;
      break;
    case FaultWalkPolicy::ReturnR3One:
      ctx.r3.u64 = 1;
      break;
    case FaultWalkPolicy::Normal:
    case FaultWalkPolicy::Stop:
      break;
  }
}

[[noreturn]] void StopAtGuardrail(std::string_view reason) {
  auto& state = GetProcessState();
  {
    std::lock_guard lock(state.mutex);
    REXLOG_CRITICAL("[FWT] GUARDRAIL STOP: {}", reason);
    WriteReportLocked(state);
    PrintSummaryLocked(state);
  }
  if (auto logger = rex::GetLogger()) {
    logger->flush();
  }
  std::abort();
}

bool TrySuppressPoisonedInvocation(PPCContext& ctx, const FaultWalkFunctionDescriptor& descriptor) {
  auto& state = GetProcessState();
  FaultWalkPolicy policy = FaultWalkPolicy::Normal;
  uint64_t function_suppressions = 0;
  uint64_t total_suppressions = 0;
  bool write_report = false;

  {
    std::lock_guard lock(state.mutex);
    const auto index_it = state.fault_indices.find(descriptor.guest_address);
    if (index_it == state.fault_indices.end()) {
      return false;
    }
    auto& fault = state.faults[index_it->second];
    policy = fault.policy;
    if (!fault.poisoned || policy == FaultWalkPolicy::Normal) {
      return false;
    }
    if (policy == FaultWalkPolicy::Stop) {
      // Report outside the locked region.
    } else {
      function_suppressions = ++fault.suppressed_invocations;
      total_suppressions = ++state.total_suppressed_invocations;
      state.summary_printed = false;
      write_report = IsReportMilestone(function_suppressions);
      if (write_report) {
        WriteReportLocked(state);
      }
    }
  }

  if (policy == FaultWalkPolicy::Stop) {
    StopAtGuardrail(
        fmt::format("policy STOP reached for guest function 0x{:08X}", descriptor.guest_address));
  }
  if (function_suppressions >= state.config.max_function_suppressions) {
    StopAtGuardrail(fmt::format("per-function suppression limit reached for 0x{:08X} ({})",
                                descriptor.guest_address, function_suppressions));
  }
  if (total_suppressions >= state.config.max_total_suppressions) {
    StopAtGuardrail(fmt::format("total suppression limit reached ({})", total_suppressions));
  }

  ApplyPolicy(ctx, policy);
  return true;
}

bool HasExplicitNormalPolicy(const FaultWalkFunctionDescriptor& descriptor) {
  auto& state = GetProcessState();
  std::lock_guard lock(state.mutex);
  const auto index_it = state.fault_indices.find(descriptor.guest_address);
  if (index_it == state.fault_indices.end()) {
    return false;
  }
  return state.faults[index_it->second].policy == FaultWalkPolicy::Normal;
}

#if REX_PLATFORM_WIN32
int FaultWalkExceptionFilter(FrameToken token, uint32_t code, void* exception_pointers) {
  if (code != kAccessViolation && code != kIntegerDivideByZero) {
    return EXCEPTION_CONTINUE_SEARCH;
  }
  if (MustPreserveExceptionSemantics()) {
    // Generated Xbox/XEX exception semantics always win over diagnostic fault
    // harvesting. An enclosing generated guest SEH scope must see the original
    // host exception before any function can be poisoned.
    return EXCEPTION_CONTINUE_SEARCH;
  }

  auto* frame = GetThreadFrame(token);
  auto* pointers = static_cast<EXCEPTION_POINTERS*>(exception_pointers);
  if (!frame || !pointers || !pointers->ExceptionRecord || !frame->descriptor ||
      !frame->descriptor->body) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  auto* record = pointers->ExceptionRecord;
  HMODULE body_module = nullptr;
  HMODULE exception_module = nullptr;
  constexpr DWORD flags =
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
  if (!GetModuleHandleExA(flags, reinterpret_cast<LPCSTR>(frame->descriptor->body), &body_module) ||
      !GetModuleHandleExA(flags, reinterpret_cast<LPCSTR>(record->ExceptionAddress),
                          &exception_module) ||
      body_module != exception_module) {
    // Reject software-raised guest exceptions and faults in ReXGlue/imported
    // host code. V1 only walks faults whose native instruction is in the same
    // generated module as the current guest body.
    return EXCEPTION_CONTINUE_SEARCH;
  }

  AccessType access_type = AccessType::NotApplicable;
  uintptr_t fault_address = 0;
  if (code == kAccessViolation) {
    if (record->NumberParameters < 2) {
      return EXCEPTION_CONTINUE_SEARCH;
    }
    switch (record->ExceptionInformation[0]) {
      case 0:
        access_type = AccessType::Read;
        break;
      case 1:
        access_type = AccessType::Write;
        break;
      case 8:
        access_type = AccessType::Execute;
        break;
      default:
        access_type = AccessType::Unknown;
        break;
    }
    fault_address = static_cast<uintptr_t>(record->ExceptionInformation[1]);
  }

  frame->exception.code = code;
  frame->exception.access_type = access_type;
  frame->exception.fault_address = fault_address;
  frame->exception.host_exception_address = reinterpret_cast<uintptr_t>(record->ExceptionAddress);
  frame->exception.host_module_base = reinterpret_cast<uintptr_t>(body_module);
  // Capture fault-time guest registers before the handler restores the entry
  // checkpoint. The checkpoint itself remains a complete byte-for-byte copy.
  std::memcpy(&frame->exception.context, &frame->checkpoint, sizeof(PPCContext));
  return EXCEPTION_EXECUTE_HANDLER;
}
#endif

void HandleFault(FrameToken token, PPCContext& ctx) {
  auto* frame = GetThreadFrame(token);
  if (!frame || !frame->descriptor) {
    StopAtGuardrail("fault handler lost its TLS guest-function frame");
  }

  // The context may have been partially mutated by the body. Capture it now,
  // then restore every field represented by PPCContext. Guest memory is not
  // restored and remains a known source of secondary observations.
  std::memcpy(&frame->exception.context, &ctx, sizeof(PPCContext));

  auto& state = GetProcessState();
  FaultRecord record_for_log;
  bool new_fault = false;
  bool stop_after_record = false;
  {
    std::lock_guard lock(state.mutex);
    const auto index_it = state.fault_indices.find(frame->descriptor->guest_address);
    if (index_it == state.fault_indices.end()) {
      FaultRecord record;
      record.sequence = static_cast<uint32_t>(state.faults.size() + 1);
      record.guest_address = frame->descriptor->guest_address;
      record.function_name = frame->descriptor->function_name;
      record.source_file = frame->descriptor->source_file;
      record.source_line = frame->descriptor->source_line;
      record.exception_code = frame->exception.code;
      record.access_type = frame->exception.access_type;
      record.fault_address = frame->exception.fault_address;
      record.host_exception_address = frame->exception.host_exception_address;
      record.host_module_base = frame->exception.host_module_base;
      record.host_exception_rva =
          frame->exception.host_exception_address - frame->exception.host_module_base;
      record.thread_id = CurrentThreadIdValue();
      record.previous_guest_function =
          token.depth > 0 && tls_frames.storage[token.depth - 1].descriptor
              ? tls_frames.storage[token.depth - 1].descriptor->guest_address
              : 0;
      record.last_indirect_target = frame->exception.context.last_indirect_target;
      std::memcpy(&record.fault_context, &frame->exception.context, sizeof(PPCContext));
      record.fault_hits = 1;
      record.poisoned = state.faults.size() < state.config.max_unique;
      record.policy = record.poisoned ? FaultWalkPolicy::ReturnR3Zero : FaultWalkPolicy::Stop;
      record.fingerprint =
          fmt::format("{:08X}-{:08X}-{:X}-{}", record.guest_address, record.exception_code,
                      record.host_exception_rva, static_cast<unsigned>(record.access_type));
      const uint32_t first_stack_index =
          tls_frames.depth > kMaxReportedGuestStack
              ? tls_frames.depth - static_cast<uint32_t>(kMaxReportedGuestStack)
              : 0;
      for (uint32_t index = first_stack_index; index < tls_frames.depth; ++index) {
        if (const auto* descriptor = tls_frames.storage[index].descriptor) {
          record.guest_call_stack.push_back(descriptor->guest_address);
        }
      }
      stop_after_record = !record.poisoned;
      state.fault_indices.emplace(record.guest_address, state.faults.size());
      state.faults.push_back(std::move(record));
      new_fault = true;
    } else {
      auto& record = state.faults[index_it->second];
      ++record.fault_hits;
      record_for_log = record;
    }
    ++state.total_fault_hits;
    state.summary_printed = false;
    if (new_fault) {
      record_for_log = state.faults.back();
    }
    WriteReportLocked(state);
  }

  if (new_fault) {
    const uint32_t caller = static_cast<uint32_t>(record_for_log.fault_context.lr) - 4;
    REXLOG_CRITICAL("[FWT] #{:03}", record_for_log.sequence);
    REXLOG_CRITICAL("[FWT] guest=0x{:08X} function={}", record_for_log.guest_address,
                    record_for_log.function_name);
    REXLOG_CRITICAL("[FWT] source={}:{} (generated function entry)", record_for_log.source_file,
                    record_for_log.source_line);
    REXLOG_CRITICAL("[FWT] exception=0x{:08X} {} address=0x{:016X}", record_for_log.exception_code,
                    AccessTypeName(record_for_log.access_type), record_for_log.fault_address);
    REXLOG_CRITICAL("[FWT] host_rip=0x{:016X} module_rva=0x{:X}",
                    record_for_log.host_exception_address, record_for_log.host_exception_rva);
    REXLOG_CRITICAL("[FWT] lr=0x{:08X} caller=0x{:08X} ctr=0x{:08X}",
                    static_cast<uint32_t>(record_for_log.fault_context.lr), caller,
                    record_for_log.fault_context.ctr.u32);
    REXLOG_CRITICAL("[FWT] r1=0x{:016X} r2=0x{:016X} r3=0x{:016X}",
                    record_for_log.fault_context.r1.u64, record_for_log.fault_context.r2.u64,
                    record_for_log.fault_context.r3.u64);
    REXLOG_CRITICAL("[FWT] r4=0x{:016X} r5=0x{:016X} r6=0x{:016X}",
                    record_for_log.fault_context.r4.u64, record_for_log.fault_context.r5.u64,
                    record_for_log.fault_context.r6.u64);
    REXLOG_CRITICAL("[FWT] r7=0x{:016X} r8=0x{:016X} r9=0x{:016X} r10=0x{:016X}",
                    record_for_log.fault_context.r7.u64, record_for_log.fault_context.r8.u64,
                    record_for_log.fault_context.r9.u64, record_for_log.fault_context.r10.u64);
    REXLOG_CRITICAL("[FWT] thread={} previous_guest=0x{:08X} last_indirect=0x{:08X}",
                    record_for_log.thread_id, record_for_log.previous_guest_function,
                    record_for_log.last_indirect_target);
    REXLOG_CRITICAL("[FWT] policy={}", PolicyName(record_for_log.policy));
    REXLOG_CRITICAL("[FWT] faults={} suppressed={}", record_for_log.fault_hits,
                    record_for_log.suppressed_invocations);
    REXLOG_CRITICAL("[FWT] {}",
                    record_for_log.poisoned ? "function poisoned" : "function NOT poisoned");
    REXLOG_CRITICAL(
        "[FWT] WARNING: PPCContext only was restored; guest memory writes were not rolled back");
  } else if (IsReportMilestone(record_for_log.fault_hits)) {
    REXLOG_WARN("[FWT] repeated fault guest=0x{:08X} fingerprint={} hits={}",
                record_for_log.guest_address, record_for_log.fingerprint,
                record_for_log.fault_hits);
  }

  if (stop_after_record) {
    StopAtGuardrail(fmt::format(
        "maximum automatically poisoned functions ({}) already reached; new fault at 0x{:08X}",
        state.config.max_unique, frame->descriptor->guest_address));
  }

  const FaultWalkPolicy policy = record_for_log.policy;
  std::memcpy(&ctx, &frame->checkpoint, sizeof(PPCContext));
  ctx.fpscr.setcsr(frame->checkpoint.fpscr.csr);
  ApplyPolicy(ctx, policy);
}

}  // namespace

void FaultWalkInvoke(PPCContext& ctx, uint8_t* base,
                     const FaultWalkFunctionDescriptor& descriptor) {
  InitializeState();
  if (TrySuppressPoisonedInvocation(ctx, descriptor)) {
    return;
  }
  if (HasExplicitNormalPolicy(descriptor)) {
    // NORMAL is an explicit request for unmodified execution. In particular,
    // another exception propagates normally rather than being restored and
    // returned without a synthetic result.
#if REX_PLATFORM_WIN32
    const FrameToken normal_token = EnterFrame(ctx, descriptor, true);
    __try {
      descriptor.body(ctx, base);
    } __finally {
      LeaveFrame(normal_token);
    }
#else
    descriptor.body(ctx, base);
#endif
    return;
  }

#if REX_PLATFORM_WIN32
  const FrameToken token = EnterFrame(ctx, descriptor);
  __try {
    __try {
      descriptor.body(ctx, base);
    } __except (FaultWalkExceptionFilter(token, static_cast<uint32_t>(GetExceptionCode()),
                                         GetExceptionInformation())) {
      HandleFault(token, ctx);
    }
  } __finally {
    LeaveFrame(token);
  }
#else
  // The v1 diagnostic boundary is intentionally Windows-SEH-only. Generated
  // projects reject REXGLUE_ENABLE_FAULT_WALK on other platforms.
  descriptor.body(ctx, base);
#endif
}

bool FaultWalkHandleInvalidFunction(PPCContext& ctx) {
  auto& state = GetProcessState();
  if (!state.active.load(std::memory_order_acquire)) {
    return false;
  }

  const uint32_t target = ctx.last_indirect_target;
  const uint32_t guest_lr = static_cast<uint32_t>(ctx.lr);
  const std::string original_fatal = fmt::format(
      "Call to invalid or unregistered function: target=0x{:08X}, ctx.lr=0x{:08X}, "
      "probable caller=0x{:08X}, ctx.ctr=0x{:08X}",
      target, guest_lr, guest_lr - 4, ctx.ctr.u32);

  FaultRecord record_for_log;
  bool new_fault = false;
  bool stop_after_record = false;
  bool write_report = false;
  uint64_t function_suppressions = 0;
  uint64_t total_suppressions = 0;
  {
    std::lock_guard lock(state.mutex);
    const auto index_it = state.fault_indices.find(target);
    if (index_it == state.fault_indices.end()) {
      FaultRecord record;
      record.kind = FaultKind::InvalidUnregisteredFunction;
      record.sequence = static_cast<uint32_t>(state.faults.size() + 1);
      record.guest_address = target;
      record.thread_id = CurrentThreadIdValue();
      record.previous_guest_function =
          tls_frames.depth > 0 && tls_frames.storage[tls_frames.depth - 1].descriptor
              ? tls_frames.storage[tls_frames.depth - 1].descriptor->guest_address
              : 0;
      record.last_indirect_target = target;
      std::memcpy(&record.fault_context, &ctx, sizeof(PPCContext));
      record.fault_hits = 1;
      record.poisoned = state.faults.size() < state.config.max_unique;
      record.policy = record.poisoned ? FaultWalkPolicy::ReturnR3Zero : FaultWalkPolicy::Stop;
      record.fingerprint = fmt::format("INVALID_UNREGISTERED_FUNCTION-{:08X}", target);
      record.original_fatal = original_fatal;
      const uint32_t first_stack_index =
          tls_frames.depth > kMaxReportedGuestStack
              ? tls_frames.depth - static_cast<uint32_t>(kMaxReportedGuestStack)
              : 0;
      for (uint32_t index = first_stack_index; index < tls_frames.depth; ++index) {
        if (const auto* descriptor = tls_frames.storage[index].descriptor) {
          record.guest_call_stack.push_back(descriptor->guest_address);
        }
      }
      stop_after_record = !record.poisoned;
      state.fault_indices.emplace(record.guest_address, state.faults.size());
      state.faults.push_back(std::move(record));
      ++state.total_fault_hits;
      state.summary_printed = false;
      record_for_log = state.faults.back();
      new_fault = true;
      WriteReportLocked(state);
    } else {
      auto& record = state.faults[index_it->second];
      if (record.kind != FaultKind::InvalidUnregisteredFunction ||
          record.policy == FaultWalkPolicy::Normal) {
        return false;
      }
      record_for_log = record;
      if (record.policy != FaultWalkPolicy::Stop) {
        function_suppressions = ++record.suppressed_invocations;
        total_suppressions = ++state.total_suppressed_invocations;
        state.summary_printed = false;
        record_for_log = record;
        write_report = IsReportMilestone(function_suppressions);
        if (write_report) {
          WriteReportLocked(state);
        }
      }
    }
  }

  if (new_fault) {
    REXLOG_CRITICAL("[FWT] #{:03}", record_for_log.sequence);
    REXLOG_CRITICAL("[FWT] event=INVALID_UNREGISTERED_FUNCTION target=0x{:08X}", target);
    REXLOG_CRITICAL("[FWT] original_fatal={}", original_fatal);
    REXLOG_CRITICAL("[FWT] lr=0x{:08X} caller=0x{:08X} ctr=0x{:08X}", guest_lr, guest_lr - 4,
                    ctx.ctr.u32);
    REXLOG_CRITICAL("[FWT] r1=0x{:016X} r2=0x{:016X} r3=0x{:016X}", ctx.r1.u64, ctx.r2.u64,
                    ctx.r3.u64);
    REXLOG_CRITICAL("[FWT] r4=0x{:016X} r5=0x{:016X} r6=0x{:016X}", ctx.r4.u64, ctx.r5.u64,
                    ctx.r6.u64);
    REXLOG_CRITICAL("[FWT] r7=0x{:016X} r8=0x{:016X} r9=0x{:016X} r10=0x{:016X}", ctx.r7.u64,
                    ctx.r8.u64, ctx.r9.u64, ctx.r10.u64);
    REXLOG_CRITICAL("[FWT] thread={} previous_guest=0x{:08X} last_indirect=0x{:08X}",
                    record_for_log.thread_id, record_for_log.previous_guest_function,
                    record_for_log.last_indirect_target);
    REXLOG_CRITICAL("[FWT] policy={}", PolicyName(record_for_log.policy));
    REXLOG_CRITICAL("[FWT] target poisoned; no target body executed");
  } else if (write_report) {
    REXLOG_WARN("[FWT] suppressed invalid target=0x{:08X} count={}", target, function_suppressions);
  }

  if (stop_after_record) {
    StopAtGuardrail(
        fmt::format("maximum automatically poisoned functions ({}) already reached; invalid target "
                    "0x{:08X}",
                    state.config.max_unique, target));
  }
  if (record_for_log.policy == FaultWalkPolicy::Stop) {
    StopAtGuardrail(fmt::format("policy STOP reached for invalid target 0x{:08X}", target));
  }
  if (function_suppressions >= state.config.max_function_suppressions) {
    StopAtGuardrail(
        fmt::format("per-function suppression limit reached for invalid target "
                    "0x{:08X} ({})",
                    target, function_suppressions));
  }
  if (total_suppressions >= state.config.max_total_suppressions) {
    StopAtGuardrail(fmt::format("total suppression limit reached ({})", total_suppressions));
  }

  ApplyPolicy(ctx, record_for_log.policy);
  return true;
}

FaultWalkStats GetFaultWalkStats() {
  InitializeState();
  auto& state = GetProcessState();
  std::lock_guard lock(state.mutex);
  uint32_t poisoned_count = 0;
  for (const auto& fault : state.faults) {
    poisoned_count += fault.poisoned ? 1u : 0u;
  }
  return {
      .unique_faults = static_cast<uint32_t>(state.faults.size()),
      .poisoned_functions = poisoned_count,
      .total_fault_hits = state.total_fault_hits,
      .total_suppressed_invocations = state.total_suppressed_invocations,
  };
}

FaultWalkFunctionStats GetFaultWalkFunctionStats(uint32_t guest_address) {
  InitializeState();
  auto& state = GetProcessState();
  std::lock_guard lock(state.mutex);
  const auto it = state.fault_indices.find(guest_address);
  if (it == state.fault_indices.end()) {
    return {};
  }
  const auto& fault = state.faults[it->second];
  return {
      .found = true,
      .poisoned = fault.poisoned,
      .policy = fault.policy,
      .fault_hits = fault.fault_hits,
      .suppressed_invocations = fault.suppressed_invocations,
  };
}

bool SetFaultWalkPolicy(uint32_t guest_address, FaultWalkPolicy policy) {
  InitializeState();
  auto& state = GetProcessState();
  std::lock_guard lock(state.mutex);
  const auto it = state.fault_indices.find(guest_address);
  if (it == state.fault_indices.end()) {
    return false;
  }
  auto& fault = state.faults[it->second];
  fault.policy = policy;
  fault.poisoned = policy != FaultWalkPolicy::Normal;
  state.summary_printed = false;
  WriteReportLocked(state);
  return true;
}

void WriteFaultWalkReport() {
  InitializeState();
  auto& state = GetProcessState();
  std::lock_guard lock(state.mutex);
  WriteReportLocked(state);
}

void PrintFaultWalkSummary() {
  InitializeState();
  auto& state = GetProcessState();
  std::lock_guard lock(state.mutex);
  PrintSummaryLocked(state);
}

void FaultWalkCaptureSetJmp(uint32_t guest_buffer_address) {
  tls_frames.setjmp_depths[guest_buffer_address] = tls_frames.depth;
}

int FaultWalkCompleteSetJmp(uint32_t guest_buffer_address, int setjmp_result) {
  if (setjmp_result == 0) {
    return setjmp_result;
  }

  const auto it = tls_frames.setjmp_depths.find(guest_buffer_address);
  if (it != tls_frames.setjmp_depths.end()) {
    const uint32_t expected_depth =
        std::min<uint32_t>(it->second, static_cast<uint32_t>(tls_frames.storage.size()));
    if (tls_frames.depth != expected_depth) {
      REXLOG_ERROR(
          "[FWT] TLS guest-function stack mismatch after longjmp: expected_depth={} "
          "current_depth={}",
          expected_depth, tls_frames.depth);
      tls_frames.depth = expected_depth;
    }
  }
  return setjmp_result;
}

void ResetFaultWalkStateForTesting() {
  InitializeState();
  auto& state = GetProcessState();
  {
    std::lock_guard lock(state.mutex);
    state.faults.clear();
    state.fault_indices.clear();
    state.total_fault_hits = 0;
    state.total_suppressed_invocations = 0;
    state.summary_printed = false;
    WriteReportLocked(state);
  }
  tls_frames.depth = 0;
  tls_frames.setjmp_depths.clear();
}

uint32_t GetFaultWalkThreadDepthForTesting() {
  return tls_frames.depth;
}

}  // namespace rex::diagnostics
