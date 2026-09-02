#include <rex/system/save_trace.h>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <system_error>

#include <fmt/format.h>
#include <fmt/chrono.h>

#include <rex/filesystem/devices/host_path_entry.h>
#include <rex/filesystem/file.h>
#include <rex/logging.h>
#include <rex/string.h>
#include <rex/system/thread_state.h>

#if REX_PLATFORM_WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

REXCVAR_DEFINE_STRING(save_trace_dir, "", "Diagnostics",
                      "Absolute directory for payload-free save-path trace output");

namespace rex::system {
namespace {

uint64_t MonotonicTicks() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count());
}

uint32_t ProcessId() {
#if REX_PLATFORM_WIN32
  return static_cast<uint32_t>(_getpid());
#else
  return static_cast<uint32_t>(getpid());
#endif
}

std::string EscapeJson(std::string_view input) {
  std::string output;
  output.reserve(input.size() + 8);
  for (const unsigned char c : input) {
    switch (c) {
      case '\"':
        output += "\\\"";
        break;
      case '\\':
        output += "\\\\";
        break;
      case '\b':
        output += "\\b";
        break;
      case '\f':
        output += "\\f";
        break;
      case '\n':
        output += "\\n";
        break;
      case '\r':
        output += "\\r";
        break;
      case '\t':
        output += "\\t";
        break;
      default:
        if (c < 0x20) {
          output += fmt::format("\\u{:04X}", c);
        } else {
          output.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return output;
}

std::string JsonValue(const SaveTraceValue& value) {
  return std::visit(
      [](const auto& item) -> std::string {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
          return "null";
        } else if constexpr (std::is_same_v<T, bool>) {
          return item ? "true" : "false";
        } else if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) {
          return std::to_string(item);
        } else {
          return fmt::format("\"{}\"", EscapeJson(item));
        }
      },
      value);
}

std::string UtcNow() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t time = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
#if REX_PLATFORM_WIN32
  gmtime_s(&utc, &time);
#else
  gmtime_r(&time, &utc);
#endif
  return fmt::format("{:%Y-%m-%dT%H:%M:%SZ}", utc);
}

}  // namespace

SaveTrace& SaveTrace::Get() {
  static SaveTrace trace;
  return trace;
}

SaveTrace::~SaveTrace() {
  std::lock_guard lock(mutex_);
  ShutdownLocked();
}

bool SaveTrace::enabled() {
  std::lock_guard lock(mutex_);
  if (!initialization_attempted_) {
    initialization_attempted_ = true;
    const auto configured_path = REXCVAR_GET(save_trace_dir);
    if (!configured_path.empty()) {
      InitializeLocked(rex::to_path(configured_path));
    }
  }
  return enabled_;
}

bool SaveTrace::InitializeLocked(const std::filesystem::path& output_directory) {
  if (!output_directory.is_absolute()) {
    REXSYS_ERROR("Save trace directory must be absolute: {}", output_directory.string());
    return false;
  }

  std::error_code ec;
  std::filesystem::create_directories(output_directory, ec);
  if (ec) {
    REXSYS_ERROR("Unable to create save trace directory '{}': {}", output_directory.string(),
                 ec.message());
    return false;
  }

  const auto event_path = output_directory / "save-trace-events-v1.ndjson";
  const auto metadata_path = output_directory / "save-trace-run-v1.json";
  if (std::filesystem::exists(event_path, ec) || std::filesystem::exists(metadata_path, ec)) {
    REXSYS_ERROR("Refusing to overwrite existing save trace in '{}'", output_directory.string());
    return false;
  }

  auto metadata_file = rex::filesystem::OpenFile(metadata_path, "wb");
  if (!metadata_file) {
    REXSYS_ERROR("Unable to create save trace metadata '{}'; tracing disabled",
                 metadata_path.string());
    return false;
  }
  const auto metadata = fmt::format(
      "{{\n  \"schema_version\": {},\n  \"event_schema_version\": {},\n  "
      "\"started_utc\": \"{}\",\n  \"process_id\": {},\n  \"trace_directory\": "
      "\"{}\",\n  \"contains_payload_bytes\": false\n}}\n",
      kMetadataSchemaVersion, kEventSchemaVersion, UtcNow(), ProcessId(),
      EscapeJson(rex::path_to_utf8(output_directory)));
  const size_t metadata_written = fwrite(metadata.data(), 1, metadata.size(), metadata_file);
  fflush(metadata_file);
  fclose(metadata_file);
  if (metadata_written != metadata.size()) {
    REXSYS_ERROR("Unable to write complete save trace metadata '{}'; tracing disabled",
                 metadata_path.string());
    return false;
  }

  auto event_file = rex::filesystem::OpenFile(event_path, "ab");
  if (!event_file) {
    REXSYS_ERROR("Unable to create save trace event stream '{}'; tracing disabled",
                 event_path.string());
    return false;
  }

  output_directory_ = output_directory;
  event_file_ = event_file;
  next_sequence_ = 1;
  start_ticks_ = MonotonicTicks();
  enabled_ = true;
  REXSYS_INFO("Save-path trace enabled in '{}' (schema v{})", output_directory.string(),
              kEventSchemaVersion);
  return true;
}

void SaveTrace::ShutdownLocked() {
  if (event_file_) {
    fflush(event_file_);
    fclose(event_file_);
  }
  event_file_ = nullptr;
  output_directory_.clear();
  pending_overlapped_.clear();
  enabled_ = false;
}

bool SaveTrace::InitializeForTesting(const std::filesystem::path& output_directory) {
  std::lock_guard lock(mutex_);
  ShutdownLocked();
  initialization_attempted_ = true;
  return InitializeLocked(output_directory);
}

void SaveTrace::ShutdownForTesting() {
  std::lock_guard lock(mutex_);
  ShutdownLocked();
  initialization_attempted_ = false;
}

SaveTrace::GuestContext SaveTrace::CaptureGuestContext() const {
  GuestContext result;
  auto* thread_state = runtime::ThreadState::Get();
  if (thread_state) {
    result.thread_id = thread_state->thread_id();
    if (thread_state->context()) {
      result.lr = thread_state->context()->lr;
    }
  }
  return result;
}

uint64_t SaveTrace::Record(std::string_view operation, std::string_view phase,
                           std::initializer_list<SaveTraceField> fields) {
  if (!enabled()) {
    return 0;
  }
  std::lock_guard lock(mutex_);
  return RecordLocked(operation, phase, fields);
}

uint64_t SaveTrace::RecordLocked(std::string_view operation, std::string_view phase,
                                 std::initializer_list<SaveTraceField> fields,
                                 std::optional<GuestContext> guest_context) {
  if (!enabled_ || !event_file_) {
    return 0;
  }
  const uint64_t sequence = next_sequence_++;
  const auto context = guest_context.value_or(CaptureGuestContext());
  const uint64_t relative_ns = MonotonicTicks() - start_ticks_;

  std::string line = fmt::format(
      "{{\"schema_version\":{},\"sequence\":{},\"relative_ns\":{},\"guest_thread_id\":{},"
      "\"guest_lr\":{},\"caller_guest_pc\":{},\"caller_pc_basis\":\"lr_minus_4\","
      "\"operation\":\"{}\",\"phase\":\"{}\"",
      kEventSchemaVersion, sequence, relative_ns, context.thread_id, context.lr,
      context.lr >= 4 ? context.lr - 4 : 0, EscapeJson(operation), EscapeJson(phase));
  for (const auto& field : fields) {
    line += fmt::format(",\"{}\":{}", EscapeJson(field.name), JsonValue(field.value));
  }
  line += "}\n";

  const size_t written = fwrite(line.data(), 1, line.size(), event_file_);
  fflush(event_file_);
  if (written != line.size()) {
    REXSYS_ERROR("Short write in save trace; disabling trace output");
    ShutdownLocked();
  }
  return sequence;
}

void SaveTrace::TrackOverlapped(uint32_t overlapped_ptr, std::string_view operation,
                                uint64_t request_sequence) {
  if (!overlapped_ptr || !enabled()) {
    return;
  }
  std::lock_guard lock(mutex_);
  pending_overlapped_[overlapped_ptr] = {
      std::string(operation), request_sequence, CaptureGuestContext()};
}

bool SaveTrace::IsTrackedOverlapped(uint32_t overlapped_ptr) {
  if (!overlapped_ptr || !enabled()) {
    return false;
  }
  std::lock_guard lock(mutex_);
  return pending_overlapped_.contains(overlapped_ptr);
}

void SaveTrace::CompleteOverlapped(uint32_t overlapped_ptr, X_RESULT result,
                                   uint32_t extended_error, uint32_t length,
                                   uint32_t event_handle, uint32_t completion_routine,
                                   bool event_signaled, bool apc_queued) {
  if (!overlapped_ptr || !enabled()) {
    return;
  }
  std::lock_guard lock(mutex_);
  const auto it = pending_overlapped_.find(overlapped_ptr);
  if (it == pending_overlapped_.end()) {
    return;
  }
  const auto pending = it->second;
  pending_overlapped_.erase(it);
  RecordLocked(pending.operation, "overlapped_completion",
               {{"request_sequence", pending.request_sequence},
                {"overlapped", uint64_t(overlapped_ptr)},
                {"result", uint64_t(result)},
                {"extended_error", uint64_t(extended_error)},
                {"length", uint64_t(length)},
                {"event_handle", uint64_t(event_handle)},
                {"event_signaled", event_signaled},
                {"completion_routine", uint64_t(completion_routine)},
                {"apc_queued", apc_queued}},
               pending.guest_context);
}

bool IsSaveGuestPath(std::string_view path) {
  return rex::string::utf8_starts_with_case(path, "save:") ||
         rex::string::utf8_starts_with_case(path, "\\device\\content\\");
}

std::string SaveTraceHostPath(const rex::filesystem::File* file) {
  if (!file || !file->entry()) {
    return {};
  }
  const auto* host_entry = dynamic_cast<const rex::filesystem::HostPathEntry*>(file->entry());
  return host_entry ? rex::path_to_utf8(host_entry->host_path()) : std::string();
}

}  // namespace rex::system
