#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <initializer_list>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

#include <rex/cvar.h>
#include <rex/system/xtypes.h>

REXCVAR_DECLARE(std::string, save_trace_dir);

namespace rex::filesystem {
class File;
}

namespace rex::system {

using SaveTraceValue =
    std::variant<std::nullptr_t, bool, int64_t, uint64_t, std::string, std::string_view>;

struct SaveTraceField {
  std::string_view name;
  SaveTraceValue value;
};

// Payload-free, append-only diagnostic trace for save/content operations. The
// trace is inactive unless --save_trace_dir is explicitly supplied.
class SaveTrace {
 public:
  static constexpr uint32_t kEventSchemaVersion = 1;
  static constexpr uint32_t kMetadataSchemaVersion = 1;

  static SaveTrace& Get();

  bool enabled();
  uint64_t Record(std::string_view operation, std::string_view phase,
                  std::initializer_list<SaveTraceField> fields = {});

  void TrackOverlapped(uint32_t overlapped_ptr, std::string_view operation,
                       uint64_t request_sequence);
  bool IsTrackedOverlapped(uint32_t overlapped_ptr);
  void CompleteOverlapped(uint32_t overlapped_ptr, X_RESULT result, uint32_t extended_error,
                          uint32_t length, uint32_t event_handle,
                          uint32_t completion_routine, bool event_signaled, bool apc_queued);

  // Used by focused tests. Production callers should configure the cvar and use
  // the singleton returned by Get().
  bool InitializeForTesting(const std::filesystem::path& output_directory);
  void ShutdownForTesting();

 private:
  struct GuestContext {
    uint32_t thread_id = 0;
    uint32_t lr = 0;
  };

  struct PendingOverlapped {
    std::string operation;
    uint64_t request_sequence = 0;
    GuestContext guest_context;
  };

  SaveTrace() = default;
  ~SaveTrace();
  SaveTrace(const SaveTrace&) = delete;
  SaveTrace& operator=(const SaveTrace&) = delete;

  bool InitializeLocked(const std::filesystem::path& output_directory);
  void ShutdownLocked();
  GuestContext CaptureGuestContext() const;
  uint64_t RecordLocked(std::string_view operation, std::string_view phase,
                        std::initializer_list<SaveTraceField> fields,
                        std::optional<GuestContext> guest_context = std::nullopt);

  std::mutex mutex_;
  bool initialization_attempted_ = false;
  bool enabled_ = false;
  std::FILE* event_file_ = nullptr;
  std::filesystem::path output_directory_;
  uint64_t next_sequence_ = 1;
  uint64_t start_ticks_ = 0;
  std::unordered_map<uint32_t, PendingOverlapped> pending_overlapped_;
};

bool IsSaveGuestPath(std::string_view path);
std::string SaveTraceHostPath(const rex::filesystem::File* file);

}  // namespace rex::system
