#include <filesystem>
#include <fstream>
#include <sstream>

#include <catch2/catch_test_macros.hpp>

#include <rex/platform.h>
#include <rex/system/save_trace.h>

#if REX_PLATFORM_WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

int CurrentProcessId() {
#if REX_PLATFORM_WIN32
  return _getpid();
#else
  return getpid();
#endif
}

class ScopedTraceDirectory {
 public:
  ScopedTraceDirectory() {
    path_ = std::filesystem::temp_directory_path() /
            ("rexglue_save_trace_test_" + std::to_string(CurrentProcessId()) + "_" +
             std::to_string(counter_++));
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }

  ~ScopedTraceDirectory() {
    rex::system::SaveTrace::Get().ShutdownForTesting();
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }

  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
  static inline uint32_t counter_ = 0;
};

std::string ReadText(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream contents;
  contents << stream.rdbuf();
  return contents.str();
}

}  // namespace

TEST_CASE("Save trace writes separate versioned metadata and payload-free events", "[save_trace]") {
  ScopedTraceDirectory directory;
  auto& trace = rex::system::SaveTrace::Get();
  REQUIRE(trace.InitializeForTesting(std::filesystem::absolute(directory.path())));

  const auto request_sequence =
      trace.Record("NtWriteFile", "request",
                   {{"guest_path", std::string_view("Save:\\Hero000\\mainsave.bin")},
                    {"requested_bytes", uint64_t(4096)},
                    {"offset_is_current", true}});
  REQUIRE(request_sequence == 1);
  trace.Record("NtWriteFile", "result",
               {{"request_sequence", request_sequence}, {"actual_bytes", uint64_t(4096)}});
  trace.ShutdownForTesting();

  const auto metadata = ReadText(directory.path() / "save-trace-run-v1.json");
  const auto events = ReadText(directory.path() / "save-trace-events-v1.ndjson");
  CHECK(metadata.find("\"schema_version\": 1") != std::string::npos);
  CHECK(metadata.find("\"contains_payload_bytes\": false") != std::string::npos);
  CHECK(events.find("\"schema_version\":1") != std::string::npos);
  CHECK(events.find("Save:\\\\Hero000\\\\mainsave.bin") != std::string::npos);
  CHECK(events.find("\"sequence\":1") != std::string::npos);
  CHECK(events.find("\"sequence\":2") != std::string::npos);
  CHECK(events.find("\"requested_bytes\":4096") != std::string::npos);
  CHECK(events.find("\"actual_bytes\":4096") != std::string::npos);
}

TEST_CASE("Save trace refuses to overwrite a prior capture", "[save_trace]") {
  ScopedTraceDirectory directory;
  auto& trace = rex::system::SaveTrace::Get();
  REQUIRE(trace.InitializeForTesting(std::filesystem::absolute(directory.path())));
  trace.Record("XamContentCreate", "request");
  trace.ShutdownForTesting();

  CHECK_FALSE(trace.InitializeForTesting(std::filesystem::absolute(directory.path())));
}

TEST_CASE("Save path filter is case insensitive and excludes unrelated paths", "[save_trace]") {
  CHECK(rex::system::IsSaveGuestPath("Save:\\Hero000\\herosave.bin"));
  CHECK(rex::system::IsSaveGuestPath("SAVE:\\Hero000\\mainsave.bin"));
  CHECK(rex::system::IsSaveGuestPath("\\Device\\Content\\3\\saveuid.bin"));
  CHECK_FALSE(rex::system::IsSaveGuestPath("game:\\data\\scripts\\gameface\\"));
}

TEST_CASE("Save trace remains disabled without an explicit output directory", "[save_trace]") {
  auto& trace = rex::system::SaveTrace::Get();
  trace.ShutdownForTesting();
  CHECK_FALSE(trace.enabled());
  CHECK(trace.Record("NtWriteFile", "request") == 0);
}
