/**
 * Unit tests for FileHandle::OpenExisting access mode handling.
 *
 * Covers the host-side handle only; guest path translation is out of scope.
 */

#include <array>
#include <cstdint>
#include <filesystem>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rex/filesystem.h>
#include <rex/platform.h>

#if REX_PLATFORM_WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

using rex::filesystem::FileAccess;
using rex::filesystem::FileHandle;

namespace {

constexpr std::string_view kPayload = "rexglue";

int CurrentProcessId() {
#if REX_PLATFORM_WIN32
  return _getpid();
#else
  return getpid();
#endif
}

class ScopedTempFile {
 public:
  ScopedTempFile() {
    path_ = std::filesystem::temp_directory_path() /
            ("rexglue_filesystem_test_" + std::to_string(CurrentProcessId()) + "_" +
             std::to_string(counter_++) + ".bin");
    FILE* file = rex::filesystem::OpenFile(path_, "wb");
    REQUIRE(file != nullptr);
    fwrite(kPayload.data(), 1, kPayload.size(), file);
    fclose(file);
  }
  ~ScopedTempFile() {
    std::error_code ec;
    std::filesystem::remove(path_, ec);
  }

  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
  static inline int counter_ = 0;
};

}  // namespace

TEST_CASE("OpenExisting read-only handle reads", "[filesystem]") {
  ScopedTempFile temp;
  auto handle = FileHandle::OpenExisting(temp.path(), FileAccess::kGenericRead);
  REQUIRE(handle != nullptr);

  std::array<uint8_t, 16> buffer{};
  size_t bytes_read = 0;
  REQUIRE(handle->Read(0, buffer.data(), kPayload.size(), &bytes_read));
  CHECK(bytes_read == kPayload.size());
  CHECK(std::string_view(reinterpret_cast<char*>(buffer.data()), bytes_read) == kPayload);
}

TEST_CASE("OpenExisting read+write handle retains read access", "[filesystem]") {
  ScopedTempFile temp;
  auto handle = FileHandle::OpenExisting(
      temp.path(), FileAccess::kGenericRead | FileAccess::kGenericWrite |
                       FileAccess::kFileReadData | FileAccess::kFileWriteData);
  REQUIRE(handle != nullptr);

  std::array<uint8_t, 16> buffer{};
  size_t bytes_read = 0;
  REQUIRE(handle->Read(0, buffer.data(), kPayload.size(), &bytes_read));
  CHECK(bytes_read == kPayload.size());

  const uint8_t patch = 'X';
  size_t bytes_written = 0;
  REQUIRE(handle->Write(0, &patch, 1, &bytes_written));
  CHECK(bytes_written == 1);

  REQUIRE(handle->Read(0, buffer.data(), 1, &bytes_read));
  CHECK(buffer[0] == patch);
}

TEST_CASE("OpenExisting kGenericAll grants both directions", "[filesystem]") {
  ScopedTempFile temp;
  auto handle = FileHandle::OpenExisting(temp.path(), FileAccess::kGenericAll);
  REQUIRE(handle != nullptr);

  const uint8_t patch = 'Z';
  size_t bytes_written = 0;
  REQUIRE(handle->Write(0, &patch, 1, &bytes_written));
  CHECK(bytes_written == 1);

  std::array<uint8_t, 4> buffer{};
  size_t bytes_read = 0;
  REQUIRE(handle->Read(0, buffer.data(), 1, &bytes_read));
  CHECK(buffer[0] == patch);
}

TEST_CASE("OpenExisting write-only handle writes at the requested offset", "[filesystem]") {
  ScopedTempFile temp;
  auto handle = FileHandle::OpenExisting(temp.path(),
                                         FileAccess::kGenericWrite | FileAccess::kFileAppendData);
  REQUIRE(handle != nullptr);

  const uint8_t patch = 'Q';
  size_t bytes_written = 0;
  REQUIRE(handle->Write(1, &patch, 1, &bytes_written));
  CHECK(bytes_written == 1);
  REQUIRE(handle->Flush());
  handle.reset();

  auto reader = FileHandle::OpenExisting(temp.path(), FileAccess::kGenericRead);
  REQUIRE(reader != nullptr);
  std::array<uint8_t, 16> buffer{};
  size_t bytes_read = 0;
  REQUIRE(reader->Read(0, buffer.data(), kPayload.size(), &bytes_read));
  CHECK(bytes_read == kPayload.size());
  CHECK(buffer[1] == patch);
}

TEST_CASE("OpenExisting failed read reports zero bytes", "[filesystem]") {
  ScopedTempFile temp;
  auto handle = FileHandle::OpenExisting(temp.path(), FileAccess::kGenericWrite);
  REQUIRE(handle != nullptr);

  std::array<uint8_t, 16> buffer{};
  size_t bytes_read = 0xDEAD;
  CHECK_FALSE(handle->Read(0, buffer.data(), buffer.size(), &bytes_read));
  CHECK(bytes_read == 0);
}

TEST_CASE("OpenExisting write handle truncates and flushes durably", "[filesystem]") {
  ScopedTempFile temp;
  auto handle =
      FileHandle::OpenExisting(temp.path(), FileAccess::kGenericWrite | FileAccess::kFileWriteData);
  REQUIRE(handle != nullptr);

  REQUIRE(handle->SetLength(3));
  REQUIRE(handle->Flush());
  handle.reset();

  CHECK(std::filesystem::file_size(temp.path()) == 3);
  auto reader = FileHandle::OpenExisting(temp.path(), FileAccess::kGenericRead);
  REQUIRE(reader != nullptr);
  std::array<uint8_t, 8> buffer{};
  size_t bytes_read = 0;
  REQUIRE(reader->Read(0, buffer.data(), 3, &bytes_read));
  CHECK(bytes_read == 3);
  CHECK(std::string_view(reinterpret_cast<char*>(buffer.data()), bytes_read) == "rex");
}

TEST_CASE("OpenExisting supports extending after an explicit-offset write", "[filesystem]") {
  ScopedTempFile temp;
  auto handle =
      FileHandle::OpenExisting(temp.path(), FileAccess::kGenericWrite | FileAccess::kFileWriteData);
  REQUIRE(handle != nullptr);

  const std::array<uint8_t, 3> suffix{'e', 'n', 'd'};
  size_t bytes_written = 0;
  REQUIRE(handle->Write(16, suffix.data(), suffix.size(), &bytes_written));
  REQUIRE(bytes_written == suffix.size());
  REQUIRE(handle->Flush());
  handle.reset();

  CHECK(std::filesystem::file_size(temp.path()) == 19);
  auto reader = FileHandle::OpenExisting(temp.path(), FileAccess::kGenericRead);
  REQUIRE(reader != nullptr);
  std::array<uint8_t, 3> buffer{};
  size_t bytes_read = 0;
  REQUIRE(reader->Read(16, buffer.data(), buffer.size(), &bytes_read));
  CHECK(bytes_read == suffix.size());
  CHECK(buffer == suffix);
}
