#include <rex/fault_walk.h>
#include <rex/platform/env.h>

#include <atomic>
#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>

#include <windows.h>

namespace {

constexpr uint32_t kGuestA = 0x82001000;
[[maybe_unused]] constexpr uint32_t kGuestB = 0x82002000;
[[maybe_unused]] constexpr uint32_t kGuestC = 0x82003000;
[[maybe_unused]] constexpr uint32_t kGuestSehParent = 0x82004000;
[[maybe_unused]] constexpr uint32_t kGuestSehChild = 0x82005000;
[[maybe_unused]] constexpr uint32_t kGuestNonAllowlisted = 0x82006000;
[[maybe_unused]] constexpr uint32_t kGuestJumpA = 0x82007000;
[[maybe_unused]] constexpr uint32_t kGuestJumpB = 0x82008000;
[[maybe_unused]] constexpr uint32_t kGuestJumpC = 0x82009000;
constexpr uint32_t kInvalidDispatchOne = 0x8200A000;
[[maybe_unused]] constexpr uint32_t kInvalidDispatchTwo = 0x8200B000;
#if FAULT_WALK_EXPECT_ENABLED
constexpr uint32_t kGuestJumpBuffer = 0x40001000;
#endif
constexpr uint32_t kNonAllowlistedException = 0xE0424242;

std::atomic<uint32_t> guest_b_body_count{0};
std::atomic<uint32_t> guest_c_body_count{0};
std::atomic<uint32_t> guest_a_continuation_count{0};
std::atomic<uint32_t> guest_seh_catch_count{0};
bool checkpoint_b_restored = false;
bool checkpoint_c_restored = false;
#if FAULT_WALK_EXPECT_ENABLED
std::jmp_buf guest_jump_buffer;
bool guest_longjmp_continued = false;
bool guest_longjmp_depth_correct = false;
#endif

#define DECLARE_TEST_REX_FUNC(name) \
  REX_EXTERN(name);                 \
  REX_EXTERN(__imp__##name)

#if FAULT_WALK_EXPECT_ENABLED
#define DEFINE_TEST_REX_FUNC(name, guest_address, has_guest_seh) \
  REX_DEFINE_FAULT_WALK_FUNC(name, guest_address, has_guest_seh)
#else
#define DEFINE_TEST_REX_FUNC(name, guest_address, has_guest_seh) \
  __attribute__((alias("__imp__" #name))) REX_WEAK_FUNC(name);   \
  REX_EXTERN(__imp__##name)
#endif

DECLARE_TEST_REX_FUNC(test_guest_a);
DECLARE_TEST_REX_FUNC(test_guest_b);
DECLARE_TEST_REX_FUNC(test_guest_c);
DECLARE_TEST_REX_FUNC(test_guest_seh_parent);
DECLARE_TEST_REX_FUNC(test_guest_seh_child);
DECLARE_TEST_REX_FUNC(test_guest_nonallowlisted);
#if FAULT_WALK_EXPECT_ENABLED
DECLARE_TEST_REX_FUNC(test_guest_jump_a);
DECLARE_TEST_REX_FUNC(test_guest_jump_b);
DECLARE_TEST_REX_FUNC(test_guest_jump_c);
#endif

void FillContext(PPCContext& ctx, uint8_t pattern) {
  const uint32_t host_fpscr = ctx.fpscr.getcsr();
  std::memset(&ctx, pattern, sizeof(ctx));
  ctx.fpscr.csr = host_fpscr;
}

bool MatchesSyntheticZeroResult(const PPCContext& actual, PPCContext expected) {
  expected.r3.u64 = 0;
  return std::memcmp(&actual, &expected, sizeof(PPCContext)) == 0;
}

__attribute__((noinline)) uint32_t CauseAccessViolation() {
  return *reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(0x18));
}

__attribute__((noinline)) int32_t CauseIntegerDivideByZero() {
  volatile int32_t divisor = 0;
  return 7 / divisor;
}

DEFINE_TEST_REX_FUNC(test_guest_b, kGuestB, false) {
  (void)base;
  ++guest_b_body_count;
  std::memset(&ctx, 0xB2, sizeof(ctx));
  ctx.r3.u64 = CauseAccessViolation();
}

DEFINE_TEST_REX_FUNC(test_guest_c, kGuestC, false) {
  (void)base;
  ++guest_c_body_count;
  std::memset(&ctx, 0xC3, sizeof(ctx));
  ctx.r3.s64 = CauseIntegerDivideByZero();
}

DEFINE_TEST_REX_FUNC(test_guest_a, kGuestA, false) {
  FillContext(ctx, 0x31);
  ctx.lr = kGuestA + 0x44;
  const PPCContext before_b = ctx;
  test_guest_b(ctx, base);
  checkpoint_b_restored = MatchesSyntheticZeroResult(ctx, before_b);

  FillContext(ctx, 0x47);
  ctx.lr = kGuestA + 0x88;
  const PPCContext before_c = ctx;
  test_guest_c(ctx, base);
  checkpoint_c_restored = MatchesSyntheticZeroResult(ctx, before_c);

  ++guest_a_continuation_count;
}

DEFINE_TEST_REX_FUNC(test_guest_seh_child, kGuestSehChild, false) {
  (void)base;
  ctx.r3.u64 = CauseAccessViolation();
}

DEFINE_TEST_REX_FUNC(test_guest_seh_parent, kGuestSehParent, true) {
  __try {
    test_guest_seh_child(ctx, base);
  } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER
                                                               : EXCEPTION_CONTINUE_SEARCH) {
    ++guest_seh_catch_count;
    ctx.r3.u64 = 0x5E5E5E5E;
  }
}

DEFINE_TEST_REX_FUNC(test_guest_nonallowlisted, kGuestNonAllowlisted, false) {
  (void)base;
  RaiseException(kNonAllowlistedException, 0, 0, nullptr);
}

#if FAULT_WALK_EXPECT_ENABLED
DEFINE_TEST_REX_FUNC(test_guest_jump_c, kGuestJumpC, false) {
  (void)ctx;
  (void)base;
  std::longjmp(guest_jump_buffer, 7);
}

DEFINE_TEST_REX_FUNC(test_guest_jump_b, kGuestJumpB, false) {
  test_guest_jump_c(ctx, base);
}

DEFINE_TEST_REX_FUNC(test_guest_jump_a, kGuestJumpA, false) {
  rex::diagnostics::FaultWalkCaptureSetJmp(kGuestJumpBuffer);
  const int jump_result =
      rex::diagnostics::FaultWalkCompleteSetJmp(kGuestJumpBuffer, setjmp(guest_jump_buffer));
  if (jump_result == 0) {
    test_guest_jump_b(ctx, base);
    return;
  }
  guest_longjmp_continued = jump_result == 7;
  guest_longjmp_depth_correct = rex::diagnostics::GetFaultWalkThreadDepthForTesting() == 1;
}
#endif

bool RunWithOuterExceptionCatch(PPCFunc* function, PPCContext& ctx, uint8_t* base,
                                uint32_t expected_code) {
  bool caught = false;
  __try {
    function(ctx, base);
  } __except (GetExceptionCode() == expected_code ? EXCEPTION_EXECUTE_HANDLER
                                                  : EXCEPTION_CONTINUE_SEARCH) {
    caught = true;
  }
  return caught;
}

int Fail(const char* message) {
  std::fprintf(stderr, "fault_walk_synthetic_test: %s\n", message);
  return 1;
}

}  // namespace

int main() {
  alignas(32) uint8_t base[64]{};
  PPCContext ctx{};

#if !FAULT_WALK_EXPECT_ENABLED
  ctx.last_indirect_target = kInvalidDispatchOne;
  ctx.lr = 0x8200C004;
  ctx.ctr.u32 = kInvalidDispatchOne;
  if (rex::diagnostics::FaultWalkHandleInvalidFunction(ctx)) {
    return Fail("disabled build tolerated an invalid function target");
  }

  const bool caught =
      RunWithOuterExceptionCatch(test_guest_a, ctx, base, EXCEPTION_ACCESS_VIOLATION);
  if (!caught) {
    return Fail("disabled build swallowed ACCESS_VIOLATION");
  }
  if (guest_b_body_count != 1 || guest_c_body_count != 0 || guest_a_continuation_count != 0) {
    return Fail("disabled build did not retain normal one-fault propagation");
  }
  std::puts("fault-walk disabled: normal ACCESS_VIOLATION propagation preserved");
  return 0;
#else
  rex::platform::env::set("REXGLUE_FAULT_WALK_REPORT", "fault-walk-synthetic-report.json");
  rex::platform::env::set("REXGLUE_FAULT_WALK_MAX_UNIQUE", "32");
  rex::diagnostics::ResetFaultWalkStateForTesting();

  test_guest_jump_a(ctx, base);
  if (!guest_longjmp_continued || !guest_longjmp_depth_correct ||
      rex::diagnostics::GetFaultWalkThreadDepthForTesting() != 0) {
    return Fail("guest longjmp did not preserve the TLS generated-function stack");
  }

  test_guest_a(ctx, base);
  if (guest_a_continuation_count != 1) {
    return Fail("Guest A did not continue after both independent faults");
  }
  if (!checkpoint_b_restored || !checkpoint_c_restored) {
    return Fail("complete PPCContext checkpoint was not restored before synthetic return");
  }
  if (guest_b_body_count != 1 || guest_c_body_count != 1) {
    return Fail("faulting guest body execution counts are incorrect");
  }

  auto totals = rex::diagnostics::GetFaultWalkStats();
  if (totals.unique_faults != 2 || totals.poisoned_functions != 2 || totals.total_fault_hits != 2) {
    return Fail("two independent faults were not attributed and poisoned");
  }
  if (rex::diagnostics::GetFaultWalkFunctionStats(kGuestA).found) {
    return Fail("nested fault was incorrectly attributed to Guest A");
  }

  FillContext(ctx, 0x66);
  const PPCContext before_suppressed_b = ctx;
  test_guest_b(ctx, base);
  if (guest_b_body_count != 1 || !MatchesSyntheticZeroResult(ctx, before_suppressed_b)) {
    return Fail("poisoned Guest B executed again or did not return r3=0");
  }
  const auto b_stats = rex::diagnostics::GetFaultWalkFunctionStats(kGuestB);
  if (!b_stats.found || b_stats.fault_hits != 1 || b_stats.suppressed_invocations != 1) {
    return Fail("Guest B suppression counters are incorrect");
  }

  if (!rex::diagnostics::SetFaultWalkPolicy(kGuestB,
                                            rex::diagnostics::FaultWalkPolicy::ReturnR3One)) {
    return Fail("failed to update a poisoned function policy");
  }
  FillContext(ctx, 0x77);
  test_guest_b(ctx, base);
  if (guest_b_body_count != 1 || ctx.r3.u64 != 1) {
    return Fail("RETURN_R3_ONE policy was not applied without executing Guest B");
  }
  rex::diagnostics::SetFaultWalkPolicy(kGuestB, rex::diagnostics::FaultWalkPolicy::ReturnR3Zero);

  std::thread suppression_thread_one([base]() {
    PPCContext thread_ctx{};
    FillContext(thread_ctx, 0x81);
    test_guest_b(thread_ctx, const_cast<uint8_t*>(base));
  });
  std::thread suppression_thread_two([base]() {
    PPCContext thread_ctx{};
    FillContext(thread_ctx, 0x82);
    test_guest_b(thread_ctx, const_cast<uint8_t*>(base));
  });
  suppression_thread_one.join();
  suppression_thread_two.join();
  if (guest_b_body_count != 1 ||
      rex::diagnostics::GetFaultWalkFunctionStats(kGuestB).suppressed_invocations != 4) {
    return Fail("TLS/thread-safe poisoned suppression failed on multiple guest threads");
  }

  rex::diagnostics::SetFaultWalkPolicy(kGuestB, rex::diagnostics::FaultWalkPolicy::Normal);
  FillContext(ctx, 0x90);
  if (!RunWithOuterExceptionCatch(test_guest_b, ctx, base, EXCEPTION_ACCESS_VIOLATION) ||
      guest_b_body_count != 2 ||
      rex::diagnostics::GetFaultWalkFunctionStats(kGuestB).fault_hits != 1) {
    return Fail("NORMAL policy did not restore unmodified exception propagation");
  }
  rex::diagnostics::SetFaultWalkPolicy(kGuestB, rex::diagnostics::FaultWalkPolicy::ReturnR3Zero);

  FillContext(ctx, 0x20);
  test_guest_seh_parent(ctx, base);
  if (guest_seh_catch_count != 1 || ctx.r3.u64 != 0x5E5E5E5E) {
    return Fail("legitimate enclosing guest SEH did not receive the original exception");
  }
  if (rex::diagnostics::GetFaultWalkFunctionStats(kGuestSehChild).found) {
    return Fail("function was poisoned before legitimate guest SEH could handle its exception");
  }

  if (!RunWithOuterExceptionCatch(test_guest_nonallowlisted, ctx, base, kNonAllowlistedException)) {
    return Fail("non-allowlisted exception was swallowed");
  }
  if (rex::diagnostics::GetFaultWalkFunctionStats(kGuestNonAllowlisted).found) {
    return Fail("non-allowlisted exception created a poison record");
  }

  FillContext(ctx, 0xA1);
  ctx.last_indirect_target = kInvalidDispatchOne;
  ctx.lr = 0x8200C004;
  ctx.ctr.u32 = kInvalidDispatchOne;
  if (!rex::diagnostics::FaultWalkHandleInvalidFunction(ctx) || ctx.r3.u64 != 0) {
    return Fail("first invalid function target was not tolerated with r3=0");
  }
  FillContext(ctx, 0xA2);
  ctx.last_indirect_target = kInvalidDispatchOne;
  ctx.lr = 0x8200C004;
  ctx.ctr.u32 = kInvalidDispatchOne;
  if (!rex::diagnostics::FaultWalkHandleInvalidFunction(ctx) || ctx.r3.u64 != 0 ||
      rex::diagnostics::GetFaultWalkFunctionStats(kInvalidDispatchOne).suppressed_invocations !=
          1) {
    return Fail("repeated invalid target was not suppressed without a second fatal");
  }

  FillContext(ctx, 0xB1);
  ctx.last_indirect_target = kInvalidDispatchTwo;
  ctx.lr = 0x8200D004;
  ctx.ctr.u32 = kInvalidDispatchTwo;
  if (!rex::diagnostics::FaultWalkHandleInvalidFunction(ctx) || ctx.r3.u64 != 0) {
    return Fail("second independent invalid function target was not tolerated");
  }

  rex::diagnostics::WriteFaultWalkReport();
  std::ifstream report("fault-walk-synthetic-report.json");
  const std::string report_text((std::istreambuf_iterator<char>(report)),
                                std::istreambuf_iterator<char>());
  if (!report || report_text.find("\"unique_faults\": 4") == std::string::npos ||
      report_text.find("0x82002000") == std::string::npos ||
      report_text.find("0x82003000") == std::string::npos ||
      report_text.find("0x8200A000") == std::string::npos ||
      report_text.find("0x8200B000") == std::string::npos ||
      report_text.find("Call to invalid or unregistered function: target=0x8200A000") ==
          std::string::npos) {
    return Fail("machine-readable report did not contain all exact synthetic fault records");
  }

  totals = rex::diagnostics::GetFaultWalkStats();
  if (totals.unique_faults != 4 || totals.total_fault_hits != 4 ||
      totals.total_suppressed_invocations != 5) {
    return Fail("final host-fault and invalid-target counters are incorrect");
  }

  std::printf(
      "fault-walk enabled: two host faults and two invalid targets tolerated in one process; "
      "unique=%u hits=%llu "
      "suppressed=%llu\n",
      totals.unique_faults, static_cast<unsigned long long>(totals.total_fault_hits),
      static_cast<unsigned long long>(totals.total_suppressed_invocations));
  return 0;
#endif
}
