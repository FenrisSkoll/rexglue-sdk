#include <rex/fault_walk.h>
#include <rex/platform/env.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>

#include <windows.h>

namespace {

constexpr uint32_t kInvalidDispatchOne = 0x8200A000;
constexpr uint32_t kInvalidDispatchTwo = 0x8200B000;

__attribute__((noinline)) uint32_t CauseAccessViolation() {
  return *reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(0x18));
}

bool HostAccessViolationPropagates(PPCContext& ctx) {
  bool caught = false;
  __try {
    ctx.r3.u64 = CauseAccessViolation();
  } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER
                                                               : EXCEPTION_CONTINUE_SEARCH) {
    caught = true;
  }
  return caught;
}

int Fail(const char* message) {
  std::fprintf(stderr, "fault_walk_dispatch_test: %s\n", message);
  return 1;
}

void SetInvalidContext(PPCContext& ctx, uint8_t pattern, uint32_t target, uint32_t lr) {
  const uint32_t host_fpscr = ctx.fpscr.getcsr();
  std::memset(&ctx, pattern, sizeof(ctx));
  ctx.fpscr.csr = host_fpscr;
  ctx.last_indirect_target = target;
  ctx.lr = lr;
  ctx.ctr.u32 = target;
}

}  // namespace

int main() {
  rex::platform::env::set("REXGLUE_FAULT_WALK_REPORT", "fault-walk-dispatch-synthetic-report.json");
  rex::platform::env::set("REXGLUE_FAULT_WALK_MAX_UNIQUE", "32");
  rex::diagnostics::InitializeFaultWalk(rex::diagnostics::FaultWalkMode::DispatchOnly);
  rex::diagnostics::ResetFaultWalkStateForTesting();

  if (rex::diagnostics::GetFaultWalkMode() != rex::diagnostics::FaultWalkMode::DispatchOnly) {
    return Fail("DISPATCH_ONLY mode was not activated");
  }

  PPCContext ctx{};
  if (!HostAccessViolationPropagates(ctx)) {
    return Fail("DISPATCH_ONLY swallowed a host ACCESS_VIOLATION");
  }

  SetInvalidContext(ctx, 0xA1, kInvalidDispatchOne, 0x8200C004);
  if (!rex::diagnostics::FaultWalkHandleInvalidFunction(ctx) || ctx.r3.u64 != 0) {
    return Fail("first invalid target was not tolerated with r3=0");
  }

  SetInvalidContext(ctx, 0xA2, kInvalidDispatchOne, 0x8200C004);
  if (!rex::diagnostics::FaultWalkHandleInvalidFunction(ctx) || ctx.r3.u64 != 0) {
    return Fail("poisoned invalid target was not suppressed with r3=0");
  }

  SetInvalidContext(ctx, 0xB1, kInvalidDispatchTwo, 0x8200D004);
  if (!rex::diagnostics::FaultWalkHandleInvalidFunction(ctx) || ctx.r3.u64 != 0) {
    return Fail("second invalid target was not tolerated in the same process");
  }

  const auto totals = rex::diagnostics::GetFaultWalkStats();
  if (totals.mode != rex::diagnostics::FaultWalkMode::DispatchOnly || totals.unique_faults != 2 ||
      totals.total_fault_hits != 2 || totals.total_suppressed_invocations != 1) {
    return Fail("DISPATCH_ONLY counters are incorrect");
  }

  rex::diagnostics::WriteFaultWalkReport();
  std::ifstream report("fault-walk-dispatch-synthetic-report.json");
  const std::string report_text((std::istreambuf_iterator<char>(report)),
                                std::istreambuf_iterator<char>());
  if (!report || report_text.find("\"mode\": \"DISPATCH_ONLY\"") == std::string::npos ||
      report_text.find("0x8200A000") == std::string::npos ||
      report_text.find("0x8200B000") == std::string::npos) {
    return Fail("DISPATCH_ONLY report did not retain exact compact events");
  }

  std::puts(
      "fault-walk DISPATCH_ONLY: two invalid targets tolerated; host AV propagation preserved");
  return 0;
}
