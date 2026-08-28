/**
 * @file        rex/fault_walk.h
 * @brief       Experimental generated guest-function fault walking
 *
 * Fault walking is diagnostic-only and intentionally violates guest execution
 * semantics. It restores PPCContext after selected host faults, but it cannot
 * roll back guest-memory writes performed before the fault.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include <rex/ppc/context.h>

namespace rex::diagnostics {

enum class FaultWalkMode : uint8_t {
  Off,
  DispatchOnly,
  Full,
};

enum class FaultWalkPolicy : uint8_t {
  Normal,
  ReturnR3Zero,
  ReturnR3One,
  Stop,
};

struct FaultWalkFunctionDescriptor {
  uint32_t guest_address;
  const char* function_name;
  const char* source_file;
  uint32_t source_line;
  bool has_guest_exception_handlers;
  PPCFunc* body;
};

struct FaultWalkStats {
  FaultWalkMode mode;
  uint32_t unique_faults;
  uint32_t poisoned_functions;
  uint64_t total_fault_hits;
  uint64_t total_suppressed_invocations;
};

/**
 * Activates one explicit diagnostic mode for this process.
 *
 * DispatchOnly intercepts only invalid/unregistered FunctionDispatcher
 * targets. It does not wrap generated guest functions and therefore cannot
 * recover host faults. Full additionally enables the generated-function
 * boundary, complete PPCContext checkpoints, nested attribution, and the
 * conservative Windows SEH allowlist.
 *
 * Mode changes may only preserve or increase diagnostic coverage. In
 * particular, a process cannot silently return to Off after activation.
 */
void InitializeFaultWalk(FaultWalkMode mode);
FaultWalkMode GetFaultWalkMode();

struct FaultWalkFunctionStats {
  bool found;
  bool poisoned;
  FaultWalkPolicy policy;
  uint64_t fault_hits;
  uint64_t suppressed_invocations;
};

/**
 * Executes one generated guest body inside the diagnostic boundary.
 *
 * This function is referenced only when REXGLUE_ENABLE_FAULT_WALK is defined
 * by the generated-code consumer. Normal generated builds retain the original
 * direct body and have no fault-walk call or checkpoint overhead.
 */
void FaultWalkInvoke(PPCContext& ctx, uint8_t* base, const FaultWalkFunctionDescriptor& descriptor);

/**
 * Handles the specific invalid/unregistered indirect-dispatch fatal while an
 * DispatchOnly or Full fault-walk process is active. Returns false in normal
 * builds and for an explicit NORMAL policy so the caller preserves the
 * original REX_FATAL.
 */
bool FaultWalkHandleInvalidFunction(PPCContext& ctx);

FaultWalkStats GetFaultWalkStats();
FaultWalkFunctionStats GetFaultWalkFunctionStats(uint32_t guest_address);
bool SetFaultWalkPolicy(uint32_t guest_address, FaultWalkPolicy policy);
void WriteFaultWalkReport();
void PrintFaultWalkSummary();

// Windows longjmp unwinds the generated wrappers' SEH __finally blocks. Record
// the destination depth before setjmp and reconcile it only after setjmp
// returns, so the ordinary LeaveFrame calls run against the live TLS depth.
void FaultWalkCaptureSetJmp(uint32_t guest_buffer_address);
int FaultWalkCompleteSetJmp(uint32_t guest_buffer_address, int setjmp_result);

// Deterministic synthetic tests use this between scenarios. Production code
// should treat fault-walk state as process-lifetime state and never reset it.
void ResetFaultWalkStateForTesting();
uint32_t GetFaultWalkThreadDepthForTesting();

}  // namespace rex::diagnostics

// Keeps the existing generated weak-alias / strong-hook override contract:
// direct calls still name `name`, while the generated implementation remains
// available through `__imp__name`. Only the generated implementation is
// wrapped; a title-provided strong hook continues to override the weak alias.
#define REX_DEFINE_FAULT_WALK_FUNC(name, guest_address, has_guest_seh)                            \
  static REX_FUNC(__rex_fault_walk_body_##name);                                                  \
  __attribute__((alias("__imp__" #name)))                                                        \
  __attribute__((weak, noinline)) extern "C" REX_FUNC(name);                                     \
  REX_EXTERN(__imp__##name) {                                                                     \
    static constexpr ::rex::diagnostics::FaultWalkFunctionDescriptor __rex_fault_walk_descriptor{ \
        static_cast<uint32_t>(guest_address), #name,           __FILE__,                          \
        static_cast<uint32_t>(__LINE__),      (has_guest_seh), __rex_fault_walk_body_##name};     \
    ::rex::diagnostics::FaultWalkInvoke(ctx, base, __rex_fault_walk_descriptor);                  \
  }                                                                                               \
  static REX_FUNC(__rex_fault_walk_body_##name)
