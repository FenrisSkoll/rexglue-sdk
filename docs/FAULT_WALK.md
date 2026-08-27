# Experimental generated-function fault walker

The ReXGlue fault walker is a Windows-only diagnostic mode for harvesting more
than one recoverable generated PPC failure in a single process. It is
intentionally incorrect execution and is compiled out unless the generated-code
consumer defines `REXGLUE_ENABLE_FAULT_WALK`.

Normal builds retain the original generated function body and have no
fault-walk checkpoint, TLS-stack, poison-table, or synthetic-return overhead.

## Boundary architecture

In an enabled build, each generated `__imp__<function>` is a wrapper around a
private generated body. The existing weak public alias remains intact, so title
strong hooks continue to override generated functions exactly as before. This
boundary covers direct generated calls, indirect dispatch, thread entrypoints,
and other host-dispatched guest calls that resolve to generated functions.

`FaultWalkInvoke` maintains a per-host-thread generated-function stack. Each
entry copies the complete current `PPCContext` into reusable TLS storage. A
Windows SEH boundary around the private body accepts only:

- `0xC0000005` — `ACCESS_VIOLATION`
- `0xC0000094` — `INTEGER_DIVIDE_BY_ZERO`

The native exception instruction must be in the same host module as the
generated body. Software-raised guest exceptions and faults in imported
ReXGlue/host modules therefore continue searching. Unknown exceptions,
breakpoints, single-step exceptions, stack overflow, fail-fast, heap corruption,
and C++ exceptions are never accepted.

Generated Xbox/XEX SEH metadata takes precedence. A fault walker filter will
continue searching if the current generated call stack contains a guest
exception scope. This lets the existing generated guest handler see the
original exception before any diagnostic poison decision. An explicit `NORMAL`
policy is protected the same way.

On an accepted fault, the innermost TLS entry is recorded and its entire entry
`PPCContext` is restored. The default policy then sets `r3=0` and returns from
that generated invocation. The function is poisoned process-wide, so later
calls apply the configured policy without executing the body or raising another
Windows exception.

Guest setjmp/longjmp records the destination TLS depth. Windows `longjmp`
unwinds each wrapper's SEH `__finally`, allowing its ordinary `LeaveFrame` to
run in order. The generated setjmp expression reconciles the resulting depth
only after control reaches the destination; pre-adjusting the depth would make
those unwind callbacks corrupt the diagnostic stack.

After the generated-boundary mechanism was proven independently, v1 also gained
one deliberately narrow `REX_FATAL` integration: an invalid/unregistered
indirect dispatch target may be recorded, poisoned by target address, and
returned from with the configured synthetic result. The exact original fatal
message is retained in the report. This path is active only after an enabled
generated wrapper initializes fault walking; normal builds still execute the
original `REX_FATAL`. No other fatal condition is intercepted.

## Policies

The v1 policy representation supports:

- `NORMAL`
- `RETURN_R3_ZERO`
- `RETURN_R3_ONE`
- `STOP`

New allowlisted faults initially select `RETURN_R3_ZERO`. Runtime diagnostic
code may change a recorded function through `SetFaultWalkPolicy`.

## Guardrails and configuration

The following environment variables are read on first use:

- `REXGLUE_FAULT_WALK_MAX_UNIQUE` (default `32`)
- `REXGLUE_FAULT_WALK_MAX_TOTAL_SUPPRESSIONS` (default `1000000`)
- `REXGLUE_FAULT_WALK_MAX_FUNCTION_SUPPRESSIONS` (default `250000`)
- `REXGLUE_FAULT_WALK_REPORT` (default `rexglue-fault-walk-report.json`)

Reaching a guardrail writes the current JSON report, prints the complete
summary, flushes logging, and aborts conspicuously. JSON is also refreshed after
every unique fault and at suppression milestones so evidence normally survives
a later forced process termination.

## Critical limitation

Fault walking restores `PPCContext` only.

**Guest-memory writes performed before an accepted fault are not rolled back.**
Those writes remain visible, and later faults may therefore be secondary or
corruption-induced. Fault-walk output is diagnostic evidence, never a
correctness result or a permanent fix.
