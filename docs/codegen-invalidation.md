# Incremental codegen inputs

Codegen has two gates: the build scheduler and `codegen.stamp` content identity.
Both must observe an executable's sibling patch, even when it was absent during
the preceding build. `UserModule::LoadFromFile` looks up the resolved XEX path
with `p` appended; `ExecutableInputPaths` mirrors that tool-mode filesystem
lookup. Every loaded module's executable inputs participate because modules
share the export resolver.

`ProjectRecompiler` emits:

* `codegen.d`: existing files read by codegen, consumed by CMake's `DEPFILE`.
* `codegen.inputs.cmake`: exact-path `CONFIGURE_DEPENDS` globs, included by the
  generated build glue. These detect optional input creation and removal.
* `codegen.stamp`: content hashes of inputs, flags, templates, actual host tool
  executable and the actual loaded runtime library; missing inputs have a
  distinct marker. Unreadable/ambiguous identities fail closed.
* `codegen.build.stamp`: scheduler completion, written after successful work.

The generated glue also explicitly depends on `rex::rexglue`. The stable SDK
channel string is retained as configuration information, but is not trusted as
the tool implementation identity. The loaded runtime path comes from the OS
loader, not a guessed install path. No runtime or guest loading behavior changes.

Directory timestamps alone are insufficient for detecting patch creation with
Windows Ninja. Missing-file depfile entries are also unsuitable: they schedule
codegen forever while the optional input is absent. The small CMake glob check
does not execute codegen on unchanged builds. Metadata is written only when its
content changes, and an already matching manifest SDK stamp preserves bytes and
mtime.

After upgrading an existing installation, run codegen once to refresh generated
build glue and dependency metadata. Thereafter ordinary builds maintain both
gates. If dependency metadata is subsequently deleted, configuration fails closed with
instructions to restore it via direct codegen, rather than disabling watches.
The scheduler follows normal CMake/Ninja filesystem change detection;
deliberately restoring all timestamps after modifying files is outside that
contract. Direct CLI invocations always compare content identities.

Validation (Windows developer environment):

```powershell
cmake --build --preset win-amd64-release --target rexglue unit_tests codegen_dependency_fixture
./out/win-amd64/Release/unit_tests.exe '[output_stamp]'
ctest --preset win-amd64-release -R codegen_dependency_scheduler --output-on-failure
```

The scheduler integration uses synthetic base/patch bytes with production input,
fingerprint and depfile functions. It checks invocation and regeneration counts,
changed image identity, removal, re-addition and no-op controls, including a
workspace containing spaces. It does not purport to parse synthetic bytes as an
XEX. Real private XEX/XEXP loader/codegen integration can be tested separately
without redistributing executable fixtures. POSIX loader-path discovery is
implemented but this closeout's execution coverage is Windows/Ninja.
