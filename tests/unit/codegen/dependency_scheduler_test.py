"""CMake/Ninja integration of production depfile + fingerprint functions.

Synthetic bytes intentionally avoid private executables. Covers changed/absent
optional files and invocation counts, not merely output timestamps.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    tool = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="rexglue dependencies ") as directory:
        root = Path(directory)
        inputs = root / "inputs"
        inputs.mkdir()
        (inputs / "module.xex").write_bytes(b"base image")
        patch = inputs / "module.xexp"
        patch.write_bytes(b"delta one")
        (root / "CMakeLists.txt").write_text(f'''cmake_minimum_required(VERSION 3.25)
project(dependency_fixture NONE)
file(GLOB _REXGLUE_INPUT_MANIFEST CONFIGURE_DEPENDS "${{CMAKE_CURRENT_SOURCE_DIR}}/output/codegen.inputs.cmake")
include("${{CMAKE_CURRENT_SOURCE_DIR}}/output/codegen.inputs.cmake" OPTIONAL)
if(EXISTS "${{CMAKE_CURRENT_SOURCE_DIR}}/output/codegen.build.stamp"
   AND NOT EXISTS "${{CMAKE_CURRENT_SOURCE_DIR}}/output/codegen.inputs.cmake")
  message(FATAL_ERROR "Missing codegen dependency metadata")
endif()
add_custom_command(
  OUTPUT "${{CMAKE_CURRENT_SOURCE_DIR}}/output/codegen.build.stamp"
  COMMAND "{tool.as_posix()}" "${{CMAKE_CURRENT_SOURCE_DIR}}"
  DEPENDS ${{REXGLUE_CODEGEN_INPUTS}}
  DEPFILE "${{CMAKE_CURRENT_SOURCE_DIR}}/output/codegen.d"
  VERBATIM)
add_custom_target(generate ALL DEPENDS "${{CMAKE_CURRENT_SOURCE_DIR}}/output/codegen.build.stamp")
''')

        def run(*command):
            process = subprocess.run(command, capture_output=True, text=True)
            if process.returncode:
                raise AssertionError(process.stdout + process.stderr)
            return process.stdout + process.stderr

        run("cmake", "-S", str(root), "-B", str(root / "build"), "-G", "Ninja")

        def build(expected, generations=None):
            decision = run("cmake", "--build", str(root / "build"), "--", "-d", "explain")
            for name in ("invocations", "generations"):
                count = expected if name == "invocations" or generations is None else generations
                assert len((root / name).read_text().splitlines()) == count, (name, decision)
            return (root / "output/image.identity").read_text()

        first = build(1)
        assert first == build(1)
        patch.write_bytes(b"delta two")
        second = build(2)
        assert first != second
        assert second == build(2)
        patch.unlink()
        absent = build(3)
        assert absent != second
        assert absent == build(3)
        patch.write_bytes(b"delta two")
        assert second == build(4)
        assert second == build(4)
        (root / "output/codegen.inputs.cmake").unlink()
        failed = subprocess.run(["cmake", "--build", str(root / "build")], capture_output=True, text=True)
        assert failed.returncode != 0
        assert "Missing codegen dependency metadata" in failed.stdout + failed.stderr
        run(str(tool), str(root))  # documented metadata recovery, no retranslation
        # A direct invocation changed the depfile completion time outside Ninja;
        # Ninja imports it once more, but the content gate must not regenerate.
        assert second == build(6, generations=4)
        assert second == build(6, generations=4)
        print(json.dumps({"status": "PASS", "invocations": 6, "generations": 4,
                          "checks": ["XEXP change", "no-op", "remove", "absent no-op", "add", "restored no-op", "metadata repair"]}))


if __name__ == "__main__":
    main()
