// Small scheduler integration driver using production codegen dependency/cache
// functions. Synthetic bytes model base-only and patched image identities;
// real XEX loading is covered by the separately supplied private integration run.
#include <rex/codegen/output_stamp.h>
#include <rex/hash.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>

namespace fs = std::filesystem;
using namespace rex::codegen;

std::string Read(const fs::path& path) {
  std::ifstream file(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(file), {}};
}

int main(int argc, char** argv) {
  if (argc != 2)
    return 2;
  const fs::path root = fs::absolute(argv[1]);
  auto inputs = ExecutableInputPaths(root / "inputs/module.xex");
  const auto tool = CodegenImplementationPaths();
  if (tool.empty())
    return 3;
  inputs.insert(inputs.end(), tool.begin(), tool.end());
  const auto fingerprint = ComputeInputFingerprint(inputs, "fixture", {});
  if (fingerprint.empty())
    return 4;
  const auto output = root / "output";
  fs::create_directories(output);
  const auto stamp = OutputStamp::Load(output / "codegen.stamp");
  if (!stamp || !OutputsAreUpToDate(*stamp, fingerprint, output)) {
    const auto image = Read(root / "inputs/module.xex") + Read(root / "inputs/module.xexp");
    std::ofstream(output / "image.identity") << rex::hash_bytes(image);
    std::ofstream(output / "codegen.stamp")
        << OutputStamp{fingerprint, {"image.identity"}}.Serialize();
    std::ofstream(root / "generations", std::ios::app) << "generate\n";
  }
  std::ofstream(root / "invocations", std::ios::app) << "invoke\n";
  if (!WriteInputDependencies(output / "codegen.inputs.cmake", inputs))
    return 6;
  if (!WriteDepfile(output / "codegen.d", output / "codegen.build.stamp",
                    ExistingInputDependencies(inputs)))
    return 5;
  std::ofstream(output / "codegen.build.stamp") << fingerprint;
  return 0;
}
