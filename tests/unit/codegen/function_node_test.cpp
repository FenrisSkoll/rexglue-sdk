#include <catch2/catch_test_macros.hpp>

#include <rex/codegen/function_node.h>

namespace {

using namespace rex::codegen;

TEST_CASE("function containment preserves out-of-line blocks around a declared range",
          "[codegen][function-node]") {
  FunctionNode node(0x1000, 0x20, FunctionAuthority::PDATA);
  node.discover({Block{0x0F00, 0x10}, Block{0x1000, 0x10}}, {}, {});

  CHECK(node.containsAddress(0x0F00));
  CHECK(node.containsAddress(0x0F0C));
  CHECK_FALSE(node.containsAddress(0x0F10));
  CHECK_FALSE(node.containsAddress(0x0FF0));
  CHECK(node.containsAddress(0x1004));
  CHECK(node.containsAddress(0x101C));
  CHECK_FALSE(node.containsAddress(0x1020));
}

TEST_CASE("function containment keeps exact fragments for discovered functions",
          "[codegen][function-node]") {
  FunctionNode node(0x2000, 0x40, FunctionAuthority::DISCOVERED);
  node.discover({Block{0x2000, 0x10}, Block{0x2030, 0x10}}, {}, {});

  CHECK(node.containsAddress(0x2008));
  CHECK_FALSE(node.containsAddress(0x2010));
  CHECK_FALSE(node.containsAddress(0x202C));
  CHECK(node.containsAddress(0x2030));
}

TEST_CASE("function containment falls back to the declared range without blocks",
          "[codegen][function-node]") {
  FunctionNode node(0x3000, 0x20, FunctionAuthority::DISCOVERED);
  node.discover({}, {}, {});

  CHECK_FALSE(node.containsAddress(0x2FFC));
  CHECK(node.containsAddress(0x3000));
  CHECK(node.containsAddress(0x301C));
  CHECK_FALSE(node.containsAddress(0x3020));

  node.discover({Block{0x2F00, 0x10}}, {}, {});
  CHECK(node.containsAddress(0x2F04));
  CHECK_FALSE(node.containsAddress(0x2F10));
}

}  // namespace
