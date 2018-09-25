// #define CATCH_CONFIG_MAIN
// #include "catch/catch.hpp"

// TODO(martun): get rid of this.

#include "gtest/gtest.h"

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
