#include <limits.h>
#include "gtest/gtest.h"
#include "hook.h"



//TEST(testHook, myHookTest) {

  //  EXPECT_EQ(true, HookTest());
//}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}