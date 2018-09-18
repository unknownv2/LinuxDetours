#include <limits.h>
#include "gtest/gtest.h"
#include <detours.h>

namespace {

    unsigned int TestDetourB(unsigned int seconds, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e)
    {
        return seconds + 1;
    }
    unsigned int TestDetourA(unsigned int seconds, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e, unsigned int f, unsigned int g, unsigned int h)
    {
        return TestDetourB(seconds + 2, a, b, c, d, e);
    }
    bool HookTest()
    {
        LhBarrierProcessAttach();

        LhCriticalInitialize();

        LONG selfHandle = 0;
        TRACED_HOOK_HANDLE outHandle = new HOOK_TRACE_INFO();
        LhInstallHook((void*)TestDetourB, (void*)TestDetourA, &selfHandle, outHandle);

        return true;
    }
}
