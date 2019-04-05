#include <cstdio>
#include "detours.h"
#include <glog/logging.h>

unsigned int sleep_detour(unsigned int seconds)
{
    LOG(INFO) << ("called sleep_detour.\n");
    DWORD ret = sleep(seconds);

    return ret;
}
unsigned int TestDetourB(unsigned int seconds, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e)
{
    LOG(INFO) << ("called TestDetourB.\n");
    return seconds + 1;
}
unsigned int TestDetourA(unsigned int seconds, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e, unsigned int f, unsigned int g, unsigned int h)
{
    LOG(INFO) << "Detoured B -> A: " << a << ", " << b << ", " << c << ", " << d << ", " << e;
    return TestDetourB(seconds + 2, a, b, c, d, e);
}

VOID* TestSleep(void*)
{
    LOG(INFO) << "detours: TestDetourB returned " << TestDetourB(1, 2, 3, 4, 5, 6);
    LOG(INFO) << "detours: Calling sleep for 1 second.";
    sleep(1);
    LOG(INFO) << "detours: Calling sleep again for 2 seconds.";
    sleep(2);
    
    LOG(INFO)  << ("detours: Done sleeping.\n\n");
    
    return NULL;
}

int test_glog(char * argv)
{
    google::InitGoogleLogging(argv);
    FLAGS_logtostderr = true;

    LOG(INFO) << "Starting detours tests";
    return 1;
}
void* DetourSetSystemRegionLowerBound_detour(void * bound)
{
    LOG(INFO) << "Called DetourSetSystemRegionLowerBound_detour";

    return NULL;
}

int main(int argc, char * argv[])
{
    test_glog(argv[0]);

    DetourBarrierProcessAttach();

    DetourCriticalInitialize();

    LONG test_detour_callback = 0;
    LONG sleep_detour_callback = 0;
    TRACED_HOOK_HANDLE test_detour_handle = new HOOK_TRACE_INFO();
    TRACED_HOOK_HANDLE sleep_detour_handle = new HOOK_TRACE_INFO();    

    DetourInstallHook((void*)TestDetourB, (void*)TestDetourA, &test_detour_callback, test_detour_handle);
    DetourInstallHook((void*)sleep, (void*)sleep_detour, &sleep_detour_callback, sleep_detour_handle);

    ULONG ret = DetourSetExclusiveACL(new ULONG(), 1, (TRACED_HOOK_HANDLE)test_detour_handle);
    ret = DetourSetExclusiveACL(new ULONG(), 1, (TRACED_HOOK_HANDLE)sleep_detour_handle);

    pthread_t t;
    pthread_create(&t, NULL, TestSleep, NULL);
    pthread_join(t, NULL);

    DetourUninstallHook(test_detour_handle);
    DetourUninstallHook(sleep_detour_handle);

    delete test_detour_handle;
    delete sleep_detour_handle;

    sleep(1);

    DetourBarrierProcessDetach();
    DetourCriticalFinalize();

    return 0;
}