#include <cstdio>
#include "detours.h"


static unsigned int(WINAPI * TrueSleepEx)(unsigned int seconds) = sleep;

unsigned int WINAPI TimedSleepEx(unsigned int seconds)
{
	DWORD ret = TrueSleepEx(seconds);

	return ret;
}

unsigned int WINAPI TestDetourA(unsigned int seconds)
{
	printf("Detoured B -> A\n");
	return seconds + 2;
}
unsigned int WINAPI TestDetourB(unsigned int seconds)
{
	return seconds + 1;
}

VOID* WINAPI TestSleep(void*)
{
	printf("\n");
	fflush(stdout);

	printf("detours: TestDetourB returned %d\n", TestDetourB(1));
	printf("detours: Calling sleep for 1 second.\n");
	sleep(1);
	printf("detours: Calling sleep again for 1 second.\n");
	sleep(1);

	printf("detours: Done sleeping.\n\n");

	return NULL;
}
int main()
{
	LhBarrierProcessAttach();

	LhCriticalInitialize();

	LONG selfHandle = NULL;
	TRACED_HOOK_HANDLE outHandle = new HOOK_TRACE_INFO();

	//sleep(1);
	//LhInstallHook((void*)TestDetourB, (void*)TestDetourA, &selfHandle, outHandle);
	LhInstallHook((void*)TrueSleepEx, (void*)TimedSleepEx, &selfHandle, outHandle);
	ULONG ret = LhSetExclusiveACL(new ULONG[1]{ 0 }, 1, (TRACED_HOOK_HANDLE)outHandle);
	pthread_t t;
	pthread_create(&t, NULL, TestSleep, NULL);
	pthread_join(t, NULL);
	LhUninstallHook(outHandle);

	delete outHandle;

	sleep(1);

    return 0;
}