#include <cstdio>
#include "detours.h"


static unsigned int(WINAPI * TrueSleepEx)(unsigned int seconds) = sleep;

unsigned int WINAPI TimedSleepEx(unsigned int seconds)
{
	DWORD ret = TrueSleepEx(seconds);

	return ret;
}
unsigned int WINAPI TestDetourB(unsigned int seconds)
{
	return seconds + 1;
}
unsigned int WINAPI TestDetourA(unsigned int seconds)
{
	printf("Detoured B -> A\n");
	return TestDetourB(seconds + 2);
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
float test2(float a1, float a2, float a3)
{
	return a1 + a2 * a3;
}
float test1(float a1, float a2, float a3)
{
	float a4 = a1 + a2 * a3;
	return test2(a4, a2, a1);
}
double test2d(double a1, double a2, double a3)
{
	return a1 + a2 * a3;
}
double test1d(double a1, double a2, double a3)
{
	float a4 = a1 + a2 * a3;
	return test2d(a4, a2, a1);
}
int main()
{

	TestDetourA(2);
	test1d(1.0, 2.0,3.0);

	LhBarrierProcessAttach();

	LhCriticalInitialize();

	LONG selfHandle = 0;
	TRACED_HOOK_HANDLE outHandle = new HOOK_TRACE_INFO();

	//sleep(1);
	LhInstallHook((void*)TestDetourB, (void*)TestDetourA, &selfHandle, outHandle);
	//LhInstallHook((void*)TrueSleepEx, (void*)TimedSleepEx, &selfHandle, outHandle);
	ULONG ret = LhSetExclusiveACL(new ULONG(), 1, (TRACED_HOOK_HANDLE)outHandle);
	pthread_t t;
	pthread_create(&t, NULL, TestSleep, NULL);
	pthread_join(t, NULL);
	LhUninstallHook(outHandle);

	delete outHandle;

	sleep(1);

	return 0;
}