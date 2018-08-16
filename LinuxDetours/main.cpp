#include <cstdio>
#include "detours.h"


static unsigned int(WINAPI * TrueSleepEx)(unsigned int seconds) = sleep;

unsigned int WINAPI TimedSleepEx(unsigned int seconds)
{
	DWORD ret = sleep(seconds);

	return ret;
}
unsigned int WINAPI TestDetourB(unsigned int seconds, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e)
{
	return seconds + 1;
}
unsigned int WINAPI TestDetourA(unsigned int seconds, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e, unsigned int f, unsigned int g, unsigned int h)
{
	printf("Detoured B -> A %d %d %d %d %d %d\n", a, b, c, d, e);
	return TestDetourB(seconds + 2, a, b, c, d, e);
}

VOID* WINAPI TestSleep(void*)
{
	printf("\n");
	fflush(stdout);
	printf("detours: TestDetourB returned %d\n", TestDetourB(1, 2, 3, 4, 5, 6));
	printf("detours: Calling sleep for 1 second.\n");
	sleep(1);
	printf("detours: Calling sleep again for 1 second.\n");
	sleep(2);
	
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
LONG DetDetourUpdateThread(pthread_t threadId)
{
	return DetourUpdateThread(threadId);
}
#define BITS 32

int rotateRight(int num, int by)
{
	return (num >> by) | (num << (BITS - by));
}
int rotateLeft(int num, int by)
{
	return (num << by) | (num >> (BITS - by));
}
int main()
{
	//__float128 ss = 128.0;
	//TestDetourA(2, 3, 4,5,6,7);
	//int as = rotateRight(0x1b, 0x14);
	//int ass = rotateLeft(0x1b, 0x14);

	//test1d(1.0, 2.0,3.0);
	
	LhBarrierProcessAttach();

	LhCriticalInitialize();
	
	LONG selfHandle = 0;
	LONG selfHandle2 = 0;
	TRACED_HOOK_HANDLE outHandle = new HOOK_TRACE_INFO();
	TRACED_HOOK_HANDLE outHandle2 = new HOOK_TRACE_INFO();
	
	//sleep(1);
	//LhInstallHook((void*)DetourUpdateThread, (void*)DetDetourUpdateThread, &selfHandle2, outHandle2);
	
	LhInstallHook((void*)sleep, (void*)TimedSleepEx, &selfHandle2, outHandle2);
	
	LhInstallHook((void*)TestDetourB, (void*)TestDetourA, &selfHandle, outHandle);
	ULONG ret = LhSetExclusiveACL(new ULONG(), 1, (TRACED_HOOK_HANDLE)outHandle);
	ret = LhSetExclusiveACL(new ULONG(), 1, (TRACED_HOOK_HANDLE)outHandle2);

	pthread_t t;
	pthread_create(&t, NULL, TestSleep, NULL);
	pthread_join(t, NULL);


	LhUninstallHook(outHandle);
	LhUninstallHook(outHandle2);

	delete outHandle;
	delete outHandle2;

	sleep(1);

	LhBarrierProcessDetach();
	LhCriticalFinalize();

	return 0;
}