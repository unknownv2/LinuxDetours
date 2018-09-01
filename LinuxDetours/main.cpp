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

extern "C" {
	extern void(*trampoline_template_thumb)();
	extern void* trampoline_data_thumb;
#if defined(_ARM64_)
	extern void* trampoline_data_arm_64;
#endif
}


__attribute__((naked)) void trampoline_template_arm64()
{
	asm(
		"NETIntro:        /* .NET Barrier Intro Function */;"
		"        .8byte 0;"
		"OldProc:        /* Original Replaced Function */;"
		"        .8byte 0;"
		"NewProc:        /* Detour Function */;"
		"        .8byte 0;"
		"NETOutro:       /* .NET Barrier Outro Function */;"
		"        .8byte 0;"
		"IsExecutedPtr:  /* Count of times trampoline was executed */;"
		"        .8byte 0;"

		"start:;"
		"stp     x29, x30, [sp, #-16]!;"
		"mov     x29, sp;"
		"sub     sp, sp, #(10*8 + 8*16);"
		"stp     q0, q1, [sp, #(0*16)];"
		"stp     q2, q3, [sp, #(2*16)];"
		"stp     q4, q5, [sp, #(4*16)];"
		"stp     q6, q7, [sp, #(6*16)];"
		"stp     x0, x1, [sp, #(8*16+0*8)];"
		"stp     x2, x3, [sp, #(8*16+2*8)];"
		"stp     x4, x5, [sp, #(8*16+4*8)];"
		"stp     x6, x7, [sp, #(8*16+6*8)];"
		"str     x8,     [sp, #(8*16+8*8)]            ;"

		" ldr     x10, IsExecutedPtr            ;"
		"try_inc_lock:       ;"
		"ldxr    w0, [x10];"
		"add     w0, w0, #1;"
		"stxr    w1, w0, [x10];"
		"cbnz    w1, try_inc_lock;"
		"ldr     x1, NewProc;"
		"cbnz    x1, CALL_NET_ENTRY;"
		"/* call original method  */    ;"
		"try_dec_lock:; "
		"ldxr    w0, [x10];"
		"add     w0, w0, #-1;"
		"stxr    w1, w0, [x10];"
		"cbnz    x1, try_dec_lock;"
		"ldr     x10, OldProc;"
		"b       TRAMPOLINE_EXIT        ;"
		"/* call hook handler or original method... */ ; "
		"CALL_NET_ENTRY: ;"

		"adr     x0, start /* call NET intro */;"
		"add     x2, sp, #(10*8 + 8*16) + 8 /* original sp (address of return address)*/;"
		"ldr     x1, [sp, #(10*8 + 8*16) + 8] /* return address (value stored in original sp) */;"
		"ldr     x10, NETIntro  ;"
		"blr     x10 /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/;"
		"/* should call original method?      */        ;"
		"cbnz    x0, CALL_HOOK_HANDLER;"

		"/* call original method */;"
		"ldr     x10, IsExecutedPtr;"
		"try_dec_lock2:        ;"
		"ldxr    w0, [x10];"
		"add     w0, w0, #-1;"
		"stxr    w1, w0, [x10];"
		"cbnz    w1, try_dec_lock2;"

		" ldr     x10, OldProc;"
		"b       TRAMPOLINE_EXIT;"
		"CALL_HOOK_HANDLER:; "

		"/* call hook handler        */;"
		"ldr     x10, NewProc;"
		"adr     x4, CALL_NET_OUTRO /*adjust return address */;"
		"str     x4, [sp, #(10*8 + 8*16) + 8] /* store outro return to stack after hook handler is called     */    ;"
		"b       TRAMPOLINE_EXIT;"
		"/* this is where the handler returns... */;"
		"CALL_NET_OUTRO:; "
		"mov     x10, #0;"
		"sub     sp, sp, #(10*8 + 8*16);"
		"stp     q0, q1, [sp, #(0*16)];"
		"stp     q2, q3, [sp, #(2*16)];"
		"stp     q4, q5, [sp, #(4*16)];"
		"stp     q6, q7, [sp, #(6*16)];"
		"stp     x0, x1, [sp, #(8*16+0*8)];"
		"stp     x2, x3, [sp, #(8*16+2*8)];"
		"stp     x4, x5, [sp, #(8*16+4*8)];"
		"stp     x6, x7, [sp, #(8*16+6*8)];"
		"stp     x8, x10,[sp, #(8*16+8*8)]    /* save return handler */;"

		"add     x1, sp, #(8*16+9*8)      /* Param 2: Address of return address */;"
		"adr     x0, start;"

		"ldr     x10, NETOutro;"
		"blr     x10       /* Hook->NETOutro(Hook, InAddrOfRetAddr)*/;"

		" ldr     x10, IsExecutedPtr ;"
		"try_dec_lock3:        ;"
		"ldxr    w0, [x10];"
		"add     w0, w0, #-1;"
		"stxr    w1, w0, [x10];"
		"cbnz    w1, try_dec_lock3;"

		"ldp     q0, q1, [sp, #(0*16)];"
		"ldp     q2, q3, [sp, #(2*16)];"
		"ldp     q4, q5, [sp, #(4*16)];"
		"ldp     q6, q7, [sp, #(6*16)];"
		"ldp     x0, x1, [sp, #(8*16+0*8)];"
		"ldp     x2, x3, [sp, #(8*16+2*8)];"
		"ldp     x4, x5, [sp, #(8*16+4*8)];"
		"ldp     x6, x7, [sp, #(8*16+6*8)];"
		"ldp     x8, x30,[sp, #(8*16+8*8)];"
		"add     sp, sp, #(10*8 + 8*16);"

		"/* finally return to saved return address - the caller of this trampoline...  */       ;"
		"ret;"

		"TRAMPOLINE_EXIT:;"
		"ldp     q0, q1, [sp, #(0*16)];"
		"ldp     q2, q3, [sp, #(2*16)];"
		"ldp     q4, q5, [sp, #(4*16)];"
		"ldp     q6, q7, [sp, #(6*16)];"
		"ldp     x0, x1, [sp, #(8*16+0*8)];"
		"ldp     x2, x3, [sp, #(8*16+2*8)];"
		"ldp     x4, x5, [sp, #(8*16+4*8)];"
		"ldp     x6, x7, [sp, #(8*16+6*8)];"
		"ldr     x8,     [sp, #(8*16+8*8)];"
		"mov     sp, x29;"
		"ldp     x29, x30, [sp], #16;"
		"br      x10;"
		"trampoline_data_arm_64:"
		".global trampoline_data_arm_64;"
		".word 0x12345678;"
		
		"ret"); /* Basic assembler statements are supported. */
}

void* trampoline_template(void* chained) {
	uintptr_t ret = 0;
#if defined(_ARM64_)
	ret = reinterpret_cast<uintptr_t>(&trampoline_template_arm64) + (5 * sizeof(PVOID));
#endif
	asm("" : "=rm"(ret)); // force compiler to abandon its assumption that ret is aligned
	ret &= ~1;
	return reinterpret_cast<void*>(ret);
}
void* trampoline_data(void* chained) {
#if defined(_ARM64_)
	return (&trampoline_data_arm_64);
#endif

	return nullptr;
}

long var;

void test_generic_constraints(int var32, long var64) {
	asm("add %0, %1, %1" : "=r"(var32) : "0"(var32));
	// CHECK: [[R32_ARG:%[a-zA-Z0-9]+]] = load i32, i32*
	// CHECK: call i32 asm "add $0, $1, $1", "=r,0"(i32 [[R32_ARG]])

	asm("add %0, %1, %1" : "=r"(var64) : "0"(var64));
	// CHECK: [[R32_ARG:%[a-zA-Z0-9]+]] = load i64, i64*
	// CHECK: call i64 asm "add $0, $1, $1", "=r,0"(i64 [[R32_ARG]])

	asm("ldr %0, %1" : "=r"(var32) : "m"(var));
	asm("ldr %0, [%1]" : "=r"(var64) : "r"(&var));
	// CHECK: call i32 asm "ldr $0, $1", "=r,*m"(i64* @var)
	// CHECK: call i64 asm "ldr $0, [$1]", "=r,r"(i64* @var)
}
void test_generic_constraints2(int var32, long var64) {
	asm("add x0, x1, x1");
	// CHECK: [[R32_ARG:%[a-zA-Z0-9]+]] = load i32, i32*
	// CHECK: call i32 asm "add $0, $1, $1", "=r,0"(i32 [[R32_ARG]])

	asm("add %0, %1, %1" : "=r"(var64) : "0"(var64));
	// CHECK: [[R32_ARG:%[a-zA-Z0-9]+]] = load i64, i64*
	// CHECK: call i64 asm "add $0, $1, $1", "=r,0"(i64 [[R32_ARG]])

	asm("ldr %0, %1" : "=r"(var32) : "m"(var));
	asm("ldr %0, [%1]" : "=r"(var64) : "r"(&var));
	// CHECK: call i32 asm "ldr $0, $1", "=r,*m"(i64* @var)
	// CHECK: call i64 asm "ldr $0, [$1]", "=r,r"(i64* @var)
}
__attribute__((naked)) long add(); /* Declaring a function with __attribute__((naked)). */

__attribute__((naked)) long add()
{
	asm("mov w0, #1;"
		"ret"); /* Basic assembler statements are supported. */
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
void test_trampoline()
{
	void* chained = (void*)2;
	uint32_t code_size_ = reinterpret_cast<uintptr_t>(trampoline_data(chained)) -
		reinterpret_cast<uintptr_t>(trampoline_template(chained));

	printf("Trampoline size is %llx\n", code_size_);

}
int main()
{
	//__float128 ss = 128.0;
	//TestDetourA(2, 3, 4,5,6,7);
	//int as = rotateRight(0x1b, 0x14);
	//int ass = rotateLeft(0x1b, 0x14);

	//test1d(1.0, 2.0,3.0);

	test_trampoline();

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