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

#if defined(_ARM64_)

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
#endif
#if defined(_ARM_)

void test_generic_constraints(int var, int var32, long var64) {

    asm("ldr %0, %1" : "=r"(var32) : "m"(var));
    asm("ldr %0, [%1]" : "=r"(var64) : "r"(&var));
    asm("ldr r0, label_1;"
        "b label_2;"
        "bl label_2;"
        "nop;"
        "label_1:"
        ".word 0x01020304;"
        "label_2:"
        "mov r0, 0;"
        "mov r1, 1;"
        "mov r2, 2;"
        "dmb ish;"
        "bx lr;"
    );

    // CHECK: call i32 asm "ldr $0, $1", "=r,*m"(i64* @var)
    // CHECK: call i64 asm "ldr $0, [$1]", "=r,r"(i64* @var)
}
void test_generic_constraints_dest(int var, int var32, long var64) {

    asm("ldr %0, %1" : "=r"(var32) : "m"(var));
    asm("ldr %0, [%1]" : "=r"(var64) : "r"(&var));
    asm("ldr r0, label_11;"
        "b label_21;"
        "bl label_21;"
        "nop;"
        "label_11:"
        ".word 0x01020304;"
        "label_21:"
        "mov r0, 0;"
        "mov r1, 1;"
        "mov r2, 2;"
        "dmb ish;"
        "bx lr;"
    );

    // CHECK: call i32 asm "ldr $0, $1", "=r,*m"(i64* @var)
    // CHECK: call i64 asm "ldr $0, [$1]", "=r,r"(i64* @var)
}
#endif
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


/*#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
namespace spd = spdlog;
*/
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
int temp = 4;
int s_temp[0x20] = { 0 };

int main(int argc, char * argv[])
{
    //__float128 ss = 128.0;
    //TestDetourA(2, 3, 4,5,6,7);
    //int as = rotateRight(0x1b, 0x14);
    //int ass = rotateLeft(0x1b, 0x14);

    //test1d(1.0, 2.0,3.0);

    //test_trampoline();
    //auto console = spd::stdout_color_mt("console");
    //console->info("Welcome to spdlog!");
    //console->error("Some error message with arg{}..", 1);

    test_glog(argv[0]);

    //test_generic_constraints(s_temp[6], 1, 2);
    DetourBarrierProcessAttach();

    DetourCriticalInitialize();

    LONG selfHandle = 0;
    LONG selfHandle2 = 0;
    TRACED_HOOK_HANDLE outHandle = new HOOK_TRACE_INFO();
    TRACED_HOOK_HANDLE outHandle2 = new HOOK_TRACE_INFO();
    
    //sleep(1);
    //DetourInstallHook((void*)DetourUpdateThread, (void*)DetDetourUpdateThread, &selfHandle2, outHandle2);
    
#ifdef DETOURS_ARM
#ifdef DETOURS_ARM32
    // BL XXX instruction
    DetourInstallHook((unsigned char*)test_generic_constraints + 0x30,
        (void*)test_generic_constraints_dest, &selfHandle2, outHandle2);
    // B XXX instruction
    DetourInstallHook((unsigned char*)test_generic_constraints + 0x2C,
        (void*)DetourSetSystemRegionLowerBound_detour, &selfHandle2, outHandle2);
    // LDR r0, [PC + XXX] instruction
    DetourInstallHook((unsigned char*)test_generic_constraints + 0x28,
        (void*)DetourSetSystemRegionLowerBound_detour, &selfHandle2, outHandle2);
#else
    // B XXX instruction
    DetourInstallHook((unsigned char*)test_generic_constraints + 0x20, 
        (void*)DetourSetSystemRegionLowerBound_detour, &selfHandle2, outHandle2);
    // LDR r0, [PC + XXX] instruction
    DetourInstallHook((unsigned char*)test_generic_constraints + 0x1C, 
        (void*)DetourSetSystemRegionLowerBound_detour, &selfHandle2, outHandle2);
#endif
#endif

    DetourInstallHook((void*)TestDetourB, (void*)TestDetourA, &selfHandle, outHandle);
    DetourInstallHook((void*)sleep, (void*)sleep_detour, &selfHandle2, outHandle2);

    ULONG ret = DetourSetExclusiveACL(new ULONG(), 1, (TRACED_HOOK_HANDLE)outHandle);
    ret = DetourSetExclusiveACL(new ULONG(), 1, (TRACED_HOOK_HANDLE)outHandle2);

    pthread_t t;
    pthread_create(&t, NULL, TestSleep, NULL);
    pthread_join(t, NULL);


    DetourUninstallHook(outHandle);
    DetourUninstallHook(outHandle2);

    delete outHandle;
    delete outHandle2;

    sleep(1);

    DetourBarrierProcessDetach();
    DetourCriticalFinalize();

    return 0;
}