#pragma once
/////////////////////////////////////////////////////////////////////////////
//
//  Core Detours Functionality
//
//

#ifndef _DETOURS_H_
#define _DETOURS_H_

#define DETOURS_VERSION     0x4c0c1   // 0xMAJORcMINORcPATCH

//////////////////////////////////////////////////////////////////////////////
//
#include "types.h"

#undef DETOURS_X64
#undef DETOURS_X86
#undef DETOURS_IA64
#undef DETOURS_ARM
#undef DETOURS_ARM64
#undef DETOURS_BITS
#undef DETOURS_32BIT
#undef DETOURS_64BIT

#if defined(_X86_)
#define DETOURS_X86
#define DETOURS_OPTION_BITS 64

#elif defined(_AMD64_)
#define DETOURS_X64
#define DETOURS_OPTION_BITS 32

#elif defined(_IA64_)
#define DETOURS_IA64
#define DETOURS_OPTION_BITS 32

#elif defined(_ARM_)
#define DETOURS_ARM
#if defined(_ARM32_)
#define DETOURS_ARM32
#endif
#elif defined(_ARM64_)
#define DETOURS_ARM64

#else
#error Unknown architecture (x86, amd64, ia64, arm, arm64)
#endif

#ifdef _UNIX64
#undef DETOURS_32BIT
#define DETOURS_64BIT 1
#define DETOURS_BITS 64
// If all 64bit kernels can run one and only one 32bit architecture.
//#define DETOURS_OPTION_BITS 32
#else
#define DETOURS_32BIT 1
#undef DETOURS_64BIT
#define DETOURS_BITS 32
// If all 64bit kernels can run one and only one 32bit architecture.
//#define DETOURS_OPTION_BITS 32
#endif

#define VER_DETOURS_BITS    DETOUR_STRINGIFY(DETOURS_BITS)
#define DetourExport        __attribute__((visibility("default")))
//////////////////////////////////////////////////////////////////////////////
//

#if (_MSC_VER < 1299)
typedef UINT64 LONG_PTR;
typedef UINT64 ULONG_PTR;
#endif
#define ERROR_INVALID_OPERATION          4317L
#define ERROR_DS_DRA_INVALID_PARAMETER   8437L
#define ERROR_NOT_ENOUGH_MEMORY          8L    // dderror
#define ERROR_INVALID_BLOCK              9L
#define ERROR_INVALID_HANDLE             6L
#define ERROR_INVALID_PARAMETER          87L    // dderror
#define __debugbreak()  
///////////////////////////////////////////////// SAL 2.0 Annotations w/o SAL.
//
//  These definitions are include so that Detours will build even if the
//  compiler doesn't have full SAL 2.0 support.
//
#ifndef DETOURS_DONT_REMOVE_SAL_20

#ifdef DETOURS_TEST_REMOVE_SAL_20
#undef _Analysis_assume_
#undef _Benign_race_begin_
#undef _Benign_race_end_
#undef _Field_range_
#undef _Field_size_
#undef _In_
#undef _In_bytecount_
#undef _In_count_
#undef _In_opt_
#undef _In_opt_bytecount_
#undef _In_opt_count_
#undef _In_opt_z_
#undef _In_range_
#undef _In_reads_
#undef _In_reads_bytes_
#undef _In_reads_opt_
#undef _In_reads_opt_bytes_
#undef _In_reads_or_z_
#undef _In_z_
#undef _Inout_
#undef _Inout_opt_
#undef _Inout_z_count_
#undef _Out_
#undef _Out_opt_
#undef _Out_writes_
#undef _Outptr_result_maybenull_
#undef _Readable_bytes_
#undef _Success_
#undef _Writable_bytes_
#undef _Pre_notnull_
#endif

#if defined(_Deref_out_opt_z_) && !defined(_Outptr_result_maybenull_)
#define _Outptr_result_maybenull_ _Deref_out_opt_z_
#endif

#if defined(_In_count_) && !defined(_In_reads_)
#define _In_reads_(x) _In_count_(x)
#endif

#if defined(_In_opt_count_) && !defined(_In_reads_opt_)
#define _In_reads_opt_(x) _In_opt_count_(x)
#endif

#if defined(_In_opt_bytecount_) && !defined(_In_reads_opt_bytes_)
#define _In_reads_opt_bytes_(x) _In_opt_bytecount_(x)
#endif

#if defined(_In_bytecount_) && !defined(_In_reads_bytes_)
#define _In_reads_bytes_(x) _In_bytecount_(x)
#endif

#ifndef _In_
#define _In_
#endif

#ifndef _In_bytecount_
#define _In_bytecount_(x)
#endif

#ifndef _In_count_
#define _In_count_(x)
#endif

#ifndef _In_opt_
#define _In_opt_
#endif

#ifndef _In_opt_bytecount_
#define _In_opt_bytecount_(x)
#endif

#ifndef _In_opt_count_
#define _In_opt_count_(x)
#endif

#ifndef _In_opt_z_
#define _In_opt_z_
#endif

#ifndef _In_range_
#define _In_range_(x,y)
#endif

#ifndef _In_reads_
#define _In_reads_(x)
#endif

#ifndef _In_reads_bytes_
#define _In_reads_bytes_(x)
#endif

#ifndef _In_reads_opt_
#define _In_reads_opt_(x)
#endif

#ifndef _In_reads_opt_bytes_
#define _In_reads_opt_bytes_(x)
#endif

#ifndef _In_reads_or_z_
#define _In_reads_or_z_
#endif

#ifndef _In_z_
#define _In_z_
#endif

#ifndef _Inout_
#define _Inout_
#endif

#ifndef _Inout_opt_
#define _Inout_opt_
#endif

#ifndef _Inout_z_count_
#define _Inout_z_count_(x)
#endif

#ifndef _Out_
#define _Out_
#endif

#ifndef _Out_opt_
#define _Out_opt_
#endif

#ifndef _Out_writes_
#define _Out_writes_(x)
#endif

#ifndef _Outptr_result_maybenull_
#define _Outptr_result_maybenull_
#endif

#ifndef _Writable_bytes_
#define _Writable_bytes_(x)
#endif

#ifndef _Readable_bytes_
#define _Readable_bytes_(x)
#endif

#ifndef _Success_
#define _Success_(x)
#endif

#ifndef _Pre_notnull_
#define _Pre_notnull_
#endif

#ifdef DETOURS_INTERNAL

#ifndef _Benign_race_begin_
#define _Benign_race_begin_
#endif

#ifndef _Benign_race_end_
#define _Benign_race_end_
#endif

#ifndef _Field_size_
#define _Field_size_(x)
#endif

#ifndef _Field_range_
#define _Field_range_(x,y)
#endif

#ifndef _Analysis_assume_
#define _Analysis_assume_(x)
#endif

#endif // DETOURS_INTERNAL
#endif // DETOURS_DONT_REMOVE_SAL_20

//////////////////////////////////////////////////////////////////////////////
//
#ifndef GUID_DEFINED
#define GUID_DEFINED
typedef struct  _GUID
{
    DWORD Data1;
    WORD  Data2;
    WORD  Data3;
    BYTE  Data4[8];
} GUID;

#ifdef INITGUID
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
        const GUID name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }
#else
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    const GUID name
#endif // INITGUID
#endif // !GUID_DEFINED

#if defined(__cplusplus)
#ifndef _REFGUID_DEFINED
#define _REFGUID_DEFINED
#define REFGUID             const GUID &
#endif // !_REFGUID_DEFINED
#else // !__cplusplus
#ifndef _REFGUID_DEFINED
#define _REFGUID_DEFINED
#define REFGUID             const GUID * const
#endif // !_REFGUID_DEFINED
#endif // !__cplusplus

#ifndef ARRAYSIZE
#define ARRAYSIZE(x)    (sizeof(x)/sizeof(x[0]))
#endif

//
//////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

    /////////////////////////////////////////////////// Instruction Target Macros.
    //
#define DETOUR_INSTRUCTION_TARGET_NONE          ((PVOID)0)
#define DETOUR_INSTRUCTION_TARGET_DYNAMIC       ((PVOID)(LONG_PTR)-1)
#define DETOUR_SECTION_HEADER_SIGNATURE         0x00727444   // "Dtr\0"

    extern const GUID DETOUR_EXE_RESTORE_GUID;
    extern const GUID DETOUR_EXE_HELPER_GUID;

#define DETOUR_TRAMPOLINE_SIGNATURE             0x21727444  // Dtr!
    typedef struct _DETOUR_TRAMPOLINE DETOUR_TRAMPOLINE, *PDETOUR_TRAMPOLINE;

    /////////////////////////////////////////////////////////// Binary Structures.
    //



#define DETOUR_SECTION_HEADER_DECLARE(cbSectionSize) \
{ \
      sizeof(DETOUR_SECTION_HEADER),\
      DETOUR_SECTION_HEADER_SIGNATURE,\
      sizeof(DETOUR_SECTION_HEADER),\
      (cbSectionSize),\
      \
      0,\
      0,\
      0,\
      0,\
      \
      0,\
      0,\
      0,\
      0,\
}

    /////////////////////////////////////////////////////////////// Helper Macros.
    //
#define DETOURS_STRINGIFY(x)    DETOURS_STRINGIFY_(x)
#define DETOURS_STRINGIFY_(x)    #x

    ///////////////////////////////////////////////////////////// Binary Typedefs.
    //
    /*
    typedef BOOL(CALLBACK *PF_DETOUR_BINARY_BYWAY_CALLBACK)(
        _In_opt_ PVOID pContext,
        _In_opt_ LPCSTR pszFile,
        _Outptr_result_maybenull_ LPCSTR *ppszOutFile);

    typedef BOOL(CALLBACK *PF_DETOUR_BINARY_FILE_CALLBACK)(
        _In_opt_ PVOID pContext,
        _In_ LPCSTR pszOrigFile,
        _In_ LPCSTR pszFile,
        _Outptr_result_maybenull_ LPCSTR *ppszOutFile);

    typedef BOOL(CALLBACK *PF_DETOUR_BINARY_SYMBOL_CALLBACK)(
        _In_opt_ PVOID pContext,
        _In_ ULONG nOrigOrdinal,
        _In_ ULONG nOrdinal,
        _Out_ ULONG *pnOutOrdinal,
        _In_opt_ LPCSTR pszOrigSymbol,
        _In_opt_ LPCSTR pszSymbol,
        _Outptr_result_maybenull_ LPCSTR *ppszOutSymbol);

    typedef BOOL(CALLBACK *PF_DETOUR_BINARY_COMMIT_CALLBACK)(
        _In_opt_ PVOID pContext);

    typedef BOOL(CALLBACK *PF_DETOUR_ENUMERATE_EXPORT_CALLBACK)(_In_opt_ PVOID pContext,
        _In_ ULONG nOrdinal,
        _In_opt_ LPCSTR pszName,
        _In_opt_ PVOID pCode);

    typedef BOOL(CALLBACK *PF_DETOUR_IMPORT_FILE_CALLBACK)(_In_opt_ PVOID pContext,
        _In_opt_ HMODULE hModule,
        _In_opt_ LPCSTR pszFile);

    typedef BOOL(CALLBACK *PF_DETOUR_IMPORT_FUNC_CALLBACK)(_In_opt_ PVOID pContext,
        _In_ DWORD nOrdinal,
        _In_opt_ LPCSTR pszFunc,
        _In_opt_ PVOID pvFunc);

    // Same as PF_DETOUR_IMPORT_FUNC_CALLBACK but extra indirection on last parameter.
    typedef BOOL(CALLBACK *PF_DETOUR_IMPORT_FUNC_CALLBACK_EX)(_In_opt_ PVOID pContext,
        _In_ DWORD nOrdinal,
        _In_opt_ LPCSTR pszFunc,
        _In_opt_ PVOID* ppvFunc);*/

    typedef VOID * PDETOUR_BINARY;
    typedef VOID * PDETOUR_LOADED_BINARY;

    //////////////////////////////////////////////////////////// Transaction APIs.
    //
    LONG DetourTransactionBegin(VOID);
    LONG DetourTransactionAbort(VOID);
    LONG DetourTransactionCommit(VOID);


    //////////////////////////////////////////////////////////////////////////////
    //
    // dotnet trampoline barrier definitions
    //
#define MAX_HOOK_COUNT              1024
#define MAX_ACE_COUNT               128
#define MAX_THREAD_COUNT            128
#define MAX_PASSTHRU_SIZE           1024 * 64

#define DETOUR_ASSERT(expr, Msg)          RtlAssert((BOOL)(expr),(LPCWSTR) Msg);
#define THROW(code, Msg)            { NtStatus = (code); RtlSetLastError(0, NtStatus, Msg); goto THROW_OUTRO; }

#define RTL_SUCCESS(ntstatus)       SUCCEEDED(ntstatus)

#define STATUS_SUCCESS              0
#define RETURN                      { RtlSetLastError(STATUS_SUCCESS, STATUS_SUCCESS, (PWCHAR)""); NtStatus = STATUS_SUCCESS; goto FINALLY_OUTRO; }
#define FORCE(expr)                 { if(!RTL_SUCCESS(NtStatus = (expr))) goto THROW_OUTRO; }
#define IsValidPointer                RtlIsValidPointer

#define PtrToUlong( p ) ((ULONG)(ULONG_PTR) (p) )
    BOOL RtlIsValidPointer(PVOID InPtr, ULONG InSize);

    typedef struct _DETOUR_TRAMPOLINE * PLOCAL_HOOK_INFO;

    typedef struct _HOOK_ACL_
    {
        ULONG                   Count;
        BOOL                    IsExclusive;
        ULONG                   Entries[MAX_ACE_COUNT];
    }HOOK_ACL;

    typedef struct _HOOK_TRACE_INFO_
    {
        PLOCAL_HOOK_INFO        Link;
    }HOOK_TRACE_INFO, *TRACED_HOOK_HANDLE;

    /*
    Setup the ACLs after hook installation. Please note that every
    hook starts suspended. You will have to set a proper ACL to
    make it active!
    */

    LONG DetourSetInclusiveACL(
        ULONG* InThreadIdList,
        ULONG InThreadCount,
        TRACED_HOOK_HANDLE InHandle);

    LONG DetourSetExclusiveACL(
        ULONG* InThreadIdList,
        ULONG InThreadCount,
        TRACED_HOOK_HANDLE InHandle);

    LONG DetourSetGlobalInclusiveACL(
        ULONG* InThreadIdList,
        ULONG InThreadCount);

    LONG DetourSetGlobalExclusiveACL(
        ULONG* InThreadIdList,
        ULONG InThreadCount);

    LONG DetourIsThreadIntercepted(
        TRACED_HOOK_HANDLE InHook,
        ULONG InThreadID,
        BOOL* OutResult);

    LONG DetourSetACL(
        HOOK_ACL* InAcl,
        BOOL InIsExclusive,
        ULONG* InThreadIdList,
        ULONG InThreadCount);

    HOOK_ACL* DetourBarrierGetAcl();
    /*
    The following barrier methods are meant to be used in hook handlers only!

    They will all fail with STATUS_NOT_SUPPORTED if called outside a
    valid hook handler...
    */
    LONG DetourBarrierGetCallback(PVOID* OutValue);

    LONG DetourBarrierGetReturnAddress(PVOID* OutValue);

    LONG DetourBarrierGetAddressOfReturnAddress(PVOID** OutValue);

    LONG DetourTransactionCommitEx(_Out_opt_ PVOID **pppFailedPointer);

    LONG DetourUpdateThread(_In_ pthread_t hThread);

    LONG DetourAttach(_Inout_ PVOID *ppPointer,
        _In_ PVOID pDetour);

    LONG DetourAttachEx(_Inout_ PVOID *ppPointer,
        _In_ PVOID pDetour,
        _Out_opt_ PDETOUR_TRAMPOLINE *ppRealTrampoline,
        _Out_opt_ PVOID *ppRealTarget,
        _Out_opt_ PVOID *ppRealDetour);

    LONG DetourDetach(_Inout_ PVOID *ppPointer,
        _In_ PVOID pDetour);

    BOOL DetourSetIgnoreTooSmall(_In_ BOOL fIgnore);
    BOOL DetourSetRetainRegions(_In_ BOOL fRetain);
    PVOID DetourSetSystemRegionLowerBound(_In_ PVOID pSystemRegionLowerBound);
    PVOID DetourSetSystemRegionUpperBound(_In_ PVOID pSystemRegionUpperBound);

    void DetourBarrierThreadDetach();

    LONG DetourBarrierProcessAttach();
    void DetourBarrierProcessDetach();

    void DetourCriticalInitialize();
    void DetourCriticalFinalize();

    LONG DetourInstallHook(
        void* InEntryPoint,
        void* InHookProc,
        void* InCallback,
        TRACED_HOOK_HANDLE OutHandle);

    LONG DetourUninstallHook(TRACED_HOOK_HANDLE InHandle);


    ////////////////////////////////////////////////////////////// Code Functions.
    //
    PVOID DetourFindFunction(_In_ LPCSTR pszModule,
        _In_ LPCSTR pszFunction);
    PVOID DetourCodeFromPointer(_In_ PVOID pPointer,
        _Out_opt_ PVOID *ppGlobals);
    PVOID DetourCopyInstruction(_In_opt_ PVOID pDst,
        _Inout_opt_ PVOID *ppDstPool,
        _In_ PVOID pSrc,
        _Out_opt_ PVOID *ppTarget,
        _Out_opt_ LONG *plExtra);


    ///////////////////////////////////////////////////// Loaded Binary Functions.
    //
    HMODULE DetourGetContainingModule(_In_ PVOID pvAddr);
    HMODULE DetourEnumerateModules(_In_opt_ HMODULE hModuleLast);
    PVOID DetourGetEntryPoint(_In_opt_ HMODULE hModule);
    ULONG DetourGetModuleSize(_In_opt_ HMODULE hModule);


    _Writable_bytes_(*pcbData)
        _Readable_bytes_(*pcbData)
        _Success_(return != NULL)
        PVOID DetourFindPayload(_In_opt_ HMODULE hModule,
            _In_ REFGUID rguid,
            _Out_ DWORD *pcbData);

    _Writable_bytes_(*pcbData)
        _Readable_bytes_(*pcbData)
        _Success_(return != NULL)
        PVOID DetourFindPayloadEx(_In_ REFGUID rguid,
            _Out_ DWORD * pcbData);

    DWORD DetourGetSizeOfPayloads(_In_opt_ HMODULE hModule);

    ///////////////////////////////////////////////// Persistent Binary Functions.
    //

    PDETOUR_BINARY DetourBinaryOpen(_In_ HANDLE hFile);

    _Writable_bytes_(*pcbData)
        _Readable_bytes_(*pcbData)
        _Success_(return != NULL)
        PVOID DetourBinaryEnumeratePayloads(_In_ PDETOUR_BINARY pBinary,
            _Out_opt_ GUID *pGuid,
            _Out_ DWORD *pcbData,
            _Inout_ DWORD *pnIterator);

    _Writable_bytes_(*pcbData)
        _Readable_bytes_(*pcbData)
        _Success_(return != NULL)
        PVOID DetourBinaryFindPayload(_In_ PDETOUR_BINARY pBinary,
            _In_ REFGUID rguid,
            _Out_ DWORD *pcbData);

    PVOID DetourBinarySetPayload(_In_ PDETOUR_BINARY pBinary,
        _In_ REFGUID rguid,
        _In_reads_opt_(cbData) PVOID pData,
        _In_ DWORD cbData);


    /////////////////////////////////////////////////// Create Process & Load Dll.
    //



    //
    //////////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus
}
#endif // __cplusplus

//////////////////////////////////////////////// Detours Internal Definitions.
//
#ifdef __cplusplus
#ifdef DETOURS_INTERNAL

#define NOTHROW
// #define NOTHROW (nothrow)

//////////////////////////////////////////////////////////////////////////////
//
#if (_MSC_VER < 1299)


static inline
LONG InterlockedCompareExchange(_Inout_ LONG *ptr, _In_ LONG nval, _In_ LONG oval)
{
    return (LONG)__sync_val_compare_and_swap(ptr, oval, nval);
}
#else
#include <dbghelp.h>
#endif

#if defined(_INC_STDIO) && !defined(_CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS)
#error detours.h must be included before stdio.h (or at least define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS earlier)
#endif
#define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS 1

#ifndef DETOUR_TRACE
#if DETOUR_DEBUG
#define DETOUR_TRACE(x) printf x
#define DETOUR_BREAK()  __debugbreak()
#include <stdio.h>
#include "limits.h"
#else
#include <glog/logging.h>
#include  <cstdarg>
const char * ___DETOUR_TRACE(const char *format, ...);
#define DETOUR_TRACE(x) LOG(INFO) << ___DETOUR_TRACE x
#define DETOUR_BREAK()
#endif
#endif

#if 1 || defined(DETOURS_IA64)


#endif // DETOURS_IA64

#ifdef DETOURS_ARM


#define DETOURS_PFUNC_TO_PBYTE(p)  ((PBYTE)(((ULONG_PTR)(p)) & ~(ULONG_PTR)1))
#define DETOURS_PBYTE_TO_PFUNC(p)  ((PBYTE)(((ULONG_PTR)(p)) | (ULONG_PTR)1))

#endif // DETOURS_ARM

//////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define DETOUR_OFFLINE_LIBRARY(x)                                       \
PVOID DetourCopyInstruction##x(_In_opt_ PVOID pDst,              \
                                      _Inout_opt_ PVOID *ppDstPool,     \
                                      _In_ PVOID pSrc,                  \
                                      _Out_opt_ PVOID *ppTarget,        \
                                      _Out_opt_ LONG *plExtra);         \
                                                                        \
BOOL DetourSetCodeModule##x(_In_ HMODULE hModule,                \
                                   _In_ BOOL fLimitReferencesToModule); \

    DETOUR_OFFLINE_LIBRARY(X86)
        DETOUR_OFFLINE_LIBRARY(X64)
        DETOUR_OFFLINE_LIBRARY(ARM)
        DETOUR_OFFLINE_LIBRARY(ARM64)
        DETOUR_OFFLINE_LIBRARY(IA64)

#undef DETOUR_OFFLINE_LIBRARY

        //////////////////////////////////////////////////////////////////////////////
        //
        // Helpers for manipulating page protection.
        //

        _Success_(return != FALSE)
        BOOL DetourVirtualProtectSameExecuteEx(_In_  pid_t hProcess,
            _In_  PVOID pAddress,
            _In_  SIZE_T nSize,
            _In_  DWORD dwNewProtect,
            _Out_ PDWORD pdwOldProtect);

    _Success_(return != FALSE)
        BOOL DetourVirtualProtectSameExecute(_In_  PVOID pAddress,
            _In_  SIZE_T nSize,
            _In_  DWORD dwNewProtect,
            _Out_ PDWORD pdwOldProtect);
#ifdef __cplusplus
}
#endif // __cplusplus

//////////////////////////////////////////////////////////////////////////////

#define MM_ALLOCATION_GRANULARITY 0x10000

//////////////////////////////////////////////////////////////////////////////


//LONG DetourBarrierBeginStackTrace(PVOID* OutBackup);

//LONG DetourBarrierEndStackTrace(PVOID InBackup);

BOOL DetourIsValidHandle(
    TRACED_HOOK_HANDLE InTracedHandle,
    PLOCAL_HOOK_INFO* OutHandle);

BOOL IsLoaderLock();
BOOL AcquireSelfProtection();

void RtlAssert(BOOL InAssert, LPCWSTR lpMessageText);
void RtlSetLastError(LONG InCode, LONG InNtStatus, WCHAR* InMessage);

typedef struct _RTL_SPIN_LOCK_
{
    pthread_mutex_t         Lock;
    BOOL                    IsOwned;
}RTL_SPIN_LOCK;

void RtlInitializeLock(RTL_SPIN_LOCK* InLock);

void RtlAcquireLock(RTL_SPIN_LOCK* InLock);

void RtlReleaseLock(RTL_SPIN_LOCK* InLock);

void RtlDeleteLock(RTL_SPIN_LOCK* InLock);

void RtlSleep(ULONG InTimeout);


PVOID detour_get_page(PVOID addr);
int detour_get_page_size();

typedef struct _RUNTIME_INFO_
{
    // "true" if the current thread is within the related hook handler
    BOOL            IsExecuting;
    // the hook this information entry belongs to... This allows a per thread and hook storage!
    DWORD           HLSIdent;
    // the return address of the current thread's hook handler...
    void*           RetAddress;
    // the address of the return address of the current thread's hook handler...
    void**          AddrOfRetAddr;
}RUNTIME_INFO;

typedef struct _THREAD_RUNTIME_INFO_
{
    RUNTIME_INFO*        Entries;
    RUNTIME_INFO*        Current;
    void*                Callback;
    BOOL                 IsProtected;
}THREAD_RUNTIME_INFO, *LPTHREAD_RUNTIME_INFO;

typedef struct _THREAD_LOCAL_STORAGE_
{
    THREAD_RUNTIME_INFO      Entries[MAX_THREAD_COUNT];
    DWORD                    IdList[MAX_THREAD_COUNT];
    RTL_SPIN_LOCK            ThreadSafe;
}THREAD_LOCAL_STORAGE;

typedef struct _BARRIER_UNIT_
{
    HOOK_ACL                GlobalACL;
    BOOL                    IsInitialized;
    THREAD_LOCAL_STORAGE    TLS;
}BARRIER_UNIT;


BOOL TlsGetCurrentValue(
    THREAD_LOCAL_STORAGE* InTls,
    THREAD_RUNTIME_INFO** OutValue);
BOOL TlsAddCurrentThread(THREAD_LOCAL_STORAGE* InTls);

void RtlFreeMemory(void* InPointer);

void* RtlAllocateMemory(
    BOOL InZeroMemory,
    ULONG InSize);

#undef RtlCopyMemory
void RtlCopyMemory(
    PVOID InDest,
    PVOID InSource,
    ULONG InByteCount);

#undef RtlZeroMemory
void RtlZeroMemory(
    PVOID InTarget,
    ULONG InByteCount);

BOOL IsThreadIntercepted(
    HOOK_ACL* LocalACL,
    ULONG InThreadID);
void ReleaseSelfProtection();

extern BARRIER_UNIT         Unit;
extern RTL_SPIN_LOCK        GlobalHookLock;


#endif // DETOURS_INTERNAL
#endif // __cplusplus

#endif // _DETOURS_H_
//
////////////////////////////////////////////////////////////////  End of File.
