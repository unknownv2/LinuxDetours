#pragma once
/**
*    types.h - These definitions are for linux/windows cross compiler compatibility
*
* author: Eric Young 01/22/2004
*/


#ifndef TYPES_H_
#define TYPES_H_

#define MIN(a,b) ((a < b) ? a : b)
#define MAX(a,b) ((a > b) ? a : b)
#define CLAMP(val,lower,upper) MAX(MIN(val,upper),lower)

// These definitions are for linux
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/timeb.h>

#if defined(__linux)
#include <linux/ioctl.h>
#endif
#include <time.h>
#include <pthread.h>

// these are needed for Win32/Linux string comparisons
#define genericStrICmp strcasecmp
#define genericStrNICmp strncasecmp

typedef char WCHAR;    // wc,   16-bit UNICODE character

#define CONST const
typedef int                     BOOL;
typedef long int                LONG;
typedef short int               SHORT;
typedef char                    CHAR;
typedef int                     INT;
typedef unsigned int            DWORD;
typedef unsigned short          WORD;
typedef unsigned char           BYTE;
typedef unsigned int            UINT;

typedef long long               INT64;
typedef unsigned long long      UINT64;

typedef int                     PT_FILEHANDLE;
typedef void*                   DLL_HANDLE;

typedef unsigned long*          LPDWORD;
typedef void*                   LPOVERLAPPED;
typedef void*                   OVERLAPPED;
typedef void*                   LPVOID;
typedef void*                   PVOID;
typedef void                    VOID;
typedef int                     HANDLE;         // note that handle here is assumed to be
                                                // a pointer to a file decriptor
typedef int*                    PHANDLE;
typedef int                     BOOL;

typedef unsigned int            UINT32;
typedef unsigned int            ULONG;
typedef unsigned long long      ULONG64;
typedef unsigned long long      ULONGLONG;
typedef long long               LONGLONG;

typedef unsigned short          USHORT;
typedef unsigned char           UCHAR;
typedef long long               INT64;
typedef long long               LARGE_INTEGER;
typedef unsigned char           BYTE;
typedef BYTE*     PBYTE;
typedef int __int32;
typedef short __int16;
typedef unsigned char __int8;

typedef int INT32;
typedef LONG NTSTATUS;
typedef BYTE  BOOLEAN;
typedef BOOLEAN *PBOOLEAN;
typedef WCHAR *LPCWSTR, *PCWSTR;
typedef WCHAR *PCHAR;
typedef WCHAR *LPSTR, *PSTR;
typedef WCHAR * PWCHAR, *UNICODE_STRING;
typedef CHAR *PCHAR, *LPCH, *PCH;
typedef CONST CHAR *LPCCH, *PCCH;

typedef void * HMODULE;

typedef CHAR *NPSTR, *LPSTR, *PSTR;
typedef PSTR *PZPSTR;
typedef CONST PSTR *PCZPSTR;
typedef CONST CHAR *LPCSTR, *PCSTR;
typedef PCSTR *PZPCSTR;
typedef CONST PCSTR *PCZPCSTR;

typedef CHAR *PZZSTR;
typedef CONST CHAR *PCZZSTR;

typedef  CHAR *PNZCH;
typedef  CONST CHAR *PCNZCH;
typedef DWORD *PDWORD;

typedef size_t SIZE_T;

//typedef unsigned long ULONG;
typedef ULONG *PULONG;
//typedef unsigned short USHORT;
typedef USHORT *PUSHORT;
//typedef unsigned char UCHAR;
typedef UCHAR *PUCHAR;
//typedef _Null_terminated_ char *PSZ;

typedef signed char         INT8, *PINT8;
typedef signed short        INT16, *PINT16;
typedef signed int          INT32, *PINT32;
typedef unsigned char       UINT8, *PUINT8;
typedef unsigned short      UINT16, *PUINT16;
typedef unsigned int        UINT32, *PUINT32;
#if defined(_ARM64_)
//
// The following types are guaranteed to be signed and 64 bits wide.
//

typedef long long LONG64, *PLONG64;

//
// The following types are guaranteed to be unsigned and 64 bits wide.
//

typedef unsigned long long ULONG64, *PULONG64;
typedef unsigned long long DWORD64, *PDWORD64;


#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))
#define ZeroMemory RtlZeroMemory
#define NO_ERROR                         0
#define ERROR_INVALID_DATA               13L
#if !defined(UNALIGNED)
#define UNALIGNED
#endif

#define UNREFERENCED_PARAMETER(P)        \
    /*lint -save -e527 -e530 */ \
    { \
        (P) = (P); \
    } \

#define CopyMemory memcpy

#define _In_

#define CALLBACK    __stdcall
#define WINAPI      
#define WINAPIV     __cdecl
#define APIENTRY    WINAPI
#define APIPRIVATE  __stdcall
#define PASCAL      __stdcall

#define STATUS_SUCCESS                   0
#define STATUS_NOT_SUPPORTED             1
#define STATUS_INVALID_PARAMETER_1       1
#define STATUS_INVALID_PARAMETER_2       2
#define STATUS_INVALID_PARAMETER_3       3
#define STATUS_INVALID_PARAMETER_4       4
#define STATUS_INTERNAL_ERROR            0
#define STATUS_NO_MEMORY                 0

#define STATUS_TIMEOUT                   1
#define STATUS_INSUFFICIENT_RESOURCES    1
#define STATUS_INVALID_PARAMETER         ((DWORD)0xC000000DL)
#define PAGE_EXECUTE_READWRITE           PROT_EXEC | PROT_READ  | PROT_WRITE
#define PAGE_READONLY                    PROT_READ
#define PAGE_READWRITE                   PROT_READ | PROT_WRITE
#define PAGE_EXECUTE_READ                PROT_EXEC | PROT_READ


/* common constants */
#define SUCCESS         0
#define FAILURE        -1

#define IOCTL_FAIL(status)    (status < 0)

/** unusual return codes */
#define UNIMPLEMENTED    -    1001

// create some equivalent constants in linux that windows have
#define STATIC                static

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE -1
#endif

/** sleep for x milliseconds */
//inline void nap(unsigned long msec) {    usleep(msec*1000); }

#define Sleep sleep
#else

#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))
#define ZeroMemory RtlZeroMemory
#define NO_ERROR 0
#define ERROR_INVALID_DATA               13L
#if !defined(UNALIGNED)
#define UNALIGNED
#endif

#define UNREFERENCED_PARAMETER(P)         \
    /*lint -save -e527 -e530 */ \
    { \
        (P) = (P); \
    } \

#define CopyMemory memcpy

#define _In_

#define CALLBACK    __stdcall
#define WINAPI      //__stdcall
#define WINAPIV     __cdecl
#define APIENTRY    WINAPI
#define APIPRIVATE  __stdcall
#define PASCAL      __stdcall

#define STATUS_SUCCESS                    0
#define STATUS_NOT_SUPPORTED              1
#define STATUS_INVALID_PARAMETER_1        1
#define STATUS_INVALID_PARAMETER_2        2
#define STATUS_INVALID_PARAMETER_3        3
#define STATUS_INVALID_PARAMETER_4        4
#define STATUS_INTERNAL_ERROR             0
#define STATUS_NO_MEMORY                  0

#define STATUS_TIMEOUT                    1
#define STATUS_INSUFFICIENT_RESOURCES     1
#define STATUS_INVALID_PARAMETER          ((DWORD)0xC000000DL)
#define PAGE_EXECUTE_READWRITE            PROT_EXEC | PROT_READ  | PROT_WRITE
#define PAGE_READONLY                     PROT_READ
#define PAGE_READWRITE                    PROT_READ | PROT_WRITE
#define PAGE_EXECUTE_READ                 PROT_EXEC | PROT_READ
/* These are defined so we can use TCHAR compatible string calls */
#define _TINT    int
#define _T(arg)  arg
#define TCHAR    char
#define tstrcpy  strcpy
#define tstrncpy strncpy
#define _tcscat  strcat
#define _tcscpy(str1, str2) strcpy(str1, str2)
#define _tcslen(str1) strlen(str1)
#define _tfopen(filename, access)  fopen(filename, access)
#define _gettc    getc
#define _puttc    putc
#define _stscanf  sscanf
#define _stprintf sprintf
#define _sntprintf snprintf
#define _tprintf  printf



/* common constants */
#define SUCCESS         0
#define FAILURE        -1

#define IOCTL_FAIL(status)    (status < 0)

/** unusual return codes */
#define UNIMPLEMENTED    -1001

// create some equivalent constants in linux that windows have
#define STATIC             static

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE -1
#endif

/** sleep for x milliseconds */
//inline void nap(unsigned long msec) {    usleep(msec*1000); }

#define Sleep sleep

//typedef double VWTIME;
/** returns the amount of time in seconds since some arbitrary moment. */
//inline VWTIME VWGetTime() { return 0.0; }


#endif // end of the WIN32/Linux definitions


// These are common declared types

typedef unsigned char*   PU8;
typedef unsigned char    U8;
typedef unsigned short   U16;
typedef unsigned long    U32;
typedef signed char      S8;
typedef signed short     S16;
typedef signed long      S32;


#if defined(_DEBUG)
#define dbgprint(string) { printf string; fflush(stdout); }
#else
#define dbgprint(string)
#endif

#include <string.h>

#endif // end of TYPES_H_
