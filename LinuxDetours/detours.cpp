//////////////////////////////////////////////////////////////////////////////
//
//  Core Detours Functionality
//
//

#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1
#include "types.h"
#include "limits.h"
#include "plthook.h"

//#define DETOUR_DEBUG 1
#define DETOURS_INTERNAL

#include "detours.h"

#define NOTHROW

//////////////////////////////////////////////////////////////////////////////
//
struct _DETOUR_ALIGN
{
    BYTE    obTarget : 3;
    BYTE    obTrampoline : 5;
};

//C_ASSERT(sizeof(_DETOUR_ALIGN) == 1);

//////////////////////////////////////////////////////////////////////////////
//
// Region reserved for system DLLs, which cannot be used for trampolines.
//
static PVOID    s_pSystemRegionLowerBound = (PVOID)(ULONG_PTR)0x70000000;
static PVOID    s_pSystemRegionUpperBound = (PVOID)(ULONG_PTR)0x80000000;


//////////////////////////////////////////////////////////////////////////////
//
// Hook Handle Slot List
//
ULONG                       GlobalSlotList[MAX_HOOK_COUNT];
static LONG                 UniqueIDCounter = 0x10000000;

//////////////////////////////////////////////////////////////////////////////
//
int detour_get_page_size()
{
    return getpagesize();
}
PVOID detour_get_page(PVOID addr)
{
    ULONG_PTR ptr = (ULONG_PTR)addr;
    return (PVOID)(ptr - (ptr % getpagesize()));
}

static bool detour_is_imported(PBYTE pbCode, PBYTE pbAddress)
{
    plthook_t *plthook;
    plthook_open(&plthook, NULL);
    unsigned int pos = 0; /* This must be initialized with zero. */
    const char *name;
    void **addr;

    while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
        if (addr != NULL && (PBYTE)addr == pbAddress) {
            plthook_close(plthook);
            return true;
        }
    }
    plthook_close(plthook);
    return false;
}

inline ULONG_PTR detour_2gb_below(ULONG_PTR address)
{
    return (address > (ULONG_PTR)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
}

inline ULONG_PTR detour_2gb_above(ULONG_PTR address)
{
#if defined(DETOURS_64BIT)
    return (address < (ULONG_PTR)0xffffffff80000000) ? address + 0x7ff80000 : (ULONG_PTR)0xfffffffffff80000;
#else
    return (address < (ULONG_PTR)0x80000000) ? address + 0x7ff80000 : (ULONG_PTR)0xfff80000;
#endif
}

///////////////////////////////////////////////////////////////////////// X86.
//
#ifdef DETOURS_X86

const ULONG DETOUR_TRAMPOLINE_CODE_SIZE = 128;

struct _DETOUR_TRAMPOLINE
{
    BYTE               rbCode[30];     // target code + jmp to pbRemain
    BYTE               cbCode;         // size of moved target code.
    BYTE               cbCodeBreak;    // padding to make debugging easier.
    BYTE               rbRestore[22];  // original target code.
    BYTE               cbRestore;      // size of original target code.
    BYTE               cbRestoreBreak; // padding to make debugging easier.
    _DETOUR_ALIGN      rAlign[8];      // instruction alignment array.
    PBYTE              pbRemain;       // first instruction after moved code. [free list]
    PBYTE              pbDetour;       // first instruction of detour function.
    HOOK_ACL           LocalACL;
    void*              Callback;
    ULONG              HLSIndex;
    ULONG              HLSIdent;
    TRACED_HOOK_HANDLE OutHandle; // handle returned to user  
    void*              Trampoline;
    INT                IsExecuted;
    void*              HookIntro; // . NET Intro function  
    UCHAR*             OldProc;  // old target function      
    void*              HookProc; // function we detour to
    void*              HookOutro;   // .NET Outro function  
    int*               IsExecutedPtr;
    BYTE               rbTrampolineCode[DETOUR_TRAMPOLINE_CODE_SIZE];
};

C_ASSERT(sizeof(_DETOUR_TRAMPOLINE) == 764);

enum {
    SIZE_OF_JMP = 5
};

inline PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE pbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 5;
    *pbCode++ = 0xE9;   // jmp +imm32
    *((INT32*&)pbCode)++ = (INT32)(pbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE detour_gen_jmp_indirect(PBYTE pbCode, PBYTE *ppbJmpVal)
{
    *pbCode++ = 0xff;   // jmp [+imm32]
    *pbCode++ = 0x25;
    *((INT32*&)pbCode)++ = (INT32)((PBYTE)ppbJmpVal);
    return pbCode;
}

inline PBYTE detour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit) {
        *pbCode++ = 0xcc;   // brk;
    }
    return pbCode;
}

inline PBYTE detour_skip_jmp(PBYTE pbCode, PVOID *ppGlobals)
{
    if (pbCode == NULL) {
        return NULL;
    }
    if (ppGlobals != NULL) {
        *ppGlobals = NULL;
    }

    // First, skip over the import vector if there is one.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [imm32]
                                                    // Looks like an import alias jump, then get the code it points to.
        PBYTE pbTarget = *(UNALIGNED PBYTE *)&pbCode[2];
        if (detour_is_imported(pbCode, pbTarget)) {
            PBYTE pbNew = *(UNALIGNED PBYTE *)pbTarget;
            DETOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
            pbCode = pbNew;
        }
    }

    // Then, skip over a patch jump
    if (pbCode[0] == 0xeb) {   // jmp +imm8
        PBYTE pbNew = pbCode + 2 + *(CHAR *)&pbCode[1];
        DETOUR_TRACE(("%p->%p: skipped over short jump.\n", pbCode, pbNew));
        pbCode = pbNew;

        // First, skip over the import vector if there is one.
        if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [imm32]
                                                        // Looks like an import alias jump, then get the code it points to.
            PBYTE pbTarget = *(UNALIGNED PBYTE *)&pbCode[2];
            if (detour_is_imported(pbCode, pbTarget)) {
                pbNew = *(UNALIGNED PBYTE *)pbTarget;
                DETOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
                pbCode = pbNew;
            }
        }
        // Finally, skip over a long jump if it is the target of the patch jump.
        else if (pbCode[0] == 0xe9) {   // jmp +imm32
            pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];
            DETOUR_TRACE(("%p->%p: skipped over long jump.\n", pbCode, pbNew));
            pbCode = pbNew;
        }
    }
    return pbCode;
}

inline void detour_find_jmp_bounds(PBYTE pbCode,
    PDETOUR_TRAMPOLINE *ppLower,
    PDETOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);
    DETOUR_TRACE(("[%p..%p..%p]\n", lo, pbCode, hi));

    // And, within +/- 2GB of relative jmp targets.
    if (pbCode[0] == 0xe9) {   // jmp +imm32
        PBYTE pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];

        if (pbNew < pbCode) {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
        DETOUR_TRACE(("[%p..%p..%p] +imm32\n", lo, pbCode, hi));
    }

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}

inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    if (pbCode[0] == 0xeb ||    // jmp +imm8
        pbCode[0] == 0xe9 ||    // jmp +imm32
        pbCode[0] == 0xe0 ||    // jmp eax
        pbCode[0] == 0xc2 ||    // ret +imm8
        pbCode[0] == 0xc3 ||    // ret
        pbCode[0] == 0xcc) {    // brk
        return TRUE;
    }
    else if (pbCode[0] == 0xf3 && pbCode[1] == 0xc3) {  // rep ret
        return TRUE;
    }
    else if (pbCode[0] == 0xff && pbCode[1] == 0x25) {  // jmp [+imm32]
        return TRUE;
    }
    else if ((pbCode[0] == 0x26 ||      // jmp es:
        pbCode[0] == 0x2e ||      // jmp cs:
        pbCode[0] == 0x36 ||      // jmp ss:
        pbCode[0] == 0x3e ||      // jmp ds:
        pbCode[0] == 0x64 ||      // jmp fs:
        pbCode[0] == 0x65) &&     // jmp gs:
        pbCode[1] == 0xff &&       // jmp [+imm32]
        pbCode[2] == 0x25) {
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    // 1-byte through 11-byte NOPs.
    if (pbCode[0] == 0x90) {
        return 1;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x90) {
        return 2;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x00) {
        return 3;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x40 &&
        pbCode[3] == 0x00) {
        return 4;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x44 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00) {
        return 5;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x44 && pbCode[4] == 0x00 && pbCode[5] == 0x00) {
        return 6;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x80 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00) {
        return 7;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x84 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00) {
        return 8;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x84 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00) {
        return 9;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x0F &&
        pbCode[3] == 0x1F && pbCode[4] == 0x84 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00) {
        return 10;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x66 &&
        pbCode[3] == 0x0F && pbCode[4] == 0x1F && pbCode[5] == 0x84 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00 && pbCode[10] == 0x00) {
        return 11;
    }

    // int 3.
    if (pbCode[0] == 0xcc) {
        return 1;
    }
    return 0;
}

#endif // DETOURS_X86

///////////////////////////////////////////////////////////////////////// X64.
//
#ifdef DETOURS_X64

const ULONG DETOUR_TRAMPOLINE_CODE_SIZE = 0x150;

struct _DETOUR_TRAMPOLINE
{
    // An X64 instuction can be 15 bytes long.
    // In practice 11 seems to be the limit.
    BYTE               rbCode[30];     // target code + jmp to pbRemain.
    BYTE               cbCode;         // size of moved target code.
    BYTE               cbCodeBreak;    // padding to make debugging easier.
    BYTE               rbRestore[30];  // original target code.
    BYTE               cbRestore;      // size of original target code.
    BYTE               cbRestoreBreak; // padding to make debugging easier.
    _DETOUR_ALIGN      rAlign[8];      // instruction alignment array.
    PBYTE              pbRemain;       // first instruction after moved code. [free list]
    PBYTE              pbDetour;       // first instruction of detour function.
    BYTE               rbCodeIn[8];    // jmp [pbDetour]
    HOOK_ACL           LocalACL;
    void*              Callback;
    ULONG              HLSIndex;
    ULONG              HLSIdent;
    TRACED_HOOK_HANDLE OutHandle; // handle returned to user  
    void*              Trampoline;
    INT                IsExecuted;
    void*              HookIntro; // . NET Intro function  
    UCHAR*             OldProc;  // old target function      
    void*              HookProc; // function we detour to
    void*              HookOutro;   // .NET Outro function  
    int*               IsExecutedPtr;
    BYTE               rbTrampolineCode[DETOUR_TRAMPOLINE_CODE_SIZE];
};

//C_ASSERT(sizeof(_DETOUR_TRAMPOLINE) == 968);

enum {
    SIZE_OF_JMP = 5
};

inline PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE pbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 5;
    *pbCode++ = 0xE9;   // jmp +imm32
    *((INT32*&)pbCode)++ = (INT32)(pbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE detour_gen_jmp_indirect(PBYTE pbCode, PBYTE *ppbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 6;
    *pbCode++ = 0xff;   // jmp [+imm32]
    *pbCode++ = 0x25;
    *((INT32*&)pbCode)++ = (INT32)((PBYTE)ppbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE detour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit) {
        *pbCode++ = 0xcc;   // brk;
    }
    return pbCode;
}

inline PBYTE detour_skip_jmp(PBYTE pbCode, PVOID *ppGlobals)
{
    if (pbCode == NULL) {
        return NULL;
    }
    if (ppGlobals != NULL) {
        *ppGlobals = NULL;
    }

    // First, skip over the import vector if there is one.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
                                                    // Looks like an import alias jump, then get the code it points to.
        PBYTE pbTarget = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];
        if (detour_is_imported(pbCode, pbTarget)) {
            PBYTE pbNew = *(UNALIGNED PBYTE *)pbTarget;
            DETOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
            pbCode = pbNew;
        }
    }

    // Then, skip over a patch jump
    if (pbCode[0] == 0xeb) {   // jmp +imm8
        PBYTE pbNew = pbCode + 2 + *(CHAR *)&pbCode[1];
        DETOUR_TRACE(("%p->%p: skipped over short jump.\n", pbCode, pbNew));
        pbCode = pbNew;

        // First, skip over the import vector if there is one.
        if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
                                                        // Looks like an import alias jump, then get the code it points to.
            PBYTE pbTarget = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];
            if (detour_is_imported(pbCode, pbTarget)) {
                pbNew = *(UNALIGNED PBYTE *)pbTarget;
                DETOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
                pbCode = pbNew;
            }
        }
        // Finally, skip over a long jump if it is the target of the patch jump.
        else if (pbCode[0] == 0xe9) {   // jmp +imm32
            pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];
            DETOUR_TRACE(("%p->%p: skipped over long jump.\n", pbCode, pbNew));
            pbCode = pbNew;
        }
    }
    return pbCode;
}

inline void detour_find_jmp_bounds(PBYTE pbCode,
    PDETOUR_TRAMPOLINE *ppLower,
    PDETOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);
    DETOUR_TRACE(("[%p..%p..%p]\n", lo, pbCode, hi));

    // And, within +/- 2GB of relative jmp vectors.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
        PBYTE pbNew = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];

        if (pbNew < pbCode) {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
        DETOUR_TRACE(("[%p..%p..%p] [+imm32]\n", lo, pbCode, hi));
    }
    // And, within +/- 2GB of relative jmp targets.
    else if (pbCode[0] == 0xe9) {   // jmp +imm32
        PBYTE pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];

        if (pbNew < pbCode) {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
        DETOUR_TRACE(("[%p..%p..%p] +imm32\n", lo, pbCode, hi));
    }

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}

inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    if (pbCode[0] == 0xeb ||    // jmp +imm8
        pbCode[0] == 0xe9 ||    // jmp +imm32
        pbCode[0] == 0xe0 ||    // jmp eax
        pbCode[0] == 0xc2 ||    // ret +imm8
        pbCode[0] == 0xc3 ||    // ret
        pbCode[0] == 0xcc) {    // brk
        return TRUE;
    }
    else if (pbCode[0] == 0xf3 && pbCode[1] == 0xc3) {  // rep ret
        return TRUE;
    }
    else if (pbCode[0] == 0xff && pbCode[1] == 0x25) {  // jmp [+imm32]
        return TRUE;
    }
    else if ((pbCode[0] == 0x26 ||      // jmp es:
        pbCode[0] == 0x2e ||      // jmp cs:
        pbCode[0] == 0x36 ||      // jmp ss:
        pbCode[0] == 0x3e ||      // jmp ds:
        pbCode[0] == 0x64 ||      // jmp fs:
        pbCode[0] == 0x65) &&     // jmp gs:
        pbCode[1] == 0xff &&       // jmp [+imm32]
        pbCode[2] == 0x25) {
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    // 1-byte through 11-byte NOPs.
    if (pbCode[0] == 0x90) {
        return 1;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x90) {
        return 2;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x00) {
        return 3;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x40 &&
        pbCode[3] == 0x00) {
        return 4;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x44 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00) {
        return 5;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x44 && pbCode[4] == 0x00 && pbCode[5] == 0x00) {
        return 6;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x80 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00) {
        return 7;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x84 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00) {
        return 8;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x84 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00) {
        return 9;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x0F &&
        pbCode[3] == 0x1F && pbCode[4] == 0x84 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00) {
        return 10;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x66 &&
        pbCode[3] == 0x0F && pbCode[4] == 0x1F && pbCode[5] == 0x84 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00 && pbCode[10] == 0x00) {
        return 11;
    }

    // int 3.
    if (pbCode[0] == 0xcc) {
        return 1;
    }
    return 0;
}

#endif // DETOURS_X64

//////////////////////////////////////////////////////////////////////// IA64.
//
#ifdef DETOURS_IA64


#endif // DETOURS_IA64

#ifdef DETOURS_ARM

const ULONG DETOUR_TRAMPOLINE_CODE_SIZE = 0x110;


struct _DETOUR_TRAMPOLINE
{
    // A Thumb-2 instruction can be 2 or 4 bytes long.
    BYTE               rbCode[62];     // target code + jmp to pbRemain
    BYTE               cbCode;         // size of moved target code.
    BYTE               cbCodeBreak;    // padding to make debugging easier.
    BYTE               rbRestore[22];  // original target code.
    BYTE               cbRestore;      // size of original target code.
    BYTE               cbRestoreBreak; // padding to make debugging easier.
    _DETOUR_ALIGN      rAlign[8];      // instruction alignment array.
    PBYTE              pbRemain;       // first instruction after moved code. [free list]
    PBYTE              pbDetour;       // first instruction of detour function.
    INT                IsThumbTarget;
    HOOK_ACL           LocalACL;
    void*              Callback;
    ULONG              HLSIndex;
    ULONG              HLSIdent;
    TRACED_HOOK_HANDLE OutHandle; // handle returned to user  
    void*              Trampoline;
    INT                IsExecuted;
    void*              HookIntro; // . NET Intro function  
    UCHAR*             OldProc;  // old target function      
    void*              HookProc; // function we detour to
    void*              HookOutro;   // .NET Outro function  
    int*               IsExecutedPtr;
    BYTE               rbTrampolineCode[DETOUR_TRAMPOLINE_CODE_SIZE];
};

//C_ASSERT(sizeof(_DETOUR_TRAMPOLINE) == 900);

enum {
    SIZE_OF_JMP = 8
};

inline PBYTE align4(PBYTE pValue)
{
    return (PBYTE)(((ULONG)pValue) & ~(ULONG)3u);
}
inline ULONG fetch_opcode(PBYTE pbCode)
{
    ULONG Opcode = *(UINT32 *)&pbCode[0];
    return Opcode;
}
inline ULONG fetch_thumb_opcode(PBYTE pbCode)
{
    ULONG Opcode = *(UINT16 *)&pbCode[0];
    if (Opcode >= 0xe800) {
        Opcode = (Opcode << 16) | *(UINT16 *)&pbCode[2];
    }
    return Opcode;
}

inline void write_thumb_opcode(PBYTE &pbCode, ULONG Opcode)
{
    if (Opcode >= 0x10000) {
        *((UINT16*&)pbCode)++ = Opcode >> 16;
    }
    *((UINT16*&)pbCode)++ = (UINT16)Opcode;
}
inline void write_arm_opcode(PBYTE &pbCode, ULONG Opcode)
{
    *((UINT32*&)pbCode)++ = (UINT32)Opcode;
}
#define A$ldr_rd_$rn_im$(rd, rn, im) /* ldr rd, [rn, #im] */ \
    (0xe5100000 | ((im) < 0 ? 0 : 1 << 23) | ((rn) << 16) | ((rd) << 12) | abs(im))

PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE *ppPool, PBYTE pbJmpVal)
{
#if defined(DETOURS_ARM32)
    PBYTE pbLiteral;
    if (ppPool != NULL) {
        *ppPool = *ppPool - 4;
        pbLiteral = *ppPool;
    }
    else {
        pbLiteral = align4(pbCode + 4);
    }
    *((PBYTE*&)pbLiteral) = pbJmpVal;
    LONG delta = pbLiteral - align4(pbCode + 4);
    // stored as: F0 04 1F E5 
    *((UINT32*&)pbCode)++ = A$ldr_rd_$rn_im$(15, 15, delta - 4);
    if (ppPool == NULL) {
        if (((ULONG)pbCode & 2) != 0) {
            write_arm_opcode(pbCode, 0xe320f000);
        }
        pbCode += 4;
    }
    //*((UINT32*&)pbCode)++ = (UINT32)0xF004E51F | (delta);
#elif defined(DETOURS_ARM)
    if (reinterpret_cast<uintptr_t>(pbCode) & 0x1) {
        // reset is_thumb_flag
        pbCode = DETOURS_PFUNC_TO_PBYTE(pbCode);
        PBYTE pbLiteral;
        if (ppPool != NULL) {
            *ppPool = *ppPool - 4;
            pbLiteral = *ppPool;
        }
        else {
            pbLiteral = align4(pbCode + 6);
        }
        *((PBYTE*&)pbLiteral) = DETOURS_PBYTE_TO_PFUNC(pbJmpVal);
        LONG delta = pbLiteral - align4(pbCode + 4);

        // stored as: DF F8 00 F0 
        write_thumb_opcode(pbCode, 0xf8dff000 | delta);     // LDR PC,[PC+n]
        //write_thumb_opcode(pbCode, 0x9FE504f0 | delta);  

        //write_thumb_opcode(pbCode, 0xF000DFF8 | delta);

        if (ppPool == NULL) {
            if (((ULONG)pbCode & 2) != 0) {
                write_thumb_opcode(pbCode, 0xdefe);         // BREAK
            }
            pbCode += 4;
        }
    }
    else {
        PBYTE pbLiteral;
        if (ppPool != NULL) {
            *ppPool = *ppPool - 4;
            pbLiteral = *ppPool;
        }
        else {
            pbLiteral = align4(pbCode + 4);
        }
        *((PBYTE*&)pbLiteral) = pbJmpVal;
        LONG delta = pbLiteral - align4(pbCode + 4);
        // stored as: F0 04 1F E5 
        *((UINT32*&)pbCode)++ = A$ldr_rd_$rn_im$(15, 15, delta - 4);
        if (ppPool == NULL) {
            if (((ULONG)pbCode & 2) != 0) {
                write_arm_opcode(pbCode, 0xe320f000);
            }
            pbCode += 4;
        }
    }
#endif
    return pbCode;
}

inline PBYTE detour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit) {
#if defined(DETOURS_ARM32)
        write_arm_opcode(pbCode, 0xe320f000);
#elif defined(DETOURS_ARM)
        write_thumb_opcode(pbCode, 0xdefe);
#endif
    }
    return pbCode;
}

inline PBYTE detour_skip_jmp(PBYTE pbCode, PVOID *ppGlobals)
{
    if (pbCode == NULL) {
        return NULL;
    }
    ULONG * isThumb = NULL;
    if (ppGlobals != NULL) {
        isThumb = (ULONG *)*ppGlobals;
        *ppGlobals = NULL;
    }

    if (isThumb != nullptr && *isThumb == 1) {
        // read Thumb instruction set

        // Skip over the import jump if there is one.
        pbCode = (PBYTE)DETOURS_PFUNC_TO_PBYTE(pbCode);
        ULONG Opcode = fetch_thumb_opcode(pbCode);

        if ((Opcode & 0xfbf08f00) == 0xf2400c00) {          // movw r12,#xxxx
            ULONG Opcode2 = fetch_thumb_opcode(pbCode + 4);

            if ((Opcode2 & 0xfbf08f00) == 0xf2c00c00) {      // movt r12,#xxxx
                ULONG Opcode3 = fetch_thumb_opcode(pbCode + 8);
                if (Opcode3 == 0xf8dcf000) {                 // ldr  pc,[r12]
                    PBYTE pbTarget = (PBYTE)(((Opcode2 << 12) & 0xf7000000) |
                        ((Opcode2 << 1) & 0x08000000) |
                        ((Opcode2 << 16) & 0x00ff0000) |
                        ((Opcode >> 4) & 0x0000f700) |
                        ((Opcode >> 15) & 0x00000800) |
                        ((Opcode >> 0) & 0x000000ff));

                    if (detour_is_imported(pbCode, pbTarget)) {
                        PBYTE pbNew = *(PBYTE *)pbTarget;
                        pbNew = DETOURS_PFUNC_TO_PBYTE(pbNew);
                        DETOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
                        return pbNew;
                    }
                }
            }
        }
    }
    else {
        // read ARM instruction set
        // Skip over the import jump if there is one.
        
        ULONG Opcode = fetch_opcode(pbCode);

        if ((Opcode & 0xe28f0000) == 0xe28f0000) {          // adr r12, #xxxx
            ULONG Opcode2 = fetch_opcode(pbCode + 4);
            if ((Opcode2 & 0xe28c0000) == 0xe28c0000) {      // add r12, r12, #xxxx
                ULONG Opcode3 = fetch_opcode(pbCode + 8);
                if ((Opcode3 & 0xe5bcf000) == 0xe5bcf000) {             // ldr  pc,[r12]
                    ULONG target = (Opcode2 << 12) & 0x000FFFFF;
                    PBYTE pbTarget = /*(PBYTE)(((Opcode2 << 12) & 0xf7000000) |
                                     ((Opcode2 << 1) & 0x08000000) |
                                     ((Opcode2 << 16) & 0x00ff0000) |
                                     ((Opcode >> 4) & 0x0000f700) |
                                     ((Opcode >> 15) & 0x00000800) |
                                     ((Opcode >> 0) & 0x000000ff)); */

                                     //pbTarget = (PBYTE)(*(ULONG*)((pbCode + 8 + tgt + (Opcode3 & 0xFFF))));
                         ((pbCode + 8 + target + (Opcode3 & 0xFFF)));
                    if (detour_is_imported(pbCode, pbTarget)) {
                        PBYTE pbNew = *(PBYTE *)pbTarget;
                        pbNew = DETOURS_PFUNC_TO_PBYTE(pbNew);
                        DETOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
                        return pbNew;
                    }
                }
            }
        }
    }

    return pbCode;
}

inline void detour_find_jmp_bounds(PBYTE pbCode,
    PDETOUR_TRAMPOLINE *ppLower,
    PDETOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);
    DETOUR_TRACE(("[%p..%p..%p]\n", lo, pbCode, hi));

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}


inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    ULONG Opcode = fetch_thumb_opcode(pbCode);
    if ((Opcode & 0xffffff87) == 0x4700 ||          // bx <reg>
        (Opcode & 0xf800d000) == 0xf0009000) {      // b <imm20>
        return TRUE;
    }
    if ((Opcode & 0xffff8000) == 0xe8bd8000) {      // pop {...,pc}
        __debugbreak();
        return TRUE;
    }
    if ((Opcode & 0xffffff00) == 0x0000bd00) {      // pop {...,pc}
        __debugbreak();
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    if (pbCode[0] == 0x00 && pbCode[1] == 0xbf) { // nop.
        return 2;
    }
    if (pbCode[0] == 0x00 && pbCode[1] == 0x00) { // zero-filled padding.
        return 2;
    }
    return 0;
}

#endif // DETOURS_ARM

#ifdef DETOURS_ARM64

// must be aligned by 8
const ULONG DETOUR_TRAMPOLINE_CODE_SIZE = 0x158;

struct _DETOUR_TRAMPOLINE
{
    // Src: https://github.com/Microsoft/Detours/commit/c5cb6c3af5a6871df47131d6cc29d4262a412623
    // An ARM64 instruction is 4 bytes long.
    // The overwrite is always 2 instructions plus a literal, so 16 bytes, 4 instructions.
    //
    // Copied instructions can expand.
    //
    // The scheme using MovImmediate can cause an instruction
    // to grow as much as 6 times.
    // That would be Bcc or Tbz with a large address space:
    //   4 instructions to form immediate
    //   inverted tbz/bcc
    //   br
    //
    // An expansion of 4 is not uncommon -- bl/blr and small address space:
    //   3 instructions to form immediate
    //   br or brl
    //
    // A theoretical maximum for rbCode is thefore 4*4*6 + 16 = 112 (another 16 for jmp to pbRemain).
    //
    // With literals, the maximum expansion is 5, including the literals: 4*4*5 + 16 = 96.
    //
    // The number is rounded up to 128. m_rbScratchDst should match this.
    //
    BYTE               rbCode[128];     // target code + jmp to pbRemain
    BYTE               cbCode;         // size of moved target code.
    BYTE               cbCodeBreak[3]; // padding to make debugging easier.
    BYTE               rbRestore[24];  // original target code.
    BYTE               cbRestore;      // size of original target code.
    BYTE               cbRestoreBreak[3]; // padding to make debugging easier.
    _DETOUR_ALIGN      rAlign[8];      // instruction alignment array.
    PBYTE              pbRemain;       // first instruction after moved code. [free list]
    PBYTE              pbDetour;       // first instruction of detour function.
    HOOK_ACL           LocalACL;
    void*              Callback;
    ULONG              HLSIndex;
    ULONG              HLSIdent;
    TRACED_HOOK_HANDLE OutHandle; // handle returned to user  
    void*              Trampoline;
    void*              HookIntro; // . NET Intro function  
    UCHAR*             OldProc;  // old target function      
    void*              HookProc; // function we detour to
    void*              HookOutro;   // .NET Outro function  
    int*               IsExecutedPtr;
    BYTE               rbTrampolineCode[DETOUR_TRAMPOLINE_CODE_SIZE];
};

//C_ASSERT(sizeof(_DETOUR_TRAMPOLINE) == 1128);

enum {
    SIZE_OF_JMP = 16
};

inline ULONG fetch_opcode(PBYTE pbCode)
{
    return *(ULONG *)pbCode;
}

inline void write_opcode(PBYTE &pbCode, ULONG Opcode)
{
    *(ULONG *)pbCode = Opcode;
    pbCode += 4;
}

PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE *ppPool, PBYTE pbJmpVal)
{
    PBYTE pbLiteral;
    if (ppPool != NULL) {
        *ppPool = *ppPool - 8;
        pbLiteral = *ppPool;
    }
    else {
        pbLiteral = pbCode + 2 * 4;
    }

    *((PBYTE*&)pbLiteral) = pbJmpVal;
    LONG delta = (LONG)(pbLiteral - pbCode);

    write_opcode(pbCode, 0x58000011 | ((delta / 4) << 5));  // LDR X17,[PC+n]
    write_opcode(pbCode, 0xd61f0000 | (17 << 5));           // BR X17

    if (ppPool == NULL) {
        pbCode += 8;
    }
    return pbCode;
}

inline PBYTE detour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit) {
        write_opcode(pbCode, 0xd4100000 | (0xf000 << 5));
    }
    return pbCode;
}
inline INT64 detour_sign_extend(UINT64 value, UINT bits)
{
    const UINT left = 64 - bits;
    const INT64 m1 = -1;
    const INT64 wide = (INT64)(value << left);
    const INT64 sign = (wide < 0) ? (m1 << left) : 0;
    return value | sign;
}
inline PBYTE detour_skip_jmp(PBYTE pbCode, PVOID *ppGlobals)
{
    if (pbCode == NULL) {
        return NULL;
    }
    if (ppGlobals != NULL) {
        *ppGlobals = NULL;
    }
    // From here: https://github.com/Microsoft/Detours/pull/8
    // Skip over the import jump if there is one.
    pbCode = (PBYTE)pbCode;
    ULONG Opcode = fetch_opcode(pbCode);
    if ((Opcode & 0x9f00001f) == 0x90000010) {           // adrp  x16, IAT
        ULONG Opcode2 = fetch_opcode(pbCode + 4);

        if ((Opcode2 & 0xffe003fe) == 0xf9400210) {      // ldr   x16, [x16, IAT] | ldr   x17, [x16, IAT]
            ULONG Opcode3 = fetch_opcode(pbCode + 8);

            if ((Opcode3 & 0x91020210) == 0x91020210) {                 // ADD             X16, X16, IAT
                ULONG Opcode4 = fetch_opcode(pbCode + 0xC);
                if ((Opcode4 & 0xd61f0200) == 0xd61f0200) {                 // br    x16 | br x17
                    /* https://static.docs.arm.com/ddi0487/bb/DDI0487B_b_armv8_arm.pdf
                    The ADRP instruction shifts a signed, 21-bit immediate left by 12 bits, adds it to the value of the program counter with
                    the bottom 12 bits cleared to zero, and then writes the result to a general-purpose register. This permits the
                    calculation of the address at a 4KB aligned memory region. In conjunction with an ADD (immediate) instruction, or
                    a Load/Store instruction with a 12-bit immediate offset, this allows for the calculation of, or access to, any address
                    within 4GB of the current PC.
                    PC-rel. addressing
                    This section describes the encoding of the PC-rel. addressing instruction class. The encodings in this section are
                    decoded from Data Processing -- Immediate on page C4-226.
                    Add/subtract (immediate)
                    This section describes the encoding of the Add/subtract (immediate) instruction class. The encodings in this section
                    are decoded from Data Processing -- Immediate on page C4-226.
                    Decode fields
                    Instruction page
                    op
                    0 ADR
                    1 ADRP
                    C6.2.10 ADRP
                    Form PC-relative address to 4KB page adds an immediate value that is shifted left by 12 bits, to the PC value to
                    form a PC-relative address, with the bottom 12 bits masked out, and writes the result to the destination register.
                    ADRP <Xd>, <label>
                    imm = SignExtend(immhi:immlo:Zeros(12), 64);
                    31  30 29 28 27 26 25 24 23 5    4 0
                    1   immlo  1  0  0  0  0  immhi  Rd
                    9             0
                    Rd is hardcoded as 0x10 above.
                    Immediate is 21 signed bits split into 2 bits and 19 bits, and is scaled by 4K.
                    */
                    UINT64 const pageLow2 = (Opcode >> 29) & 3;
                    UINT64 const pageHigh19 = (Opcode >> 5) & ~(~(INT64)0 << 19);
                    INT64 const page = detour_sign_extend((pageHigh19 << 2) | pageLow2, 21) << 12;
                    
                    /* https://static.docs.arm.com/ddi0487/bb/DDI0487B_b_armv8_arm.pdf
                    C6.2.101 LDR (immediate)
                    Load Register (immediate) loads a word or doubleword from memory and writes it to a register. The address that is
                    used for the load is calculated from a base register and an immediate offset.
                    The Unsigned offset variant scales the immediate offset value by the size of the value accessed before adding it
                    to the base register value.
                    Unsigned offset
                    64-bit variant Applies when size == 11.
                    31 30 29 28  27 26 25 24  23 22  21   10   9 5   4 0
                    1  x  1  1   1  0  0  1   0  1  imm12      Rn    Rt
                    F             9        4              200    10
                    That is, two low 5 bit fields are registers, hardcoded as 0x10 and 0x10 << 5 above,
                    then unsigned size-unscaled (8) 12-bit offset, then opcode bits 0xF94.
                    */
                    UINT64 const offset = ((Opcode2 >> 10) & ~(~(INT64)0 << 12)) << 3;
                    
                    PBYTE const pbTarget = (PBYTE)((ULONG64)pbCode & 0xfffffffffffff000ULL) + page + offset;
                    if (detour_is_imported(pbCode, pbTarget)) {
                        PBYTE pbNew = *(PBYTE *)pbTarget;
                        DETOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
                        return pbNew;
                    }
                }
            }
        }
    }
    return pbCode;
}

inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    ULONG Opcode = fetch_opcode(pbCode);
    if ((Opcode & 0xfffffc1f) == 0xd65f0000 ||      // br <reg>
        (Opcode & 0xfc000000) == 0x14000000) {      // b <imm26>
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    if (*(ULONG *)pbCode == 0xd503201f) {   // nop.
        return 4;
    }
    if (*(ULONG *)pbCode == 0x00000000) {   // zero-filled padding.
        return 4;
    }
    return 0;
}
inline void detour_find_jmp_bounds(PBYTE pbCode,
    PDETOUR_TRAMPOLINE *ppLower,
    PDETOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);
    DETOUR_TRACE(("[%p..%p..%p]\n", lo, pbCode, hi));

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}
#endif // DETOURS_ARM64

//////////////////////////////////////////////// Trampoline Memory Management.
//
struct DETOUR_REGION
{
    ULONG               dwSignature;
    DETOUR_REGION *     pNext;  // Next region in list of regions.
    DETOUR_TRAMPOLINE * pFree;  // List of free trampolines in this region.
};
typedef DETOUR_REGION * PDETOUR_REGION;

const ULONG DETOUR_REGION_SIGNATURE = 'Rrtd';
const ULONG DETOUR_REGION_SIZE = 0x10000;
const ULONG DETOUR_TRAMPOLINES_PER_REGION = (DETOUR_REGION_SIZE
    / (sizeof(DETOUR_TRAMPOLINE))) - 1;
static PDETOUR_REGION s_pRegions = NULL;            // List of all regions.
static PDETOUR_REGION s_pRegion = NULL;             // Default region.

static DWORD detour_writable_trampoline_regions()
{
    // Mark all of the regions as writable.
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext) {
        if (mprotect(detour_get_page((PBYTE)pRegion), DETOUR_REGION_SIZE, PAGE_EXECUTE_READWRITE)) {
            // Failed
            return -1;
        }
    }
    return NO_ERROR;
}

static void detour_runnable_trampoline_regions()
{
    // Mark all of the regions as executable.
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext) {
        if (mprotect(detour_get_page((PBYTE)pRegion), DETOUR_REGION_SIZE, PAGE_EXECUTE_READ)) {
            // Failed
        }
    }
}

static PBYTE detour_alloc_round_down_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0) {
        pbTry -= extra;
    }
    return pbTry;
}

static PBYTE detour_alloc_round_up_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0) {
        ULONG_PTR adjust = DETOUR_REGION_SIZE - extra;
        pbTry += adjust;
    }
    return pbTry;
}

// Starting at pbLo, try to allocate a memory region, continue until pbHi.

static PVOID detour_alloc_region_from_lo(PBYTE pbLo, PBYTE pbHi)
{
    PBYTE pbTry = detour_alloc_round_up_to_region(pbLo);

    DETOUR_TRACE((" Looking for free region in %p..%p from %p:\n", pbLo, pbHi, pbTry));
    for (; pbTry < pbHi;) {
        PVOID pv = mmap(pbTry, DETOUR_REGION_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pv != NULL) {
            return pv;
        }
        pbTry += DETOUR_REGION_SIZE;

        //else {
        //pbTry = detour_alloc_round_up_to_region((PBYTE)mbi.BaseAddress + mbi.RegionSize);
        //}
    }
    /*
    for (; pbTry < pbHi;) {
    MEMORY_BASIC_INFORMATION mbi;

    if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound) {
    // Skip region reserved for system DLLs, but preserve address space entropy.
    pbTry += 0x08000000;
    continue;
    }

    ZeroMemory(&mbi, sizeof(mbi));
    if (!VirtualQuery(pbTry, &mbi, sizeof(mbi))) {
    break;
    }

    DETOUR_TRACE(("  Try %p => %p..%p %6x\n",
    pbTry,
    mbi.BaseAddress,
    (PBYTE)mbi.BaseAddress + mbi.RegionSize - 1,
    mbi.State));

    if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE) {

    PVOID pv = malloc(DETOUR_REGION_SIZE);
    VirtualAlloc(pbTry,
    DETOUR_REGION_SIZE,
    MEM_COMMIT|MEM_RESERVE,
    PAGE_EXECUTE_READWRITE);
    if (pv != NULL) {
    return pv;
    }
    pbTry += DETOUR_REGION_SIZE;
    }
    else {
    pbTry = detour_alloc_round_up_to_region((PBYTE)mbi.BaseAddress + mbi.RegionSize);
    }
    }
    */
    return NULL;
}

// Starting at pbHi, try to allocate a memory region, continue until pbLo.

static PVOID detour_alloc_region_from_hi(PBYTE pbLo, PBYTE pbHi)
{
    PBYTE pbTry = detour_alloc_round_down_to_region(pbHi - DETOUR_REGION_SIZE);
    DETOUR_TRACE((" Looking for free region in %p..%p from %p:\n", pbLo, pbHi, pbTry));
    for (; pbTry < pbHi;) {
        PVOID pv = mmap(pbTry, DETOUR_REGION_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pv != NULL) {
            return pv;
        }
        pbTry += DETOUR_REGION_SIZE;

        //else {
        //pbTry = detour_alloc_round_up_to_region((PBYTE)mbi.BaseAddress + mbi.RegionSize);
        //}
    }
    /*
    DETOUR_TRACE((" Looking for free region in %p..%p from %p:\n", pbLo, pbHi, pbTry));

    for (; pbTry > pbLo;) {
    MEMORY_BASIC_INFORMATION mbi;

    DETOUR_TRACE(("  Try %p\n", pbTry));
    if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound) {
    // Skip region reserved for system DLLs, but preserve address space entropy.
    pbTry -= 0x08000000;
    continue;
    }

    ZeroMemory(&mbi, sizeof(mbi));
    if (!VirtualQuery(pbTry, &mbi, sizeof(mbi))) {
    break;
    }

    DETOUR_TRACE(("  Try %p => %p..%p %6x\n",
    pbTry,
    mbi.BaseAddress,
    (PBYTE)mbi.BaseAddress + mbi.RegionSize - 1,
    mbi.State));

    if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE) {

    PVOID pv = VirtualAlloc(pbTry,
    DETOUR_REGION_SIZE,
    MEM_COMMIT|MEM_RESERVE,
    PAGE_EXECUTE_READWRITE);
    if (pv != NULL) {
    return pv;
    }
    pbTry -= DETOUR_REGION_SIZE;
    }
    else {
    pbTry = detour_alloc_round_down_to_region((PBYTE)mbi.AllocationBase
    - DETOUR_REGION_SIZE);
    }
    }
    */
    return NULL;
}

static PDETOUR_TRAMPOLINE detour_alloc_trampoline(PBYTE pbTarget)
{
    // We have to place trampolines within +/- 2GB of target.

    PDETOUR_TRAMPOLINE pLo;
    PDETOUR_TRAMPOLINE pHi;

    detour_find_jmp_bounds(pbTarget, &pLo, &pHi);

    PDETOUR_TRAMPOLINE pTrampoline = NULL;

    // Insure that there is a default region.
    if (s_pRegion == NULL && s_pRegions != NULL) {
        s_pRegion = s_pRegions;
    }

    // First check the default region for an valid free block.
    if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
        s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi) {

    found_region:
        pTrampoline = s_pRegion->pFree;
        // do a last sanity check on region.
        if (pTrampoline < pLo || pTrampoline > pHi) {
            return NULL;
        }
        s_pRegion->pFree = (PDETOUR_TRAMPOLINE)pTrampoline->pbRemain;
        memset(pTrampoline, 0xcc, sizeof(*pTrampoline));
        return pTrampoline;
    }

    // Then check the existing regions for a valid free block.
    for (s_pRegion = s_pRegions; s_pRegion != NULL; s_pRegion = s_pRegion->pNext) {
        if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
            s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi) {
            goto found_region;
        }
    }

    // We need to allocate a new region.

    // Round pbTarget down to 64KB block.
    pbTarget = pbTarget - (PtrToUlong(pbTarget) & 0xffff);

    PVOID pbTry = NULL;

    // NB: We must always also start the search at an offset from pbTarget
    //     in order to maintain ASLR entropy.

#if defined(DETOURS_64BIT)
    // Try looking 1GB below or lower.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000) {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget - 0x40000000);
    }
    // Try looking 1GB above or higher.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000) {
        pbTry = detour_alloc_region_from_lo(pbTarget + 0x40000000, (PBYTE)pHi);
    }
    // Try looking 1GB below or higher.
    if (pbTry == NULL && pbTarget >(PBYTE)0x40000000) {
        pbTry = detour_alloc_region_from_lo(pbTarget - 0x40000000, pbTarget);
    }
    // Try looking 1GB above or lower.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000) {
        pbTry = detour_alloc_region_from_hi(pbTarget, pbTarget + 0x40000000);
    }
#endif

    // Try anything below.
    if (pbTry == NULL) {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget);
    }
    // try anything above.
    if (pbTry == NULL) {
        pbTry = detour_alloc_region_from_lo(pbTarget, (PBYTE)pHi);
    }

    if (pbTry != NULL) {
        s_pRegion = (DETOUR_REGION*)pbTry;
        s_pRegion->dwSignature = DETOUR_REGION_SIGNATURE;
        s_pRegion->pFree = NULL;
        s_pRegion->pNext = s_pRegions;
        s_pRegions = s_pRegion;
        DETOUR_TRACE(("  Allocated region %p..%p\n\n",
            s_pRegion, ((PBYTE)s_pRegion) + DETOUR_REGION_SIZE - 1));

        // Put everything but the first trampoline on the free list.
        PBYTE pFree = NULL;
        pTrampoline = ((PDETOUR_TRAMPOLINE)s_pRegion) + 1;
        for (int i = DETOUR_TRAMPOLINES_PER_REGION - 1; i > 1; i--) {
            pTrampoline[i].pbRemain = pFree;
            pFree = (PBYTE)&pTrampoline[i];
        }
        s_pRegion->pFree = (PDETOUR_TRAMPOLINE)pFree;
        goto found_region;
    }

    DETOUR_TRACE(("Couldn't find available memory region!\n"));
    return NULL;
}

static void detour_free_trampoline(PDETOUR_TRAMPOLINE pTrampoline)
{
    PDETOUR_REGION pRegion = (PDETOUR_REGION)
        ((ULONG_PTR)pTrampoline & ~(ULONG_PTR)0xffff);
#if defined(DETOURS_X86) || defined(DETOURS_X64) || defined(DETOURS_ARM) || defined(DETOURS_ARM64)
    if (pTrampoline->IsExecutedPtr != NULL) {
        delete pTrampoline->IsExecutedPtr;
    }
    if (pTrampoline->OutHandle != NULL) {
        delete pTrampoline->OutHandle;
    }
    if (GlobalSlotList[pTrampoline->HLSIndex] == pTrampoline->HLSIdent)
    {
        GlobalSlotList[pTrampoline->HLSIndex] = 0;
    }
#endif
    memset(pTrampoline, 0, sizeof(*pTrampoline));
    pTrampoline->pbRemain = (PBYTE)pRegion->pFree;
    pRegion->pFree = pTrampoline;
}

static BOOL detour_is_region_empty(PDETOUR_REGION pRegion)
{
    // Stop if the region isn't a region (this would be bad).
    if (pRegion->dwSignature != DETOUR_REGION_SIGNATURE) {
        return FALSE;
    }

    PBYTE pbRegionBeg = (PBYTE)pRegion;
    PBYTE pbRegionLim = pbRegionBeg + DETOUR_REGION_SIZE;

    // Stop if any of the trampolines aren't free.
    PDETOUR_TRAMPOLINE pTrampoline = ((PDETOUR_TRAMPOLINE)pRegion) + 1;
    for (int i = 0; i < DETOUR_TRAMPOLINES_PER_REGION; i++) {
        if (pTrampoline[i].pbRemain != NULL &&
            (pTrampoline[i].pbRemain < pbRegionBeg ||
                pTrampoline[i].pbRemain >= pbRegionLim)) {
            return FALSE;
        }
    }

    // OK, the region is empty.
    return TRUE;
}

static void detour_free_unused_trampoline_regions()
{
    PDETOUR_REGION *ppRegionBase = &s_pRegions;
    PDETOUR_REGION pRegion = s_pRegions;

    while (pRegion != NULL) {
        if (detour_is_region_empty(pRegion)) {
            *ppRegionBase = pRegion->pNext;

            munmap(pRegion, DETOUR_REGION_SIZE);
            //VirtualFree(pRegion, 0, MEM_RELEASE);
            s_pRegion = NULL;
        }
        else {
            ppRegionBase = &pRegion->pNext;
        }
        pRegion = *ppRegionBase;
    }
}

///////////////////////////////////////////////////////// Transaction Structs.
//
struct DetourThread
{
    DetourThread *      pNext;
    HANDLE              hThread;
};

struct DetourOperation
{
    DetourOperation *   pNext;
    BOOL                fIsRemove;
    PBYTE *             ppbPointer;
    PBYTE               pbTarget;
    PDETOUR_TRAMPOLINE  pTrampoline;
    ULONG               dwPerm;
};

static BOOL                 s_fIgnoreTooSmall = FALSE;
static BOOL                 s_fRetainRegions = FALSE;

static LONG                 s_nPendingThreadId = 0; // Thread owning pending transaction.
static LONG                 s_nPendingError = NO_ERROR;
static PVOID *              s_ppPendingError = NULL;
static DetourThread *       s_pPendingThreads = NULL;
static DetourOperation *    s_pPendingOperations = NULL;

//////////////////////////////////////////////////////////////////////////////
//
PVOID DetourCodeFromPointer(_In_ PVOID pPointer,
    _Out_opt_ PVOID *ppGlobals)
{
    return detour_skip_jmp((PBYTE)pPointer, ppGlobals);
}

//////////////////////////////////////////////////////////// Transaction APIs.
//
BOOL DetourSetIgnoreTooSmall(_In_ BOOL fIgnore)
{
    BOOL fPrevious = s_fIgnoreTooSmall;
    s_fIgnoreTooSmall = fIgnore;
    return fPrevious;
}

BOOL DetourSetRetainRegions(_In_ BOOL fRetain)
{
    BOOL fPrevious = s_fRetainRegions;
    s_fRetainRegions = fRetain;
    return fPrevious;
}

PVOID DetourSetSystemRegionLowerBound(_In_ PVOID pSystemRegionLowerBound)
{
    PVOID pPrevious = s_pSystemRegionLowerBound;
    s_pSystemRegionLowerBound = pSystemRegionLowerBound;
    return pPrevious;
}

PVOID DetourSetSystemRegionUpperBound(_In_ PVOID pSystemRegionUpperBound)
{
    PVOID pPrevious = s_pSystemRegionUpperBound;
    s_pSystemRegionUpperBound = pSystemRegionUpperBound;
    return pPrevious;
}

LONG DetourTransactionBegin()
{
    // Only one transaction is allowed at a time.
    _Benign_race_begin_
        if (s_nPendingThreadId != 0) {
            return ERROR_INVALID_OPERATION;
        }
    _Benign_race_end_

        // Make sure only one thread can start a transaction.
        if (InterlockedCompareExchange(&s_nPendingThreadId, (LONG)pthread_self(), 0) != 0) {
            return ERROR_INVALID_OPERATION;
        }

    s_pPendingOperations = NULL;
    s_pPendingThreads = NULL;
    s_ppPendingError = NULL;

    // Make sure the trampoline pages are writable.
    s_nPendingError = detour_writable_trampoline_regions();

    return s_nPendingError;
}

LONG DetourTransactionAbort()
{
    if (s_nPendingThreadId != (LONG)pthread_self()) {
        return ERROR_INVALID_OPERATION;
    }

    // Restore all of the page permissions.
    for (DetourOperation *o = s_pPendingOperations; o != NULL;) {
        // We don't care if this fails, because the code is still accessible.
        //DWORD dwOld;
        //VirtualProtect(o->pbTarget, o->pTrampoline->cbRestore,
        //  o->dwPerm, &dwOld);
        mprotect(detour_get_page(o->pbTarget), detour_get_page_size(), PAGE_EXECUTE_READ);
        if (!o->fIsRemove) {
            if (o->pTrampoline) {
                detour_free_trampoline(o->pTrampoline);
                o->pTrampoline = NULL;
            }
        }

        DetourOperation *n = o->pNext;
        delete o;
        o = n;
    }
    s_pPendingOperations = NULL;

    // Make sure the trampoline pages are no longer writable.
    detour_runnable_trampoline_regions();

    // Resume any suspended threads.
    for (DetourThread *t = s_pPendingThreads; t != NULL;) {
        // There is nothing we can do if this fails.
        //ResumeThread(t->hThread);

        DetourThread *n = t->pNext;
        delete t;
        t = n;
    }
    s_pPendingThreads = NULL;
    s_nPendingThreadId = 0;

    return NO_ERROR;
}

LONG DetourTransactionCommit()
{
    return DetourTransactionCommitEx(NULL);
}

static BYTE detour_align_from_trampoline(PDETOUR_TRAMPOLINE pTrampoline, BYTE obTrampoline)
{
    for (LONG n = 0; n < ARRAYSIZE(pTrampoline->rAlign); n++) {
        if (pTrampoline->rAlign[n].obTrampoline == obTrampoline) {
            return pTrampoline->rAlign[n].obTarget;
        }
    }
    return 0;
}

static LONG detour_align_from_target(PDETOUR_TRAMPOLINE pTrampoline, LONG obTarget)
{
    for (LONG n = 0; n < ARRAYSIZE(pTrampoline->rAlign); n++) {
        if (pTrampoline->rAlign[n].obTarget == obTarget) {
            return pTrampoline->rAlign[n].obTrampoline;
        }
    }
    return 0;
}
static ULONG ___TrampolineSize = 0;


#ifdef DETOURS_X64
extern "C" {
    //extern void Trampoline_ASM_x64();
    extern void* trampoline_data_x64;
    extern void(*trampoline_template_x64)();
}
#endif

#ifdef DETOURS_X86
extern "C" void Trampoline_ASM_x86();
#endif

#ifdef DETOURS_ARM
//extern "C" void Trampoline_ASM_ARM();
//extern "C" void Trampoline_ASM_ARM_T();
#endif

#ifdef DETOURS_ARM64
//extern "C" void Trampoline_ASM_ARM64();
#endif

#if defined(DETOURS_X64) || defined(DETOURS_X86)
void* trampoline_template() {

    uintptr_t ret = 0;
#if defined(DETOURS_X64)
    ret = reinterpret_cast<uintptr_t>(&trampoline_template_x64);
#endif
    asm("" : "=rm"(ret)); // force compiler to abandon its assumption that ret is aligned
    //ret &= ~1;
    return reinterpret_cast<void*>(ret);
}

void* trampoline_data() {
#if defined(DETOURS_X64)
    return (&trampoline_data_x64);
#endif
    return nullptr;
}
UCHAR* DetourGetTrampolinePtr()
{
#ifdef DETOURS_X64
    UCHAR* Ptr = (UCHAR*)trampoline_template();
#endif

#ifdef DETOURS_X86
    UCHAR* Ptr = (UCHAR*)Trampoline_ASM_x86;
#endif

    if (*Ptr == 0xE9)
        Ptr += *((int*)(Ptr + 1)) + 5;

    return Ptr;  
}
ULONG GetTrampolineSize()
{
    if (___TrampolineSize != 0)
        return ___TrampolineSize;
    uint32_t code_size_ = reinterpret_cast<uintptr_t>(trampoline_data()) -
        reinterpret_cast<uintptr_t>(trampoline_template());

    ___TrampolineSize = code_size_;
    return ___TrampolineSize;
}
#endif
#if defined(DETOURS_ARM) || defined(DETOURS_ARM64)

extern "C" {

#if defined(_ARM64_)
    extern void* trampoline_data_arm_64;
    extern void(*trampoline_template_arm64)();
#elif defined(_ARM32_) || defined(_ARM_)
    extern void(*trampoline_template_thumb)();
    extern void(*trampoline_template_arm)();
    extern void* trampoline_data_thumb;
    extern void* trampoline_data_arm;
#endif
}
static ULONG ___TrampolineThumbSize = 0;

void* trampoline_template(ULONG isThumb) {
    uintptr_t ret = 0;
#if defined(_ARM64_)
    ret = reinterpret_cast<uintptr_t>(&trampoline_template_arm64);
#elif defined(_ARM32_) || defined(_ARM_)
    if (isThumb) {
        ret = reinterpret_cast<uintptr_t>(&trampoline_template_thumb);
    }
    else {
        ret = reinterpret_cast<uintptr_t>(&trampoline_template_arm);
    }
#endif
    asm("" : "=rm"(ret)); // force compiler to abandon its assumption that ret is aligned
    ret &= ~1;
    return reinterpret_cast<void*>(ret);
}
void* trampoline_data(ULONG isThumb) {
#if defined(_ARM64_)
    return (&trampoline_data_arm_64);
#elif defined(_ARM32_) || defined(_ARM_)
    if (isThumb) {
        return &trampoline_data_thumb;
    }
    else {
        return &trampoline_data_arm;
    }
#endif
    return nullptr;
}

UCHAR* DetourGetArmTrampolinePtr(ULONG isThumb)
{
    // bypass possible Visual Studio debug jump table
    UCHAR* Ptr = NULL;
#if defined(DETOURS_ARM)
    if (isThumb) {
        Ptr = static_cast<UCHAR*>(trampoline_template(isThumb));
    }
    else {
        Ptr = static_cast<UCHAR*>(trampoline_template(isThumb));
    }
#elif defined(DETOURS_ARM64)
    Ptr = (UCHAR*)trampoline_template(NULL);
#endif
    return Ptr;
}
ULONG GetTrampolineSize(ULONG isThumb)
{
    if (isThumb ) {
        if (___TrampolineThumbSize != 0) {
            return ___TrampolineThumbSize;
        }
    }
    else {
        if (___TrampolineSize != 0) {
            return ___TrampolineSize;
        }
    }
    uint32_t code_size_ = reinterpret_cast<uintptr_t>(trampoline_data(isThumb)) -
        reinterpret_cast<uintptr_t>(trampoline_template(isThumb));
    if (isThumb) {
        ___TrampolineThumbSize = code_size_;
    }
    else {
        ___TrampolineSize = code_size_;
    }
    return code_size_;
}
#endif

ULONGLONG BarrierIntro(DETOUR_TRAMPOLINE* InHandle, void* InRetAddr, void** InAddrOfRetAddr)
{
    /*
    Description:

    Will be called from assembler code and enters the
    thread deadlock barrier.
    */
    LPTHREAD_RUNTIME_INFO        Info;
    RUNTIME_INFO*                Runtime;
    BOOL                        Exists;

    DETOUR_TRACE(("Barrier Intro InHandle=%p, InRetAddr=%p, InAddrOfRetAddr=%p \n",
        InHandle, InRetAddr, InAddrOfRetAddr));

#if defined(DETOURS_X64) || defined(DETOURS_ARM) || defined(DETOURS_ARM64)
    InHandle = (DETOUR_TRAMPOLINE*)((PBYTE)(InHandle)-(sizeof(DETOUR_TRAMPOLINE) - DETOUR_TRAMPOLINE_CODE_SIZE));
#endif

    // are we in OS loader lock?
    if (IsLoaderLock())
    {
        /*
        Execution of managed code or even any other code within any loader lock
        may lead into unpredictable application behavior and therefore we just
        execute without intercepting the call...
        */

        /*  !!Note that the assembler code does not invoke DetourBarrierOutro() in this case!! */

        return FALSE;
    }

    // open pointer table
    Exists = TlsGetCurrentValue(&Unit.TLS, &Info);

    if (!Exists)
    {
        if (!TlsAddCurrentThread(&Unit.TLS))
            return FALSE;
    }

    /*
    To minimize APIs that can't be hooked, we are now entering the self protection.
    This will allow anybody to hook any APIs except those required to setup
    self protection.

    Self protection prevents any further hook interception for the current fiber,
    while setting up the "Thread Deadlock Barrier"...
    */
    if (!AcquireSelfProtection())
    {
        /*  !!Note that the assembler code does not invoke DetourBarrierOutro() in this case!! */

        return FALSE;
    }

    DETOUR_ASSERT(InHandle->HLSIndex < MAX_HOOK_COUNT, "detours.cpp - InHandle->HLSIndex < MAX_HOOK_COUNT");

    if (!Exists)
    {
        TlsGetCurrentValue(&Unit.TLS, &Info);

        Info->Entries = (RUNTIME_INFO*)RtlAllocateMemory(TRUE, sizeof(RUNTIME_INFO) * MAX_HOOK_COUNT);

        if (Info->Entries == NULL)
            goto DONT_INTERCEPT;
    }

    // get hook runtime info...
    Runtime = &Info->Entries[InHandle->HLSIndex];

    if (Runtime->HLSIdent != InHandle->HLSIdent)
    {
        // just reset execution information
        Runtime->HLSIdent = InHandle->HLSIdent;
        Runtime->IsExecuting = FALSE;
    }

    // detect loops in hook execution hiearchy.
    if (Runtime->IsExecuting)
    {
        /*
        This implies that actually the handler has invoked itself. Because of
        the special HookLocalStorage, this is now also signaled if other
        hooks invoked by the related handler are calling it again.

        I call this the "Thread deadlock barrier".

        !!Note that the assembler code does not invoke DetourBarrierOutro() in this case!!
        */

        goto DONT_INTERCEPT;
    }

    Info->Callback = InHandle->Callback;
    Info->Current = Runtime;

    /*
    Now we will negotiate thread/process access based on global and local ACL...
    */
    Runtime->IsExecuting = IsThreadIntercepted(&InHandle->LocalACL, pthread_self());

    if (!Runtime->IsExecuting)
        goto DONT_INTERCEPT;

    // save some context specific information
    Runtime->RetAddress = InRetAddr;
    Runtime->AddrOfRetAddr = InAddrOfRetAddr;

    ReleaseSelfProtection();
    
    return TRUE;

DONT_INTERCEPT:
    /*  !!Note that the assembler code does not invoke UnmanagedHookOutro() in this case!! */

    if (Info != NULL)
    {
        Info->Current = NULL;
        Info->Callback = NULL;

        ReleaseSelfProtection();
    }
    
    return FALSE;
}
void* BarrierOutro(DETOUR_TRAMPOLINE* InHandle, void** InAddrOfRetAddr)
{
    DETOUR_TRACE(("Barrier Outro InHandle=%p, InAddrOfRetAddr=%p \n",
        InHandle, InAddrOfRetAddr));
    
    /*
    Description:
    
    Will just reset the "thread deadlock barrier" for the current hook handler and provides
    some important integrity checks.

    The hook handle is just passed through, because the assembler code has no chance to
    save it in any efficient manner at this point of execution...
    */
    RUNTIME_INFO*            Runtime;
    LPTHREAD_RUNTIME_INFO    Info;
    
#if defined(DETOURS_X64) || defined(DETOURS_ARM) || defined(DETOURS_ARM64)
    InHandle = (DETOUR_TRAMPOLINE*)((PBYTE)(InHandle)-(sizeof(DETOUR_TRAMPOLINE) - DETOUR_TRAMPOLINE_CODE_SIZE));
    //InHandle -= 1;
#endif
    
    DETOUR_ASSERT(AcquireSelfProtection(), "detours.cpp - AcquireSelfProtection()");

    DETOUR_ASSERT(TlsGetCurrentValue(&Unit.TLS, &Info) && (Info != NULL), "detours.cpp - TlsGetCurrentValue(&Unit.TLS, &Info) && (Info != NULL)");

    Runtime = &Info->Entries[InHandle->HLSIndex];

    // leave handler context
    Info->Current = NULL;
    Info->Callback = NULL;

    DETOUR_ASSERT(Runtime != NULL, "detours.cpp - Runtime != NULL");

    DETOUR_ASSERT(Runtime->IsExecuting, "detours.cpp - Runtime->IsExecuting");

    Runtime->IsExecuting = FALSE;

    DETOUR_ASSERT(*InAddrOfRetAddr == NULL, "detours.cpp - *InAddrOfRetAddr == NULL");

    *InAddrOfRetAddr = Runtime->RetAddress;

    ReleaseSelfProtection();

    return InHandle;
}

TRACED_HOOK_HANDLE DetourGetHookHandleForFunction(PDETOUR_TRAMPOLINE pTrampoline)
{
    if (pTrampoline != NULL) {
        return pTrampoline->OutHandle;
    }
    return NULL;
}
LONG DetourSetCallbackForLocalHook(PDETOUR_TRAMPOLINE pTrampoline, PVOID pCallback)
{
    if (pTrampoline != NULL) {
        pTrampoline->Callback = pCallback;
        return 0;
    }

    return -1;
}

VOID InsertTraceHandle(PDETOUR_TRAMPOLINE pTrampoline)
{
    if (pTrampoline != NULL && pTrampoline->OutHandle != NULL) {
        memset(&pTrampoline->LocalACL, 0, sizeof(HOOK_ACL));

        TRACED_HOOK_HANDLE OutHandle = new HOOK_TRACE_INFO();

        pTrampoline->OutHandle = OutHandle;

        OutHandle->Link = pTrampoline;
    }
}
LONG AddTrampolineToGlobalList(PDETOUR_TRAMPOLINE pTrampoline)
{
    ULONG   Index;
    BOOL    Exists;
    // register in global HLS list
    RtlAcquireLock(&GlobalHookLock);
    {
        pTrampoline->HLSIdent = UniqueIDCounter++;

        Exists = FALSE;

        for (Index = 0; Index < MAX_HOOK_COUNT; Index++)
        {
            if (GlobalSlotList[Index] == 0)
            {
                GlobalSlotList[Index] = pTrampoline->HLSIdent;

                pTrampoline->HLSIndex = Index;

                Exists = TRUE;

                break;
            }
        }
    }
    RtlReleaseLock(&GlobalHookLock);

    return Exists;
}

LONG DetourExport DetourUninstallHook(TRACED_HOOK_HANDLE InHandle)
{
    /*
    Description:

    Removes the given hook. To also release associated resources,
    you will have to call DetourWaitForPendingRemovals(). In any case
    your hook handler will never be executed again, after calling this
    method.

    Parameters:

    - InHandle

    A traced hook handle. If the hook is already removed, this method
    will still return STATUS_SUCCESS.
    */
    LONG error = -1;

    PDETOUR_TRAMPOLINE      Hook = NULL;
    LONG                    NtStatus = -1;
    BOOLEAN                 IsAllocated = FALSE;

    if (!IsValidPointer(InHandle, sizeof(HOOK_TRACE_INFO)))
        return FALSE;

    RtlAcquireLock(&GlobalHookLock);
    {
        if ((InHandle->Link != NULL) && DetourIsValidHandle(InHandle, &Hook))
        {
            DetourTransactionBegin();
            DetourUpdateThread(pthread_self());
            DetourDetach(&(PVOID&)Hook->OldProc, Hook->pbDetour);

            InHandle->Link = NULL;

            if (Hook->HookProc != NULL)
            {
                Hook->HookProc = NULL;

                IsAllocated = TRUE;
            }

            error = DetourTransactionCommit();

            if (!IsAllocated)
            {
                RtlReleaseLock(&GlobalHookLock);

                RETURN;
            }
        }
    }
    RtlReleaseLock(&GlobalHookLock);

    RETURN(STATUS_SUCCESS);

FINALLY_OUTRO:
    return NtStatus;
}

LONG DetourIsThreadIntercepted(
    TRACED_HOOK_HANDLE InHook,
    ULONG InThreadID,
    BOOL* OutResult)
{
    /*
    Description:

    This method will negotiate whether a given thread passes
    the ACLs and would invoke the related hook handler. Refer
    to the source code of Is[Thread/Process]Intercepted() for more information
    about the implementation.

    */
    LONG                NtStatus;
    PLOCAL_HOOK_INFO    Handle;

    if (!DetourIsValidHandle(InHook, &Handle))
        THROW(-1, (PWCHAR)"The given hook handle is invalid or already disposed.");

    if (!IsValidPointer(OutResult, sizeof(BOOL)))
        THROW(-3, (PWCHAR)"Invalid pointer for result storage.");

    *OutResult = IsThreadIntercepted(&Handle->LocalACL, InThreadID);

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG DetourSetInclusiveACL(
    ULONG* InThreadIdList,
    ULONG InThreadCount,
    TRACED_HOOK_HANDLE InHandle)
{
    /*
    Description:

    Sets an inclusive hook local ACL based on the given thread ID list.
    Only threads in this list will be intercepted by the hook. If the
    global ACL also is inclusive, then all threads stated there are
    intercepted too.

    Parameters:
    - InThreadIdList
    An array of thread IDs. If you specific zero for an entry in this array,
    it will be automatically replaced with the calling thread ID.

    - InThreadCount
    The count of entries listed in the thread ID list. This value must not exceed
    MAX_ACE_COUNT!

    - InHandle
    The hook handle whose local ACL is going to be set.
    */
    PLOCAL_HOOK_INFO        Handle;

    if (!DetourIsValidHandle(InHandle, &Handle))
        return -3;

    return DetourSetACL(&Handle->LocalACL, FALSE, InThreadIdList, InThreadCount);
}

LONG DetourGetHookBypassAddress(
    TRACED_HOOK_HANDLE InHook,
    PVOID** OutAddress)
{
    /*
    Description:

    Retrieves the address to bypass the hook. Using the returned value to call the original
    function bypasses all thread safety measures and must be used with care.
    This function should be called each time the address is required to ensure the hook  and
    associated memory is still valid at the time of use.
    CAUTION:
    This must be used with extreme caution. If the hook is uninstalled and pending hooks
    removed, the address returned by this function will no longer point to valid memory and
    attempting to use the address will result in unexpected behaviour, most likely crashing
    the process.

    Parameters:

    - InHook

    The hook to retrieve the relocated entry point for.

    - OutAddress

    Upon successfully retrieving the hook details this will contain
    the address of the relocated function entry point. This address
    can be used to call the original function from outside of a hook
    while still bypassing the hook.

    Returns:

    STATUS_SUCCESS             - OutAddress will contain the result
    STATUS_INVALID_PARAMETER_1 - the hook is invalid
    STATUS_INVALID_PARAMETER_3 - the target pointer is invalid

    */
    LONG                NtStatus;
    PLOCAL_HOOK_INFO    Handle;

    if (!DetourIsValidHandle(InHook, &Handle))
        THROW(-1, (PWCHAR)"The given hook handle is invalid or already disposed.");

    if (!IsValidPointer(OutAddress, sizeof(PVOID*)))
        THROW(-3, (PWCHAR)"Invalid pointer for result storage.");

    *OutAddress = (PVOID*)Handle->OldProc;

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG DetourExport DetourInstallHook(
    void* InEntryPoint,
    void* InHookProc,
    void* InCallback,
    TRACED_HOOK_HANDLE OutHandle)
{
    /*
    Description:

    Installs a hook at the given entry point, redirecting all
    calls to the given hooking method. The returned handle will
    either be released on library unloading or explicitly through
    DetourUninstallHook() or DetourUninstallAllHooks().

    Parameters:

    - InEntryPoint

    An entry point to hook. Not all entry points are hookable. In such
    a case STATUS_NOT_SUPPORTED will be returned.

    - InHookProc

    The method that should be called instead of the given entry point.
    Please note that calling convention, parameter count and return value
    shall match EXACTLY!

    - InCallback

    An uninterpreted callback later available through
    DetourBarrierGetCallback().

    - OutPHandle

    The memory portion supplied by *OutHandle is expected to be preallocated
    by the caller. This structure is then filled by the method on success and
    must stay valid for hook-life time. Only if you explicitly call one of
    the hook uninstallation APIs, you can safely release the handle memory.

    Returns:

    STATUS_NO_MEMORY

    Unable to allocate memory around the target entry point.

    STATUS_NOT_SUPPORTED

    The target entry point contains unsupported instructions.

    STATUS_INSUFFICIENT_RESOURCES

    The limit of MAX_HOOK_COUNT simultaneous hooks was reached.

    */

    LONG    NtStatus = -1;
    LONG    error = -1;
    PDETOUR_TRAMPOLINE pTrampoline = NULL;

    // validate parameters
    if (!IsValidPointer(InEntryPoint, 1))
        THROW(-2, (PWCHAR)"Invalid entry point.");

    if (!IsValidPointer(InHookProc, 1))
        THROW(-3, (PWCHAR)"Invalid hook procedure.");
    
    if (!IsValidPointer(OutHandle, sizeof(HOOK_TRACE_INFO)))
        THROW(-4, (PWCHAR)"The hook handle storage is expected to be allocated by the caller.");

    if (OutHandle->Link != NULL)
        THROW(-5, (PWCHAR)"The given trace handle seems to already be associated with a hook.");

    error = DetourTransactionBegin();

    error = DetourUpdateThread(pthread_self());

    error = DetourAttachEx(&(PVOID &)InEntryPoint, InHookProc, &pTrampoline, NULL, NULL);

    if (error == NO_ERROR)
    {
        DetourSetCallbackForLocalHook(pTrampoline, InCallback);
    }
    error = DetourTransactionCommit();
    if (OutHandle != NULL && error == NO_ERROR)
    {
        TRACED_HOOK_HANDLE handle = DetourGetHookHandleForFunction(pTrampoline);
        if (handle != NULL) {
            OutHandle->Link = handle->Link;
        }        
    }
THROW_OUTRO:

    return error;
}

LONG DetourSetExclusiveACL(
    ULONG* InThreadIdList,
    ULONG InThreadCount,
    TRACED_HOOK_HANDLE InHandle)
{
    /*
    Description:

    Sets an exclusive hook local ACL based on the given thread ID list.

    Parameters:
    - InThreadIdList
    An array of thread IDs. If you specific zero for an entry in this array,
    it will be automatically replaced with the calling thread ID.

    - InThreadCount
    The count of entries listed in the thread ID list. This value must not exceed
    MAX_ACE_COUNT!

    - InHandle
    The hook handle whose local ACL is going to be set.
    */
    PLOCAL_HOOK_INFO        Handle;

    if (!DetourIsValidHandle(InHandle, &Handle))
        return -3;

    return DetourSetACL(&Handle->LocalACL, TRUE, InThreadIdList, InThreadCount);
}

LONG DetourTransactionCommitEx(_Out_opt_ PVOID **pppFailedPointer)
{
    if (pppFailedPointer != NULL) {
        // Used to get the last error.
        *pppFailedPointer = s_ppPendingError;
    }
    if (s_nPendingThreadId != (LONG)pthread_self()) {
        return ERROR_INVALID_OPERATION;
    }

    // If any of the pending operations failed, then we abort the whole transaction.
    if (s_nPendingError != NO_ERROR) {
        DETOUR_BREAK();
        DetourTransactionAbort();
        return s_nPendingError;
    }

    // Common variables.
    DetourOperation *o;
    DetourThread *t;
    BOOL freed = FALSE;

    // Insert or remove each of the detours.
    for (o = s_pPendingOperations; o != NULL; o = o->pNext) {
        if (o->fIsRemove) {
            CopyMemory(o->pbTarget,
                o->pTrampoline->rbRestore,
                o->pTrampoline->cbRestore);
#ifdef DETOURS_IA64
            *o->ppbPointer = (PBYTE)o->pTrampoline->ppldTarget;
#endif // DETOURS_IA64

#ifdef DETOURS_X86
            *o->ppbPointer = o->pbTarget;
#endif // DETOURS_X86

#ifdef DETOURS_X64
            *o->ppbPointer = o->pbTarget;
#endif // DETOURS_X64

#ifdef DETOURS_ARM
            *o->ppbPointer = DETOURS_PBYTE_TO_PFUNC(o->pbTarget);
#endif // DETOURS_ARM

#ifdef DETOURS_ARM64
            *o->ppbPointer = o->pbTarget;
#endif // DETOURS_ARM
        }
        else {
            DETOUR_TRACE(("detours: pbTramp =%p, pbRemain=%p, pbDetour=%p, cbRestore=%d\n",
                o->pTrampoline,
                o->pTrampoline->pbRemain,
                o->pTrampoline->pbDetour,
                o->pTrampoline->cbRestore));

            DETOUR_TRACE(("detours: pbTarget=%p: "
                "%02x %02x %02x %02x "
                "%02x %02x %02x %02x "
                "%02x %02x %02x %02x [before]\n",
                o->pbTarget,
                o->pbTarget[0], o->pbTarget[1], o->pbTarget[2], o->pbTarget[3],
                o->pbTarget[4], o->pbTarget[5], o->pbTarget[6], o->pbTarget[7],
                o->pbTarget[8], o->pbTarget[9], o->pbTarget[10], o->pbTarget[11]));

#ifdef DETOURS_IA64
            ((DETOUR_IA64_BUNDLE*)o->pbTarget)
                ->SetBrl((UINT64)&o->pTrampoline->bAllocFrame);
            *o->ppbPointer = (PBYTE)&o->pTrampoline->pldTrampoline;
#endif // DETOURS_IA64

#ifdef DETOURS_X64
            PBYTE trampoline = DetourGetTrampolinePtr();
            const ULONG TrampolineSize = GetTrampolineSize();
            if (TrampolineSize > DETOUR_TRAMPOLINE_CODE_SIZE) {
                //error, handle this better
                DETOUR_TRACE(("detours: TrampolineSize > DETOUR_TRAMPOLINE_CODE_SIZE (%08X != %08X)",
                    TrampolineSize, DETOUR_TRAMPOLINE_CODE_SIZE));
                LOG(FATAL) << "Invalid trampoline size: " << TrampolineSize;
            }
            PBYTE endOfTramp = (PBYTE)&o->pTrampoline->rbTrampolineCode;
            memcpy(endOfTramp, trampoline, TrampolineSize);
            o->pTrampoline->HookIntro = (PVOID)BarrierIntro;
            o->pTrampoline->HookOutro = (PVOID)BarrierOutro;
            o->pTrampoline->Trampoline = endOfTramp;
            o->pTrampoline->OldProc = o->pTrampoline->rbCode;
            o->pTrampoline->HookProc = o->pTrampoline->pbDetour;
            o->pTrampoline->IsExecutedPtr = new int();

            detour_gen_jmp_indirect(o->pTrampoline->rbCodeIn, (PBYTE*)&o->pTrampoline->Trampoline);
            PBYTE pbCode = detour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->rbCodeIn);
            pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);
#endif // DETOURS_X64

#ifdef DETOURS_X86
            PBYTE trampoline = DetourGetTrampolinePtr();
            const ULONG TrampolineSize = GetTrampolineSize();
            if (TrampolineSize > DETOUR_TRAMPOLINE_CODE_SIZE) {
                //error, handle this better
                DETOUR_TRACE(("detours: TrampolineSize > DETOUR_TRAMPOLINE_CODE_SIZE (%08X != %08X)",
                    TrampolineSize, DETOUR_TRAMPOLINE_CODE_SIZE));
                LOG(FATAL) << "Invalid trampoline size: " << TrampolineSize;

            }
            PBYTE endOfTramp = (PBYTE)&o->pTrampoline->rbTrampolineCode;
            memcpy(endOfTramp, trampoline, TrampolineSize);
            o->pTrampoline->HookIntro = BarrierIntro;
            o->pTrampoline->HookOutro = BarrierOutro;
            o->pTrampoline->Trampoline = endOfTramp;
            o->pTrampoline->OldProc = o->pTrampoline->rbCode;
            o->pTrampoline->HookProc = o->pTrampoline->pbDetour;
            o->pTrampoline->IsExecutedPtr = new int();
            PBYTE Ptr = (PBYTE)o->pTrampoline->Trampoline;
            for (ULONG Index = 0; Index < TrampolineSize; Index++)
            {
                switch (*((ULONG*)(Ptr)))
                {
                /*Handle*/            case 0x1A2B3C05: *((ULONG*)Ptr) = (ULONG)o->pTrampoline; break;
                /*UnmanagedIntro*/    case 0x1A2B3C03: *((ULONG*)Ptr) = (ULONG)o->pTrampoline->HookIntro; break;
                /*OldProc*/           case 0x1A2B3C01: *((ULONG*)Ptr) = (ULONG)o->pTrampoline->OldProc; break;
                /*Ptr:NewProc*/       case 0x1A2B3C07: *((ULONG*)Ptr) = (ULONG)&o->pTrampoline->HookProc; break;
                /*NewProc*/           case 0x1A2B3C00: *((ULONG*)Ptr) = (ULONG)o->pTrampoline->HookProc; break;
                /*UnmanagedOutro*/    case 0x1A2B3C06: *((ULONG*)Ptr) = (ULONG)o->pTrampoline->HookOutro; break;
                /*IsExecuted*/        case 0x1A2B3C02: *((ULONG*)Ptr) = (ULONG)o->pTrampoline->IsExecutedPtr; break;
                /*RetAddr*/           case 0x1A2B3C04: *((ULONG*)Ptr) = (ULONG)((PBYTE)o->pTrampoline->Trampoline + 92); break;
                }

                Ptr++;
            }

            PBYTE pbCode = detour_gen_jmp_immediate(o->pbTarget, (PBYTE)o->pTrampoline->Trampoline);
            pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);
#endif // DETOURS_X86

#ifdef DETOURS_ARM
            UCHAR * trampoline = DetourGetArmTrampolinePtr(o->pTrampoline->IsThumbTarget);
            const ULONG TrampolineSize = GetTrampolineSize(o->pTrampoline->IsThumbTarget);
            if (TrampolineSize > DETOUR_TRAMPOLINE_CODE_SIZE) {
                //error, handle this better
                DETOUR_TRACE(("detours: TrampolineSize > DETOUR_TRAMPOLINE_CODE_SIZE (%08X != %08X)",
                    TrampolineSize, DETOUR_TRAMPOLINE_CODE_SIZE));
                LOG(FATAL) << "Invalid trampoline size: " << TrampolineSize;
            }

            PBYTE endOfTramp = (PBYTE)&o->pTrampoline->rbTrampolineCode;

            PBYTE trampolineStart = align4(trampoline);
            // means thumb_to_arm thunk is not compiled
            uint32_t arm_to_thunk_code_size_offset = 0;
#if not defined(DETOURS_ARM32)
            // otherwise, copy to (trampoline + 4) to offset thumb_to_arm thunk code (byte size = 4)
            if (!o->pTrampoline->IsThumbTarget) {
                arm_to_thunk_code_size_offset = 4;
            }
#endif
            memcpy(endOfTramp + arm_to_thunk_code_size_offset, trampolineStart, TrampolineSize);

            o->pTrampoline->HookIntro = (PVOID)BarrierIntro;
            o->pTrampoline->HookOutro = (PVOID)BarrierOutro;
            if (o->pTrampoline->IsThumbTarget) {
                o->pTrampoline->Trampoline = DETOURS_PBYTE_TO_PFUNC(endOfTramp);
                o->pTrampoline->OldProc = DETOURS_PBYTE_TO_PFUNC(o->pTrampoline->rbCode);
                o->pTrampoline->HookProc = DETOURS_PBYTE_TO_PFUNC(o->pTrampoline->pbDetour);
                *o->ppbPointer = DETOURS_PBYTE_TO_PFUNC(o->pTrampoline->rbCode);
            }
            else {
                o->pTrampoline->Trampoline = (endOfTramp);
                o->pTrampoline->OldProc = (o->pTrampoline->rbCode);
                o->pTrampoline->HookProc = (o->pTrampoline->pbDetour);
                *o->ppbPointer = (o->pTrampoline->rbCode);
            }
            o->pTrampoline->IsExecutedPtr = new int();
            PBYTE pbCode = detour_gen_jmp_immediate(o->pbTarget + o->pTrampoline->IsThumbTarget, NULL,
                (PBYTE)o->pTrampoline->Trampoline + arm_to_thunk_code_size_offset);
            pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
    
            UNREFERENCED_PARAMETER(pbCode);
#endif // DETOURS_ARM

#ifdef DETOURS_ARM64
            UCHAR * trampolineStart = DetourGetArmTrampolinePtr(NULL);
            const ULONG TrampolineSize = GetTrampolineSize(NULL);
            if (TrampolineSize > DETOUR_TRAMPOLINE_CODE_SIZE) {
                //error, handle this better
                DETOUR_TRACE(("detours: TrampolineSize > DETOUR_TRAMPOLINE_CODE_SIZE (%08X != %08X)", 
                    TrampolineSize, DETOUR_TRAMPOLINE_CODE_SIZE));
                LOG(FATAL) << "Invalid trampoline size: " << TrampolineSize;
            }
            PBYTE endOfTramp = (PBYTE)&o->pTrampoline->rbTrampolineCode;
            memcpy(endOfTramp, trampolineStart, TrampolineSize);
            
            o->pTrampoline->HookIntro = (PVOID)BarrierIntro;
            o->pTrampoline->HookOutro = (PVOID)BarrierOutro;
            o->pTrampoline->Trampoline = endOfTramp;
            o->pTrampoline->OldProc = o->pTrampoline->rbCode;
            o->pTrampoline->HookProc = o->pTrampoline->pbDetour;
            o->pTrampoline->IsExecutedPtr = new int();
            PBYTE pbCode = detour_gen_jmp_immediate(o->pbTarget, NULL, (PBYTE)o->pTrampoline->Trampoline);
            pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);
#endif // DETOURS_ARM64
            
            DETOUR_TRACE(("detours: pbTarget=%p: "
                "%02x %02x %02x %02x "
                "%02x %02x %02x %02x "
                "%02x %02x %02x %02x [after]\n",
                o->pbTarget,
                o->pbTarget[0], o->pbTarget[1], o->pbTarget[2], o->pbTarget[3],
                o->pbTarget[4], o->pbTarget[5], o->pbTarget[6], o->pbTarget[7],
                o->pbTarget[8], o->pbTarget[9], o->pbTarget[10], o->pbTarget[11]));
            
            DETOUR_TRACE(("detours: pbTramp =%p: "
                "%02x %02x %02x %02x "
                "%02x %02x %02x %02x "
                "%02x %02x %02x %02x\n",
                o->pTrampoline,
                o->pTrampoline->rbCode[0], o->pTrampoline->rbCode[1],
                o->pTrampoline->rbCode[2], o->pTrampoline->rbCode[3],
                o->pTrampoline->rbCode[4], o->pTrampoline->rbCode[5],
                o->pTrampoline->rbCode[6], o->pTrampoline->rbCode[7],
                o->pTrampoline->rbCode[8], o->pTrampoline->rbCode[9],
                o->pTrampoline->rbCode[10], o->pTrampoline->rbCode[11]));

#ifdef DETOURS_IA64
            DETOUR_TRACE(("\n"));
            DETOUR_TRACE(("detours:  &pldTrampoline  =%p\n",
                &o->pTrampoline->pldTrampoline));
            DETOUR_TRACE(("detours:  &bMovlTargetGp  =%p [%p]\n",
                &o->pTrampoline->bMovlTargetGp,
                o->pTrampoline->bMovlTargetGp.GetMovlGp()));
            DETOUR_TRACE(("detours:  &rbCode         =%p [%p]\n",
                &o->pTrampoline->rbCode,
                ((DETOUR_IA64_BUNDLE&)o->pTrampoline->rbCode).GetBrlTarget()));
            DETOUR_TRACE(("detours:  &bBrlRemainEip  =%p [%p]\n",
                &o->pTrampoline->bBrlRemainEip,
                o->pTrampoline->bBrlRemainEip.GetBrlTarget()));
            DETOUR_TRACE(("detours:  &bMovlDetourGp  =%p [%p]\n",
                &o->pTrampoline->bMovlDetourGp,
                o->pTrampoline->bMovlDetourGp.GetMovlGp()));
            DETOUR_TRACE(("detours:  &bBrlDetourEip  =%p [%p]\n",
                &o->pTrampoline->bCallDetour,
                o->pTrampoline->bCallDetour.GetBrlTarget()));
            DETOUR_TRACE(("detours:  pldDetour       =%p [%p]\n",
                o->pTrampoline->ppldDetour->EntryPoint,
                o->pTrampoline->ppldDetour->GlobalPointer));
            DETOUR_TRACE(("detours:  pldTarget       =%p [%p]\n",
                o->pTrampoline->ppldTarget->EntryPoint,
                o->pTrampoline->ppldTarget->GlobalPointer));
            DETOUR_TRACE(("detours:  pbRemain        =%p\n",
                o->pTrampoline->pbRemain));
            DETOUR_TRACE(("detours:  pbDetour        =%p\n",
                o->pTrampoline->pbDetour));
            DETOUR_TRACE(("\n"));
#endif // DETOURS_IA64

            AddTrampolineToGlobalList(o->pTrampoline);
        }
    }


    // Update any suspended threads.
    for (t = s_pPendingThreads; t != NULL; t = t->pNext) {
        /*
        CONTEXT cxt;
        cxt.ContextFlags = CONTEXT_CONTROL;

        #undef DETOURS_EIP

        #ifdef DETOURS_X86
        #define DETOURS_EIP         Eip
        #endif // DETOURS_X86

        #ifdef DETOURS_X64
        #define DETOURS_EIP         Rip
        #endif // DETOURS_X64

        #ifdef DETOURS_IA64
        #define DETOURS_EIP         StIIP
        #endif // DETOURS_IA64

        #ifdef DETOURS_ARM
        #define DETOURS_EIP         Pc
        #endif // DETOURS_ARM

        #ifdef DETOURS_ARM64
        #define DETOURS_EIP         Pc
        #endif // DETOURS_ARM64

        typedef ULONG_PTR DETOURS_EIP_TYPE;

        if (GetThreadContext(t->hThread, &cxt)) {
        for (o = s_pPendingOperations; o != NULL; o = o->pNext) {
        if (o->fIsRemove) {
        if (cxt.DETOURS_EIP >= (DETOURS_EIP_TYPE)(ULONG_PTR)o->pTrampoline &&
        cxt.DETOURS_EIP < (DETOURS_EIP_TYPE)((ULONG_PTR)o->pTrampoline
        + sizeof(o->pTrampoline))
        ) {

        cxt.DETOURS_EIP = (DETOURS_EIP_TYPE)
        ((ULONG_PTR)o->pbTarget
        + detour_align_from_trampoline(o->pTrampoline,
        (BYTE)(cxt.DETOURS_EIP
        - (DETOURS_EIP_TYPE)(ULONG_PTR)
        o->pTrampoline)));

        SetThreadContext(t->hThread, &cxt);
        }
        }
        else {
        if (cxt.DETOURS_EIP >= (DETOURS_EIP_TYPE)(ULONG_PTR)o->pbTarget &&
        cxt.DETOURS_EIP < (DETOURS_EIP_TYPE)((ULONG_PTR)o->pbTarget
        + o->pTrampoline->cbRestore)
        ) {

        cxt.DETOURS_EIP = (DETOURS_EIP_TYPE)
        ((ULONG_PTR)o->pTrampoline
        + detour_align_from_target(o->pTrampoline,
        (BYTE)(cxt.DETOURS_EIP
        - (DETOURS_EIP_TYPE)(ULONG_PTR)
        o->pbTarget)));

        SetThreadContext(t->hThread, &cxt);
        }
        }
        }
        }
        */
#undef DETOURS_EIP
    }

    // Restore all of the page permissions and flush the icache.
    //HANDLE hProcess = GetCurrentProcess();
    for (o = s_pPendingOperations; o != NULL;) {

        // We don't care if this fails, because the code is still accessible.
        mprotect(detour_get_page(o->pbTarget), detour_get_page_size(), PAGE_EXECUTE_READ);

        if (o->fIsRemove && o->pTrampoline) {
            detour_free_trampoline(o->pTrampoline);
            o->pTrampoline = NULL;
            freed = true;
        }

        DetourOperation *n = o->pNext;
        delete o;
        o = n;
    }
    s_pPendingOperations = NULL;

    // Free any trampoline regions that are now unused.
    if (freed && !s_fRetainRegions) {
        detour_free_unused_trampoline_regions();
    }

    // Make sure the trampoline pages are no longer writable.
    detour_runnable_trampoline_regions();

    // Resume any suspended threads.
    for (t = s_pPendingThreads; t != NULL;) {
        // There is nothing we can do if this fails.
        //ResumeThread(t->hThread);

        DetourThread *n = t->pNext;
        delete t;
        t = n;
    }
    s_pPendingThreads = NULL;
    s_nPendingThreadId = 0;

    if (pppFailedPointer != NULL) {
        *pppFailedPointer = s_ppPendingError;
    }

    return s_nPendingError;
}

LONG DetourUpdateThread(_In_ pthread_t hThread)
{
    /*
    LONG error;

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != NO_ERROR) {
    return s_nPendingError;
    }

    // Silently (and safely) drop any attempt to suspend our own thread.
    if (hThread == GetCurrentThread()) {
    return NO_ERROR;
    }

    DetourThread *t = new NOTHROW DetourThread;
    if (t == NULL) {
    error = ERROR_NOT_ENOUGH_MEMORY;
    fail:
    if (t != NULL) {
    delete t;
    t = NULL;
    }
    s_nPendingError = error;
    s_ppPendingError = NULL;
    DETOUR_BREAK();
    return error;
    }

    if (SuspendThread(hThread) == (DWORD)-1) {
    error = GetLastError();
    DETOUR_BREAK();
    goto fail;
    }

    t->hThread = hThread;
    t->pNext = s_pPendingThreads;
    s_pPendingThreads = t;
    */
    return NO_ERROR;
}

const unsigned int max_print_buffer_size = 1024;

char buffer_print[max_print_buffer_size];
const char* ___DETOUR_TRACE(const char *format, ...)
{
    memset(buffer_print, 0, max_print_buffer_size);
    va_list arg;

    va_start(arg, format);
    vsnprintf(buffer_print, max_print_buffer_size, format, arg);
    va_end(arg);

    return buffer_print;
}
///////////////////////////////////////////////////////////// Transacted APIs.
//
LONG DetourAttach(_Inout_ PVOID *ppPointer,
    _In_ PVOID pDetour)
{
    return DetourAttachEx(ppPointer, pDetour, NULL, NULL, NULL);
}

LONG DetourAttachEx(_Inout_ PVOID *ppPointer,
    _In_ PVOID pDetour,
    _Out_opt_ PDETOUR_TRAMPOLINE *ppRealTrampoline,
    _Out_opt_ PVOID *ppRealTarget,
    _Out_opt_ PVOID *ppRealDetour)
{
    LONG error = NO_ERROR;

    if (ppRealTrampoline != NULL) {
        *ppRealTrampoline = NULL;
    }
    if (ppRealTarget != NULL) {
        *ppRealTarget = NULL;
    }
    if (ppRealDetour != NULL) {
        *ppRealDetour = NULL;
    }
    if (pDetour == NULL) {
        DETOUR_TRACE(("empty detour\n"));
        return ERROR_INVALID_PARAMETER;
    }

    if (s_nPendingThreadId != (LONG)pthread_self()) {
        DETOUR_TRACE(("transaction conflict with thread id=%d\n", s_nPendingThreadId));
        return ERROR_INVALID_OPERATION;
    }

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != NO_ERROR) {
        DETOUR_TRACE(("pending transaction error=%d\n", s_nPendingError));
        return s_nPendingError;
    }

    if (ppPointer == NULL) {
        DETOUR_TRACE(("ppPointer is null\n"));
        return ERROR_INVALID_HANDLE;
    }
    if (*ppPointer == NULL) {
        error = ERROR_INVALID_HANDLE;
        s_nPendingError = error;
        s_ppPendingError = ppPointer;
        DETOUR_TRACE(("*ppPointer is null (ppPointer=%p)\n", ppPointer));
        DETOUR_BREAK();
        return error;
    }

    PBYTE pbTarget = (PBYTE)*ppPointer;
    PDETOUR_TRAMPOLINE pTrampoline = NULL;
    DetourOperation *o = NULL;

#ifdef DETOURS_IA64
    PPLABEL_DESCRIPTOR ppldDetour = (PPLABEL_DESCRIPTOR)pDetour;
    PPLABEL_DESCRIPTOR ppldTarget = (PPLABEL_DESCRIPTOR)pbTarget;
    PVOID pDetourGlobals = NULL;
    PVOID pTargetGlobals = NULL;

    pDetour = (PBYTE)DetourCodeFromPointer(ppldDetour, &pDetourGlobals);
    pbTarget = (PBYTE)DetourCodeFromPointer(ppldTarget, &pTargetGlobals);
    DETOUR_TRACE(("  ppldDetour=%p, code=%p [gp=%p]\n",
        ppldDetour, pDetour, pDetourGlobals));
    DETOUR_TRACE(("  ppldTarget=%p, code=%p [gp=%p]\n",
        ppldTarget, pbTarget, pTargetGlobals));
#else // DETOURS_IA64
#ifdef DETOURS_ARM
    ULONG IsThumbTarget = (ULONG)pbTarget & 1;
    PVOID pGlobals = &IsThumbTarget;
#else 
    PVOID pGlobals = NULL;
#endif
    pbTarget = (PBYTE)DetourCodeFromPointer(pbTarget, &(PVOID &)pGlobals);
    pDetour = DetourCodeFromPointer(pDetour, &(PVOID &)pGlobals);
#endif // !DETOURS_IA64

    // Don't follow a jump if its destination is the target function.
    // This happens when the detour does nothing other than call the target.
    if (pDetour == (PVOID)pbTarget) {
        if (s_fIgnoreTooSmall) {
            goto stop;
        }
        else {
            DETOUR_BREAK();
            goto fail;
        }
    }

    if (ppRealTarget != NULL) {
        *ppRealTarget = pbTarget;
    }
    if (ppRealDetour != NULL) {
        *ppRealDetour = pDetour;
    }

    o = new NOTHROW DetourOperation;
    if (o == NULL) {
        error = ERROR_NOT_ENOUGH_MEMORY;
    fail:
        s_nPendingError = error;
        DETOUR_BREAK();
    stop:
        if (pTrampoline != NULL) {
            detour_free_trampoline(pTrampoline);
            pTrampoline = NULL;
            if (ppRealTrampoline != NULL) {
                *ppRealTrampoline = NULL;
            }
        }
        if (o != NULL) {
            delete o;
            o = NULL;
        }
        s_ppPendingError = ppPointer;
        return error;
    }

    pTrampoline = detour_alloc_trampoline(pbTarget);
    if (pTrampoline == NULL) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        DETOUR_BREAK();
        goto fail;
    }

    if (ppRealTrampoline != NULL) {
        *ppRealTrampoline = pTrampoline;
    }

    DETOUR_TRACE(("detours: pbTramp=%p, pDetour=%p\n", pTrampoline, pDetour));

    memset(pTrampoline->rAlign, 0, sizeof(pTrampoline->rAlign));

    // Determine the number of movable target instructions.
    PBYTE pbSrc = pbTarget;
    PBYTE pbTrampoline = pTrampoline->rbCode;
#ifdef DETOURS_IA64
    PBYTE pbPool = (PBYTE)(&pTrampoline->bBranchIslands + 1);
#else
    PBYTE pbPool = pbTrampoline + sizeof(pTrampoline->rbCode);
#endif
    ULONG cbTarget = 0;
    ULONG cbJump = SIZE_OF_JMP;
    ULONG nAlign = 0;

#ifdef DETOURS_ARM

    // On ARM, we need an extra instruction when the function isn't 32-bit aligned.
    // Check if the existing code is another detour (or at least a similar
    // "ldr pc, [PC+0]" jump.
    pTrampoline->IsThumbTarget = IsThumbTarget;

    if ((ULONG)pbTarget & 2) {
        cbJump += 2;

        ULONG op = fetch_thumb_opcode(pbSrc);
        if (op == 0xbf00) {
            op = fetch_thumb_opcode(pbSrc + 2);
            if (op == 0xf8dff000) { // LDR PC,[PC]
                *((PUSHORT&)pbTrampoline)++ = *((PUSHORT&)pbSrc)++;
                *((PULONG&)pbTrampoline)++ = *((PULONG&)pbSrc)++;
                *((PULONG&)pbTrampoline)++ = *((PULONG&)pbSrc)++;
                cbTarget = (LONG)(pbSrc - pbTarget);
                // We will fall through the "while" because cbTarget is now >= cbJump.
            }
        }
    }
    else {
        ULONG op = fetch_thumb_opcode(pbSrc);
        if (op == 0xf8dff000) { // LDR PC,[PC]
            *((PULONG&)pbTrampoline)++ = *((PULONG&)pbSrc)++;
            *((PULONG&)pbTrampoline)++ = *((PULONG&)pbSrc)++;
            cbTarget = (LONG)(pbSrc - pbTarget);
            // We will fall through the "while" because cbTarget is now >= cbJump.
        }
    }
#endif

    while (cbTarget < cbJump) {
        PBYTE pbOp = pbSrc;
#ifdef DETOURS_ARM
        LONG lExtra = IsThumbTarget;
#else
        LONG lExtra = NULL;
#endif
        DETOUR_TRACE((" DetourCopyInstruction(%p,%p)\n",
            pbTrampoline, pbSrc));
        pbSrc = (PBYTE)
            DetourCopyInstruction(pbTrampoline, (PVOID*)&pbPool, pbSrc, NULL, &lExtra);
        DETOUR_TRACE((" DetourCopyInstruction() = %p (%d bytes)\n",
            pbSrc, (int)(pbSrc - pbOp)));
        pbTrampoline += (pbSrc - pbOp) + lExtra;
        cbTarget = (LONG)(pbSrc - pbTarget);
        pTrampoline->rAlign[nAlign].obTarget = cbTarget;
        pTrampoline->rAlign[nAlign].obTrampoline = pbTrampoline - pTrampoline->rbCode;
        nAlign++;

        if (nAlign >= ARRAYSIZE(pTrampoline->rAlign)) {
            break;
        }

        if (detour_does_code_end_function(pbOp)) {
            break;
        }
    }

    // Consume, but don't duplicate padding if it is needed and available.
    while (cbTarget < cbJump) {
        LONG cFiller = detour_is_code_filler(pbSrc);
        if (cFiller == 0) {
            break;
        }

        pbSrc += cFiller;
        cbTarget = (LONG)(pbSrc - pbTarget);
    }

#if DETOUR_DEBUG
    {
        DETOUR_TRACE((" detours: rAlign ["));
        LONG n = 0;
        for (n = 0; n < ARRAYSIZE(pTrampoline->rAlign); n++) {
            if (pTrampoline->rAlign[n].obTarget == 0 &&
                pTrampoline->rAlign[n].obTrampoline == 0) {
                break;
            }
            DETOUR_TRACE((" %d/%d",
                pTrampoline->rAlign[n].obTarget,
                pTrampoline->rAlign[n].obTrampoline
                ));

        }
        DETOUR_TRACE((" ]\n"));
    }
#endif

    if (cbTarget < cbJump || nAlign > ARRAYSIZE(pTrampoline->rAlign)) {
        // Too few instructions.

        error = ERROR_INVALID_BLOCK;
        if (s_fIgnoreTooSmall) {
            goto stop;
        }
        else {
            DETOUR_BREAK();
            goto fail;
        }
    }

    if (pbTrampoline > pbPool) {
        __debugbreak();
    }

    pTrampoline->cbCode = (BYTE)(pbTrampoline - pTrampoline->rbCode);
    pTrampoline->cbRestore = (BYTE)cbTarget;
    CopyMemory(pTrampoline->rbRestore, pbTarget, cbTarget);

#if !defined(DETOURS_IA64)
    if (cbTarget > sizeof(pTrampoline->rbCode) - cbJump) {
        // Too many instructions.
        error = ERROR_INVALID_HANDLE;
        DETOUR_BREAK();
        goto fail;
    }
#endif // !DETOURS_IA64

    pTrampoline->pbRemain = pbTarget + cbTarget;
    pTrampoline->pbDetour = (PBYTE)pDetour;

    InsertTraceHandle(pTrampoline);

#ifdef DETOURS_IA64
    pTrampoline->ppldDetour = ppldDetour;
    pTrampoline->ppldTarget = ppldTarget;
    pTrampoline->pldTrampoline.EntryPoint = (UINT64)&pTrampoline->bMovlTargetGp;
    pTrampoline->pldTrampoline.GlobalPointer = (UINT64)pDetourGlobals;

    ((DETOUR_IA64_BUNDLE *)pTrampoline->rbCode)->SetStop();

    pTrampoline->bMovlTargetGp.SetMovlGp((UINT64)pTargetGlobals);
    pTrampoline->bBrlRemainEip.SetBrl((UINT64)pTrampoline->pbRemain);

    // Alloc frame:      alloc r41=ar.pfs,11,0,8,0; mov r40=rp
    pTrampoline->bAllocFrame.wide[0] = 0x00000580164d480c;
    pTrampoline->bAllocFrame.wide[1] = 0x00c4000500000200;
    // save r36, r37, r38.
    pTrampoline->bSave37to39.wide[0] = 0x031021004e019001;
    pTrampoline->bSave37to39.wide[1] = 0x8401280600420098;
    // save r34,r35,r36: adds r47=0,r36; adds r46=0,r35; adds r45=0,r34
    pTrampoline->bSave34to36.wide[0] = 0x02e0210048017800;
    pTrampoline->bSave34to36.wide[1] = 0x84011005a042008c;
    // save gp,r32,r33"  adds r44=0,r33; adds r43=0,r32; adds r42=0,gp ;;
    pTrampoline->bSaveGPto33.wide[0] = 0x02b0210042016001;
    pTrampoline->bSaveGPto33.wide[1] = 0x8400080540420080;
    // set detour GP.
    pTrampoline->bMovlDetourGp.SetMovlGp((UINT64)pDetourGlobals);
    // call detour:      brl.call.sptk.few rp=detour ;;
    pTrampoline->bCallDetour.wide[0] = 0x0000000100000005;
    pTrampoline->bCallDetour.wide[1] = 0xd000001000000000;
    pTrampoline->bCallDetour.SetBrlTarget((UINT64)pDetour);
    // pop frame & gp:   adds gp=0,r42; mov rp=r40,+0;; mov.i ar.pfs=r41
    pTrampoline->bPopFrameGp.wide[0] = 0x4000210054000802;
    pTrampoline->bPopFrameGp.wide[1] = 0x00aa029000038005;
    // return to caller: br.ret.sptk.many rp ;;
    pTrampoline->bReturn.wide[0] = 0x0000000100000019;
    pTrampoline->bReturn.wide[1] = 0x0084000880000200;

    DETOUR_TRACE(("detours: &bMovlTargetGp=%p\n", &pTrampoline->bMovlTargetGp));
    DETOUR_TRACE(("detours: &bMovlDetourGp=%p\n", &pTrampoline->bMovlDetourGp));
#endif // DETOURS_IA64

    pbTrampoline = pTrampoline->rbCode + pTrampoline->cbCode;
#ifdef DETOURS_X64
    pbTrampoline = detour_gen_jmp_indirect(pbTrampoline, &pTrampoline->pbRemain);
    pbTrampoline = detour_gen_brk(pbTrampoline, pbPool);
#endif // DETOURS_X64

#ifdef DETOURS_X86
    pbTrampoline = detour_gen_jmp_immediate(pbTrampoline, pTrampoline->pbRemain);
    pbTrampoline = detour_gen_brk(pbTrampoline, pbPool);
#endif // DETOURS_X86

#ifdef DETOURS_ARM
    pbTrampoline = detour_gen_jmp_immediate(pbTrampoline + pTrampoline->IsThumbTarget, &pbPool, pTrampoline->pbRemain);
    pbTrampoline = detour_gen_brk(pbTrampoline, pbPool);
#endif // DETOURS_ARM

#ifdef DETOURS_ARM64
    pbTrampoline = detour_gen_jmp_immediate(pbTrampoline, &pbPool, pTrampoline->pbRemain);
    pbTrampoline = detour_gen_brk(pbTrampoline, pbPool);
#endif // DETOURS_ARM64

    (void)pbTrampoline;

    DWORD dwOld = PAGE_EXECUTE_READ;

    if (mprotect(detour_get_page(pbTarget), detour_get_page_size(), PAGE_EXECUTE_READWRITE)) {
        error = -1;
        DETOUR_BREAK();
        goto fail;
    }


    DETOUR_TRACE(("detours: pbTarget=%p: "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x\n",
        pbTarget,
        pbTarget[0], pbTarget[1], pbTarget[2], pbTarget[3],
        pbTarget[4], pbTarget[5], pbTarget[6], pbTarget[7],
        pbTarget[8], pbTarget[9], pbTarget[10], pbTarget[11]));
    DETOUR_TRACE(("detours: pbTramp =%p: "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x\n",
        pTrampoline,
        pTrampoline->rbCode[0], pTrampoline->rbCode[1],
        pTrampoline->rbCode[2], pTrampoline->rbCode[3],
        pTrampoline->rbCode[4], pTrampoline->rbCode[5],
        pTrampoline->rbCode[6], pTrampoline->rbCode[7],
        pTrampoline->rbCode[8], pTrampoline->rbCode[9],
        pTrampoline->rbCode[10], pTrampoline->rbCode[11]));

    o->fIsRemove = FALSE;
    o->ppbPointer = (PBYTE*)ppPointer;
    o->pTrampoline = pTrampoline;
    o->pbTarget = pbTarget;
    o->dwPerm = dwOld;
    o->pNext = s_pPendingOperations;
    s_pPendingOperations = o;

    return NO_ERROR;
}

LONG DetourDetach(_Inout_ PVOID *ppPointer,
    _In_ PVOID pDetour)
{
    LONG error = NO_ERROR;

    if (s_nPendingThreadId != (LONG)pthread_self()) {
        return ERROR_INVALID_OPERATION;
    }

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != NO_ERROR) {
        return s_nPendingError;
    }

    if (pDetour == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (ppPointer == NULL) {
        return ERROR_INVALID_HANDLE;
    }
    if (*ppPointer == NULL) {
        error = ERROR_INVALID_HANDLE;
        s_nPendingError = error;
        s_ppPendingError = ppPointer;
        DETOUR_BREAK();
        return error;
    }

    DetourOperation *o = new NOTHROW DetourOperation;
    if (o == NULL) {
        error = ERROR_NOT_ENOUGH_MEMORY;
    fail:
        s_nPendingError = error;
        DETOUR_BREAK();
    stop:
        if (o != NULL) {
            delete o;
            o = NULL;
        }
        s_ppPendingError = ppPointer;
        return error;
    }


#ifdef DETOURS_IA64
    PPLABEL_DESCRIPTOR ppldTrampo = (PPLABEL_DESCRIPTOR)*ppPointer;
    PPLABEL_DESCRIPTOR ppldDetour = (PPLABEL_DESCRIPTOR)pDetour;
    PVOID pDetourGlobals = NULL;
    PVOID pTrampoGlobals = NULL;

    pDetour = (PBYTE)DetourCodeFromPointer(ppldDetour, &pDetourGlobals);
    PDETOUR_TRAMPOLINE pTrampoline = (PDETOUR_TRAMPOLINE)
        DetourCodeFromPointer(ppldTrampo, &pTrampoGlobals);
    DETOUR_TRACE(("  ppldDetour=%p, code=%p [gp=%p]\n",
        ppldDetour, pDetour, pDetourGlobals));
    DETOUR_TRACE(("  ppldTrampo=%p, code=%p [gp=%p]\n",
        ppldTrampo, pTrampoline, pTrampoGlobals));


    DETOUR_TRACE(("\n"));
    DETOUR_TRACE(("detours:  &pldTrampoline  =%p\n",
        &pTrampoline->pldTrampoline));
    DETOUR_TRACE(("detours:  &bMovlTargetGp  =%p [%p]\n",
        &pTrampoline->bMovlTargetGp,
        pTrampoline->bMovlTargetGp.GetMovlGp()));
    DETOUR_TRACE(("detours:  &rbCode         =%p [%p]\n",
        &pTrampoline->rbCode,
        ((DETOUR_IA64_BUNDLE&)pTrampoline->rbCode).GetBrlTarget()));
    DETOUR_TRACE(("detours:  &bBrlRemainEip  =%p [%p]\n",
        &pTrampoline->bBrlRemainEip,
        pTrampoline->bBrlRemainEip.GetBrlTarget()));
    DETOUR_TRACE(("detours:  &bMovlDetourGp  =%p [%p]\n",
        &pTrampoline->bMovlDetourGp,
        pTrampoline->bMovlDetourGp.GetMovlGp()));
    DETOUR_TRACE(("detours:  &bBrlDetourEip  =%p [%p]\n",
        &pTrampoline->bCallDetour,
        pTrampoline->bCallDetour.GetBrlTarget()));
    DETOUR_TRACE(("detours:  pldDetour       =%p [%p]\n",
        pTrampoline->ppldDetour->EntryPoint,
        pTrampoline->ppldDetour->GlobalPointer));
    DETOUR_TRACE(("detours:  pldTarget       =%p [%p]\n",
        pTrampoline->ppldTarget->EntryPoint,
        pTrampoline->ppldTarget->GlobalPointer));
    DETOUR_TRACE(("detours:  pbRemain        =%p\n",
        pTrampoline->pbRemain));
    DETOUR_TRACE(("detours:  pbDetour        =%p\n",
        pTrampoline->pbDetour));
    DETOUR_TRACE(("\n"));
#else // !DETOURS_IA64
    PDETOUR_TRAMPOLINE pTrampoline =
        (PDETOUR_TRAMPOLINE)DetourCodeFromPointer(*ppPointer, NULL);
    pDetour = DetourCodeFromPointer(pDetour, NULL);
#endif // !DETOURS_IA64

    ////////////////////////////////////// Verify that Trampoline is in place.
    //
    LONG cbTarget = pTrampoline->cbRestore;
    PBYTE pbTarget = pTrampoline->pbRemain - cbTarget;
    if (cbTarget == 0 || cbTarget > sizeof(pTrampoline->rbCode)) {
        error = ERROR_INVALID_BLOCK;
        if (s_fIgnoreTooSmall) {
            goto stop;
        }
        else {
            DETOUR_BREAK();
            goto fail;
        }
    }

    if (pTrampoline->pbDetour != pDetour) {
        error = ERROR_INVALID_BLOCK;
        if (s_fIgnoreTooSmall) {
            goto stop;
        }
        else {
            DETOUR_BREAK();
            goto fail;
        }
    }
    if (mprotect(detour_get_page(pbTarget), detour_get_page_size(), PAGE_EXECUTE_READWRITE)) {
        error = -1;
        DETOUR_BREAK();
        goto fail;
    }

    o->fIsRemove = TRUE;
    o->ppbPointer = (PBYTE*)ppPointer;
    o->pTrampoline = pTrampoline;
    o->pbTarget = pbTarget;
    o->dwPerm = 0;
    o->pNext = s_pPendingOperations;
    s_pPendingOperations = o;

    return NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////////
//
// Helpers for manipulating page protection.
//

// For reference:
//   PAGE_NOACCESS          0x01
//   PAGE_READONLY          0x02
//   PAGE_READWRITE         0x04
//   PAGE_WRITECOPY         0x08
//   PAGE_EXECUTE           0x10
//   PAGE_EXECUTE_READ      0x20
//   PAGE_EXECUTE_READWRITE 0x40
//   PAGE_EXECUTE_WRITECOPY 0x80
//   PAGE_GUARD             ...
//   PAGE_NOCACHE           ...
//   PAGE_WRITECOMBINE      ...

#define DETOUR_PAGE_EXECUTE_ALL    (PROT_EXEC |              \
                                    PROT_READ |         \
                                    PROT_WRITE )

#define DETOUR_PAGE_NO_EXECUTE_ALL (PROT_READ |             \
                                    PROT_WRITE )

#define DETOUR_PAGE_ATTRIBUTES     (~(DETOUR_PAGE_EXECUTE_ALL | DETOUR_PAGE_NO_EXECUTE_ALL))

//C_ASSERT((DETOUR_PAGE_NO_EXECUTE_ALL << 4) == DETOUR_PAGE_EXECUTE_ALL);

static DWORD DetourPageProtectAdjustExecute(_In_  DWORD dwOldProtect,
    _In_  DWORD dwNewProtect)
    //  Copy EXECUTE from dwOldProtect to dwNewProtect.
{
    bool const fOldExecute = ((dwOldProtect & DETOUR_PAGE_EXECUTE_ALL) != 0);
    bool const fNewExecute = ((dwNewProtect & DETOUR_PAGE_EXECUTE_ALL) != 0);

    if (fOldExecute && !fNewExecute) {
        dwNewProtect = ((dwNewProtect & DETOUR_PAGE_NO_EXECUTE_ALL) << 4)
            | (dwNewProtect & DETOUR_PAGE_ATTRIBUTES);
    }
    else if (!fOldExecute && fNewExecute) {
        dwNewProtect = ((dwNewProtect & DETOUR_PAGE_EXECUTE_ALL) >> 4)
            | (dwNewProtect & DETOUR_PAGE_ATTRIBUTES);
    }
    return dwNewProtect;
}

_Success_(return != FALSE)
BOOL DetourVirtualProtectSameExecuteEx(_In_  pid_t hProcess,
    _In_  PVOID pAddress,
    _In_  SIZE_T nSize,
    _In_  DWORD dwNewProtect,
    _Out_ PDWORD pdwOldProtect)
    // Some systems do not allow executability of a page to change. This function applies
    // dwNewProtect to [pAddress, nSize), but preserving the previous executability.
    // This function is meant to be a drop-in replacement for some uses of VirtualProtectEx.
    // When "restoring" page protection, there is no need to use this function.
{
    return TRUE;
    /*
    MEMORY_BASIC_INFORMATION mbi;

    // Query to get existing execute access.

    ZeroMemory(&mbi, sizeof(mbi));

    if (VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi)) == 0) {
    return FALSE;
    }
    return VirtualProtectEx(hProcess, pAddress, nSize,
    DetourPageProtectAdjustExecute(mbi.Protect, dwNewProtect),
    pdwOldProtect);
    */
}

_Success_(return != FALSE)
BOOL DetourVirtualProtectSameExecute(_In_  PVOID pAddress,
    _In_  SIZE_T nSize,
    _In_  DWORD dwNewProtect,
    _Out_ PDWORD pdwOldProtect)
{
    return DetourVirtualProtectSameExecuteEx(getpid(),
                                           pAddress, nSize, dwNewProtect, pdwOldProtect);
}
void library_entry_point(void) __attribute__((constructor));

void library_entry_point()
{
    DetourBarrierProcessAttach();
    DetourCriticalInitialize();
}
__attribute__((destructor))
void library_exit()
{
    DetourCriticalFinalize();    
    DetourBarrierProcessDetach();
}
//  End of File
