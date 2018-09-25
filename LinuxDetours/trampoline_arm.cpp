#include "detours.h"

#if defined(DETOURS_ARM) 
__attribute__((naked))
 void trampoline_template_arm_func() {
    asm(

".global trampoline_template_thumb;"
".global trampoline_template_arm;"
".global trampoline_data_arm;"
".global trampoline_data_thumb;"

    "NETIntro:"        /* .NET Barrier Intro Function */
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"
    "OldProc:"        /* Original Replaced Function */
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"
    "NewProc:"        /* Detour Function */
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"
    "NETOutro:"       /* .NET Barrier Outro Function */
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"
    "IsExecutedPtr:"  /* Count of times trampoline was executed */
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"
        ".byte 0;"

    "start:"

    "trampoline_template_thumb:"
#if not defined(DETOURS_ARM32)
    ".thumb_func;"
        "bx pc;"
        "mov r8, r8;" // padding since pc is set to (current_instruction + 4) in Thumb Mode
#endif
    "trampoline_template_arm:"
    ".code 32;"

        "push    {r0, r1, r2, r3, r4, lr};"
        "push    {r5, r6, r7, r8, r9, r10};"
        "vpush   {d0-d7};"
        "ldr     r5, IsExecutedPtr;"
        "dmb     ish;"
    "try_inc_lock:"
        "ldrex   r0, [r5];"
        "add     r0, r0, #1;"
        "strex   r1, r0, [r5];"
        "cmp     r1, #0;"
        "bne     try_inc_lock;"
        "dmb     ish;"
        "ldr     r2, NewProc;"
        "cmpeq   r2, #0;"
        "bne     call_net_entry;"
        /* call original method  */
        "dmb     ish;"
    "try_dec_lock:"
        "ldrex   r0, [r5];"
        "add     r0, r0, #-1;"
        "strex   r1, r0, [r5];"
        "cmp     r1, #0;"
        "bne     try_dec_lock;"
        "dmb     ish;"
        "ldr     r5, OldProc;"
        "b       trampoline_exit;"

        /* call hook handler or original method... */
    "call_net_entry:"

        "adr     r0, start;" /* Hook handle (only a position hint) */
        "add     r2, sp, #0x6c;" /* original sp (address of return address)*/
        "ldr     r1, [sp, #0x6c];" /* return address (value stored in original sp) */
        "ldr     r4, NETIntro;" /* call NET intro */
        "blx     r4;" /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/

        /* should call original method?      */
        "cmp     r0, #0;"
        "bne     call_hook_handler;"

        /* call original method */ 
        "ldr     r5, IsExecutedPtr;"
        "dmb     ish;"

    "try_dec_lock2:"
        "ldrex   r0, [r5];"
        "add     r0, r0, #-1;"
        "strex   r1, r0, [r5];"
        "cmp     r1, #0;"
        "bne     try_dec_lock2;"
        "dmb     ish;"

        "ldr     r5, OldProc;"
        "b       trampoline_exit;"

    "call_hook_handler:"
        /* call hook handler        */
        "ldr     r5, NewProc;"
        "adr     r4, call_net_outro;"
        "str     r4, [sp, #0x6c];" /* store outro return to stack after hook handler is called     */
        "b       trampoline_exit;"
        /* this is where the handler returns... */
    "call_net_outro:"
        "mov     r5, #0;"
        "push    {r0, r1, r2, r3, r4, r5};" /* save return handler */
        "add     r1, sp, #5*4;"
        "adr     r0, start;" /* get address of next Hook struct pointer */
        /* Param 2: Address of return address */
        "ldr     r5, NETOutro;"
        "blx     r5;"       /* Hook->NETOutro(Hook, InAddrOfRetAddr)*/
        "ldr     r5, IsExecutedPtr;"
        "dmb     ish;"
    "try_dec_lock3:"
        "ldrex   r0, [r5];"
        "add     r0, r0, #-1;"
        "strex   r1, r0, [r5];"
        "cmp     r1, #0;"
        "bne     try_dec_lock3;"
        "dmb     ish;"
        "pop     {r0, r1, r2, r3, r4, lr} /* restore return value of user handler... */;"
        /* finally return to saved return address - the caller of this trampoline...  */
        "bx      lr;"

    "trampoline_exit:"
        "mov     r12, r5;"
        "vpop    {d0-d7};"
        "pop     {r5, r6, r7, r8, r9, r10};"
        "pop     {r0, r1, r2, r3, r4, lr};"
        "bx      r12 ; mov     pc, r12;"
    "trampoline_data_arm:"
    "trampoline_data_thumb:"
        ".word 0x12345678;"
    );
}
#elif defined(DETOURS_ARM64) 
__attribute__((naked))
void trampoline_template_arm_64_func() {
    asm(R"(
    
 .global trampoline_template_arm64
 .global trampoline_data_arm_64

NETIntro:        /* .NET Barrier Intro Function */
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
OldProc:        /* Original Replaced Function */
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
NewProc:        /* Detour Function */
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
NETOutro:       /* .NET Barrier Outro Function */
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
IsExecutedPtr:  /* Count of times trampoline was executed */
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0
        .byte 0

trampoline_template_arm64:
  
start:     
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp
        sub     sp, sp, #(10*8 + 8*16)
        stp     q0, q1, [sp, #(0*16)]
        stp     q2, q3, [sp, #(2*16)]
        stp     q4, q5, [sp, #(4*16)]
        stp     q6, q7, [sp, #(6*16)]
        stp     x0, x1, [sp, #(8*16+0*8)]
        stp     x2, x3, [sp, #(8*16+2*8)]
        stp     x4, x5, [sp, #(8*16+4*8)]
        stp     x6, x7, [sp, #(8*16+6*8)]
        str     x8,     [sp, #(8*16+8*8)]

        ldr     x10, IsExecutedPtr
try_inc_lock:       
        ldxr    w0, [x10]
        add     w0, w0, #1
        stxr    w1, w0, [x10]
        cbnz    w1, try_inc_lock
        ldr     x1, NewProc
        cbnz    x1, call_net_entry
/* call original method  */
try_dec_lock:       
        ldxr    w0, [x10]
        add     w0, w0, #-1
        stxr    w1, w0, [x10]
        cbnz    x1, try_dec_lock
        ldr     x10, OldProc
        b       trampoline_exit
/* call hook handler or original method... */
call_net_entry:
        adr     x0, start /* call NET intro */
        add     x2, sp, #(10*8 + 8*16) + 8 /* original sp (address of return address)*/
        ldr     x1, [sp, #(10*8 + 8*16) + 8] /* return address (value stored in original sp) */
        ldr     x10, NETIntro  
        blr     x10 /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/
/* should call original method?      */
        cbnz    x0, call_hook_handler

/* call original method */
        ldr     x10, IsExecutedPtr
try_dec_lock2:        
        ldxr    w0, [x10]
        add     w0, w0, #-1
        stxr    w1, w0, [x10]
        cbnz    w1, try_dec_lock2

        ldr     x10, OldProc
        b       trampoline_exit
call_hook_handler:

/* call hook handler        */
        ldr     x10, NewProc
        adr     x4, call_net_outro /*adjust return address */
        str     x4, [sp, #(10*8 + 8*16) + 8] /* store outro return to stack after hook handler is called     */    
        b       trampoline_exit
 /* this is where the handler returns... */
call_net_outro:
        mov     x10, #0
        sub     sp, sp, #(10*8 + 8*16)
        stp     q0, q1, [sp, #(0*16)]
        stp     q2, q3, [sp, #(2*16)]
        stp     q4, q5, [sp, #(4*16)]
        stp     q6, q7, [sp, #(6*16)]
        stp     x0, x1, [sp, #(8*16+0*8)]
        stp     x2, x3, [sp, #(8*16+2*8)]
        stp     x4, x5, [sp, #(8*16+4*8)]
        stp     x6, x7, [sp, #(8*16+6*8)]
        stp     x8, x10,[sp, #(8*16+8*8)]    /* save return handler */

        add     x1, sp, #(8*16+9*8)      /* Param 2: Address of return address */
        adr     x0, start
        
        ldr     x10, NETOutro
        blr     x10       /* Hook->NETOutro(Hook, InAddrOfRetAddr)*/

        ldr     x10, IsExecutedPtr 
try_dec_lock3:        
        ldxr    w0, [x10]
        add     w0, w0, #-1
        stxr    w1, w0, [x10]
        cbnz    w1, try_dec_lock3
        
        ldp     q0, q1, [sp, #(0*16)]
        ldp     q2, q3, [sp, #(2*16)]
        ldp     q4, q5, [sp, #(4*16)]
        ldp     q6, q7, [sp, #(6*16)]
        ldp     x0, x1, [sp, #(8*16+0*8)]
        ldp     x2, x3, [sp, #(8*16+2*8)]
        ldp     x4, x5, [sp, #(8*16+4*8)]
        ldp     x6, x7, [sp, #(8*16+6*8)]
        ldp     x8, x30,[sp, #(8*16+8*8)]
        add     sp, sp, #(10*8 + 8*16)

/* finally return to saved return address - the caller of this trampoline...  */
        ret

trampoline_exit:
        ldp     q0, q1, [sp, #(0*16)]
        ldp     q2, q3, [sp, #(2*16)]
        ldp     q4, q5, [sp, #(4*16)]
        ldp     q6, q7, [sp, #(6*16)]
        ldp     x0, x1, [sp, #(8*16+0*8)]
        ldp     x2, x3, [sp, #(8*16+2*8)]
        ldp     x4, x5, [sp, #(8*16+4*8)]
        ldp     x6, x7, [sp, #(8*16+6*8)]
        ldr     x8,     [sp, #(8*16+8*8)]
        mov     sp, x29
        ldp     x29, x30, [sp], #16
        br      x10

/* outro signature, to automatically determine code size   */
trampoline_data_arm_64:
        .word 0x12345678
)");
}
#endif