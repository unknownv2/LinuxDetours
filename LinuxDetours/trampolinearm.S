.text
.global Trampoline_ASM_ARM_T
.code 16
.align 2
.syntax unified
Trampoline_ASM_ARM_T:

NETIntro:        /* .NET Barrier Intro Function */
        .byte 0
        .byte 0
        .byte 0
        .byte 0
OldProc:        /* Original Replaced Function */
        .byte 0
        .byte 0
        .byte 0
        .byte 0
NewProc:        /* Detour Function */
        .byte 0
        .byte 0
        .byte 0
        .byte 0
NETOutro:       /* .NET Barrier Outro Function */
        .byte 0
        .byte 0
        .byte 0
        .byte 0
IsExecutedPtr:  /* Count of times trampoline was executed */
        .byte 0
        .byte 0
        .byte 0
        .byte 0

start:
        push    {r0, r1, r2, r3, r4, lr}
        push    {r5, r6, r7, r8, r9, r10}
        vpush   {d0-d7}
        ldr     r5, IsExecutedPtr
        dmb     ish
try_inc_lock:       
        ldrex   r0, [r5]
        add     r0, r0, #1
        strex   r1, r0, [r5]
        cmp     r1, #0
        bne     try_inc_lock
        dmb     ish
        ldr     r2, NewProc
        cmp     r2, #0
        bne     CALL_NET_ENTRY
/* call original method  */
        dmb     ish
try_dec_lock:
        ldrex   r0, [r5]
        add     r0, r0, #-1
        strex   r1, r0, [r5]
        cmp     r1, #0
        bne     try_dec_lock
        dmb     ish

        ldr   r5, OldProc
        b     TRAMPOLINE_EXIT
/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call hook handler or original method... */
CALL_NET_ENTRY:

/* call NET intro */
        adr     r0, start /* Hook handle (only a position hint) */
        add     r2, sp, #0x6c /* original sp (address of return address)*/
        ldr     r1, [sp, #0x6c] /* return address (value stored in original sp) */
        ldr     r4, NETIntro /* call NET intro */
        blx     r4 /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/

/* should call original method?      */
        cmp     r0, #0
        bne     CALL_HOOK_HANDLER

/* call original method */
        ldr     r5, IsExecutedPtr
        dmb     ish
try_dec_lock2:
        ldrex   r0, [r5]
        add     r0, r0, #-1
        strex   r1, r0, [r5]
        cmp     r1, #0
        bne     try_dec_lock2
        dmb     ish

        ldr     r5, OldProc
        b       TRAMPOLINE_EXIT

CALL_HOOK_HANDLER:

/* call hook handler */
        ldr     r5, NewProc
        adr     r4, CALL_NET_OUTRO
        str     r4, [sp, #0x6c] /* store outro return to stack after hook handler is called     */    
        b       TRAMPOLINE_EXIT
 /* this is where the handler returns... */
CALL_NET_OUTRO:
        mov     r5, #0
        push    {r0, r1, r2, r3, r4, r5} /* save return handler */
        add     r1, sp, #5*4
        adr     r0, start /* get address of next Hook struct pointer */
        /* Param 2: Address of return address */
        ldr     r5, NETOutro
        blx     r5       /* Hook->NETOutro(Hook, InAddrOfRetAddr)*/

        ldr     r5, IsExecutedPtr
        dmb     ish
try_dec_lock3:
        ldrex   r0, [r5]
        add     r0, r0, #-1
        strex   r1, r0, [r5]
        cmp     r1, #0
        bne     try_dec_lock3
        dmb     ish

       pop     {r0, r1, r2, r3, r4, lr} /* restore return value of user handler... */
/* finally return to saved return address - the caller of this trampoline...  */       
        bx      lr

TRAMPOLINE_EXIT:
        mov     r12, r5
        vpop    {d0-d7}
        pop     {r5, r6, r7, r8, r9, r10}         
        pop     {r0, r1, r2, r3, r4, lr}
        
        bx      r12 ; mov     pc, r12

/* outro signature, to automatically determine code size   */     
        .byte     0x78
        .byte     0x56
        .byte     0x34
        .byte     0x12