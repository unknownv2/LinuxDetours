.text
.global Trampoline_ASM_ARM 
.code 16     /* Here we say we will use Thumb */
.align 2     /* Make sure instructions are aligned at 2-byte boundary */
.syntax unified
Trampoline_ASM_ARM:

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
        PUSH    {r0, r1, r2, r3, r4, lr}
        PUSH    {r5, r6, r7, r8, r10, r11}        
        VPUSH   {d0-d7}                              
        ADR     r5, IsExecutedPtr
        LDR     r5, [r5]
        MOV     r1, #0x0               
        DMB     ish
try_inc_lock:       
        LDREX   r0, [r5]
        ADDS    r0, r0, #1
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_inc_lock
        DMB     ish
        ADR     r1, NewProc
        LDR     r2, [r1]
        CMP     r2, #0
        BNE     CALL_NET_ENTRY
/* call original method  */    
        DMB     ish
try_dec_lock :       
        LDREX   r0, [r5]
        SUBS    r0, r0, #1
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_dec_lock
        DMB     ish		

        ADR     r5, OldProc
        LDR     r5, [r5]
        B     TRAMPOLINE_EXIT
/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call hook handler or original method... */
CALL_NET_ENTRY:

/* call NET intro */
        ADR     r0, start
        
        ADDS    r2, sp, #0x6c /* original sp (address of return address)*/
        LDR     r1, [sp, #0x6c] /* return address (value stored in original sp) */
        ADR     r4, NETIntro
        LDR     r4, [r4]
        BLX     r4 /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/

/* should call original method? */              
        CMP     r0, #0
        BNE     CALL_HOOK_HANDLER

/* call original method */
        ADR     r5, IsExecutedPtr
        LDR     r5, [r5]        
        DMB     ish
try_dec_lock2:        
        LDREX   r0, [r5]
        SUBS    r0, r0, #1
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_dec_lock2
        DMB     ish

        ADR     r5, OldProc
        LDR     r5, [r5]
        B       TRAMPOLINE_EXIT

CALL_HOOK_HANDLER:

/* call hook handler */       
        ADR     r5, NewProc
        LDR     r5, [r5]
        ADR     r4, CALL_NET_OUTRO
        ORR      r4, r4, #1
        STR     r4, [sp, #0x6c] /* store outro return to stack after hook handler is called     */    
        B       TRAMPOLINE_EXIT
 /* this is where the handler returns... */
CALL_NET_OUTRO:
        MOV     r5, #0
        PUSH    {r0, r1, r2, r3, r4, r5}
        ADD    r1, sp, #5*4
        ADR     r0, start
        /* Param 2: Address of return address */
        ADR     r5, NETOutro
        LDR     r5, [r5]
        BLX     r5       /* Hook->NETOutro(Hook, InAddrOfRetAddr)*/

        ADR     r5, IsExecutedPtr
        LDR     r5, [r5]
        DMB     ish        
try_dec_lock3:        
        LDREX   r0, [r5]
        SUBS    r0, r0, #1
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_dec_lock3
        DMB     ish

        POP     {r0, r1, r2, r3, r4, lr} /* restore return value of user handler... */
/* finally return to saved return address - the caller of this trampoline...  */       
        BX      lr

TRAMPOLINE_EXIT:
        MOV     r9, r5
        VPOP    {d0-d7}    
        POP     {r5, r6, r7, r8, r10, r11}            
        POP     {r0, r1, r2, r3, r4, lr}
        
        BX      r9  /* MOV     pc, r9 */

/* outro signature, to automatically determine code size   */     
        .byte     0x78
        .byte     0x56
        .byte     0x34
        .byte     0x12  
