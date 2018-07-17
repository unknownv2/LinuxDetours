/* This is a comment */
.text
.global Trampoline_ASM_ARM /* 'main' is our entry point and must be global */
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
        sub 	sp, sp, #64
        vstr    d0, [sp, #56]
        vstr    d1, [sp, #48]
        vstr    d2, [sp, #40]
        vstr    d3, [sp, #32]
        vstr    d4, [sp, #24]
        vstr    d5, [sp, #16]
        vstr    d6, [sp, #8]    
        vstr    d7, [sp, #0]                                          
        /*VPUSH   {s0-s7}*/ 
        LDR     r5, =IsExecutedPtr
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
        LDR     r1, =NewProc
        LDR     r2, [r1]
        CMPEQ   r2, #0
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

        LDR   r5, =OldProc
        B     TRAMPOLINE_EXIT
/* call hook handler or original method... */
CALL_NET_ENTRY:

/* call NET intro */

        LDR     r0, =IsExecutedPtr
        ADD     r0, r0, #4 /* Hook handle (only a position hint) */
        ADDS    r2, sp, #0x54 /* original sp (address of return address)*/
        LDR     r1, [sp, #0x54] /* return address (value stored in original sp) */
        LDR     r4, =NETIntro
        LDR     r4, [r4]
        BLX     r4 /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/
/* should call original method?      */        
        CMP     r0, #0
        BNE     CALL_HOOK_HANDLER

/* call original method */
        LDR     r5, =IsExecutedPtr
        LDR     r5, [r5]        
        DMB     ish
try_dec_lock2:        
        LDREX   r0, [r5]
        SUBS    r0, r0, #1
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_dec_lock2
        DMB     ish

        LDR     r5, =OldProc
        LDR     r5, [r5]
        B       TRAMPOLINE_EXIT

CALL_HOOK_HANDLER:

/* call hook handler        */
        LDR     r5, =NewProc
        LDR     r5, [r5]
        LDR     r4, =CALL_NET_OUTRO  /*adjust return address */
        ORR      r4, r4, #1
        #MOVT     r4, #1
        #ADD     r4, r4, #0x808
        STR     r4, [sp, #0x54] /* store outro return to stack after hook handler is called     */    
        B       TRAMPOLINE_EXIT
 /* this is where the handler returns... */
CALL_NET_OUTRO:
        MOV     r1, #0
        PUSH    {r1}
        ADDS    r1, sp, #0
        PUSH    {r0} /* save return handler */
        LDR     r0, =IsExecutedPtr
        ADD     r0, r0, #4 /* get address of next Hook struct pointer */
        /* Param 2: Address of return address */
        LDR     r5, =NETOutro
        LDR     r5, [r5]
        BLX     r5       /* Hook->NETOutro(Hook, InAddrOfRetAddr)*/

        LDR     r5, =IsExecutedPtr
        LDR     r5, [r5]
        DMB     ish        
try_dec_lock3:        
        LDREX   r0, [r5]
        SUBS    r0, r0, #1
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_dec_lock3
        DMB     ish

        POP     {r0,lr} /* restore return value of user handler... */
/* finally return to saved return address - the caller of this trampoline...  */       
        BX      lr

TRAMPOLINE_EXIT:
        
        /*VPOP   {s0-s7}*/
        add 	sp, sp, #64
        vldr    d0, [sp, #-64]
        vldr    d1, [sp, #-56]
        vldr    d2, [sp, #-48]
        vldr    d3, [sp, #-40]
        vldr    d4, [sp, #-32]
        vldr    d5, [sp, #-24]
        vldr    d6, [sp, #-16]    
        vldr    d7, [sp, #-8]  
        POP    {r0, r1, r2, r3, r4, lr}

        bx     r5




/* outro signature, to automatically determine code size   */     
        .byte     0x78
        .byte     0x56
        .byte     0x34
        .byte     0x12  
