/* This is a comment */
.text
.align 5
.globl Trampoline_ASM_ARM64 /* 'main' is our entry point and must be global */
Trampoline_ASM_ARM64:

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
        
      
start:     
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp
        sub	sp, sp, #(10*8 + 8*16)
        stp	q0, q1, [sp, #(0*16)]
        stp	q2, q3, [sp, #(2*16)]
        stp	q4, q5, [sp, #(4*16)]
        stp	q6, q7, [sp, #(6*16)]
        stp	x0, x1, [sp, #(8*16+0*8)]
        stp	x2, x3, [sp, #(8*16+2*8)]
        stp	x4, x5, [sp, #(8*16+4*8)]
        stp	x6, x7, [sp, #(8*16+6*8)]
        str	x8,     [sp, #(8*16+8*8)]            

        LDR     x10, IsExecutedPtr
        #LDR     x10, [x10]
        MOV     X1, #0x0               
try_inc_lock:       
        ldxr    x0, [x10]
        ADDS    x0, x0, #1
        stxr    w1, x0, [x10]
        CMP     w1, #0
        BNE     try_inc_lock
        LDR     x1, NewProc
        /*LDR     X2, [x1] */
        cmp     X2, #0
        BNE     CALL_NET_ENTRY    
/* call original method  */    
try_dec_lock :       
        ldxr    x0, [x10]
        SUBS    x0, x0, #1
        stxr    w1, x0, [x10]
        CMP     x1, #0
        BNE     try_dec_lock
        LDR     x10, OldProc
        B       TRAMPOLINE_EXIT        
/* call hook handler or original method... */
CALL_NET_ENTRY:

/* call NET intro */

        #LDR     x0, =IsExecutedPtr
        #ADD     x0, x0, #8 /* Hook handle (only a position hint) */
        ADR     x0, start
        ADDS    x2, sp, #(10*8 + 8*16) + 8 /* original sp (address of return address)*/
        LDR     x1, [sp, #(10*8 + 8*16) + 8] /* return address (value stored in original sp) */
        LDR     x10, NETIntro
        /*LDR     x10, [x10] */
        BLR     x10 /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/
/* should call original method?      */        
        CMP     x0, #0
        BNE     CALL_HOOK_HANDLER

/* call original method */
        LDR     x10, IsExecutedPtr
        /*LDR     x10, [x10]    */    
try_dec_lock2:        
        ldxr    x0, [x10]
        SUBS    x0, x0, #1
        stxr    w1, x0, [x10]
        CMP     w1, #0
        BNE     try_dec_lock2

        LDR     x10, OldProc
        /*LDR     x10, [x10] */
        B       TRAMPOLINE_EXIT
CALL_HOOK_HANDLER:

/* call hook handler        */
        LDR     x10, NewProc
        /*LDR     x10, [x10] */
        #LDR     x4, =CALL_NET_OUTRO  /*adjust return address */
        ADR     x4, CALL_NET_OUTRO
        STR     x4, [sp, #(10*8 + 8*16) + 8] /* store outro return to stack after hook handler is called     */    
        B       TRAMPOLINE_EXIT
 /* this is where the handler returns... */
CALL_NET_OUTRO:
        MOV     x9, #0
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp        
        sub	sp, sp, #(10*8 + 8*16)
        stp	q0, q1, [sp, #(0*16)]
        stp	q2, q3, [sp, #(2*16)]
        stp	q4, q5, [sp, #(4*16)]
        stp	q6, q7, [sp, #(6*16)]
        stp	x0, x1, [sp, #(8*16+0*8)]
        stp	x2, x3, [sp, #(8*16+2*8)]
        stp	x4, x5, [sp, #(8*16+4*8)]
        stp	x6, x7, [sp, #(8*16+6*8)]
        stp	x8, x9, [sp, #(8*16+8*8)]    

        #stp     q0, q1, [sp, #-16]!
        #STP     X8, X0, [SP, #-0x10]!  /* save return handler */
        ADD      x1, sp, #(8*16+9*8)    /* Param 2: Address of return address */    
        #LDR     x0, =IsExecutedPtr
        #ADD     x0, x0, #8 /* get address of next Hook struct pointer */
        ADR     x0, start
        LDR     x9, NETOutro
        /*LDR     x9, [x9] */
        BLR     x9       /* Hook->NETOutro(Hook, InAddrOfRetAddr)*/

        LDR     x9, IsExecutedPtr
        /*LDR     x9, [x9]  */  
try_dec_lock3:        
        ldxr    x0, [x9]
        SUBS    x0, x0, #1
        stxr    w1, x0, [x9]
        CMP     w1, #0
        BNE     try_dec_lock3

        ldp	q0, q1, [sp, #(0*16)]
        ldp	q2, q3, [sp, #(2*16)]
        ldp	q4, q5, [sp, #(4*16)]
        ldp	q6, q7, [sp, #(6*16)]
        ldp	x0, x1, [sp, #(8*16+0*8)]
        ldp	x2, x3, [sp, #(8*16+2*8)]
        ldp	x4, x5, [sp, #(8*16+4*8)]
        ldp	x6, x7, [sp, #(8*16+6*8)]
        ldp	x8, x9, [sp, #(8*16+8*8)]
        mov	sp, x29
        ldp	x29, x30, [sp], #16
        mov     x30, x9
        #LDP     X30, X0, [SP], #0x10
        #LDP     q0, q1, [SP], #0x10
/* finally return to saved return address - the caller of this trampoline...  */       
        RET

TRAMPOLINE_EXIT:
        ldp	q0, q1, [sp, #(0*16)]
        ldp	q2, q3, [sp, #(2*16)]
        ldp	q4, q5, [sp, #(4*16)]
        ldp	q6, q7, [sp, #(6*16)]
        ldp	x0, x1, [sp, #(8*16+0*8)]
        ldp	x2, x3, [sp, #(8*16+2*8)]
        ldp	x4, x5, [sp, #(8*16+4*8)]
        ldp	x6, x7, [sp, #(8*16+6*8)]
        ldr	x8,     [sp, #(8*16+8*8)]
        mov	sp, x29
        ldp	x29, x30, [sp], #16
        BR      x10
/* outro signature, to automatically determine code size   */     
        .byte     0x78
        .byte     0x56
        .byte     0x34
        .byte     0x12  
