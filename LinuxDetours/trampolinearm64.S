/* This is a comment */
.text
.global Trampoline_ASM_ARM64 /* 'main' is our entry point and must be global */
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
        STP     X29, X30, [SP, #-0x50]!
        STP     X6, X7, [SP, #0x10]
        STP     X4, X5, [SP, #0x20]       
        STP     X2, X3, [SP, #0x30]             
        STP     X0, X1, [SP, #0x40]
        sub 	sp, sp, #64
        str     d0, [sp, #56]
        str     d1, [sp, #48]
        str     d2, [sp, #40]
        str     d3, [sp, #32]
        str     d4, [sp, #24]
        str     d5, [sp, #16]
        str     d6, [sp, #8]    
        str     d7, [sp, #0] 
        LDR     x10, =IsExecutedPtr
        LDR     x10, [x10]
        MOV     X1, #0x0               
try_inc_lock:       
        ldxr    x0, [x10]
        ADDS    x0, x0, #1
        stxr    w1, x0, [x10]
        CMP     w1, #0
        BNE     try_inc_lock
        LDR     x1, =NewProc
        LDR     X2, [x1]
        cmp     X2, #0
        BNE     CALL_NET_ENTRY    
/* call original method  */    
try_dec_lock :       
        ldxr    x0, [x10]
        SUBS    x0, x0, #1
        stxr    w1, x0, [x10]
        CMP     x1, #0
        BNE     try_dec_lock
        LDR     x10, =OldProc
        B     TRAMPOLINE_EXIT        
/* call hook handler or original method... */
CALL_NET_ENTRY:

/* call NET intro */

        LDR     x0, =IsExecutedPtr
        ADD     x0, x0, #8 /* Hook handle (only a position hint) */
        ADDS    x2, sp, #72 /* original sp (address of return address)*/
        LDR     x1, [sp, #72] /* return address (value stored in original sp) */
        LDR     x10, =NETIntro
        LDR     x10, [x10]
        BLR      x10 /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/
/* should call original method?      */        
        CMP     x0, #0
        BNE     CALL_HOOK_HANDLER

/* call original method */
        LDR     x10, =IsExecutedPtr
        LDR     x10, [x10]        
try_dec_lock2:        
        ldxr   x0, [x10]
        SUBS    x0, x0, #1
        stxr   w1, x0, [x10]
        CMP     w1, #0
        BNE     try_dec_lock2

        LDR     x10, =OldProc
        LDR     x10, [x10]
        B       TRAMPOLINE_EXIT
CALL_HOOK_HANDLER:

/* call hook handler        */
        LDR     x10, =NewProc
        LDR     x10, [x10]
        LDR     x4, =CALL_NET_OUTRO  /*adjust return address */
        STR     x4, [sp, #72] /* store outro return to stack after hook handler is called     */    
        B       TRAMPOLINE_EXIT
 /* this is where the handler returns... */
CALL_NET_OUTRO:
        MOV     x8, #0
        STP     X8, X0, [SP, #-0x10]!  /* save return handler */
        ADDS    x1, sp, #0    /* Param 2: Address of return address */    
        LDR     x0, =IsExecutedPtr
        ADD     x0, x0, #8 /* get address of next Hook struct pointer */
        
        LDR     x9, =NETOutro
        LDR     x9, [x9]
        BLR      x9       /* Hook->NETOutro(Hook, InAddrOfRetAddr)*/

        LDR     x9, =IsExecutedPtr
        LDR     x9, [x9]    
try_dec_lock3:        
        ldxr   x0, [x9]
        SUBS    x0, x0, #1
        stxr    w1, x0, [x9]
        CMP     w1, #0
        BNE     try_dec_lock3

        LDP     X30, X0, [SP], #0x10
/* finally return to saved return address - the caller of this trampoline...  */       
        RET

TRAMPOLINE_EXIT:
        add 	sp, sp, #64
        ldr     d0, [sp, #-64]
        ldr     d1, [sp, #-56]
        ldr     d2, [sp, #-48]
        ldr     d3, [sp, #-40]
        ldr     d4, [sp, #-32]
        ldr     d5, [sp, #-24]
        ldr     d6, [sp, #-16]    
        ldr     d7, [sp, #-8]  

        LDP     X0, X1, [SP, #0x40]
        LDP     X2, X3, [SP, #0x30]
        LDP     X4, X5, [SP, #0x20]
        LDP     X6, X7, [SP, #0x10]
        LDP     X29, X30, [SP], #0x50 
        BR      x10
/* outro signature, to automatically determine code size   */     
        .byte     0x78
        .byte     0x56
        .byte     0x34
        .byte     0x12  
