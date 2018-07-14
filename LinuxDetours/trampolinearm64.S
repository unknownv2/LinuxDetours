.text
.global Trampoline_ASM_ARM64 /* our entry point which must be global */
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
        STP     x29, x30, [sp, #-0x50]!
        STP     x6, x7, [sp, #0x10]
        STP     x4, x5, [sp, #0x20]       
        STP     x2, x3, [sp, #0x30]             
        STP     x0, x1, [sp, #0x40]
        SUB     sp, sp, #64
        STR     d0, [sp, #56]
        STR     d1, [sp, #48]
        STR     d2, [sp, #40]
        STR     d3, [sp, #32]
        STR     d4, [sp, #24]
        STR     d5, [sp, #16]
        STR     d6, [sp, #8]    
        STR     d7, [sp, #0] 
        LDR     x10, =IsExecutedPtr
        LDR     x10, [x10]
        MOV     x1, #0x0               
try_inc_lock:       
        LDXR    x0, [x10]
        ADDS    x0, x0, #1
        STXR    w1, x0, [x10]
        CMP     w1, #0
        BNE     try_inc_lock
        LDR     x1, =NewProc
        LDR     x2, [x1]
        CMP     x2, #0
        BNE     CALL_NET_ENTRY    
/* call original method  */    
try_dec_lock :       
        LDXR    x0, [x10]
        SUBS    x0, x0, #1
        STXR    w1, x0, [x10]
        CMP     x1, #0
        BNE     try_dec_lock
        LDR     x10, =OldProc
        B       TRAMPOLINE_EXIT        
/* call hook handler or original method... */
CALL_NET_ENTRY:

/* call NET intro */

        LDR     x0, =IsExecutedPtr
        ADD     x0, x0, #8 /* Hook handle (only a position hint) */
        ADDS    x2, sp, #72 /* original sp (address of return address)*/
        LDR     x1, [sp, #72] /* return address (value stored in original sp) */
        LDR     x10, =NETIntro
        LDR     x10, [x10]
        BLR     x10 /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/
/* should call original method?      */        
        CMP     x0, #0
        BNE     CALL_HOOK_HANDLER

/* call original method */
        LDR     x10, =IsExecutedPtr
        LDR     x10, [x10]        
try_dec_lock2:        
        ldxr    x0, [x10]
        SUBS    x0, x0, #1
        STXR    w1, x0, [x10]
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
        STP     x8, x0, [SP, #-0x10]!  /* save return handler */
        ADDS    x1, sp, #0    /* Param 2: Address of return address */    
        LDR     x0, =IsExecutedPtr
        ADD     x0, x0, #8 /* get address of next Hook struct pointer */
        
        LDR     x9, =NETOutro
        LDR     x9, [x9]
        BLR      x9       /* Hook->NETOutro(Hook, InAddrOfRetAddr)*/

        LDR     x9, =IsExecutedPtr
        LDR     x9, [x9]    
try_dec_lock3:        
        LDXR    x0, [x9]
        SUBS    x0, x0, #1
        STXR    w1, x0, [x9]
        CMP     w1, #0
        BNE     try_dec_lock3

        LDP     x30, x0, [SP], #0x10
/* finally return to saved return address - the caller of this trampoline...  */       
        RET

TRAMPOLINE_EXIT:
        ADD     sp, sp, #64
        LDR     d0, [sp, #-64]
        LDR     d1, [sp, #-56]
        LDR     d2, [sp, #-48]
        LDR     d3, [sp, #-40]
        LDR     d4, [sp, #-32]
        LDR     d5, [sp, #-24]
        LDR     d6, [sp, #-16]    
        LDR     d7, [sp, #-8]  

        LDP     x0, x1, [SP, #0x40]
        LDP     x2, x3, [SP, #0x30]
        LDP     x4, x5, [SP, #0x20]
        LDP     x6, x7, [SP, #0x10]
        LDP     x29, x30, [SP], #0x50 
        BR      x10
/* outro signature, to automatically determine code size   */     
        .byte     0x78
        .byte     0x56
        .byte     0x34
        .byte     0x12  
