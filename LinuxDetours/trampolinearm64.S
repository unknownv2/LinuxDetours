.text
.align 5
.globl Trampoline_ASM_ARM64 
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
        cbnz    x1, CALL_NET_ENTRY
/* call original method  */    
try_dec_lock:       
        ldxr    w0, [x10]
        add     w0, w0, #-1
        stxr    w1, w0, [x10]
        cbnz    x1, try_dec_lock
        ldr     x10, OldProc
        b       TRAMPOLINE_EXIT        
/* call hook handler or original method... */
CALL_NET_ENTRY:

        adr     x0, start /* call NET intro */
        add     x2, sp, #(10*8 + 8*16) + 8 /* original sp (address of return address)*/
        ldr     x1, [sp, #(10*8 + 8*16) + 8] /* return address (value stored in original sp) */
        ldr     x10, NETIntro  
        blr     x10 /* Hook->NETIntro(Hook, RetAddr, InitialSP)*/
/* should call original method?      */        
        cbnz    x0, CALL_HOOK_HANDLER

/* call original method */
        ldr     x10, IsExecutedPtr
try_dec_lock2:        
        ldxr    w0, [x10]
        add     w0, w0, #-1
        stxr    w1, w0, [x10]
        cbnz    w1, try_dec_lock2

        ldr     x10, OldProc
        b       TRAMPOLINE_EXIT
CALL_HOOK_HANDLER:

/* call hook handler        */
        ldr     x10, NewProc
        adr     x4, CALL_NET_OUTRO /*adjust return address */
        str     x4, [sp, #(10*8 + 8*16) + 8] /* store outro return to stack after hook handler is called     */    
        b       TRAMPOLINE_EXIT
 /* this is where the handler returns... */
CALL_NET_OUTRO:
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

TRAMPOLINE_EXIT:
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
        .byte   0x78
        .byte   0x56
        .byte   0x34
        .byte   0x12  
