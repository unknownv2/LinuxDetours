#include "detours.h"

#if defined(DETOURS_X64) 
__asm__
(R"(.intel_syntax
.globl Trampoline_ASM_x64
.globl trampoline_template_x64
.globl trampoline_data_x64

Trampoline_ASM_x64:

NETIntro:
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0 
OldProc:
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
NewProc:
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
NETOutro:
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
IsExecutedPtr: 
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0

trampoline_template_x64:

    push rsp
    push qword ptr [rsp]
    and rsp, 0xFFFFFFFFFFFFFFF0

    mov rax, rsp
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    sub rsp, 8 * 16 ## space for SSE registers

    movups [rsp + 7 * 16], xmm0
    movups [rsp + 6 * 16], xmm1
    movups [rsp + 5 * 16], xmm2
    movups [rsp + 4 * 16], xmm3
    movups [rsp + 3 * 16], xmm4
    movups [rsp + 2 * 16], xmm5
    movups [rsp + 1 * 16], xmm6
    movups [rsp + 0 * 16], xmm7

    sub rsp, 32## shadow space for method calls

    lea rax, [rip + IsExecutedPtr]
    mov rax, [rax]
    .byte 0xF0 ## interlocked increment execution counter
    inc qword ptr [rax]

## is a user handler available?
    cmp qword ptr [rip + NewProc], 0

    .byte 0x3E ## branch usually taken
    jne call_net_entry

###################################################################################### call original method
        lea rax, [rip + IsExecutedPtr]
        mov rax, [rax]
        .byte 0xF0 ## interlocked decrement execution counter
        dec qword ptr [rax]

        lea rax, [rip + OldProc]
        jmp trampoline_exit

###################################################################################### call hook handler or original method...
call_net_entry:


## call NET intro
    lea rdi, [rip + IsExecutedPtr + 8] ## Hook handle (only a position hint)
    ## Here we are under the alignment trick.
    mov rdx, [rsp + 32 + 8 * 16 + 6 * 8 + 8] ## rdx = original rsp (address of return address)
    mov rsi, [rdx] ## return address (value stored in original rsp)
    call qword ptr [rip + NETIntro] ## Hook->NETIntro(Hook, RetAddr, InitialRSP)##

## should call original method?
    test rax, rax

    .byte 0x3E ## branch usually taken
    jne call_hook_handler

    ## call original method
        lea rax, [rip + IsExecutedPtr]
        mov rax, [rax]
        .byte 0xF0 ## interlocked decrement execution counter
        dec qword ptr [rax]

        lea rax, [rip + OldProc]
        jmp trampoline_exit

call_hook_handler:
## adjust return address
    lea rax, [rip + call_net_outro]
    ## Here we are under the alignment trick.
    mov r9, [rsp + 32 + 8 * 16 + 6 * 8 + 8] ## r9 = original rsp
    mov qword ptr [r9], rax

## call hook handler
    lea rax, [rip + NewProc]
    jmp trampoline_exit

call_net_outro: ## this is where the handler returns...

## call NET outro
    ## Here we are NOT under the alignment trick.

    push 0 ## space for return address
    push rax

    sub rsp, 32 + 16## shadow space for method calls and SSE registers
    movups [rsp + 32], xmm0

    lea rdi, [rip + IsExecutedPtr + 8]  ## Param 1: Hook handle hint
    lea rsi, [rsp + 56] ## Param 2: Address of return address
    call qword ptr [rip + NETOutro] ## Hook->NETOutro(Hook)##

    lea rax, [rip + IsExecutedPtr]
    mov rax, [rax]
    .byte 0xF0 ## interlocked decrement execution counter
    dec qword ptr [rax]

    add rsp, 32 + 16
    movups xmm0, [rsp - 16]

    pop rax ## restore return value of user handler...

## finally return to saved return address - the caller of this trampoline...
    ret

######################################################################################## generic outro for both cases...
trampoline_exit:

    add rsp, 32 + 16 * 8
    movups xmm7, [rsp - 8 * 16]
    movups xmm6, [rsp - 7 * 16]
    movups xmm5, [rsp - 6 * 16]
    movups xmm4, [rsp - 5 * 16]
    movups xmm3, [rsp - 4 * 16]
    movups xmm2, [rsp - 3 * 16]
    movups xmm1, [rsp - 2 * 16]
    movups xmm0, [rsp - 1 * 16]

    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi

    ## Remove alignment trick: https://stackoverflow.com/a/9600102
    mov rsp, [rsp + 8]

    jmp qword ptr [rax] ## ATTENTION: In case of hook handler we will return to call_net_outro, otherwise to the caller...

## outro signature, to automatically determine code size

trampoline_data_x64:
    .byte 0x78
    .byte 0x56
    .byte 0x34
    .byte 0x12

)");

#endif
