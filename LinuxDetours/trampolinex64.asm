;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; Trampoline_ASM_x64
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; This method is highly optimized and executes within 78 nanoseconds
; including the intro, outro and return...
; "IsExecuted" has to be within the next code subpage to prevent the
; Self-Modifing-Code-Condition to apply which would reduce performance
; about 200 ns.

; Only for comparsion: The first proof of concept was unoptimized and
; did execute within 10000 nanoseconds... This optimized version just
; uses RIP relative addressing instead of register relative addressing,
; prevents the SMC condition and uses RIP relative jumps...


default rel
section .text
global Trampoline_ASM_x64

Trampoline_ASM_x64:

NETIntro:
	;void*			NETEntry; // fixed 0 (0)
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0

OldProc:
	;BYTE*			OldProc; // fixed 4 (8)
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0

NewProc:
	;BYTE*			NewProc; // fixed 8 (16)
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0

NETOutro:
	;void*			NETOutro; // fixed 12 (24)
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0

IsExecutedPtr:
	;size_t*		IsExecutedPtr; // fixed 16 (32)
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0


; ATTENTION: 64-Bit requires stack alignment (RSP) of 16 bytes!!
	; Apply alignment trick: https://stackoverflow.com/a/9600102
	push rsp
	push qword [rsp]
	and rsp, 0FFFFFFFFFFFFFFF0H

	mov rax, rsp
	push rdi ; save not sanitized registers...
	push rsi
	push rdx
	push rcx
	push r8
	push r9

	sub rsp, 8 * 16 ; space for SSE registers

	movups [rsp + 7 * 16], xmm0
	movups [rsp + 6 * 16], xmm1
	movups [rsp + 5 * 16], xmm2
	movups [rsp + 4 * 16], xmm3
	movups [rsp + 3 * 16], xmm4
	movups [rsp + 2 * 16], xmm5
	movups [rsp + 1 * 16], xmm6
	movups [rsp + 0 * 16], xmm7

	sub rsp, 32; shadow space for method calls

	lea rax, [IsExecutedPtr]
	mov rax, [rax]
	db 0F0h ; interlocked increment execution counter
	inc qword [rax]

; is a user handler available?
	cmp qword [NewProc], 0

	db 3Eh ; branch usually taken
	jne CALL_NET_ENTRY

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call original method
		lea rax, [IsExecutedPtr]
		mov rax, [rax]
		db 0F0h ; interlocked decrement execution counter
		dec qword [rax]

		lea rax, [OldProc]
		jmp TRAMPOLINE_EXIT

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call hook handler or original method...
CALL_NET_ENTRY:


; call NET intro
	lea rdi, [IsExecutedPtr + 8] ; Hook handle (only a position hint)
	; Here we are under the alignment trick.
	mov rdx, [rsp + 32 + 8 * 16 + 6 * 8 + 8]  ; rdx = original rsp (address of return address)
	mov rsi, [rdx] ; return address (value stored in original rsp)
	call qword [NETIntro] ; Hook->NETIntro(Hook, RetAddr, InitialRSP);

; should call original method?
	test rax, rax

	db 3Eh ; branch usually taken
	jne CALL_HOOK_HANDLER

	; call original method
		lea rax, [IsExecutedPtr]
		mov rax, [rax]
		db 0F0h ; interlocked decrement execution counter
		dec qword [rax]

		lea rax, [OldProc]
		jmp TRAMPOLINE_EXIT

CALL_HOOK_HANDLER:
; adjust return address
	lea rax, [CALL_NET_OUTRO]
	; Here we are under the alignment trick.
	mov r9, [rsp + 32 + 8 * 16 + 6 * 8 + 8] ; r9 = original rsp
	mov qword [r9], rax

; call hook handler
	lea rax, [NewProc]
	jmp TRAMPOLINE_EXIT

CALL_NET_OUTRO: ; this is where the handler returns...

; call NET outro
	; Here we are NOT under the alignment trick.

	push 0 ; space for return address
	push rax

	sub rsp, 32 + 16; shadow space for method calls and SSE registers
	movups [rsp + 32], xmm0

	lea rdi, [IsExecutedPtr + 8]  ; Param 1: Hook handle hint
	lea rsi, [rsp + 56] ; Param 2: Address of return address
	call qword [NETOutro] ; Hook->NETOutro(Hook);

	lea rax, [IsExecutedPtr]
	mov rax, [rax]
	db 0F0h ; interlocked decrement execution counter
	dec qword [rax]

	add rsp, 32 + 16
	movups xmm0, [rsp - 16]

	pop rax ; restore return value of user handler...

; finally return to saved return address - the caller of this trampoline...
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; generic outro for both cases...
TRAMPOLINE_EXIT:


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

	; Remove alignment trick: https://stackoverflow.com/a/9600102
	mov rsp, [rsp + 8]

	jmp qword [rax] ; ATTENTION: In case of hook handler we will return to CALL_NET_OUTRO, otherwise to the caller...


; outro signature, to automatically determine code size
	db 78h
	db 56h
	db 34h
	db 12h

;Trampoline_ASM_x64 ENDP