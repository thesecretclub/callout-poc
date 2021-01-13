;	Copyright (c) 2021 by Drew P. (reserveblue@protonmail.com)
;
;	Permission is hereby granted, free of charge, to any person obtaining a copy
;	of this software and associated documentation files (the "Software"), to deal
;	in the Software without restriction, including without limitation the rights
;	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
;	copies of the Software, and to permit persons to whom the Software is
;	furnished to do so, subject to the following conditions:
;
;	The above copyright notice and this permission notice shall be included in all
;	copies or substantial portions of the Software.
;
;	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
;	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
;	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
;	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
;	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
;	SOFTWARE.

.code

extern g_ret_instruction_addr:qword
extern g_rop_gadget_addr:qword

align 10h

;void *callout_invoke(void *function, void *old_kernel_stack, size_t stack_arg_count, ULONG64 eflags_xor, ULONG64 r1, ULONG64 r2, ULONG64 r3, ULONG64 r4, ...)
;note that the old_kernel_stack is always misaligned; it is always aligned to 8 bytes.
callout_invoke proc

push rdi
push rsi
push rbp

mov rax, rcx ;put function pointer into rax as we need to overwrite rcx
lea r10, [rsp + 20h] ;stack context at function call (before call instruction to this function, taking into account the register pushes and return address push)
sub rsp, 10h ;align the stack if an odd number of registers are preserved; this should subtract only 8 bytes instead of 16 out if an even number of registers are pushed as the stack would be aligned. note that alignment is a relative term for the sub rsp, 8 that would normally occur (see the iret frame right below)
;because of this, there is also an add rsp, 8 at the end of the function; this can be removed if this instruction only subtracts 8 bytes

;push iret frame into rdx
sub rdx, 138h ;28h for the iret frame + E8h for the stack pointer offset + 8 bytes for alignment + 20h for the function call frame

mov rcx, [g_ret_instruction_addr]
mov [rdx + 110h], rcx ;rip

mov ecx, cs
mov [rdx + 118h], rcx ;cs

pushfq
pop rcx
mov [rdx + 120h], rcx ;rflags

lea rcx, [return_loc]
mov [rsp], rcx							;the relevant stack memory is allocated above! make sure your alignment is correct
mov [rdx + 128h], rsp ;rsp to load

mov ecx, ss
mov [rdx + 130h], rcx ;ss

;confuse someone by putting some address on this otherwise unused space
mov rcx, [g_ret_instruction_addr]
mov [rdx + 28h], rcx

;keep this in rbp. this will be used by our ROP gadget to jump back here
lea rbp, [rdx + 28h]

;if we have more than 4 args, we need to push shit on to the stack
test r8, r8
jz no_sub_rsp

lea r11, [r8 * 8] ;total bytes allocated
sub rdx, r11

;we must always call the function with a misaligned stack (rather, including the return address; before the function is called, the stack is aligned)
;this function has three sections: the entry, the stack argument handling, and the call. the entry always has an aligned stack and the call always has a misaligned stack
;to keep the stack misaligned by the end we must keep the stack aligned in this function
;however, if the caller specifies an odd amount of stack arguments, we misalign the stack (r8 * 8 will be a multiple of 8 and not of 16)
;so, to fix this, we can simply re-align the stack by subtracting an extra argument (AND rsp by ~0xF, making it conditionally aligned)
and rdx, 0FFFFFFFFFFFFFFF0h

;copy bytes from our special stack to this stack
lea rsi, [r10 + 40h] ;register to hold source; points to first stack argument (the 40h is due to register shadow (20h) plus the first 4 arguments (4 * 8 = 20h) pushed to the function)
lea rdi, [rdx + 20h] ;register to hold dest; points to first stack argument (add 20h as otherwise the arguments would be inside of the shadow space)
mov rcx, r8 ;register to hold size (movsq mul by 8)

rep movsq ;set stack args

;NO TRACES
xor esi, esi
xor edi, edi

no_sub_rsp:

;so far:
;rdx holds the stack pointer we need to load
;rax holds the address of the function we need to call
;r9 holds the value used to xor rflags
;r10 holds our original stack pointer
;rbp holds an address loaded by an IRET

;construct an IRET frame

;simulate a call
mov rcx, [g_rop_gadget_addr]
sub rdx, 8
mov [rdx], rcx

mov ecx, ss
push rcx		;ss		+ 20h
push rdx		;rsp	+ 18h
pushfq			;rflags	+ 10h

xor [rsp], r9

mov ecx, cs
push rcx		;cs		+ 8h
push rax		;rip	+ 0

;rax can be cleared
xor eax, eax

;set arguments
mov rcx, [r10 + 20h]
mov rdx, [r10 + 28h]
mov r8, [r10 + 30h]
mov r9, [r10 + 38h]

;r10 can be cleared
xor r10, r10

;at this point, the only register with incriminating evidence is RBP - which points to the IRET (part of the) kernel stack
;as well, we have this information left over on the kernel stack with no real way to clear it
;although finding it would be nigh impossible since it's likely to get wiped anyways, meaning the only real marking is RBP and the iret stack allocation (which is pointed to by RBP)
;as well as the function's return address being set to a fixed iret pattern (too non-specific to check?)
;the stack may also not be perfectly normal and contain random pool allocations which don't point to any code
iretq

align 10h
;when that function returns, it goes to a routine like
;mov rsp, rbp
;mov rbp, [rbp + offset]
;add rsp, offset
;iretq
;so by setting rbp to a valid IRET stack (after adding the rsp offset), we can have it load back our stack and instruction pointer - with interrupts disabled
;the only problem is that putting our instruction pointer here would leave it exposed on the stack - which is solved by having it point towards a RET instruction (which is valid) and pushing return_loc on to the stack that is loaded (our stack)
;which means that this routine loads our stack, disables interrupts, jumps to a ret instruction, causing it to return here - all with interrupts disabled and no obvious traces on the kernel stack
;we may have to add 8 to rsp, depending on if i had to align it earlier

return_loc:
add rsp, 8
pop rbp
pop rsi
pop rdi

ret

callout_invoke endp


align 10h

;void callout_bugcheck(void)
callout_bugcheck proc

;construct an iret frame
;give it a zeroed or garbage stack and instruction pointer
;this will cause it to page fault (bad RIP) which will then cause another page fault (bad RSP) which will cause a double fault
xor eax, eax

mov ebx, ss
push rbx        ;ss		+ 20h
push rax        ;rsp	+ 18h
pushfq          ;rflags	+ 10h

mov ebx, cs
push rbx        ;cs		+ 8h
push rax		;rip	+ 0

;clear registers
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
xor esi, esi
xor edi, edi
xor ebp, ebp
xor r8, r8
xor r9, r9
xor r10, r10
xor r11, r11
xor r12, r12
xor r13, r13
xor r14, r14
xor r15, r15

iretq

callout_bugcheck endp

end