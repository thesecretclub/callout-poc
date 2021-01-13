/*
	Copyright (c) 2021 by Drew P. (reserveblue@protonmail.com)

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

#include "callout.h"
#include "util.h"
#include <ntimage.h>

uintptr_t g_ret_instruction_addr = 0; //referenced by asm_callout
uintptr_t g_rop_gadget_addr = 0; //referenced by asm_callout

static void thread_boostrapper(void *start_context, void *kernel_stack_preserve)
{
	UNREFERENCED_PARAMETER(start_context);

	//missing, or can optionally be added:
	//-free startup shellcode
	//-spoof thread start address
	//-find all references to the startup shellcode in the original kernel stack and remove them

	//we can otherwise execute regularly. note the limitations of callouts:
	//-certain blocking operations (e.g. file I/O) may unpredictably cause crashes if used excessively
	//-the thread must constantly run with interrupts disabled until it performs a callout. until then, all blocking must involve a callout; either to a NOP/PAUSE, or to KeDelayExecutionThread or similar
		//-in other words, non-callout blocking (e.g. a while (true) or even a simple spin loop) must involve a callout.
	//-interrupts are disabled; you can not read or write paged memory without a callout. this can potentially be mitigated with an imported memcpy (NOTING CAREFULLY TO NOT PREVENT THE COMPILER FROM INSERTING ITS OWN MEMCPY! YOU WANT THE MEMCPY EXPORTED BY NTOSKRNL.EXE)

	//here, we can mostly do what we want.
	callout_invoke((void *)DbgPrintEx, kernel_stack_preserve, 3, CALLOUT_ENABLE_INTERRUPT_FLAG, DPFLTR_IHVDRIVER_ID, 0, (ULONG64)"Test of printing. varargs: %u %u %u %u\n", 1, 2, 3, 4);

	//we can even sleep...
	LARGE_INTEGER sleep_interval;
	sleep_interval.QuadPart = (ULONG64)-(1000 * 1000 * 10);

	callout_invoke((void *)KeDelayExecutionThread, kernel_stack_preserve, 0, CALLOUT_ENABLE_INTERRUPT_FLAG, KernelMode, TRUE, (ULONG64)&sleep_interval, 0);
	callout_invoke((void *)DbgPrintEx, kernel_stack_preserve, 0, CALLOUT_ENABLE_INTERRUPT_FLAG, DPFLTR_IHVDRIVER_ID, 0, (ULONG64)"(Probably) slept for one second\n", 0);

	//...or allocate memory...
	size_t *const alloc_base = callout_invoke((void *)ExAllocatePool, kernel_stack_preserve, 0, CALLOUT_ENABLE_INTERRUPT_FLAG, NonPagedPool, sizeof(size_t), 0, 0);

	if (alloc_base)
	{
		callout_invoke((void *)DbgPrintEx, kernel_stack_preserve, 0, CALLOUT_ENABLE_INTERRUPT_FLAG, DPFLTR_IHVDRIVER_ID, 0, (ULONG64)"Alloc succeeded 0x%llX\n", (ULONG64)alloc_base);
		callout_invoke((void *)ExFreePoolWithTag, kernel_stack_preserve, 0, CALLOUT_ENABLE_INTERRUPT_FLAG, (ULONG64)alloc_base, 0, 0, 0);
	}

	//and we can enter an infinite loop.
	for (size_t i = 0;; i++)
	{
		callout_invoke((void *)KeDelayExecutionThread, kernel_stack_preserve, 0, CALLOUT_ENABLE_INTERRUPT_FLAG, KernelMode, TRUE, (ULONG64)&sleep_interval, 0);
		callout_invoke((void *)DbgPrintEx, kernel_stack_preserve, 0, CALLOUT_ENABLE_INTERRUPT_FLAG, DPFLTR_IHVDRIVER_ID, 0, (ULONG64)"iter %u\n", i);
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	const uintptr_t ntoskrnl_base = util_get_kernel_module("ntoskrnl.exe");
	
	const IMAGE_DOS_HEADER *const dos_header = (void *)ntoskrnl_base;
	const IMAGE_NT_HEADERS64 *const nt_header = (void *)(ntoskrnl_base + dos_header->e_lfanew);

	const size_t ntoskrnl_size = nt_header->OptionalHeader.SizeOfImage;

	//this is just a POC. lazily increment the start address past the file header to what is likely the start of the nonpaged text section of ntoskrnl.exe
	const uintptr_t likely_code_section = ntoskrnl_base + 0x1000;
	const size_t likely_code_size = ntoskrnl_size - 0x1000;

	g_ret_instruction_addr = (uintptr_t)util_generic_sigscan_within_module(likely_code_section, likely_code_size, (const UCHAR *)"\xC3", "x");

	if (!g_ret_instruction_addr)
		return STATUS_INTERNAL_ERROR; //something REALLY went wrong...

	//48 8B E5 48 8B AD ? ? ? ? 48 81 C4 ? ? ? ? 48 CF
	/*
	mov rsp, rbp
	mov rbp, [rbp+????????h]	;4 byte reference
	add rsp, ????????h	;ditto
	iretq

	note that the first offset does not matter but the second offset is assumed to never change. it is therefore hardcoded within the assembly routines and assumed to be 0xE8.
	*/
	g_rop_gadget_addr = (uintptr_t)util_generic_sigscan_within_module(likely_code_section, likely_code_size, (const UCHAR *)"\x48\x8B\xE5\x48\x8B\xAD\x00\x00\x00\x00\x48\x81\xC4\x00\x00\x00\x00\x48\xCF", "xxxxxx????xxx????xx");

	if (!g_rop_gadget_addr)
		return STATUS_INTERNAL_ERROR;

	const size_t stack_size = 0x1000 * 8;
	const uintptr_t real_stack = (uintptr_t)ExAllocatePoolWithTag(NonPagedPool, stack_size, 'COPC');

	if (!real_stack)
		return STATUS_INTERNAL_ERROR; //failed to allocate stack memory

	memset((void *)real_stack, 0, stack_size);

	/*
	cli
	mov rdx, rsp ;store stack pointer; this value is always unaligned
	mov rsp, ????????????????h ;stack pointer to load
	movabs rax, ????????????????h ;routine to jump to
	jmp rax
	*/
	const UCHAR thread_start_shellcode[] = { 0xFA, 0x48, 0x89, 0xE2, 0x48, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
	UCHAR *const shellcode_base = ExAllocatePoolWithTag(NonPagedPool, sizeof(thread_start_shellcode), 'COPC');

	if (!shellcode_base)
		return STATUS_INTERNAL_ERROR;

	//note that shellcode_base is not freed in this implementation, and neither is the real thread stack.
	memcpy(shellcode_base, &thread_start_shellcode[0], sizeof(thread_start_shellcode));

	*(ULONG64 *)(&shellcode_base[6]) = real_stack + stack_size - 40; //allocate an aligned stack frame for the real stack; and point the stack pointer to the stack base
	*(ULONG64 *)(&shellcode_base[0x10]) = (uintptr_t)thread_boostrapper;

	//create system thread
	OBJECT_ATTRIBUTES object_attr;
	InitializeObjectAttributes(&object_attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE thread_handle = NULL;
	const NTSTATUS status = PsCreateSystemThread(&thread_handle, 0, &object_attr, NULL, NULL, (PKSTART_ROUTINE)shellcode_base, NULL);

	if (!NT_SUCCESS(status))
		return status;

	ZwClose(thread_handle);
	return STATUS_SUCCESS;
}