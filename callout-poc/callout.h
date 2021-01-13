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

#pragma once
#include <ntifs.h>

#define CALLOUT_ENABLE_INTERRUPT_FLAG (0x200)

//function: the address of the function to call
//old_kernel_stack: the stack it will use; the given address of the original kernel stack
//stack_arg_count: the amount of stack arguments; if you pass more than 4 arguments, you have (arg_count - 4) amount of stack arguments. if you pass fewer than 4 arguments, stack_arg_count must be zero.
//eflags_xor: the value that eflags will be xored by; use a value 0x200 (CALLOUT_ENABLE_INTERRUPT_FLAG) to enable interrupts if they are disabled, for example.
//the remaning variadic arguments are simply given to the function.
//if the function you are calling returns an argument with a value greater than 64 bits, you should call it with the first argument pointing to a variable of that type;
//the return value will point to that structure.
//also, to avoid leaking sensitive information (and to avoid potential crashes), make sure to always pass at least 4 arguments - fill unused arguments with NULL
//also important to note: this function does not support the calling of functions that return floating-point values as the value will be present in XMM0.
extern void *callout_invoke(void *function, void *old_kernel_stack, size_t stack_arg_count, ULONG64 eflags_xor, ULONG64 r1, ULONG64 r2, ULONG64 r3, ULONG64 r4, ...);

//traceless bugcheck; minidumps will show absolutely no discernable context.
extern __declspec(noreturn) void callout_bugcheck(void);