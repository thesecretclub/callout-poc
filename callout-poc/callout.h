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
//old_kernel_stack: the stack it will use; the given address of the original kernel stack (e.g. kernel_stack_preserve)
//stack_arg_count: the amount of stack arguments; if you pass more than 4 arguments, you have (arg_count - 4) amount of stack arguments. if you pass fewer than 4 arguments, stack_arg_count must be zero.
//eflags_xor: the value that eflags will be xored by; use a value 0x200 (CALLOUT_ENABLE_INTERRUPT_FLAG) to enable interrupts if they are disabled, for example.
//the register arguments, r1-r4, are directly given as x64 fastcall argument registers; on function entry, r1 = rcx, r2 = rdx, r3 = r8, and r4 = r9.
//this also beckons an expectation of stack layout. do not redefine this function to have a fewer number of required register arguments.
//furthermore, unused arguments should be initialized with NULL/0 to prevent information leaks.
//the remaning variadic arguments are simply given to the function as-is.
//if the function you are calling returns an argument with a value greater than the size of a GPR (8 bytes), you must call it with r1 pointing to a variable of that type.
//note that the return value of the function will point to the buffer you had allocated and given in r1.
//also important to note: this function does not support the calling of functions that return floating-point values as the value will be present in XMM0.

//if you think this is cumbersome, you are welcome to make a wrapper/alternative like this:
//void *callout_invoke_wrapper(void *function, void *old_kernel_stack, size_t stack_arg_count, size_t eflags_xor, ...);
//and to use a macro/C++ to fill in the gaps; or to use C++ to default-initialize unused register parameters to 0/NULL.

//it is also easily possible to adapt this to a floating-point return type by defining a duplicate version of this function that returns a floating point value, noting, of course, that you likely will not run into that situation.
extern void *callout_invoke(void *function, void *old_kernel_stack, size_t stack_arg_count, size_t eflags_xor, void *r1, void *r2, void *r3, void *r4, ...);

//traceless bugcheck; minidumps will show absolutely no discernable context.
extern __declspec(noreturn) void callout_bugcheck(void);