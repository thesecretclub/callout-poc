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

//!!!this may not resolve for some older or newer windows versions!!!
extern __declspec(dllimport) NTSTATUS ZwQuerySystemInformation(
	_In_      ULONG SystemInformationClass,
	_Inout_   void *SystemInformation,
	_In_      ULONG SystemInformationLength,
	_Out_opt_ ULONG *ReturnLength
);

//find the base address of a kernel module/driver given its ascii-converted name
//this function is kind of bad, but should generally work for most (if not all) people
uintptr_t util_get_kernel_module(const char *module_name)
{
	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

	//try to allocate enough space for the RTL_PROCESS_MODULES struct and all the modules that follow
	ULONG needed_bytes = 8192;
	void *buffer_bytes = ExAllocatePoolWithTag(PagedPool, needed_bytes, 'COPC');

	if (!buffer_bytes)
		return 0;

	NTSTATUS last_status = ZwQuerySystemInformation(11, buffer_bytes, needed_bytes, &needed_bytes);

	while (last_status == STATUS_INFO_LENGTH_MISMATCH)
	{
		//we don't have enough bytes
		ExFreePool(buffer_bytes);
		buffer_bytes = ExAllocatePoolWithTag(PagedPool, needed_bytes, 'COPC');

		if (!buffer_bytes)
			return 0;

		last_status = ZwQuerySystemInformation(11, buffer_bytes, needed_bytes, &needed_bytes);
	}

	if (!NT_SUCCESS(last_status) && last_status != STATUS_INFO_LENGTH_MISMATCH)
	{
		ExFreePool(buffer_bytes);
		return 0;
	}

	const RTL_PROCESS_MODULES *const process_modules = (RTL_PROCESS_MODULES *)buffer_bytes;
	uintptr_t result = 0;

	//loop through modules
	for (ULONG i = 0; i < process_modules->NumberOfModules; i++)
	{
		//OffsetToFileName is the offset from the full path to the filename of the module
		if (!_stricmp((char *)(process_modules->Modules[i].FullPathName + process_modules->Modules[i].OffsetToFileName), module_name))
		{
			result = (uintptr_t)(process_modules->Modules[i].ImageBase);
			break;
		}
	}

	ExFreePool(buffer_bytes);
	return result;
}

//simple and bad signature scan. this will check the entire module indiscriminately; it may or may not run into unmapped sections or return pointers into non-code sections.
//this function only returns the address in which the signature had appeared. if no signature is found, the function returns NULL.
static void *util_generic_sigscan_within_module(uintptr_t base, size_t size, const UCHAR *sig, const char *mask)
{
	const size_t pattern_size = strlen(mask);
	uintptr_t rva = 0;

	for (; rva < size - pattern_size + 1; rva++)
	{
		BOOLEAN bytes_fit_pattern = TRUE;

		//search at this rva for the pattern
		for (size_t i = 0; i < pattern_size; i++)
		{
			if (mask[i] == 'x' && (*(UCHAR *)(i + rva + base) != sig[i]))
			{
				bytes_fit_pattern = FALSE;
				break;
			}
		}

		if (bytes_fit_pattern)
			return (void *)(rva + base);
	}

	return NULL;
}