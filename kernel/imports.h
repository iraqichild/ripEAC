#ifndef IMPORTS_H
#define IMPORTS_H

#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>
#include <windef.h>
#include <intrin.h>
#include <cstdint>
#include "structure.h"

UNICODE_STRING unicodeStr(const LPWSTR str)
{
	UNICODE_STRING x = { 0 };

	if (str)
		RtlInitUnicodeString(&x, str);

	return x;
}

inline uintptr_t get_kernel_base() {
	uintptr_t idt_base = *reinterpret_cast<uintptr_t*>(__readgsqword(0x18) + 0x38);
	uintptr_t base_addr = *reinterpret_cast<uintptr_t*>(reinterpret_cast<uint8_t*>(idt_base) + 4) & 0xFFFFFFFFFFFFF000;

start:
	uintptr_t index = 0;

	while (true) {
		if (*reinterpret_cast<uint8_t*>(base_addr + index) == 0x48 &&
			*reinterpret_cast<uint8_t*>(base_addr + index + 1) == 0x8D &&
			*reinterpret_cast<uint8_t*>(base_addr + index + 2) == 0x1D &&
			*reinterpret_cast<uint8_t*>(base_addr + index + 6) == 0xFF) { // 48 8D 1D ?? ?? ?? FF

			uint32_t offset = *reinterpret_cast<uint32_t*>(base_addr + index + 3);

			if (((static_cast<uint16_t>(base_addr) + static_cast<uint16_t>(index) + static_cast<uint16_t>(offset) + 7) & 0xFFF) == 0)
				return base_addr & 0xFFFFFFFF00000000 | static_cast<unsigned int>(index + base_addr + offset + 7);
		}

		if (++index == 4089) {
			base_addr -= 0x1000;
			goto start;
		}
	}

	return 0x0;
}

extern "C" {
	NTSYSAPI
		NTSTATUS
		NTAPI
		NtQuerySystemInformation(
			IN	DWORD					SystemInformationClass,
			OUT PVOID                   SystemInformation,
			IN	ULONG                   SystemInformationLength,
			OUT PULONG                  ReturnLength
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		MmCopyVirtualMemory(
			PEPROCESS SourceProcess,
			PVOID SourceAddress,
			PEPROCESS TargetProcess,
			PVOID TargetAddress,
			SIZE_T BufferSize,
			KPROCESSOR_MODE PreviousMode,
			PSIZE_T ReturnSize
		);

	NTSYSAPI
		NTSTATUS
		WINAPI
		ZwQuerySystemInformation(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			IN OUT PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT OPTIONAL PULONG ReturnLength
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwProtectVirtualMemory(
			IN HANDLE ProcessHandle,
			IN OUT PVOID* BaseAddress,
			IN SIZE_T* NumberOfBytesToProtect,
			IN ULONG NewAccessProtection,
			OUT PULONG OldAccessProtection
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ObReferenceObjectByName(
			__in PUNICODE_STRING ObjectName,
			__in ULONG Attributes,
			__in_opt PACCESS_STATE AccessState,
			__in_opt ACCESS_MASK DesiredAccess,
			__in POBJECT_TYPE ObjectType,
			__in KPROCESSOR_MODE AccessMode,
			__inout_opt PVOID ParseContext,
			__out PVOID* Object
		);

	PLIST_ENTRY NTKERNELAPI PsLoadedModuleList;

	NTKERNELAPI
		PVOID
		NTAPI 
		RtlFindExportedRoutineByName(
			_In_ PVOID ImageBase, 
			_In_ PCCH RoutineName
		);

	NTKERNELAPI 
		NTSTATUS 
		IoCreateDriver(PUNICODE_STRING DriverName, 
			PDRIVER_INITIALIZE InitializationFunction
		);


	NTKERNELAPI
		NTSTATUS
		PsGetContextThread(_In_ PETHREAD Thread,
			_Inout_ PCONTEXT ThreadContext, 
			_In_ KPROCESSOR_MODE Mode
		);

	NTKERNELAPI
		NTSTATUS 
		PsSetContextThread(_In_ PETHREAD Thread, 
			_In_ PCONTEXT ThreadContext, 
			_In_ KPROCESSOR_MODE Mode
		);

	PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
}

#endif