#ifndef KERNELUTIL_H
#define KERNELUTIL_H

#include <ntifs.h>
#include <ntddk.h>
#include "imports.h"
#include "structure.h"

inline IMAGE_DOS_HEADER* GetImageDosHeader(const PVOID Image) {
	if (!Image)
		return nullptr;
	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(Image);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;
	return dosHeader;
}
inline IMAGE_NT_HEADERS* GetImageNtHeader(const PVOID Image) {
	IMAGE_DOS_HEADER* dosHeader = GetImageDosHeader(Image);
	if (!dosHeader || dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew > 0x10000)
		return nullptr;
	IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>((BYTE*)Image + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;
	return ntHeaders;
}

PVOID get_kernel_proc_address(const LPWSTR system_routine_name)
{
	UNICODE_STRING name = unicodeStr(system_routine_name);
	return MmGetSystemRoutineAddress(&name);
}

PVOID get_module_base(const LPWSTR module_name)
{
	PLIST_ENTRY ps_loaded_module_list = PsLoadedModuleList;
	if (!ps_loaded_module_list)
		return (PVOID)NULL;

	UNICODE_STRING name = unicodeStr(module_name);
	for (PLIST_ENTRY link = ps_loaded_module_list; link != ps_loaded_module_list->Blink; link = link->Flink)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlEqualUnicodeString((PCUNICODE_STRING)&entry->BaseDllName, (PCUNICODE_STRING)&name, TRUE))
		{
			return (PVOID)entry->DllBase;
		}
	}

	return (PVOID)NULL;
}

SIZE_T get_module_size(const LPWSTR module_name)
{
	PLIST_ENTRY ps_loaded_module_list = PsLoadedModuleList;
	if (!ps_loaded_module_list)
		return (SIZE_T)NULL;

	UNICODE_STRING name = unicodeStr(module_name);
	for (PLIST_ENTRY link = ps_loaded_module_list; link != ps_loaded_module_list->Blink; link = link->Flink)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlEqualUnicodeString((PCUNICODE_STRING)&entry->BaseDllName, (PCUNICODE_STRING)&name, TRUE))
		{
			return (SIZE_T)entry->SizeOfImage;
		}
	}

	return (SIZE_T)NULL;
}


PVOID get_system_base_export(const LPWSTR module_name, LPCSTR routine_name)
{
	PVOID lp_module = get_module_base(module_name);
	if (!lp_module)
		return NULL;

	return RtlFindExportedRoutineByName(lp_module, routine_name);
}

PVOID GetExportAddress(PVOID ModuleBase, const char* ExportName) {
    if (!ModuleBase || !ExportName) {
        return NULL;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!exportDir->AddressOfNames || !exportDir->AddressOfFunctions || !exportDir->AddressOfNameOrdinals) {
        return NULL;
    }

    PULONG nameTable = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
    PUSHORT ordinalTable = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);
    PULONG funcTable = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);

    for (ULONG i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((PUCHAR)ModuleBase + nameTable[i]);
        if (_stricmp(name, ExportName) == 0) {
            USHORT ordinal = ordinalTable[i];
            PVOID address = (PVOID)((PUCHAR)ModuleBase + funcTable[ordinal]);
            return address;
        }
    }

    return NULL;
}

#define X64_PML4E_ADDRESS_BITS 47
#define X64_PDPTE_ADDRESS_BITS 39
#define X64_PDTE_ADDRESS_BITS 30
#define X64_PTE_ADDRESS_BITS 21
#define PT_SHIFT 12
#define PDT_SHIFT 21
#define PDPT_SHIFT 30
#define PML4_SHIFT 39
#define ENTRY_SHIFT 3
#define X64_PX_MASK(_ADDRESS_BITS) ((((UINT64)1) << _ADDRESS_BITS) - 1)
#define Pml4Index(Va) ((UINT64)((Va & (UINT64)(X64_PX_MASK(X64_PML4E_ADDRESS_BITS)) >> PML4_SHIFT)))
#define PdptIndex(Va) ((UINT64)((Va & (UINT64)(X64_PX_MASK(X64_PDPTE_ADDRESS_BITS)) >> PDPT_SHIFT)))
#define PdtIndex(Va) ((UINT64)((Va & (UINT64)(X64_PX_MASK(X64_PDTE_ADDRESS_BITS)) >> PDT_SHIFT)))
#define PtIndex(Va) ((UINT64)((Va & (UINT64)(X64_PX_MASK(X64_PTE_ADDRESS_BITS)) >> PT_SHIFT)))
#define GetPml4e(Cr3, Va) ((PPTE_64)((Cr3 & ~0xFFF) + (Pml4Index(Va) << ENTRY_SHIFT)))
#define GetPdpte(Pml4e, Va) ((PPTE_64)((Pml4e->PageFrameNumber << 12) + (PdptIndex(Va) << ENTRY_SHIFT)))
#define GetPdte(Pdpte, Va) ((PPTE_64)((Pdpte->PageFrameNumber << 12) + (PdtIndex(Va) << ENTRY_SHIFT)))
#define GetPte(Pdte, Va) ((PPTE_64)((Pdte->PageFrameNumber << 12) + (PtIndex(Va) << ENTRY_SHIFT)))

#endif