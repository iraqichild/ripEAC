#include "interface.h"
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>

struct InjectionStruct
{
    Interface Driver;

    PVOID Module{};
    PVOID RemoteModule{};

    SIZE_T ModuleSize;

    IMAGE_DOS_HEADER* pDosHeader{};
    IMAGE_NT_HEADERS* pNtHeader{};
};

class CInjector
{
public:
    void vLog(const char* const _Format, ...)
    {
        va_list args;
        va_start(args, _Format);
        printf("[ripEAC] ");
        vprintf(_Format, args);
        printf("\n");
        va_end(args);
    }

    IMAGE_DOS_HEADER* GetImageDosHeader(InjectionStruct& Module);
    IMAGE_NT_HEADERS* GetImageNtHeader(InjectionStruct& Module);
    BOOLEAN FixModuleSections(InjectionStruct& Module);
    BOOLEAN FixModuleReallocations(InjectionStruct& Module);
    BOOLEAN FixModuleIAT(InjectionStruct& Module);
    BOOLEAN CleanModuleSections(InjectionStruct& Module);
    BOOLEAN CleanModulePeHeader(InjectionStruct& Module);
    PVOID GetModuleExportFunction(InjectionStruct& Module, const char* ExportName);

    BOOLEAN LoadFileIntoMemory(const wchar_t* FilePath, PVOID& FileBytes, SIZE_T& FileSize);
    BOOLEAN MapDll(Interface& ctx, PVOID Module, SIZE_T ModuleSize);
};

IMAGE_DOS_HEADER* CInjector::GetImageDosHeader(InjectionStruct& Module) {
    return reinterpret_cast<IMAGE_DOS_HEADER*>(Module.Module);
}

IMAGE_NT_HEADERS* CInjector::GetImageNtHeader(InjectionStruct& Module) {
    return reinterpret_cast<IMAGE_NT_HEADERS*>(
        static_cast<BYTE*>(Module.Module) + Module.pDosHeader->e_lfanew);
}

BOOLEAN CInjector::FixModuleSections(InjectionStruct& Module)
{
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(Module.pNtHeader);
    for (WORD i = 0; i < Module.pNtHeader->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData) {
            void* dest = static_cast<BYTE*>(Module.RemoteModule) + pSectionHeader[i].VirtualAddress;
            void* src = static_cast<BYTE*>(Module.Module) + pSectionHeader[i].PointerToRawData;
            if (!Module.Driver.write_memory(dest, src, pSectionHeader[i].SizeOfRawData)) {
                return false;
            }
        }
    }
  
    return true;
}
BOOLEAN CInjector::FixModuleReallocations(InjectionStruct& Module) {
    bool is_64bit = Module.pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (Module.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        SIZE_T delta = reinterpret_cast<SIZE_T>(Module.RemoteModule) - Module.pNtHeader->OptionalHeader.ImageBase;
        if (delta != 0) {
            void* reloc_address = static_cast<BYTE*>(Module.RemoteModule) +
                Module.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            IMAGE_BASE_RELOCATION reloc_block;

            while (Module.Driver.read_memory(reloc_address, &reloc_block, sizeof(IMAGE_BASE_RELOCATION)) && reloc_block.VirtualAddress) {
                DWORD num_entries = (reloc_block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                std::vector<WORD> reloc_entries(num_entries);
                void* entries_address = static_cast<BYTE*>(reloc_address) + sizeof(IMAGE_BASE_RELOCATION);

                if (!Module.Driver.read_memory(entries_address, reloc_entries.data(), num_entries * sizeof(WORD))) {
                    return FALSE;
                }

                for (DWORD i = 0; i < num_entries; i++) {
                    WORD reloc_type = reloc_entries[i] >> 12;
                    DWORD offset = reloc_entries[i] & 0xFFF;

                    if (reloc_type == IMAGE_REL_BASED_HIGHLOW && !is_64bit) {
                        DWORD* patch_address = reinterpret_cast<DWORD*>(
                            static_cast<BYTE*>(Module.RemoteModule) + reloc_block.VirtualAddress + offset);
                        DWORD current_value;
                        if (!Module.Driver.read_memory(patch_address, &current_value, sizeof(DWORD)) ||
                            !Module.Driver.write_memory(patch_address, &(current_value += static_cast<DWORD>(delta)), sizeof(DWORD))) {
                            return FALSE;
                        }
                    }
                    else if (reloc_type == IMAGE_REL_BASED_DIR64 && is_64bit) {
                        ULONGLONG* patch_address = reinterpret_cast<ULONGLONG*>(
                            static_cast<BYTE*>(Module.RemoteModule) + reloc_block.VirtualAddress + offset);
                        ULONGLONG current_value;
                        if (!Module.Driver.read_memory(patch_address, &current_value, sizeof(ULONGLONG)) ||
                            !Module.Driver.write_memory(patch_address, &(current_value += delta), sizeof(ULONGLONG))) {
                            return FALSE;
                        }
                    }
                }

                reloc_address = static_cast<BYTE*>(reloc_address) + reloc_block.SizeOfBlock;
            }
        }
    }
    return TRUE;
}
BOOLEAN CInjector::FixModuleIAT(InjectionStruct& Module) {
    if (Module.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            static_cast<BYTE*>(Module.RemoteModule) +
            Module.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        IMAGE_IMPORT_DESCRIPTOR import_desc = {};
        if (!Module.Driver.read_memory(pImportDesc, &import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            return FALSE;
        }

        while (import_desc.Name) {
            char dll_name[256] = { 0 };
            void* name_address = static_cast<BYTE*>(Module.RemoteModule) + import_desc.Name;
            if (!Module.Driver.read_memory(name_address, dll_name, sizeof(dll_name) - 1)) {
                return FALSE;
            }

            HMODULE hModule = LoadLibraryA(dll_name);
            if (!hModule) {
                return FALSE;
            }

            IMAGE_THUNK_DATA* pThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                static_cast<BYTE*>(Module.RemoteModule) + import_desc.FirstThunk);
            IMAGE_THUNK_DATA* pOrigThunk = import_desc.OriginalFirstThunk ?
                reinterpret_cast<IMAGE_THUNK_DATA*>(
                    static_cast<BYTE*>(Module.RemoteModule) + import_desc.OriginalFirstThunk) :
                pThunk;

            IMAGE_THUNK_DATA thunk_data = {};
            if (!Module.Driver.read_memory(pOrigThunk, &thunk_data, sizeof(IMAGE_THUNK_DATA))) {
                FreeLibrary(hModule);
                return FALSE;
            }

            while (thunk_data.u1.AddressOfData) {
                if (thunk_data.u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    SIZE_T func_address = reinterpret_cast<SIZE_T>(
                        GetProcAddress(hModule, reinterpret_cast<LPCSTR>(thunk_data.u1.Ordinal & 0xFFFF)));
                    if (!func_address) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }
                    if (!Module.Driver.write_memory(pThunk, &func_address, sizeof(SIZE_T))) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }
                }
                else {
                    IMAGE_IMPORT_BY_NAME import_by_name = {};
                    void* import_by_name_address = static_cast<BYTE*>(Module.RemoteModule) + thunk_data.u1.AddressOfData;
                    if (!Module.Driver.read_memory(import_by_name_address, &import_by_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }

                    char func_name[256] = { 0 };
                    if (!Module.Driver.read_memory(static_cast<BYTE*>(import_by_name_address) + offsetof(IMAGE_IMPORT_BY_NAME, Name), func_name, sizeof(func_name) - 1)) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }

                    SIZE_T func_address = reinterpret_cast<SIZE_T>(GetProcAddress(hModule, func_name));
                    if (!func_address) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }
                    if (!Module.Driver.write_memory(pThunk, &func_address, sizeof(SIZE_T))) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }
                }

                pThunk++;
                pOrigThunk++;
                if (!Module.Driver.read_memory(pOrigThunk, &thunk_data, sizeof(IMAGE_THUNK_DATA))) {
                    break;
                }
            }
            FreeLibrary(hModule);

            pImportDesc++;
            if (!Module.Driver.read_memory(pImportDesc, &import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
                break;
            }
        }
    }
    return TRUE;
}
BOOLEAN CInjector::CleanModuleSections(InjectionStruct& Module) {
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(Module.pNtHeader);
    static const char* uselessSections[] = { ".reloc", ".rsrc", ".edata", ".idata", ".pdata" };
    constexpr size_t numUselessSections = sizeof(uselessSections) / sizeof(uselessSections[0]);

    for (WORD i = 0; i < Module.pNtHeader->FileHeader.NumberOfSections; ++i) {
        char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
        strncpy_s(sectionName, reinterpret_cast<const char*>(sectionHeader[i].Name), IMAGE_SIZEOF_SHORT_NAME);

        bool isUseless = false;
        for (size_t j = 0; j < numUselessSections; ++j) {
            if (strcmp(sectionName, uselessSections[j]) == 0) {
                isUseless = true;
                break;
            }
        }

        if (isUseless && sectionHeader[i].SizeOfRawData > 0) {
            void* sectionAddress = static_cast<BYTE*>(Module.RemoteModule) + sectionHeader[i].VirtualAddress;
            std::vector<char> zeroBuffer(sectionHeader[i].SizeOfRawData, 0);
            if (!Module.Driver.write_memory(sectionAddress, zeroBuffer.data(), sectionHeader[i].SizeOfRawData)) {
                return FALSE;
            }
        }
    }
    return TRUE;
}
BOOLEAN CInjector::CleanModulePeHeader(InjectionStruct& Module) {
    char CleanBuffer = 0;
    return Module.Driver.write_memory(Module.RemoteModule, &CleanBuffer, Module.pNtHeader->OptionalHeader.SizeOfHeaders);
}
PVOID CInjector::GetModuleExportFunction(InjectionStruct& Module, const char* ExportName) {
    if (Module.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        IMAGE_EXPORT_DIRECTORY* pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            static_cast<BYTE*>(Module.RemoteModule) +
            Module.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        IMAGE_EXPORT_DIRECTORY export_dir = {};
        if (!Module.Driver.read_memory(pExportDir, &export_dir, sizeof(IMAGE_EXPORT_DIRECTORY))) {
            return nullptr;
        }

        if (export_dir.NumberOfFunctions > 0) {
            DWORD* pAddressOfFunctions = reinterpret_cast<DWORD*>(
                static_cast<BYTE*>(Module.RemoteModule) + export_dir.AddressOfFunctions);
            DWORD* pAddressOfNames = reinterpret_cast<DWORD*>(
                static_cast<BYTE*>(Module.RemoteModule) + export_dir.AddressOfNames);
            WORD* pAddressOfNameOrdinals = reinterpret_cast<WORD*>(
                static_cast<BYTE*>(Module.RemoteModule) + export_dir.AddressOfNameOrdinals);

            std::vector<DWORD> func_rvas(export_dir.NumberOfFunctions);
            if (!Module.Driver.read_memory(pAddressOfFunctions, func_rvas.data(),
                export_dir.NumberOfFunctions * sizeof(DWORD))) {
                return nullptr;
            }

            std::vector<DWORD> name_rvas(export_dir.NumberOfNames);
            if (!Module.Driver.read_memory(pAddressOfNames, name_rvas.data(),
                export_dir.NumberOfNames * sizeof(DWORD))) {
                return nullptr;
            }

            std::vector<WORD> ordinals(export_dir.NumberOfNames);
            if (!Module.Driver.read_memory(pAddressOfNameOrdinals, ordinals.data(),
                export_dir.NumberOfNames * sizeof(WORD))) {
                return nullptr;
            }

            for (DWORD i = 0; i < export_dir.NumberOfNames; i++) {
                char func_name[256] = { 0 };
                void* name_address = static_cast<BYTE*>(Module.RemoteModule) + name_rvas[i];
                if (!Module.Driver.read_memory(name_address, func_name, sizeof(func_name) - 1)) {
                    return nullptr;
                }

                if (strcmp(func_name, ExportName) == 0) {
                    DWORD func_rva = func_rvas[ordinals[i]];
                    return static_cast<BYTE*>(Module.RemoteModule) + func_rva;
                }
            }
        }
    }
    return nullptr;
}
BOOLEAN CInjector::LoadFileIntoMemory(const wchar_t* FilePath, PVOID& FileBytes, SIZE_T& FileSize) {
    if (GetFileAttributes(FilePath) == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    std::ifstream File(FilePath, std::ios::binary | std::ios::ate);
    if (File.fail()) {
        File.close();
        return FALSE;
    }

    auto tFileSize = File.tellg();
    if (tFileSize < 0x1000) {
        File.close();
        return FALSE;
    }

    void* FilePointer = malloc(tFileSize);
    if (!FilePointer) {
        File.close();
        return FALSE;
    }

    File.seekg(0, std::ios::beg);
    File.read((char*)FilePointer, tFileSize);
    File.close();

    FileBytes = FilePointer;
    FileSize = tFileSize;
    return TRUE;
}

BOOLEAN CInjector::MapDll(Interface& ctx, PVOID Module, SIZE_T ModuleSize) {
    if (!Module || !ModuleSize || !ctx.is_attached()) {
        vLog("invaild module");
        return FALSE;
    }
    
    vLog("vaild input");

    InjectionStruct Injection{};
    Injection.Driver = ctx;
    Injection.Module = Module;
    Injection.ModuleSize = ModuleSize;
    Injection.pDosHeader = GetImageDosHeader(Injection);
    Injection.pNtHeader = GetImageNtHeader(Injection);

    if (Injection.pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        vLog("invaild dos header");
        return FALSE;
    }


    if (Injection.pNtHeader->Signature != IMAGE_NT_SIGNATURE || Injection.pNtHeader->OptionalHeader.SizeOfImage == 0) {
        vLog("invaild ntheader or size");
        return FALSE;
    }

    vLog("vaild module");

    SIZE_T regionSize = Injection.pNtHeader->OptionalHeader.SizeOfImage;
    if (!Injection.Driver.virtual_alloc(&Injection.RemoteModule, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
        vLog("failed to allocate remote memory");
        return FALSE;
    }

    vLog("allocated remote memory -> %p", Injection.RemoteModule);

    if (!Injection.Driver.write_memory(Injection.RemoteModule, Module, ModuleSize)) {
        vLog("failed to write module");
        Injection.Driver.virtual_free(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }
   
    vLog("wrote module to -> %p", Injection.RemoteModule);

    if (!FixModuleSections(Injection)) {
        vLog("failed to fix sections");
        Injection.Driver.virtual_free(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }

    vLog("fixed sections");

    if (!FixModuleReallocations(Injection)) {
        vLog("failed to fix reallocations");
        Injection.Driver.virtual_free(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }
    
    vLog("fixed reallocations");

    if (!FixModuleIAT(Injection)) {
        vLog("failed to fix IAT");
        Injection.Driver.virtual_free(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }

    vLog("fixed IAT");

    void* dllEntry = GetModuleExportFunction(Injection, "DllEntry");
    if (!dllEntry) {
        vLog("DllEntry does not exist in module");
        Injection.Driver.virtual_free(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }

    vLog("got DllEntry -> %p", dllEntry);

     if (!CleanModuleSections(Injection))
     {
         vLog("failed to clean module sections");
     }
     else
         vLog("cleaned module sections");
     
    
    
     if (!CleanModulePeHeader(Injection))
     {
         vLog("failed to clean pe header");
     }
     else
         vLog("cleaned pe header");

    if (!Injection.Driver.create_remote_thread(dllEntry)) {
        vLog("failed to call DllEntry");
        Injection.Driver.virtual_free(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }
   
    vLog("called DllEntry");

    vLog("pray for no crashes, should be injected");

    return TRUE;
}

int main() {
    SetConsoleTitle(L"ripEAC ( kernel injector ) ");

    wchar_t ProcessName[256] = { 0 };

    wprintf(L"enter process name -> ");
    if (scanf_s("%255ls", ProcessName, (unsigned)sizeof(ProcessName) / sizeof(wchar_t)) <= 0) {
        return 1;
    }

    while (getchar() != '\n');

    Interface ctx;
    if (!ctx.attach(ProcessName)) {
        printf("failed to attach to the process \n");
        getchar();
        return 1;
    }

    printf("attached \n");

    CInjector injector;
    PVOID moduleData = nullptr;
    SIZE_T moduleSize = 0;

    if (!injector.LoadFileIntoMemory(L"module.dll", moduleData, moduleSize)) {
        printf("failed to load module.dll\n");
        ctx.detach();
        getchar();
        return 1;
    }

    if (!injector.MapDll(ctx, moduleData, moduleSize)) {
        printf("failed to inject dll\n");
        getchar();
        ctx.detach();
        free(moduleData);
        return 1;
    }


    // maybe use SetCoalescableTimer for entry??

    printf("injected dll\n");

    free(moduleData);
    
    ctx.detach();
    printf("detached from kernel \n");

    printf("enter to close ...\n");
    getchar();
    return 0;
}