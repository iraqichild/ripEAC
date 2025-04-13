#include "interface.h"
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <fstream>

struct InjectionStruct
{
    CDriver Driver;

    PVOID Module{};
    PVOID RemoteModule{};

    SIZE_T ModuleSize;

    IMAGE_DOS_HEADER* pDosHeader{};
    IMAGE_NT_HEADERS* pNtHeader{};
};

class CInjector
{
public:
    IMAGE_DOS_HEADER* GetImageDosHeader(InjectionStruct& Module);
    IMAGE_NT_HEADERS* GetImageNtHeader(InjectionStruct& Module);
    BOOLEAN FixModuleSections(InjectionStruct& Module);
    BOOLEAN FixModuleReallocations(InjectionStruct& Module);
    BOOLEAN FixModuleIAT(InjectionStruct& Module);
    BOOLEAN CleanModuleSections(InjectionStruct& Module);
    BOOLEAN CleanModulePeHeader(InjectionStruct& Module);
    PVOID GetModuleExportFunction(InjectionStruct& Module, const char* ExportName);

    BOOLEAN LoadFileIntoMemory(const wchar_t* FilePath, PVOID& FileBytes, SIZE_T& FileSize);
    BOOLEAN MapDll(CDriver& Driver, PVOID Module, SIZE_T ModuleSize);
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
            if (!Module.Driver.WriteProcessMemory(dest, src, pSectionHeader[i].SizeOfRawData)) {
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

            while (Module.Driver.ReadProcessMemory(reloc_address, &reloc_block, sizeof(IMAGE_BASE_RELOCATION)) && reloc_block.VirtualAddress) {
                DWORD num_entries = (reloc_block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                std::vector<WORD> reloc_entries(num_entries);
                void* entries_address = static_cast<BYTE*>(reloc_address) + sizeof(IMAGE_BASE_RELOCATION);

                if (!Module.Driver.ReadProcessMemory(entries_address, reloc_entries.data(), num_entries * sizeof(WORD))) {
                    return FALSE;
                }

                for (DWORD i = 0; i < num_entries; i++) {
                    WORD reloc_type = reloc_entries[i] >> 12;
                    DWORD offset = reloc_entries[i] & 0xFFF;

                    if (reloc_type == IMAGE_REL_BASED_HIGHLOW && !is_64bit) {
                        DWORD* patch_address = reinterpret_cast<DWORD*>(
                            static_cast<BYTE*>(Module.RemoteModule) + reloc_block.VirtualAddress + offset);
                        DWORD current_value;
                        if (!Module.Driver.ReadProcessMemory(patch_address, &current_value, sizeof(DWORD)) ||
                            !Module.Driver.WriteProcessMemory(patch_address, &(current_value += static_cast<DWORD>(delta)), sizeof(DWORD))) {
                            return FALSE;
                        }
                    }
                    else if (reloc_type == IMAGE_REL_BASED_DIR64 && is_64bit) {
                        ULONGLONG* patch_address = reinterpret_cast<ULONGLONG*>(
                            static_cast<BYTE*>(Module.RemoteModule) + reloc_block.VirtualAddress + offset);
                        ULONGLONG current_value;
                        if (!Module.Driver.ReadProcessMemory(patch_address, &current_value, sizeof(ULONGLONG)) ||
                            !Module.Driver.WriteProcessMemory(patch_address, &(current_value += delta), sizeof(ULONGLONG))) {
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
        if (!Module.Driver.ReadProcessMemory(pImportDesc, &import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            return FALSE;
        }

        while (import_desc.Name) {
            char dll_name[256] = { 0 };
            void* name_address = static_cast<BYTE*>(Module.RemoteModule) + import_desc.Name;
            if (!Module.Driver.ReadProcessMemory(name_address, dll_name, sizeof(dll_name) - 1)) {
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
            if (!Module.Driver.ReadProcessMemory(pOrigThunk, &thunk_data, sizeof(IMAGE_THUNK_DATA))) {
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
                    if (!Module.Driver.WriteProcessMemory(pThunk, &func_address, sizeof(SIZE_T))) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }
                }
                else {
                    IMAGE_IMPORT_BY_NAME import_by_name = {};
                    void* import_by_name_address = static_cast<BYTE*>(Module.RemoteModule) + thunk_data.u1.AddressOfData;
                    if (!Module.Driver.ReadProcessMemory(import_by_name_address, &import_by_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }

                    char func_name[256] = { 0 };
                    if (!Module.Driver.ReadProcessMemory(static_cast<BYTE*>(import_by_name_address) + offsetof(IMAGE_IMPORT_BY_NAME, Name), func_name, sizeof(func_name) - 1)) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }

                    SIZE_T func_address = reinterpret_cast<SIZE_T>(GetProcAddress(hModule, func_name));
                    if (!func_address) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }
                    if (!Module.Driver.WriteProcessMemory(pThunk, &func_address, sizeof(SIZE_T))) {
                        FreeLibrary(hModule);
                        return FALSE;
                    }
                }

                pThunk++;
                pOrigThunk++;
                if (!Module.Driver.ReadProcessMemory(pOrigThunk, &thunk_data, sizeof(IMAGE_THUNK_DATA))) {
                    break;
                }
            }
            FreeLibrary(hModule);

            pImportDesc++;
            if (!Module.Driver.ReadProcessMemory(pImportDesc, &import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
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
            if (!Module.Driver.WriteProcessMemory(sectionAddress, zeroBuffer.data(), sectionHeader[i].SizeOfRawData)) {
                return FALSE;
            }
        }
    }
    return TRUE;
}

BOOLEAN CInjector::CleanModulePeHeader(InjectionStruct& Module) {
    char CleanBuffer = 0;
    return Module.Driver.WriteProcessMemory(Module.RemoteModule, &CleanBuffer, Module.pNtHeader->OptionalHeader.SizeOfHeaders);
}

PVOID CInjector::GetModuleExportFunction(InjectionStruct& Module, const char* ExportName) {
    if (Module.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        IMAGE_EXPORT_DIRECTORY* pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            static_cast<BYTE*>(Module.RemoteModule) +
            Module.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        IMAGE_EXPORT_DIRECTORY export_dir = {};
        if (!Module.Driver.ReadProcessMemory(pExportDir, &export_dir, sizeof(IMAGE_EXPORT_DIRECTORY))) {
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
            if (!Module.Driver.ReadProcessMemory(pAddressOfFunctions, func_rvas.data(),
                export_dir.NumberOfFunctions * sizeof(DWORD))) {
                return nullptr;
            }

            std::vector<DWORD> name_rvas(export_dir.NumberOfNames);
            if (!Module.Driver.ReadProcessMemory(pAddressOfNames, name_rvas.data(),
                export_dir.NumberOfNames * sizeof(DWORD))) {
                return nullptr;
            }

            std::vector<WORD> ordinals(export_dir.NumberOfNames);
            if (!Module.Driver.ReadProcessMemory(pAddressOfNameOrdinals, ordinals.data(),
                export_dir.NumberOfNames * sizeof(WORD))) {
                return nullptr;
            }

            for (DWORD i = 0; i < export_dir.NumberOfNames; i++) {
                char func_name[256] = { 0 };
                void* name_address = static_cast<BYTE*>(Module.RemoteModule) + name_rvas[i];
                if (!Module.Driver.ReadProcessMemory(name_address, func_name, sizeof(func_name) - 1)) {
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

BOOLEAN CInjector::MapDll(CDriver& Driver, PVOID Module, SIZE_T ModuleSize) {
    if (!Module || !ModuleSize || !Driver.attached) {
        printf("MapDll failed: Invalid input (Module=%p, ModuleSize=%zu, attached=%d)\n", Module, ModuleSize, Driver.attached);
        return FALSE;
    }
    printf("MapDll: Input validated\n");

    InjectionStruct Injection{};
    Injection.Driver = Driver;
    Injection.Module = Module;
    Injection.ModuleSize = ModuleSize;
    Injection.pDosHeader = GetImageDosHeader(Injection);
    Injection.pNtHeader = GetImageNtHeader(Injection);

    if (Injection.pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("MapDll failed: Invalid DOS signature\n");
        return FALSE;
    }
    printf("MapDll: DOS header validated\n");

    if (Injection.pNtHeader->Signature != IMAGE_NT_SIGNATURE || Injection.pNtHeader->OptionalHeader.SizeOfImage == 0) {
        printf("MapDll failed: Invalid NT signature or image size\n");
        return FALSE;
    }
    printf("MapDll: NT header validated\n");

    PVOID baseAddress = nullptr;
    SIZE_T regionSize = Injection.pNtHeader->OptionalHeader.SizeOfImage;
    if (!Injection.Driver.VirtualAllocEx(&baseAddress, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
        printf("MapDll failed: VirtualAllocEx failed\n");
        return FALSE;
    }
    Injection.RemoteModule = baseAddress;
    printf("MapDll: Allocated memory at %p\n", baseAddress);

    if (!Injection.Driver.WriteProcessMemory(Injection.RemoteModule, Module, ModuleSize)) {
        printf("MapDll failed: WriteProcessMemory failed\n");
        Injection.Driver.VirtualFreeEx(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }
    printf("MapDll: Wrote module to remote memory\n");

    if (!FixModuleSections(Injection)) {
        printf("MapDll failed: FixModuleSections failed\n");
        Injection.Driver.VirtualFreeEx(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }
    printf("MapDll: Fixed module sections\n");

    if (!FixModuleReallocations(Injection)) {
        printf("MapDll failed: FixModuleReallocations failed\n");
        Injection.Driver.VirtualFreeEx(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }
    printf("MapDll: Fixed module relocations\n");

    if (!FixModuleIAT(Injection)) {
        printf("MapDll failed: FixModuleIAT failed\n");
        Injection.Driver.VirtualFreeEx(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }
    printf("MapDll: Fixed module IAT\n");

    void* dllEntry = GetModuleExportFunction(Injection, "DllEntry");
    if (!dllEntry) {
        printf("MapDll failed: GetModuleExportFunction failed for DllEntry\n");
        Injection.Driver.VirtualFreeEx(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }
    printf("MapDll: Resolved DllMain at %p\n", dllEntry);

    CleanModuleSections(Injection);
    printf("MapDll: Cleaned module sections\n");

    CleanModulePeHeader(Injection);
    printf("MapDll: Cleaned PE header\n");

    if (!Injection.Driver.CreateRemoteThread(dllEntry)) {
        printf("MapDll failed: CreateRemoteThread failed\n");
        Injection.Driver.VirtualFreeEx(&Injection.RemoteModule, &regionSize, MEM_RELEASE);
        return FALSE;
    }
    printf("MapDll: Executed DllMain\n");

    printf("MapDll: Injection completed successfully\n");
    return TRUE;
}

int main() {
    CDriver driver;
    if (!driver.Attach(L"Unturned.exe")) {
        std::wcout << L"Failed to attach to target process\n";
        std::cin.get();
        return 1;
    }

    CInjector injector;
    PVOID moduleData = nullptr;
    SIZE_T moduleSize = 0;

    if (!injector.LoadFileIntoMemory(L"module.dll", moduleData, moduleSize)) {
        std::wcout << L"Failed to load DLL file\n";
        std::cin.get();
        return 1;
    }

    if (!injector.MapDll(driver, moduleData, moduleSize)) {
        std::wcout << L"Failed to map DLL\n";
        std::cin.get();
        free(moduleData);
        return 1;
    }

    free(moduleData);
    std::wcout << L"DLL injected successfully\n";
    driver.Detach();
    std::cin.get();
    return 0;
}