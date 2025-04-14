#include "interface.h"
#include <stdexcept>


BOOLEAN CDriver::Attach(const wchar_t* processName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32{ sizeof(pe32) };
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                this->processPid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);

    if (!this->processPid)
        return FALSE;

    this->deviceHandle = CreateFileW(deviceName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    this->attached = true;
    return this->attached;
}
BOOLEAN CDriver::Detach()
{
    if (this->attached || this->deviceHandle)
    {
        CloseHandle(this->deviceHandle);
        this->deviceHandle = 0;
        this->processPid = 0;
        attached = false;
        return attached;
    }
    else
        return attached;
}

BOOLEAN CDriver::syscall(DWORD ioctlCode, LPVOID inBuffer, DWORD inBufferSize, LPVOID outBuffer, DWORD outBufferSize)
{
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(this->deviceHandle, ioctlCode, inBuffer, inBufferSize, outBuffer, outBufferSize, &bytesReturned, nullptr);
    return success != FALSE;
}

BOOLEAN CDriver::VirtualAllocEx(PVOID* baseAddress, SIZE_T* regionSize, ULONG allocationType, ULONG protectionType) {
    VirtualAlloc_ params = { this->processPid, baseAddress, regionSize, allocationType, protectionType };
    return syscall(IOCTL_ALLOCATE_MEMORY, &params, sizeof(params), &params, sizeof(params));
}

BOOLEAN CDriver::VirtualFreeEx(PVOID* baseAddress, SIZE_T* regionSize, ULONG freeType) {
    VirtualFree_ params = { this->processPid, baseAddress, regionSize, freeType };
    return syscall(IOCTL_FREE_MEMORY, &params, sizeof(params), &params, sizeof(params));
}

BOOLEAN CDriver::ReadProcessMemory(PVOID address, PVOID buffer, SIZE_T size) {
    ReadWriteVirtual_ params = { this->processPid, address, buffer, size, ReadWriteVirtual_::read };
    return syscall(IOCTL_READ_WRITE_MEMORY, &params, sizeof(params), &params, sizeof(params));
}

BOOLEAN CDriver::WriteProcessMemory(PVOID address, PVOID buffer, SIZE_T size) {
    ReadWriteVirtual_ params = { this->processPid, address, buffer, size, ReadWriteVirtual_::write };
    return syscall(IOCTL_READ_WRITE_MEMORY, &params, sizeof(params), &params, sizeof(params));
}

BOOLEAN CDriver::VirtualProtectEx(PVOID* baseAddress, SIZE_T* regionSize, ULONG newProtection, PULONG oldProtection) {
    VirtualProtect_ params = { this->processPid, baseAddress, regionSize, newProtection, oldProtection };
    return syscall(IOCTL_PROTECT_MEMORY, &params, sizeof(params), &params, sizeof(params));
}

BOOLEAN CDriver::CreateRemoteThread(PVOID startAddress) {
    ThreadHijack_ params = { this->processPid, NULL, startAddress };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    THREADENTRY32 te32{ sizeof(te32) };
    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == this->processPid) {
                CloseHandle(snapshot);
                params.threadId = te32.th32ThreadID;
                
                break;
            }
        } while (Thread32Next(snapshot, &te32));
    }

    CloseHandle(snapshot);

 
    return syscall(IOCTL_HIJACK_THREAD, &params, sizeof(params), &params, sizeof(params));
}
