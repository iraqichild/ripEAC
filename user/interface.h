#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>

#define IOCTL_BASE 0x8000
#define IOCTL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ALLOCATE_MEMORY IOCTL_CODE(1)
#define IOCTL_FREE_MEMORY IOCTL_CODE(2)
#define IOCTL_READ_WRITE_MEMORY IOCTL_CODE(3)
#define IOCTL_PROTECT_MEMORY IOCTL_CODE(4)
#define IOCTL_HIJACK_THREAD IOCTL_CODE(5)

struct VirtualAlloc_ {
	ULONG processId;
	PVOID* baseAddress;
	SIZE_T* RegionSize;
	ULONG allocationType;
	ULONG ProtectionType;
};

struct VirtualFree_ {
	ULONG processId;
	PVOID* baseAddress;
	SIZE_T* RegionSize;
	ULONG FreeType;
};

struct ReadWriteVirtual_
{
	ULONG processId;
	PVOID address;
	PVOID buffer;
	SIZE_T size;
	enum eflag
	{
		read,
		write
	}flag;
};

struct VirtualProtect_ {
	ULONG processId;
	PVOID* baseAddress;
	SIZE_T* RegionSize;
	ULONG newProtection;
	PULONG oldProtection;
};

struct ThreadHijack_ {
	ULONG processId;
	ULONG threadId;
	PVOID startAddress;
};

class CDriver {
public:
	BOOLEAN attached{};
private:
	ULONG processPid{};
	PVOID deviceHandle{};
	const wchar_t* deviceName = L"\\\\.\\dsdaadfAD";

public:
	BOOLEAN Attach(const wchar_t* processName);
	BOOLEAN Detach();

    BOOLEAN VirtualAllocEx(PVOID* baseAddress, SIZE_T* regionSize, ULONG allocationType, ULONG protectionType);
    BOOLEAN VirtualFreeEx(PVOID* baseAddress, SIZE_T* regionSize, ULONG freeType);
    BOOLEAN ReadProcessMemory(PVOID address, PVOID buffer, SIZE_T size);
    BOOLEAN WriteProcessMemory(PVOID address, PVOID buffer, SIZE_T size);
    BOOLEAN VirtualProtectEx(PVOID* baseAddress, SIZE_T* regionSize, ULONG newProtection, PULONG oldProtection);
    BOOLEAN CreateRemoteThread(PVOID startAddress);
private:
	BOOLEAN syscall(DWORD ioctlCode, LPVOID inBuffer, DWORD inBufferSize, LPVOID outBuffer, DWORD outBufferSize);
};