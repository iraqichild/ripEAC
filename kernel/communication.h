#ifndef COMMUNCATION_H
#define COMMUNCATION_H

#include "imports.h"

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

#endif