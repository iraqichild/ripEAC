#ifndef INJECTION_H
#define INJECTION_H

#include "ia32.h"
#include "kernelutil.h"
#include "imports.h"
#include "structure.h"
#include "communication.h"

NTSTATUS GetThreadContext(PETHREAD thread, PCONTEXT ctx)
{
    if (!thread || !ctx)
        return STATUS_INVALID_PARAMETER;


    CONTEXT* BaseAddress = nullptr;
    SIZE_T Size = sizeof(CONTEXT);
    NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), (void**)&BaseAddress, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    BaseAddress->ContextFlags = ctx->ContextFlags;
    status = PsGetContextThread(thread, BaseAddress, UserMode);
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(ctx, BaseAddress, sizeof(CONTEXT));
    }
    else {
    }

    ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&BaseAddress, &Size, MEM_RELEASE);
    return status;
}

NTSTATUS SetThreadContext(PETHREAD thread, PCONTEXT ctx)
{
    if (!thread || !ctx)
        return STATUS_INVALID_PARAMETER;

    CONTEXT* BaseAddress = nullptr;
    SIZE_T Size = sizeof(CONTEXT);
    NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), (void**)&BaseAddress, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(BaseAddress, ctx, sizeof(CONTEXT));
    BaseAddress->ContextFlags = ctx->ContextFlags;
    status = PsSetContextThread(thread, BaseAddress, UserMode);

    ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&BaseAddress, &Size, MEM_RELEASE);
    return status;
}

NTSTATUS AllocateVirtualMemory(VirtualAlloc_* Params)
{
	if (!Params || !Params->baseAddress)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS pProcess{};
	NTSTATUS ntStatus{};

	ntStatus = PsLookupProcessByProcessId((HANDLE)Params->processId, &pProcess);
	if (!NT_SUCCESS(ntStatus))
		return ntStatus;


	PVOID Address{};
	SIZE_T Size{};

	Address = *Params->baseAddress;
	Size = *Params->RegionSize;
    KAPC_STATE kState{};

    KeStackAttachProcess(pProcess, &kState);

	ntStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), &Address, NULL, &Size, Params->allocationType, Params->ProtectionType);
    KeUnstackDetachProcess(&kState);

	*Params->baseAddress = Address;
	*Params->RegionSize = Size;

	ObDereferenceObject(pProcess);


	return ntStatus;
}

NTSTATUS FreeVirtualMemory(VirtualFree_* Params)
{
	if (!Params || !Params->baseAddress)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS pProcess{};
	NTSTATUS ntStatus{};

	ntStatus = PsLookupProcessByProcessId((HANDLE)Params->processId, &pProcess);
	if (!NT_SUCCESS(ntStatus))
		return ntStatus;


	PVOID Address{};
	SIZE_T Size{};

	Address = *Params->baseAddress;
	Size = *Params->RegionSize;


    KAPC_STATE kState{};

    KeStackAttachProcess(pProcess, &kState);

	ntStatus = ZwFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, Params->FreeType);
    KeUnstackDetachProcess(&kState);


	*Params->baseAddress = Address;
	*Params->RegionSize = Size;

	ObDereferenceObject(pProcess);


	return ntStatus;
}

NTSTATUS ReadWriteVirtualMemory(ReadWriteVirtual_* Params)
{
    if (!Params || !Params->address || !Params->buffer)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS pProcess{};
    NTSTATUS ntStatus{};

    ntStatus = PsLookupProcessByProcessId((HANDLE)Params->processId, &pProcess);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    SIZE_T bytesTransferred = 0;

    if (Params->flag == ReadWriteVirtual_::read)
    {
        ntStatus = MmCopyVirtualMemory(
            pProcess,
            Params->address,
            PsGetCurrentProcess(),
            Params->buffer,
            Params->size,
            KernelMode,
            &bytesTransferred
        );
    }
    else if (Params->flag == ReadWriteVirtual_::write)
    {
        ntStatus = MmCopyVirtualMemory(
            PsGetCurrentProcess(),
            Params->buffer,
            pProcess,
            Params->address,
            Params->size,
            KernelMode,
            &bytesTransferred
       
       
        );
    }
    else
    {
        ntStatus = STATUS_INVALID_PARAMETER;
    }

    ObDereferenceObject(pProcess);

    return ntStatus;
}

NTSTATUS ProtectVirtualMemory(VirtualProtect_* Params)
{
    if (!Params || !Params->baseAddress || !Params->RegionSize || !Params->oldProtection)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS pProcess = nullptr;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    ntStatus = PsLookupProcessByProcessId((HANDLE)Params->processId, &pProcess);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    PVOID address = *Params->baseAddress;
    SIZE_T size = *Params->RegionSize;
    ULONG oldProtect = 0;

    KAPC_STATE kState{};

    KeStackAttachProcess(pProcess, &kState);
    ntStatus = ZwProtectVirtualMemory(NtCurrentProcess(), &address, &size, Params->newProtection, &oldProtect);
    KeUnstackDetachProcess(&kState);

    *Params->baseAddress = address;
    *Params->RegionSize = size;
    *Params->oldProtection = oldProtect;

    ObDereferenceObject(pProcess);

    return ntStatus;
}

const char* PsSuspendThreadSig = "\x48\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x53\x56\x57\x41\x56\x41\x57\x48\x83\xEC\x20";
const char* PsSuspendThreadMask = "xxxxxxxxxxxxxxxxxxxx";

const char* PsResumeThreadSig = "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\xDA\x48\x8B\xF9\xE8";
const char* PsResumeThreadMask = "xxxxxxxxxxxxxxxxxxxx";


PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) {

    auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
        {
            for (auto x = buffer; *mask; pattern++, mask++, x++) {
                auto addr = *(BYTE*)(pattern);
                if (addr != *x && *mask != '?')
                    return FALSE;
            }

            return TRUE;
        };

    for (auto x = 0; x < size - strlen(mask); x++) {

        auto addr = (PBYTE)module + x;
        if (checkMask(addr, pattern, mask))
            return addr;
    }

    return NULL;
}

typedef NTSTATUS(__fastcall* PsResumeThread_t)(PETHREAD pThread, PULONG SuspendTimes);
typedef NTSTATUS(__fastcall* PsSuspendThread_t)(PETHREAD pThread, PULONG SuspendTimes);

static PsResumeThread_t PsResumeThread = nullptr;
static PsSuspendThread_t PsSuspendThread = nullptr;

void InitFunctions() {
    PVOID ntoskrnlBase = get_module_base(L"ntoskrnl.exe");
    if (!ntoskrnlBase) {
        return;
    }

    ULONG ntoskrnlSize = get_module_size(L"ntoskrnl.exe");

    if (ntoskrnlSize == 0) {
        return;
    }

    PBYTE suspendAddr = FindPattern(ntoskrnlBase, ntoskrnlSize, PsSuspendThreadSig, PsSuspendThreadMask);
    if (suspendAddr) {
        PsSuspendThread = (PsSuspendThread_t)((uintptr_t)ntoskrnlBase + 0x6C0640);
    }

    PBYTE resumeAddr = FindPattern(ntoskrnlBase, ntoskrnlSize, PsResumeThreadSig, PsResumeThreadMask);
    if (resumeAddr) {
        PsResumeThread = (PsResumeThread_t)((uintptr_t)ntoskrnlBase + 0x70AD60);
    }
}

NTSTATUS CallFunctionViaThreadHijacking(ThreadHijack_* Params)
{
    if (!Params || !Params->startAddress || !Params->processId || !Params->threadId)
        return STATUS_INVALID_PARAMETER;

    if (!SeSinglePrivilegeCheck(LUID{ RtlConvertUlongToLuid(SE_TCB_PRIVILEGE) }, KernelMode))
        return STATUS_PRIVILEGE_NOT_HELD;

    PEPROCESS pProcess = nullptr;
    PETHREAD pThread = nullptr;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    ntStatus = PsLookupProcessByProcessId((HANDLE)Params->processId, &pProcess);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    if (pProcess == nullptr || PsGetProcessExitStatus(pProcess) != STATUS_PENDING)
    {
        if (pProcess)
            ObDereferenceObject(pProcess);
        return STATUS_INVALID_PARAMETER;
    }

    ntStatus = PsLookupThreadByThreadId((HANDLE)Params->threadId, &pThread);
    if (!NT_SUCCESS(ntStatus))
    {
        ObDereferenceObject(pProcess);
        return ntStatus;
    }

    if (pThread == nullptr)
    {
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();

    ULONG suspendCount = 0;
    ntStatus = PsSuspendThread(pThread, &suspendCount);
    if (!NT_SUCCESS(ntStatus))
    {
        KeLeaveCriticalRegion();
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return ntStatus;
    }

    CONTEXT threadContext = { 0 };
    threadContext.ContextFlags = CONTEXT_FULL;

    ntStatus = GetThreadContext(pThread, &threadContext);
    if (!NT_SUCCESS(ntStatus))
    {
        PsResumeThread(pThread, &suspendCount);
        KeLeaveCriticalRegion();
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return ntStatus;
    }

    threadContext.Rip = (ULONGLONG)Params->startAddress;

    ntStatus = SetThreadContext(pThread, &threadContext);
    if (!NT_SUCCESS(ntStatus))
    {
        PsResumeThread(pThread, &suspendCount);
        KeLeaveCriticalRegion();
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return ntStatus;
    }

    ntStatus = PsResumeThread(pThread, &suspendCount);
    if (!NT_SUCCESS(ntStatus))
    {
        KeLeaveCriticalRegion();
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return ntStatus;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -1000000; // 100ms
    KeDelayExecutionThread(KernelMode, FALSE, &timeout);


    KeLeaveCriticalRegion();
    ObDereferenceObject(pThread);
    ObDereferenceObject(pProcess);

    return STATUS_SUCCESS;
}
#endif