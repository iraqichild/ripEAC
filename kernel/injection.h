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

	KeAttachProcess(pProcess);
	ntStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), &Address, NULL, &Size, Params->allocationType, Params->ProtectionType);
	KeDetachProcess();

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

	KeAttachProcess(pProcess);
	ntStatus = ZwFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, Params->FreeType);
	KeDetachProcess();

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

    KeAttachProcess(pProcess);
    ntStatus = ZwProtectVirtualMemory(NtCurrentProcess(), &address, &size, Params->newProtection, &oldProtect);
    KeDetachProcess();

    *Params->baseAddress = address;
    *Params->RegionSize = size;
    *Params->oldProtection = oldProtect;

    ObDereferenceObject(pProcess);

    return ntStatus;
}

NTSTATUS CallFunctionViaThreadHijacking(ThreadHijack_* Params)
{
    if (!Params || !Params->startAddress || !Params->processId || !Params->threadId)
        return STATUS_INVALID_PARAMETER;
    

    PEPROCESS pProcess = nullptr;
    PETHREAD pThread = nullptr;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    ntStatus = PsLookupProcessByProcessId((HANDLE)Params->processId, &pProcess);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;
    

    if (pProcess == nullptr || PsGetProcessExitStatus(pProcess) != STATUS_PENDING) {
        ObDereferenceObject(pProcess);
        return STATUS_INVALID_PARAMETER;
    }

    ntStatus = PsLookupThreadByThreadId((HANDLE)Params->threadId, &pThread);
    if (!NT_SUCCESS(ntStatus)) {
        ObDereferenceObject(pProcess);
        return ntStatus;
    }

    if (pThread == nullptr) {
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return STATUS_INVALID_PARAMETER;
    }

    CONTEXT threadContext = { 0 };
    threadContext.ContextFlags = CONTEXT_CONTROL; 

    ntStatus = GetThreadContext(pThread, &threadContext);
    if (!NT_SUCCESS(ntStatus)) {
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return ntStatus;
    }

    if ((ULONGLONG)Params->startAddress >= 0x7FFFFFFFFFFF) {
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return STATUS_INVALID_PARAMETER;
    }

    threadContext.Rip = (ULONGLONG)Params->startAddress;

    ntStatus = SetThreadContext(pThread, &threadContext);
    if (!NT_SUCCESS(ntStatus)) {
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return ntStatus;
    }

    ObDereferenceObject(pThread);
    ObDereferenceObject(pProcess);
    return ntStatus;
}

#endif