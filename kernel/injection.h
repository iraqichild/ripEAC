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

NTSTATUS AllocateVirtualMemory(virtual_alloc_t* Params)
{
	if (!Params || !Params->base_address)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS pProcess{};
	NTSTATUS ntStatus{};

	ntStatus = PsLookupProcessByProcessId((HANDLE)Params->process_id, &pProcess);
	if (!NT_SUCCESS(ntStatus))
		return ntStatus;


	PVOID Address{};
	SIZE_T Size{};

	Address = *Params->base_address;
	Size = *Params->region_size;
    KAPC_STATE kState{};

    KeStackAttachProcess(pProcess, &kState);

	ntStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), &Address, NULL, &Size, Params->allocation_type, Params->protection_type);
    KeUnstackDetachProcess(&kState);

	*Params->base_address = Address;
	*Params->region_size = Size;

	ObDereferenceObject(pProcess);


	return ntStatus;
}

NTSTATUS FreeVirtualMemory(virtual_free_t* Params)
{
	if (!Params || !Params->base_address)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS pProcess{};
	NTSTATUS ntStatus{};

	ntStatus = PsLookupProcessByProcessId((HANDLE)Params->process_id, &pProcess);
	if (!NT_SUCCESS(ntStatus))
		return ntStatus;


	PVOID Address{};
	SIZE_T Size{};

	Address = *Params->base_address;
	Size = *Params->region_size;


    KAPC_STATE kState{};

    KeStackAttachProcess(pProcess, &kState);

	ntStatus = ZwFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, Params->free_type);
    KeUnstackDetachProcess(&kState);


	*Params->base_address = Address;
	*Params->region_size = Size;

	ObDereferenceObject(pProcess);


	return ntStatus;
}

NTSTATUS ReadWriteVirtualMemory(read_write_t* Params)
{
    if (!Params || !Params->address || !Params->buffer)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS pProcess{};
    NTSTATUS ntStatus{};

    ntStatus = PsLookupProcessByProcessId((HANDLE)Params->process_id, &pProcess);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    SIZE_T bytesTransferred = 0;

    if (Params->flag == read_write_t::flag_t::read)
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
    else if (Params->flag == read_write_t::flag_t::write)
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

NTSTATUS ProtectVirtualMemory(virtual_protect_t* Params)
{
    if (!Params || !Params->base_address || !Params->region_size || !Params->old_protection)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS pProcess = nullptr;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    ntStatus = PsLookupProcessByProcessId((HANDLE)Params->process_id, &pProcess);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    PVOID address = *Params->base_address;
    SIZE_T size = *Params->region_size;
    ULONG oldProtect = 0;

    KAPC_STATE kState{};

    KeStackAttachProcess(pProcess, &kState);
    ntStatus = ZwProtectVirtualMemory(NtCurrentProcess(), &address, &size, Params->new_protection, &oldProtect);
    KeUnstackDetachProcess(&kState);

    *Params->base_address = address;
    *Params->region_size = size;
    *Params->old_protection = oldProtect;

    ObDereferenceObject(pProcess);

    return ntStatus;
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

    // 22h2
    PsSuspendThread = (PsSuspendThread_t)((uintptr_t)ntoskrnlBase + 0x6C0640);
    PsResumeThread = (PsResumeThread_t)((uintptr_t)ntoskrnlBase + 0x70AD60);
}

NTSTATUS CallFunctionViaThreadHijacking(thread_hijack_t* Params)
{
    if (!Params || !Params->start_address || !Params->process_id || !Params->thread_id)
        return STATUS_INVALID_PARAMETER;

    if (!SeSinglePrivilegeCheck(LUID{ RtlConvertUlongToLuid(SE_TCB_PRIVILEGE) }, KernelMode))
        return STATUS_PRIVILEGE_NOT_HELD;

    PEPROCESS pProcess = nullptr;
    PETHREAD pThread = nullptr;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    ntStatus = PsLookupProcessByProcessId((HANDLE)Params->process_id, &pProcess);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    if (pProcess == nullptr || PsGetProcessExitStatus(pProcess) != STATUS_PENDING)
    {
        if (pProcess)
            ObDereferenceObject(pProcess);
        return STATUS_INVALID_PARAMETER;
    }

    ntStatus = PsLookupThreadByThreadId((HANDLE)Params->thread_id, &pThread);
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
    threadContext.ContextFlags = CONTEXT_ALL;

    ntStatus = GetThreadContext(pThread, &threadContext);
    if (!NT_SUCCESS(ntStatus))
    {
        PsResumeThread(pThread, &suspendCount);
        KeLeaveCriticalRegion();
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);
        return ntStatus;
    }

    threadContext.Rip = (ULONGLONG)Params->start_address;

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

    KeLeaveCriticalRegion();
    ObDereferenceObject(pThread);
    ObDereferenceObject(pProcess);

    return STATUS_SUCCESS;
}
#endif