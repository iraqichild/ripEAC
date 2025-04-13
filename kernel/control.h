#ifndef CONTROL_H
#define CONTROL_H

#include "device.h"
#include "imports.h"
#include "ia32.h"
#include "communication.h"
#include "injection.h"

NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(device_obj);
    pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS dispatch_io(PDEVICE_OBJECT device_obj, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(device_obj);
    PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(pIrp);
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS device_io(PDEVICE_OBJECT device_obj, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(device_obj);
    PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(pIrp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG information = 0;

    switch (irp_stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_ALLOCATE_MEMORY:
    {
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(VirtualAlloc_))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        VirtualAlloc_* params = (VirtualAlloc_*)pIrp->AssociatedIrp.SystemBuffer;
        status = AllocateVirtualMemory(params);
        information = sizeof(VirtualAlloc_);
        break;
    }

    case IOCTL_FREE_MEMORY:
    {
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(VirtualFree_))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        VirtualFree_* params = (VirtualFree_*)pIrp->AssociatedIrp.SystemBuffer;
        status = FreeVirtualMemory(params);
        information = sizeof(VirtualFree_);
        break;
    }

    case IOCTL_READ_WRITE_MEMORY:
    {
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ReadWriteVirtual_))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ReadWriteVirtual_* params = (ReadWriteVirtual_*)pIrp->AssociatedIrp.SystemBuffer;
        status = ReadWriteVirtualMemory(params);
        information = sizeof(ReadWriteVirtual_);
        break;
    }

    case IOCTL_PROTECT_MEMORY:
    {
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(VirtualProtect_))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        VirtualProtect_* params = (VirtualProtect_*)pIrp->AssociatedIrp.SystemBuffer;
        status = ProtectVirtualMemory(params);
        information = sizeof(VirtualProtect_);
        break;
    }

    case IOCTL_HIJACK_THREAD:
    {
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ThreadHijack_))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ThreadHijack_* params = (ThreadHijack_*)pIrp->AssociatedIrp.SystemBuffer;
        status = CallFunctionViaThreadHijacking(params);
        information = sizeof(ThreadHijack_);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = information;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

#endif