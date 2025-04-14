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
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(virtual_alloc_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        virtual_alloc_t* params = (virtual_alloc_t*)pIrp->AssociatedIrp.SystemBuffer;
        status = AllocateVirtualMemory(params);
        information = sizeof(virtual_alloc_t);
        break;
    }

    case IOCTL_FREE_MEMORY:
    {
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(virtual_free_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        virtual_free_t* params = (virtual_free_t*)pIrp->AssociatedIrp.SystemBuffer;
        status = FreeVirtualMemory(params);
        information = sizeof(virtual_free_t);
        break;
    }

    case IOCTL_READ_WRITE_MEMORY:
    {
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(read_write_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        read_write_t* params = (read_write_t*)pIrp->AssociatedIrp.SystemBuffer;
        status = ReadWriteVirtualMemory(params);
        information = sizeof(read_write_t);
        break;
    }

    case IOCTL_PROTECT_MEMORY:
    {
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(virtual_protect_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        virtual_protect_t* params = (virtual_protect_t*)pIrp->AssociatedIrp.SystemBuffer;
        status = ProtectVirtualMemory(params);
        information = sizeof(virtual_protect_t);
        break;
    }

    case IOCTL_HIJACK_THREAD:
    {
        if (irp_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(thread_hijack_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        thread_hijack_t* params = (thread_hijack_t*)pIrp->AssociatedIrp.SystemBuffer;
        status = CallFunctionViaThreadHijacking(params);
        information = sizeof(thread_hijack_t);
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