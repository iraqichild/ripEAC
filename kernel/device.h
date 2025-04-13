#ifndef DEVICE_H
#define DEVICE_H

#include <ntifs.h>
#include <ntddk.h>
#include "imports.h"

typedef NTSTATUS(*PFN_WDMLIB_IO_CREATE_DEVICE_SECURE)(
    PDRIVER_OBJECT DriverObject,
    ULONG DeviceExtensionSize,
    PUNICODE_STRING DeviceName,
    DEVICE_TYPE DeviceType,
    ULONG DeviceCharacteristics,
    BOOLEAN Exclusive,
    PCUNICODE_STRING DefaultSDDLString,
    LPCGUID DeviceClassGuid,
    PDEVICE_OBJECT* DeviceObject
    );

UNICODE_STRING drvName = { 0 };
UNICODE_STRING drvSymLink = { 0 };
UNICODE_STRING drvSDDL = { 0 };

#define DEVICE_SDDL L"D:P(A;;GRGW;;;BU)"

NTSTATUS createdevice(_In_ PDRIVER_OBJECT driver_obj, _Out_ PDEVICE_OBJECT* deviceobject)
{
    if (!driver_obj) {
        return STATUS_INVALID_PARAMETER;
    }

    if(!deviceobject) 
        return STATUS_INVALID_PARAMETER;

    *deviceobject = 0;

    PDEVICE_OBJECT dev_obj = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    drvName = unicodeStr(L"\\Device\\uwuinjector");
    drvSymLink = unicodeStr(L"\\DosDevices\\uwuinjector");
    drvSDDL = unicodeStr(DEVICE_SDDL);
    UNICODE_STRING funcName = unicodeStr(L"IoCreateDeviceSecure");

    PFN_WDMLIB_IO_CREATE_DEVICE_SECURE IoCreateDeviceSecure =
        (PFN_WDMLIB_IO_CREATE_DEVICE_SECURE)MmGetSystemRoutineAddress(&funcName);

    if (IoCreateDeviceSecure == NULL) {
        return STATUS_NOT_FOUND;
    }

    status = IoCreateDeviceSecure(
        driver_obj,              // Driver object
        0,                       // Device extension size
        &drvName,                // Device name
        FILE_DEVICE_UNKNOWN,     // Device type
        FILE_DEVICE_SECURE_OPEN, // Device characteristics
        FALSE,                   // Not exclusive
        &drvSDDL,                // SDDL string
        NULL,                    // Device class GUID 
        &dev_obj                 // Output device object
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = IoCreateSymbolicLink(&drvSymLink, &drvName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(dev_obj);
        return status;
    }

    if (!deviceobject) {
        *deviceobject = NULL;
        return STATUS_INVALID_PARAMETER;
    }
    
    *deviceobject = dev_obj;



    return STATUS_SUCCESS;
}

#endif