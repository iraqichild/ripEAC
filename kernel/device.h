#ifndef DEVICE_H
#define DEVICE_H

#include <ntifs.h>
#include <ntddk.h>
#include <wdmsec.h>
#include "imports.h"

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

    drvName = unicodeStr(L"\\Device\\ripEAC");
    drvSymLink = unicodeStr(L"\\DosDevices\\ripEAC");
    drvSDDL = unicodeStr(DEVICE_SDDL);

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