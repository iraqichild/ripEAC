#include "device.h"
#include "imports.h"
#include "kernelutil.h"
#include "ia32.h"
#include "control.h"

NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP pIrp);
NTSTATUS dispatch_io(PDEVICE_OBJECT device_obj, PIRP pIrp);
NTSTATUS device_io(PDEVICE_OBJECT device_obj, PIRP pIrp);


NTSTATUS entry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(reg_path);

	NTSTATUS ntStatus = STATUS_SUCCESS;

    PDEVICE_OBJECT device_obj{};

	ntStatus = createdevice(driver_obj, &device_obj);
	if (!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("failed to create device");
		return ntStatus;
	}

     SetFlag(device_obj->Flags, DO_BUFFERED_IO);
     
     for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
     	driver_obj->MajorFunction[t] = unsupported_io;
     
     driver_obj->MajorFunction[IRP_MJ_CREATE] = dispatch_io;
     driver_obj->MajorFunction[IRP_MJ_CLOSE] = dispatch_io;
     driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = device_io;
     driver_obj->DriverUnload = NULL;
     
     ClearFlag(device_obj->Flags, DO_DEVICE_INITIALIZING);

     return ntStatus;
}


extern "C" NTSTATUS FxDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    return IoCreateDriver(NULL, entry);
}