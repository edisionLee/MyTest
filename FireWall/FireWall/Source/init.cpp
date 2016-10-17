#if 1
#include "common.h"
#include "wall.h"
#include "crc32.h"
#include "memtrace.h"
#include "ctlcode.h"
#endif

//#include<netioapi.h>
#include <ntddk.h>

DRIVER_INITIALIZE		driver_entry;
DRIVER_UNLOAD			driver_unload;

__drv_dispatchType_other            DRIVER_DISPATCH					wall_dispatch_request;
__drv_dispatchType( IRP_MJ_CREATE )   DRIVER_DISPATCH				wall_dispatch_create;
__drv_dispatchType( IRP_MJ_CLOSE )    DRIVER_DISPATCH				wall_dispatch_close;
__drv_dispatchType( IRP_MJ_CLEANUP )  DRIVER_DISPATCH				wall_dispatch_cleanup;
__drv_dispatchType( IRP_MJ_DEVICE_CONTROL ) DRIVER_DISPATCH			wall_dispatch_device_control;


NTSTATUS driver_entry ( IN PDRIVER_OBJECT driver_object, IN PUNICODE_STRING registry_path );

VOID driver_unload ( IN PDRIVER_OBJECT driver_object );

//==========================global variables================================

PDEVICE_OBJECT              g_dev_obj = {0};
BOOLEAN                     gb_monitor_on = FALSE;
extern BOOLEAN				gb_enable_monitor;			// from wall.c

//==========================================================================

NTSTATUS wall_dispatch_request ( IN PDEVICE_OBJECT device_object, IN PIRP irp )
{
    LOG("into\n");

    return STATUS_SUCCESS;
}

NTSTATUS wall_dispatch_create ( IN PDEVICE_OBJECT device_object, IN PIRP irp )
{
    NTSTATUS status = STATUS_SUCCESS;

    LOG("into\n");

    return STATUS_SUCCESS;
}

NTSTATUS wall_dispatch_close ( IN PDEVICE_OBJECT device_object, IN PIRP irp )
{
    LOG("into\n");

    return STATUS_SUCCESS;
}

NTSTATUS wall_dispatch_cleanup ( IN PDEVICE_OBJECT device_object, IN PIRP irp )
{
    LOG("into\n");

    return STATUS_SUCCESS;
}

NTSTATUS start_monitor ()
/*++
--*/
{
    NTSTATUS		status = STATUS_SUCCESS;
    BOOLEAN			b_worker_thread = FALSE;
    BOOLEAN			b_connect_list = FALSE;
    BOOLEAN			b_packet_list = FALSE;
    BOOLEAN			b_inject_handle = FALSE;

    LOG("into\n");

	if ( gb_monitor_on )	{
        KdPrint(("monitor has started!\n"));
        return STATUS_SUCCESS;
    }

    status = create_worker_thread ();
    if( !NT_SUCCESS(status) )	{
        KdPrint(("Create Worker Thread failed!\n"));
        goto exit;
    }
    b_worker_thread = TRUE;
    
    status = wall_create_connect_list();
    if( !NT_SUCCESS(status) )	{
        KdPrint(("Create conn list failed!\n"));
        goto exit;
    }
    b_connect_list = TRUE;

    status = wall_create_packet_list();
    if( !NT_SUCCESS(status) )	{
        KdPrint(("Create packet list failed!\n"));
        goto exit;
    }
    b_packet_list = TRUE;

    status = wall_create_injection_handle();
    if( !NT_SUCCESS(status) )	{
        KdPrint(("Create Injection Handle failed!\n"));
        goto exit;
    }
    b_inject_handle = TRUE;

    crc32_init();

    create_volume_link_table();

    wall_load_config();

    status = wall_register_callouts();
    if( !NT_SUCCESS( status) )
        goto exit;

exit:
    if( !NT_SUCCESS(status) )	{
        LOG("ERROR OCCURED!\n");

        if ( b_worker_thread )
            destroy_worker_thread();

        if( b_connect_list )
            wall_destroy_connect_list();

        if( b_packet_list )
            wall_destroy_packet_list();

        if( b_inject_handle )
            wall_destroy_injection_handle();

    }
    else	{
        gb_monitor_on = TRUE;
        KdPrint( ("monitor start success!\n") );
    }

    return status;
}

VOID stop_monitor()
/*++
--*/
{
    LOG("into\n");

    if( !gb_monitor_on )	{
        KdPrint( ("monitor has already stopped!\n") );
        return;
    }

    wall_un_register_callouts();

    destroy_worker_thread();

    wall_destroy_connect_list();

    wall_destroy_packet_list();

    wall_destroy_injection_handle();

    wall_unload_config();

#if DBG
    if( dbg_is_mem_leak() )
        KdPrint( ("Mem leak occured!\n") );
#endif

    gb_monitor_on = FALSE;
    KdPrint( ("monitor has been stopped!\n") );
}

NTSTATUS wall_dispatch_device_control ( IN PDEVICE_OBJECT device_object, IN PIRP irp )
{
    PIO_STACK_LOCATION		irp_sp = NULL;

    LOG("into\n");

    irp_sp = IoGetCurrentIrpStackLocation( irp );
    KdPrint( ("inBuffer=%x\n", irp_sp->Parameters.DeviceIoControl.Type3InputBuffer) );

    switch( irp_sp->Parameters.DeviceIoControl.IoControlCode )	{
        case IOCTL_LOAD_PROCESS_CONFIG:
            KdPrint( ("user request load process config!\n") );

            wall_load_process_config();
            //wall_load_ip_config();
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;

            break;
        case IOCTL_UNLOAD_PROCESS_CONFIG:
            KdPrint( ("user request unload process config!\n") );

            wall_unload_process_config();
            //wall_load_ip_config();
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;

            break;
         case IOCTL_LOAD_IP_CONFIG:
            KdPrint( ("user request load ip config!\n") );

            wall_load_ip_config();
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;

            break;
        case IOCTL_UNLOAD_IP_CONFIG:
            KdPrint( ("user request unload ip config!\n") );

            wall_unload_ip_config();
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;

            break;
        case IOCTL_LOAD_DNS_CONFIG:
            KdPrint( ("user request unload dns config!\n") );

            wall_load_dns_config();
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;

            break;
        case IOCTL_UNLOAD_DNS_CONFIG:
            KdPrint( ("user request unload dns config!\n") );

            wall_unload_dns_config();
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;

            break;
        
        case IOCTL_MONITOR_ON:
            start_monitor();

            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;

            break;

        case IOCTL_MONITOR_OFF:
            stop_monitor();

            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;

            break;
        case IOCTL_BLOCK_ALL:
			ASSERT( sizeof(BOOLEAN) == irp_sp->Parameters.DeviceIoControl.InputBufferLength );
            ASSERT( NULL != irp_sp->Parameters.DeviceIoControl.Type3InputBuffer );
            wall_block_all( *(PBOOLEAN)irp_sp->Parameters.DeviceIoControl.Type3InputBuffer );

            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;

            break;


        default:
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;
            break;
    }

    IoCompleteRequest( irp,IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry( IN PDRIVER_OBJECT driver_object, IN PUNICODE_STRING registry_path )
/*++
--*/
{
    int						i;
    NTSTATUS				status = STATUS_SUCCESS;
    UNICODE_STRING			device_name = {0};
    UNICODE_STRING			device_dos_name = {0};

    LOG("into\n");

#if DBG
    dbg_mem_trace_init();
#endif

    driver_object->DriverUnload = DriverUnload;
    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)	{
        driver_object->MajorFunction[i] = wall_dispatch_request;
    }
    driver_object->MajorFunction[IRP_MJ_CREATE] = wall_dispatch_create;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = wall_dispatch_close;
    driver_object->MajorFunction[IRP_MJ_CLEANUP] = wall_dispatch_cleanup;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = wall_dispatch_device_control;


    RtlInitUnicodeString( &device_name, DEVICE_NAME );
    status = IoCreateDevice( driver_object,
                            0,
                            &device_name,
                            FILE_DEVICE_NETWORK,
                            0,
                            FALSE,
							&g_dev_obj);
    if( !NT_SUCCESS(status) )
        goto exit;

    RtlInitUnicodeString( &device_dos_name, DEVICE_DOSNAME );
    status = IoCreateSymbolicLink( &device_dos_name, &device_name );
    if( !NT_SUCCESS( status ))	{
        KdPrint( ("Create Symbolink name failed!\n") );
        goto exit;
    }

    wall_load_global_config();
    if( gb_enable_monitor )	{
        status = start_monitor();
        if( !NT_SUCCESS(status) )	{
            KdPrint( ("Start monitor failed!\n") );
            goto exit;
        }
    }
exit:
    if( !NT_SUCCESS(status) )	{
        LOG("ERROR OCCURED!\n");

        if( g_dev_obj ) {
            IoDeleteDevice( g_dev_obj );
			g_dev_obj = NULL;
        }

    }
    return status;
}

VOID DriverUnload( IN PDRIVER_OBJECT driver_object )
{
    UNICODE_STRING  device_dos_name = {0};
    LOG("into\n");
    
    stop_monitor();
    
    if( g_dev_obj )	{
		IoDeleteDevice( g_dev_obj );
		g_dev_obj = NULL;
    }

    RtlInitUnicodeString ( &device_dos_name, DEVICE_DOSNAME );
    IoDeleteSymbolicLink ( &device_dos_name );

#if DBG
    if( dbg_is_mem_leak() )
        KdPrint(("Mem leak occured!\n"));
#endif

    return;
}

                                                                                                                                                                                                                                                          