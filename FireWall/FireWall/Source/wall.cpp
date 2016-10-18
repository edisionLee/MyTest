#include<stdio.h>
#include<stdlib.h>

#include "common.h"
#include "callouts.h"
#include "wall.h"
#include "rules.h"

//////////////////////////引用的外部变量////////////////////////////////////

extern PDEVICE_OBJECT		g_dev_obj;

////////////////////////////////////////////////////////////////////////////



///////////////////////////////模块全局变量定义//////////////////////////////
HANDLE					g_engine_handle = 0;
HANDLE					g_inject_handle = 0;
pwall_connect_list		g_connect_list = NULL;
pwall_packet_list		g_packet_list = NULL;
UINT32					g_ale_connect_callout_id = 0;
UINT32					g_ale_recv_accept_callout_id = 0;
UINT64					g_ale_connect_filter_id = 0;
UINT64					g_ale_recv_accept_filter_id = 0;
BOOLEAN					gb_process_config_other_allow = FALSE;
BOOLEAN					gb_ip_config_other_allow = TRUE;
BOOLEAN					gb_dns_config_other_allow = TRUE;
BOOLEAN					gb_block_all = FALSE;
BOOLEAN					gb_enable_process_monitor = TRUE;
BOOLEAN					gb_enable_ip_monitor = FALSE;
BOOLEAN					gb_enable_dns_monitor = FALSE;
BOOLEAN					gb_enable_monitor = FALSE;
WCHAR					g_process_log_file_path[MAX_PATH_LEN] = {0};

/////////////////////////////////////////////////////////////////////////////



///////////////////////////函数定义开始//////////////////////////////////////

NTSTATUS register_callout_for_layer( IN const GUID* layer_key,
   IN const GUID* callout_key,
   IN FWPS_CALLOUT_CLASSIFY_FN classify_fn,
   IN FWPS_CALLOUT_NOTIFY_FN notify_fn,
   IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flow_delete_notify_fn,
   OUT UINT32* callout_id,
   OUT UINT64* filter_id
   )
{
    NTSTATUS					status = STATUS_SUCCESS;

    FWPS_CALLOUT				s_callout = {0};

    FWPM_FILTER					m_filter = {0};
    FWPM_FILTER_CONDITION		m_filter_condition[1] = {0};

    FWPM_CALLOUT				m_callout = {0};
    FWPM_DISPLAY_DATA			m_display_data = {0};

    BOOLEAN						b_callout_registered = FALSE; //用于失败退出时检测状态，正确释放已经申请的资源

    LOG("into\n");

	s_callout.calloutKey = *callout_key;
	s_callout.classifyFn = classify_fn;
	s_callout.flowDeleteFn = flow_delete_notify_fn;
	s_callout.notifyFn = notify_fn;

	status = FwpsCalloutRegister( g_dev_obj, &s_callout, callout_id );
    if( !NT_SUCCESS(status))
        goto exit;

    b_callout_registered = TRUE;

    m_display_data.name = L"Wall ALE Callout";
    m_display_data.description = L"Callout that capture the wall acquired event";

    m_callout.applicableLayer = *layer_key;
    m_callout.calloutKey = *callout_key;
    m_callout.displayData = m_display_data;

    status = FwpmCalloutAdd( g_engine_handle, &m_callout, NULL, NULL);
    if( !NT_SUCCESS(status))
        goto exit;

    m_filter.action.calloutKey = *callout_key;
    m_filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    m_filter.displayData.name = L"Wall Filter";
    m_filter.displayData.description = L"filter that used to capture the wall needed event";
    m_filter.layerKey = *layer_key;
    m_filter.numFilterConditions = 0;
    m_filter.filterCondition = m_filter_condition;
    m_filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    m_filter.weight.type = FWP_EMPTY;
    
    //initialize m_filter_condition
    //...........................

    status = FwpmFilterAdd( g_engine_handle, &m_filter, NULL, filter_id );

    if( !NT_SUCCESS( status))
        goto exit;

exit:
    if( !NT_SUCCESS(status))	{
        LOG("ERROR OCCURED!\n");

        if( b_callout_registered )	{
            FwpsCalloutUnregisterById( *callout_id );
        }
    }
    return status;
}

NTSTATUS wall_register_callouts ()
/*++
--*/
{
    NTSTATUS		status = STATUS_SUCCESS;

    //用于出错时正确销毁已经申请到的资源
    BOOLEAN			b_in_transaction = FALSE;
    BOOLEAN			b_engine_opened = FALSE;

    FWPM_SESSION session = {0};

    LOG("into\n");

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    
    status = FwpmEngineOpen( NULL,
                            RPC_C_AUTHN_WINNT,
                            NULL,
                            &session,
                            &g_engine_handle );
    if( !NT_SUCCESS(status))
        goto exit;
    b_engine_opened = TRUE;
    
    status = FwpmTransactionBegin( g_engine_handle, 0 );
    if( !NT_SUCCESS(status) )
        goto exit;

    b_in_transaction = TRUE;

    status = register_callout_for_layer( &FWPM_LAYER_ALE_AUTH_CONNECT_V4 ,
        &WALL_ALE_AUTH_CONNECT_CALLOUT_V4,
        wall_ale_connect_classify,
        wall_ale_connect_notify,
        wall_ale_connect_flow_delete,
        &g_ale_connect_callout_id,
        &g_ale_connect_filter_id);
    if( !NT_SUCCESS(status))
        goto exit;

    status = register_callout_for_layer( &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ,
        &WALL_ALE_AUTH_RECV_ACCEPT_CALLOUT_V4,
        wall_ale_recv_accept_classify,
        wall_ale_recv_accept_notify,
        wall_ale_recv_accept_flow_delete,//没必要
        &g_ale_recv_accept_callout_id,
        &g_ale_recv_accept_filter_id);
    if( !NT_SUCCESS(status))
        goto exit;

    status = FwpmTransactionCommit( g_engine_handle );
    if( !NT_SUCCESS(status) )
        goto exit;

    b_in_transaction = FALSE;

exit:
    if( !NT_SUCCESS(status) )	{
        LOG("ERROR OCCURED!\n");

        if( b_in_transaction)	{
            FwpmTransactionAbort( g_engine_handle );
        }

        if( b_engine_opened )	{
            FwpmEngineClose( g_engine_handle );
            g_engine_handle = 0;
        }
    }

    return status;
}

NTSTATUS wall_un_register_callouts()
/*++
--*/
{
    LOG("into\n");

    if( NULL !=g_engine_handle ) {
        FwpmFilterDeleteById ( g_engine_handle, g_ale_connect_filter_id );
        FwpmFilterDeleteById ( g_engine_handle, g_ale_recv_accept_filter_id );
        FwpmCalloutDeleteById ( g_engine_handle, g_ale_connect_callout_id );
        FwpmCalloutDeleteById ( g_engine_handle, g_ale_recv_accept_callout_id );

        FwpmEngineClose( g_engine_handle );
        g_engine_handle = 0;
        g_ale_recv_accept_filter_id = 0;
        g_ale_recv_accept_filter_id = 0;

    }
    FwpsCalloutUnregisterById( g_ale_connect_callout_id );
    g_ale_connect_callout_id = 0;
    FwpsCalloutUnregisterById( g_ale_recv_accept_callout_id );
    g_ale_recv_accept_callout_id = 0;

    return STATUS_SUCCESS;
}


VOID wall_write_connect_log_data ( IN PVOID context )
/*++

注意：此函数运行在PASSIVE_LEVEL ，这里被工作线程调用
--*/
{
    NTSTATUS			status = STATUS_SUCCESS;
    TIME_FIELDS			time;
    WCHAR				buffer[100] = L"";
    UNICODE_STRING		unicode_str = {0};
    OBJECT_ATTRIBUTES	object_attr = {0};
	IO_STATUS_BLOCK		io_block = {0};
    HANDLE				h_database_log_file = NULL;
	PUNICODE_STRING		data = NULL;

	if (NULL != context)	{
		data = ( PUNICODE_STRING )context;
	}
	

    LOG("into\n");
    
    ASSERT( NULL != data );

    //KdPrint(("hash(%wZ)=%x\n",data,hash_unicode_string( data )));
    RtlInitUnicodeString ( &unicode_str, g_process_log_file_path );
    InitializeObjectAttributes( &object_attr, &unicode_str, OBJ_KERNEL_HANDLE, NULL, NULL );
    status = ZwCreateFile( &h_database_log_file,
                            FILE_APPEND_DATA/*FILE_ALL_ACCESS*/,
                            &object_attr,
                            &io_block,
                            NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_OPEN_IF,
                            FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL,
                            0);
    if( !NT_SUCCESS( status ) )	{
        KdPrint(("file create ERROR!\n"));
        goto exit;
    }

    GetLocalTime( &time );
#pragma warning(push)
#pragma warning(disable:28719)              //banned API
    swprintf( buffer,L"[%d-%d-%d-%d-%d-%d]",
            time.Year,
            time.Month,
            time.Day,
            time.Hour,
            time.Minute,
            time.Second);
#pragma warning(pop)

    status = ZwWriteFile( h_database_log_file,
                          NULL,
                          NULL,
                          NULL,
                          &io_block,
                          buffer,
                          wcslen( buffer ) * sizeof(WCHAR),
                          NULL,
                          NULL);
    if( !NT_SUCCESS(status))
    {
        KdPrint(("Write to log file failed!\n"));
        goto exit;
    }

    status = ZwWriteFile( h_database_log_file,
                          NULL,
                          NULL,
                          NULL,
                          &io_block,
                          data->Buffer,
                          data->Length,
                          NULL,
                          NULL);
    if( !NT_SUCCESS(status))
    {
        KdPrint(("Write to log file failed!\n"));
        goto exit;
    }

    status = ZwWriteFile( h_database_log_file,
                          NULL,
                          NULL,
                          NULL,
                          &io_block,
                          L"\r\n",
                          2 * sizeof(WCHAR),
                          NULL,
                          NULL);
    if( !NT_SUCCESS(status))
    {
        KdPrint(("Write to log file failed!\n"));
        goto exit;
    }

exit:
    if( h_database_log_file != NULL )
        ZwClose( h_database_log_file );

    if( data != NULL )
        my_ex_free_pool( data );

    return;
}


NTSTATUS wall_create_connect_list ()
/*++
--*/
{
    pwall_connect_list		p = NULL;
    NTSTATUS				status = STATUS_SUCCESS;

    LOG("into\n");

    p = (pwall_connect_list) my_ex_allocate_pool( sizeof( wall_connect_list) );
    if( NULL == p )	{
        status = STATUS_UNSUCCESSFUL;
        goto exit;
    }
    
    KeInitializeSpinLock( &p->lock );
    InitializeListHead( &p->list );
    g_connect_list = p;

exit:

    return status;
}

NTSTATUS wall_create_packet_list()
/*++
--*/
{
    pwall_connect_list		p = NULL;
    NTSTATUS				status = STATUS_SUCCESS;

    LOG("into\n");

    p = ( pwall_connect_list )my_ex_allocate_pool( sizeof( wall_connect_list) );
    if( NULL == p )	{
        status = STATUS_UNSUCCESSFUL;
        goto exit;
    }
    
    KeInitializeSpinLock( &p->lock );
    InitializeListHead( &p->list );
    g_packet_list = p;

exit:

    return status;
}

VOID wall_destroy_connect_list ()
/*++
--*/
{
    LOG("into\n");

    if( NULL == g_connect_list )
        return;

    ASSERT( IsListEmpty( &g_connect_list->list ) );
    my_ex_free_pool( g_connect_list );
    g_connect_list = NULL;

}

VOID wall_destroy_packet_list ()
/*++
--*/
{
    LOG("into\n");

    if( NULL == g_packet_list )
        return;

    ASSERT( IsListEmpty( &g_packet_list->list ));
    my_ex_free_pool( g_packet_list );
    g_packet_list = NULL;
}

NTSTATUS wall_create_injection_handle ()
/*++
--*/
{
    NTSTATUS		status = STATUS_SUCCESS;

    LOG("into\n");

    status = FwpsInjectionHandleCreate ( AF_UNSPEC, FWPS_INJECTION_TYPE_TRANSPORT, &g_inject_handle);

    return status;
}

NTSTATUS wall_destroy_injection_handle ()
/*++
--*/
{
    NTSTATUS		status = STATUS_SUCCESS;

    LOG("into\n");

    status = FwpsInjectionHandleDestroy ( g_inject_handle );
    if( NT_SUCCESS( status ) )
		g_inject_handle = NULL;

    ASSERT( NULL ==g_inject_handle );
    return status;
}

__inline void get_network_5_tuple_indexes_for_layer( IN UINT16 layer_id,
   OUT UINT* local_address_index,
   OUT UINT* remote_address_index,
   OUT UINT* local_port_index,
   OUT UINT* remote_port_index,
   OUT UINT* protocol_index
   )
{
   switch (layer_id)	{
   case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
      *local_address_index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
      *remote_address_index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
      *local_port_index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
      *remote_port_index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
      *protocol_index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
      break;
   case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
      *local_address_index = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
      *remote_address_index = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
      *local_port_index = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
      *remote_port_index = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
      *protocol_index = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
      *local_address_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
      *remote_address_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
      *local_port_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
      *remote_port_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
      *protocol_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
      *local_address_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
      *remote_address_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
      *local_port_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
      *remote_port_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
      *protocol_index = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
      break;
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
      *local_address_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS;
      *remote_address_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
      *local_port_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT;
      *remote_port_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT;
      *protocol_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL;
      break;
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
      *local_address_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS;
      *remote_address_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS;
      *local_port_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT;
      *remote_port_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT;
      *protocol_index = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V4:
      *local_address_index = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS;
      *remote_address_index = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
      *local_port_index = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT;
      *remote_port_index = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT;
      *protocol_index = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V6:
      *local_address_index = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS;
      *remote_address_index = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS;
      *local_port_index = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT;
      *remote_port_index = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT;
      *protocol_index = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL;
      break;
   default:
      *local_address_index = UINT_MAX;
      *remote_address_index = UINT_MAX;
      *local_port_index = UINT_MAX;
      *remote_port_index = UINT_MAX;
      *protocol_index = UINT_MAX;      
      ASSERT(0);
   }
}

void FillNetwork5Tuple( IN const FWPS_INCOMING_VALUES0* in_fixed_values,
   IN ADDRESS_FAMILY address_family,
   IN OUT wall_pended_packet* packet
   )
{
   UINT		local_addr_index = -1;
   UINT		remote_addr_index = -1;
   UINT		local_port_index = -1;
   UINT		remote_port_index = -1;
   UINT		protocol_index = -1;

   LOG("into\n");

   get_network_5_tuple_indexes_for_layer( in_fixed_values->layerId,
      &local_addr_index,
      &remote_addr_index,
      &local_port_index,
      &remote_port_index,
      &protocol_index
      );

   if ( AF_INET == address_family )
   {
      packet->ipv4LocalAddr = RtlUlongByteSwap( /* host-order -> network-order conversion */
            in_fixed_values->incomingValue[local_addr_index].value.uint32
            );
      packet->ipv4RemoteAddr = 
         RtlUlongByteSwap( /* host-order -> network-order conversion */
            in_fixed_values->incomingValue[remote_addr_index].value.uint32
            );
   }
   else
   {
      RtlCopyMemory(
         (UINT8*)&packet->localAddr,
         in_fixed_values->incomingValue[local_addr_index].value.byteArray16,
         sizeof(FWP_BYTE_ARRAY16)
         );
      RtlCopyMemory(
         (UINT8*)&packet->remoteAddr,
         in_fixed_values->incomingValue[remote_addr_index].value.byteArray16,
         sizeof(FWP_BYTE_ARRAY16)
         );
   }

   packet->localPort = 
      RtlUshortByteSwap(
         in_fixed_values->incomingValue[local_port_index].value.uint16
         );
   packet->remotePort = 
      RtlUshortByteSwap(
         in_fixed_values->incomingValue[remote_port_index].value.uint16
         );
   packet->protocol = in_fixed_values->incomingValue[protocol_index].value.uint8;

   return;
}

__inline
void
GetDeliveryInterfaceIndexesForLayer(
   IN UINT16 layer_id,
   OUT UINT* interfaceIndexIndex,
   OUT UINT* subInterfaceIndexIndex
   )
{
   switch (layer_id)
   {
   case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
      *interfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_CONNECT_V4_SUB_INTERFACE_INDEX;
#else
      //
      // Prior to Vista SP1, sub/interface-index are not being indicated to
      // ALE_AUTH_CONNECT layers. A callout driver would need to derive them
      // from the interface LUID using iphlpapi functions.
      //
      ASSERT(0);
#endif
      break;
   case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
      *interfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_CONNECT_V6_SUB_INTERFACE_INDEX;
#else
      ASSERT(0);
#endif
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
      *interfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SUB_INTERFACE_INDEX;
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
      *interfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SUB_INTERFACE_INDEX;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V4:
      *interfaceIndexIndex = 
         FWPS_FIELD_INBOUND_TRANSPORT_V4_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_INBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V6:
      *interfaceIndexIndex = 
         FWPS_FIELD_INBOUND_TRANSPORT_V6_INTERFACE_INDEX;
      *subInterfaceIndexIndex = 
         FWPS_FIELD_INBOUND_TRANSPORT_V6_SUB_INTERFACE_INDEX;
      break;
   default:
      ASSERT(0);
      break;
   }
}

BOOLEAN
is_matching_connect_packet(
   IN const FWPS_INCOMING_VALUES0* in_fixed_values,
   IN ADDRESS_FAMILY address_family,
   IN FWP_DIRECTION direction,
   IN wall_pended_packet* pended_packet
   )
{
   UINT local_addr_index;
   UINT remote_addr_index;
   UINT local_port_index;
   UINT remote_port_index;
   UINT protocol_index;

   ASSERT(pended_packet->type == WALL_CONNECT_PACKET);

   LOG("into\n");

   get_network_5_tuple_indexes_for_layer(
      in_fixed_values->layer_id,
      &local_addr_index,
      &remote_addr_index,
      &local_port_index,
      &remote_port_index,
      &protocol_index
      );

   if(local_addr_index == UINT_MAX)
   {
      return FALSE;
   }

   if (address_family != pended_packet->address_family)
   {
      return FALSE;
   }

   if (direction != pended_packet->direction)
   {
      return FALSE;
   }

   if (in_fixed_values->incomingValue[protocol_index].value.uint8 != 
       pended_packet->protocol)
   {
      return FALSE;
   }

   if (RtlUshortByteSwap(
         in_fixed_values->incomingValue[local_port_index].value.uint16
         ) != pended_packet->localPort)
   {
      return FALSE;
   }

   if (RtlUshortByteSwap(
         in_fixed_values->incomingValue[remote_port_index].value.uint16
         ) != pended_packet->remotePort)
   {
      return FALSE;
   }

   if (address_family == AF_INET)
   {
      UINT32 ipv4LocalAddr = 
         RtlUlongByteSwap(
            in_fixed_values->incomingValue[local_addr_index].value.uint32
            );
      UINT32 ipv4RemoteAddr = 
         RtlUlongByteSwap( /* host-order -> network-order conversion */
            in_fixed_values->incomingValue[remote_addr_index].value.uint32
            );
      if (ipv4LocalAddr != pended_packet->ipv4LocalAddr)
      {
         return FALSE;
      }

      if (ipv4RemoteAddr != pended_packet->ipv4RemoteAddr)
      {
         return FALSE;
      }
   }
   else
   {
      if (RtlCompareMemory(
            in_fixed_values->incomingValue[local_addr_index].value.byteArray16, 
            &pended_packet->localAddr,
            sizeof(FWP_BYTE_ARRAY16)) !=  sizeof(FWP_BYTE_ARRAY16))
      {
         return FALSE;
      }

      if (RtlCompareMemory(
            in_fixed_values->incomingValue[remote_addr_index].value.byteArray16, 
            &pended_packet->remoteAddr,
            sizeof(FWP_BYTE_ARRAY16)) !=  sizeof(FWP_BYTE_ARRAY16))
      {
         return FALSE;
      }
   }

   return TRUE;
}


ADDRESS_FAMILY get_address_family_for_layer(
   IN UINT16 layer_id
   )
{
   ADDRESS_FAMILY address_family;

   LOG("into\n");

   switch (layer_id)
   {
   case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
   case FWPS_LAYER_INBOUND_TRANSPORT_V4:
      address_family = AF_INET;
      break;
   case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
   case FWPS_LAYER_INBOUND_TRANSPORT_V6:
      address_family = AF_INET6;
      break;
   default:
      address_family = AF_UNSPEC;
      ASSERT(0);
   }

   return address_family;
}

wall_pended_packet*
wall_allocate_and_init_pended_packet(
   IN const FWPS_INCOMING_VALUES0* in_fixed_values,
   IN const FWPS_INCOMING_METADATA_VALUES0* in_meta_values,
   IN ADDRESS_FAMILY address_family,
   IN OUT void* layer_data,
   IN wall_packet_type packet_type,
   IN FWP_DIRECTION packet_direction
   )
/*++
功能描述：缓冲原始的packet，分配相关的PACKET结构变量

参数说明：
    in_fixed_values：classify_out回调中的in_fixed_values
    in_meta_values：classify_out回调中的in_meta_values
    address_family：IP地址类型，取值为AF_INET或者AF_INET6
    layer_data:classify_out回调中的layer_data
    packet_type:packet类型，取值为WALL_CONNECT_PACKET,WALL_DATA_PACKET或者WALL_REAUTH_PACKET
    packet_direction:packet方向，上行为:FWP_DIRECTION_OUTBOUND,下行为：FWP_DIRECTION_INBOUND;

返回值说明：
    所分配的packet的指针，将来必须用wall_free_pended_packet释放
    分配失败返回NULL
--*/
{
    NTSTATUS                status = STATUS_SUCCESS;
    wall_pended_packet      *pended_packet;
    UNICODE_STRING          dev_name,dos_name;
    WCHAR                   buffer[MAX_PATH_LEN];

    LOG("into\n");

    // pended_packet gets deleted in Freepended_packet
    #pragma warning( suppress : 28197 )
    pended_packet = my_ex_allocate_pool(sizeof( wall_pended_packet));
    if (pended_packet == NULL)
    {
       return NULL;
    }

    RtlZeroMemory(pended_packet, sizeof(wall_pended_packet));

    pended_packet->type = packet_type;
    pended_packet->direction = packet_direction;

    pended_packet->address_family = address_family;

    FillNetwork5Tuple(
       in_fixed_values,
       address_family,
       pended_packet
       );

    if (layer_data != NULL)
    {
       pended_packet->netBufferList = layer_data;

       //
       // Reference the net buffer list to make it accessible outside of 
       // classify_fn.
       //
       FwpsReferenceNetBufferList0(pended_packet->netBufferList, TRUE);
    }

    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(in_meta_values, 
                                          FWPS_METADATA_FIELD_COMPARTMENT_ID));
    pended_packet->compartmentId = in_meta_values->compartmentId;

    if ((pended_packet->direction == FWP_DIRECTION_OUTBOUND) &&
        (layer_data != NULL))
    {
       ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
                   in_meta_values, 
                   FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE));
       pended_packet->endpointHandle = in_meta_values->transportEndpointHandle;

       pended_packet->remoteScopeId = in_meta_values->remoteScopeId;

       if (FWPS_IS_METADATA_FIELD_PRESENT(
             in_meta_values, 
             FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA))
       {
          ASSERT(in_meta_values->controlDataLength > 0);

          // pended_packet->controlData gets deleted in Freepended_packet
          #pragma warning( suppress : 28197 )
          pended_packet->controlData = my_ex_allocate_pool(in_meta_values->controlDataLength);
         if (pended_packet->controlData == NULL)
         {
            goto Exit;
         }

         RtlCopyMemory(
            pended_packet->controlData,
            in_meta_values->controlData,
            in_meta_values->controlDataLength
            );

         pended_packet->controlDataLength =  in_meta_values->controlDataLength;
      }
   }
   else if (pended_packet->direction == FWP_DIRECTION_INBOUND)
   {
      UINT interfaceIndexIndex;
      UINT subInterfaceIndexIndex;

      GetDeliveryInterfaceIndexesForLayer(
         in_fixed_values->layer_id,
         &interfaceIndexIndex,
         &subInterfaceIndexIndex
         );

      pended_packet->interfaceIndex = 
         in_fixed_values->incomingValue[interfaceIndexIndex].value.uint32;
      pended_packet->subInterfaceIndex = 
         in_fixed_values->incomingValue[subInterfaceIndexIndex].value.uint32;
      
      ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
               in_meta_values, 
               FWPS_METADATA_FIELD_IP_HEADER_SIZE));
      ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
               in_meta_values, 
               FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE));
      pended_packet->ipHeaderSize = in_meta_values->ipHeaderSize;
      pended_packet->transportHeaderSize = in_meta_values->transportHeaderSize;

      if (pended_packet->netBufferList != NULL)
      {
         FWPS_PACKET_LIST_INFORMATION0 packetInfo = {0};
         FwpsGetPacketListSecurityInformation0(
            pended_packet->netBufferList,
            FWPS_PACKET_LIST_INFORMATION_QUERY_IPSEC |
            FWPS_PACKET_LIST_INFORMATION_QUERY_INBOUND,
            &packetInfo
            );

         pended_packet->ipSecProtected = 
            (BOOLEAN)packetInfo.ipsecInformation.inbound.isSecure;

         pended_packet->nblOffset = 
            NET_BUFFER_DATA_OFFSET(\
               NET_BUFFER_LIST_FIRST_NB(pended_packet->netBufferList));
      }
   }

    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(in_meta_values, 
                                FWPS_METADATA_FIELD_PROCESS_PATH));

    RtlInitUnicodeString( &dev_name,(PWCHAR)in_meta_values->processPath->data );
    KdPrint(("tname:%wZ\nlayer_data = %x\n",&dev_name,layer_data ));
    RtlInitEmptyUnicodeString( &dos_name,buffer,MAX_PATH_LEN * sizeof(WCHAR));

    status = DevicePathToDosPath( &dev_name,&dos_name );//BUG!!!!  irql level must be passive level.
    if( status == STATUS_SUCCESS )
    {
        KdPrint(("PNAME:%wZ\n",&dos_name ));
        pended_packet->crcProcessPath = hash_unicode_string( &dos_name );
    }
    else
    {
        KdPrint(("PNAME:%wZ\n",&dev_name ));
        pended_packet->crcProcessPath = hash_unicode_string( &dev_name );
    }
    KdPrint(("crc = %x\n",pended_packet->crcProcessPath ));

    return pended_packet;

Exit:

    if (pended_packet != NULL)
    {
        LOG("free packet\n");
       wall_free_pended_packet(pended_packet);
    }

    return NULL;
}

VOID
wall_free_pended_packet( IN pwall_pended_packet packet )
/*++
功能说明：释放被缓冲的packet

参数说明：
    packet:指向所释放packet的指针

返回值说明：
    无返回值
--*/
{
    LOG("into\n");

   if (packet->netBufferList != NULL)
   {
      FwpsDereferenceNetBufferList0(packet->netBufferList, FALSE);
   }
   if (packet->controlData != NULL)
   {
      my_ex_free_pool(packet->controlData);
   }
   if (packet->completion_context != NULL)
   {
      //ASSERT(packet->type == WALL_CONNECT_PACKET);
      //ASSERT(packet->direction == FWP_DIRECTION_INBOUND); // complete for ALE connect
                                                          // is done prior to freeing
                                                          // of the packet.
      FwpsCompleteOperation0(packet->completion_context, NULL);
   }
   my_ex_free_pool(packet);
    
}

VOID
NTAPI
WallInspectInjectComplete(
   IN VOID * context,
   IN OUT NET_BUFFER_LIST* netBufferList,
   IN BOOLEAN dispatchLevel
   )
/*++
功能描述：注入完成事件的回调函数，用来做清除资源的工作

参数说明：
    context:指向注入完成packet的指针
    netBufferList:克隆的NET_BUFFER_LIST结构
    dispatchLevel：执行的中断级，此处未用

返回值说明：无返回值

--*/
{
   wall_pended_packet* packet = context;

   UNREFERENCED_PARAMETER(dispatchLevel);   

   LOG("into\n");

   FwpsFreeCloneNetBufferList0(netBufferList, 0);

   LOG("free packet\n");
   wall_free_pended_packet(packet);
}


NTSTATUS
WallInspectCloneReinjectOutbound(
   IN wall_pended_packet* packet
   )
/* ++

   This function clones the outbound net buffer list and reinject it back.

-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   NET_BUFFER_LIST* clonedNetBufferList = NULL;
   FWPS_TRANSPORT_SEND_PARAMS0 sendArgs = {0};

   LOG("into\n");

   status = FwpsAllocateCloneNetBufferList0(
               packet->netBufferList,
               NULL,
               NULL,
               0,
               &clonedNetBufferList
               );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   sendArgs.remoteAddress = (UINT8*)(&packet->remoteAddr);
   sendArgs.remoteScopeId = packet->remoteScopeId;
   sendArgs.controlData = packet->controlData;
   sendArgs.controlDataLength = packet->controlDataLength;
   //
   // Send-inject the cloned net buffer list.
   //

   status = FwpsInjectTransportSendAsync0(
               g_inject_handle,
               NULL,
               packet->endpointHandle,
               0,
               &sendArgs,
               packet->address_family,
               packet->compartmentId,
               clonedNetBufferList,
               WallInspectInjectComplete,
               packet
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   clonedNetBufferList = NULL; // ownership transferred to the 
                               // completion function.

Exit:

   if (clonedNetBufferList != NULL)
   {
      FwpsFreeCloneNetBufferList0(clonedNetBufferList, 0);
   }

   return status;
}

NTSTATUS
WallInspectCloneReinjectInbound(
   IN OUT wall_pended_packet* packet
   )
/* ++

   This function clones the inbound net buffer list and, if needed, 
   rebuild the IP header to remove the IpSec headers and receive-injects 
   the clone back to the tcpip stack.

-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   NET_BUFFER_LIST* clonedNetBufferList = NULL;
   NET_BUFFER* netBuffer;
   ULONG nblOffset;

   LOG("into\n");

   //
   // For inbound net buffer list, we can assume it contains only one 
   // net buffer.
   //
   netBuffer = NET_BUFFER_LIST_FIRST_NB(packet->netBufferList);
   
   nblOffset = NET_BUFFER_DATA_OFFSET(netBuffer);

   //
   // The TCP/IP stack could have retreated the net buffer list by the 
   // transportHeaderSize amount; detect the condition here to avoid
   // retreating twice.
   //
   if (nblOffset != packet->nblOffset)
   {
      ASSERT(packet->nblOffset - nblOffset == packet->transportHeaderSize);
      packet->transportHeaderSize = 0;
   }

   //
   // Adjust the net buffer list offset to the start of the IP header.
   //
   NdisRetreatNetBufferDataStart(
      netBuffer,
      packet->ipHeaderSize + packet->transportHeaderSize,
      0,
      NULL
      );

   //
   // Note that the clone will inherit the original net buffer list's offset.
   //

   status = FwpsAllocateCloneNetBufferList0(
               packet->netBufferList,
               NULL,
               NULL,
               0,
               &clonedNetBufferList
               );

   //
   // Undo the adjustment on the original net buffer list.
   //

   NdisAdvanceNetBufferDataStart(
      netBuffer,
      packet->ipHeaderSize + packet->transportHeaderSize,
      FALSE,
      NULL
      );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   if (packet->ipSecProtected)
   {
      //
      // When an IpSec protected packet is indicated to AUTH_RECV_ACCEPT or 
      // INBOUND_TRANSPORT layers, for performance reasons the tcpip stack
      // does not remove the AH/ESP header from the packet. And such 
      // packets cannot be recv-injected back to the stack w/o removing the
      // AH/ESP header. Therefore before re-injection we need to "re-build"
      // the cloned packet.
      // 
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)

      status = FwpsConstructIpHeaderForTransportPacket0(
                  clonedNetBufferList,
                  packet->ipHeaderSize,
                  packet->address_family,
                  (UINT8*)&packet->remoteAddr, 
                  (UINT8*)&packet->localAddr,  
                  packet->protocol,
                  0,
                  NULL,
                  0,
                  0,
                  NULL,
                  0,
                  0
                  );
#else
      ASSERT(FALSE); // Prior to Vista SP1, IP address needs to be updated 
                     // manually (including updating IP checksum).

      status = STATUS_NOT_IMPLEMENTED;
#endif

      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }
   }

   if (packet->completion_context != NULL)
   {
      //ASSERT(packet->type == WALL_CONNECT_PACKET);

      FwpsCompleteOperation0(
         packet->completion_context,
         clonedNetBufferList
         );

      packet->completion_context = NULL;
   }

   status = FwpsInjectTransportReceiveAsync0(
               g_inject_handle,
               NULL,
               NULL,
               0,
               packet->address_family,
               packet->compartmentId,
               packet->interfaceIndex,
               packet->subInterfaceIndex,
               clonedNetBufferList,
               WallInspectInjectComplete,
               packet
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   clonedNetBufferList = NULL; // ownership transferred to the 
                               // completion function.

Exit:

   if (clonedNetBufferList != NULL)
   {
      FwpsFreeCloneNetBufferList0(clonedNetBufferList, 0);
   }

   return status;
}


VOID
wall_inspect_wall_packets( IN PVOID context )
/*++
功能描述：处理被缓冲的packet

参数说明：
    context:未定义

返回值说明：无返回值

注意：此函数在工作线程中执行，中断级为PASSIVE_LEVEL
--*/
{
    pwall_pended_packet     packet = NULL;
    KIRQL                   irql,irql2;
    PLIST_ENTRY             listEntry = NULL;
    NTSTATUS                status = STATUS_SUCCESS;
    LOG("into\n");
    

    for( ;!IsListEmpty( &g_connect_list->list ) || !IsListEmpty( &g_packet_list->list);)
    {
        listEntry = NULL;
        
        if( !IsListEmpty( &g_connect_list->list ))
        {
            KeAcquireSpinLock( &g_connect_list->lock,&irql );
            listEntry = g_connect_list->list.Flink;
            if(((pwall_pended_packet)listEntry)->netBufferList != NULL)
            {
                ((pwall_pended_packet)listEntry)->type = WALL_DATA_PACKET;
                //((pwall_pended_packet)listEntry)->completion_context = NULL;
                RemoveEntryList( listEntry );
            }
            KeReleaseSpinLock( &g_connect_list->lock,irql );
        }

        if( listEntry == NULL && !IsListEmpty( &g_packet_list->list ))
        {
            KeAcquireSpinLock( &g_packet_list->lock,&irql2 );
            listEntry = g_packet_list->list.Flink;
            RemoveEntryList( listEntry );
            KeReleaseSpinLock( &g_packet_list->lock,irql2 );
        }

        ASSERT(listEntry != NULL );

        packet = (pwall_pended_packet)listEntry;

        if( gb_block_all )
            packet->authConnectDecision = FWP_ACTION_BLOCK;
        else if( gb_enable_process_monitor && !wall_is_process_traffic_permit(packet))
            packet->authConnectDecision = FWP_ACTION_BLOCK;
        else if ( gb_enable_ip_monitor && !wall_is_ip_traffic_permit(packet))
            packet->authConnectDecision = FWP_ACTION_BLOCK;
        else if( gb_enable_dns_monitor && !wall_is_dns_traffic_permit( packet ))
            packet->authConnectDecision = FWP_ACTION_BLOCK;
        else
            packet->authConnectDecision = FWP_ACTION_PERMIT;

        if( packet->type == WALL_CONNECT_PACKET )
        {
            if( packet->authConnectDecision == FWP_ACTION_PERMIT )
                FwpsCompleteOperation( packet->completion_context,NULL);
            else
            {
                KeAcquireSpinLock( &g_connect_list->lock,&irql );
                RemoveEntryList( &packet->list );
                KeReleaseSpinLock( &g_connect_list->lock,irql );

                wall_free_pended_packet( packet );
                packet = NULL;
                
            }

        }
        else
        {
            ASSERT( packet->type == WALL_DATA_PACKET );

            if( packet->direction == FWP_DIRECTION_OUTBOUND )
            {
                
                FwpsCompleteOperation( packet->completion_context,NULL);
                packet->completion_context = NULL;
                
                if( packet->authConnectDecision == FWP_ACTION_PERMIT )
                    status = WallInspectCloneReinjectOutbound( packet );
                else
                {
                    wall_free_pended_packet( packet );
                    packet = NULL;
                }
            }
            else
            {
                if( packet->authConnectDecision == FWP_ACTION_PERMIT )
                    status = WallInspectCloneReinjectInbound( packet );
                else
                {
                    packet->completion_context = NULL;
                    wall_free_pended_packet( packet );
                    packet = NULL;
                }
            }
            ASSERT(NT_SUCCESS(status));
        }

    }
}

VOID    wall_load_global_config()
/*++
功能描述：加载全局配置数据

参数说明：无

返回值说明：无
--*/
{
    NTSTATUS                status;
    HANDLE                  hCactiKey = 0,hGlobalRulesKey = 0;
    OBJECT_ATTRIBUTES       KeyObjAttr;
    UNICODE_STRING          RegDirectory;
    ULONG                   i;
    UCHAR                   RetInfor[ 88+ sizeof( KEY_FULL_INFORMATION ) + MAX_PATH_LEN * sizeof( WCHAR) ];//NOTICE!
    PKEY_FULL_INFORMATION   pKeyFullInfor;
    PKEY_BASIC_INFORMATION  pKeyBasicInfor;
    PKEY_VALUE_PARTIAL_INFORMATION pKeyValuePartialInfor;
    PKEY_VALUE_FULL_INFORMATION    pKeyValueFullInfor;
    ULONG                   retLength = 0;
    ULONG                   subKeys = 0,KeyValues = 0;
    UNICODE_STRING          uniKeyName;
    UNICODE_STRING          uniValueName;

    LOG("into\n");

    RtlInitUnicodeString( &RegDirectory,CACTIWALL_REG_DIRECTORY );
    InitializeObjectAttributes( &KeyObjAttr,
                                &RegDirectory,
                                OBJ_KERNEL_HANDLE,
                                0,
                                NULL);
    status = ZwCreateKey( &hCactiKey,
                          KEY_ALL_ACCESS,
                          &KeyObjAttr,
                          0,
                          NULL,
                          0,
                          NULL);
    if( !NT_SUCCESS( status ) ){
        KdPrint(("Create key 1 failed!\n"));
        return;
    }

    RtlInitUnicodeString( &RegDirectory,L"globalrules" );
    InitializeObjectAttributes( &KeyObjAttr,
                                &RegDirectory,
                                OBJ_KERNEL_HANDLE,
                                hCactiKey,
                                NULL);
    status = ZwCreateKey( &hGlobalRulesKey,
                          KEY_ALL_ACCESS,
                          &KeyObjAttr,
                          0,
                          NULL,
                          0,
                          NULL);
    if( !NT_SUCCESS( status ) ){
        KdPrint(("Create key 2 failed!\n"));
        ZwClose( hCactiKey );
        hCactiKey = NULL;
        return;
    }

    RtlInitUnicodeString( &uniValueName,L"processmonitorenable");
    status = ZwQueryValueKey( hGlobalRulesKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
    if( !NT_SUCCESS( status ))
    {
        KdPrint(("query value key(ProcessMonitorEnable) failed!(%x)\n",status));
        gb_enable_process_monitor = TRUE;
    }
    else
    {
        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        if( *(UINT32 *)pKeyValuePartialInfor->Data == 0 )
            gb_enable_process_monitor = FALSE;
        else
            gb_enable_process_monitor = TRUE;
        KdPrint(("global_config:gb_enable_process_monitor = %x\n",gb_enable_process_monitor ));
    }

    RtlInitUnicodeString( &uniValueName,L"IpMonitorEnable");
    status = ZwQueryValueKey( hGlobalRulesKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
    if( !NT_SUCCESS( status ))
    {
        KdPrint(("query value key(IpMonitorEnable) failed!\n"));
        gb_enable_ip_monitor = FALSE;
    }
    else
    {
        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        if( *(UINT32 *)pKeyValuePartialInfor->Data == 0 )
            gb_enable_ip_monitor = FALSE;
        else
            gb_enable_ip_monitor = TRUE;
        KdPrint(("global_config:gb_enable_ip_monitor = %x\n",gb_enable_ip_monitor ));
    }

    RtlInitUnicodeString( &uniValueName,L"DnsMonitorEnable");
    status = ZwQueryValueKey( hGlobalRulesKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
    if( !NT_SUCCESS( status ))
    {
        KdPrint(("query value key(DnsMonitorEnable) failed!\n"));
        gb_enable_dns_monitor = FALSE;
    }
    else
    {
        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        if( *(UINT32 *)pKeyValuePartialInfor->Data == 0 )
            gb_enable_dns_monitor = FALSE;
        else
            gb_enable_dns_monitor = TRUE;
        KdPrint(("global_config:gb_enable_dns_monitor = %x\n",gb_enable_dns_monitor ));
    }

    RtlInitUnicodeString( &uniValueName,L"MonitorEnable");
    status = ZwQueryValueKey( hGlobalRulesKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
    if( !NT_SUCCESS( status ))
    {
        KdPrint(("query value key(MonitorEnable) failed!\n"));
        gb_enable_monitor = FALSE;
    }
    else
    {
        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        if( *(UINT32 *)pKeyValuePartialInfor->Data == 0 )
            gb_enable_monitor = FALSE;
        else
            gb_enable_monitor = TRUE;
        KdPrint(("global_config:gb_enable_monitor = %x\n",gb_enable_monitor ));
    }

    RtlInitUnicodeString( &uniValueName,L"ProcessLogFile");
    status = ZwQueryValueKey( hGlobalRulesKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
    if( !NT_SUCCESS( status ))
    {
        KdPrint(("query value key(ProcessLogFile) failed!\n"));
        gb_enable_ip_monitor = FALSE;
    }
    else
    {
        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_SZ );
        if( pKeyValuePartialInfor->DataLength > MAX_PATH_LEN * sizeof(WCHAR))
        {
            //缓冲区长度检查
            KdPrint(("log file path is too long!\n"));
            wcscpy_s( g_process_log_file_path,MAX_PATH_LEN,L"c:\\wall_processlog.db");
        }
        else
        {
            RtlCopyMemory( g_process_log_file_path,pKeyValuePartialInfor->Data,pKeyValuePartialInfor->DataLength);

        }
        KdPrint(("global_config:g_process_log_file_path = %ws\n",g_process_log_file_path ));
    }

    ZwClose( hGlobalRulesKey );
    hGlobalRulesKey = NULL;
    ZwClose(  hCactiKey );
    hCactiKey = NULL;

    return;
}

NTSTATUS    wall_load_process_config()
/*++
功能说明：载入进程规则

参数说明：无

返回值：成功返回STATUS_SUCCESS

--*/
{
    NTSTATUS                status;
    HANDLE                  hCactiKey = 0,hProcessRulesKey = 0;
    OBJECT_ATTRIBUTES       KeyObjAttr;
    UNICODE_STRING          RegDirectory;
    ULONG                   i;
    UCHAR                   RetInfor[ sizeof( KEY_FULL_INFORMATION ) + 88 ];//NOTICE!
    PKEY_FULL_INFORMATION   pKeyFullInfor;
    PKEY_BASIC_INFORMATION  pKeyBasicInfor;
    PKEY_VALUE_PARTIAL_INFORMATION pKeyValuePartialInfor;
    PKEY_VALUE_FULL_INFORMATION    pKeyValueFullInfor;
    ULONG                    retLength = 0;
    ULONG                    subKeys = 0,KeyValues = 0;
    UNICODE_STRING          uniKeyName;
    UNICODE_STRING          uniValueName;
    UINT32                  crcProcessPath;
    UINT32                  rule;

    LOG("into\n");

    init_process_rules();

    RtlInitUnicodeString( &RegDirectory,CACTIWALL_REG_DIRECTORY );
    InitializeObjectAttributes( &KeyObjAttr,
                                &RegDirectory,
                                OBJ_KERNEL_HANDLE,
                                0,
                                NULL);
    status = ZwCreateKey( &hCactiKey,
                          KEY_ALL_ACCESS,
                          &KeyObjAttr,
                          0,
                          NULL,
                          0,
                          NULL);
    if( !NT_SUCCESS( status ) ){
        KdPrint(("Create key 1 failed!\n"));
        return status;
    }

    RtlInitUnicodeString( &RegDirectory,L"processrules" );
    InitializeObjectAttributes( &KeyObjAttr,
                                &RegDirectory,
                                OBJ_KERNEL_HANDLE,
                                hCactiKey,
                                NULL);
    status = ZwCreateKey( &hProcessRulesKey,
                          KEY_ALL_ACCESS,
                          &KeyObjAttr,
                          0,
                          NULL,
                          0,
                          NULL);
    if( !NT_SUCCESS( status ) ){
        KdPrint(("Create key 2 failed!\n"));
        return status;
    }

    RtlInitUnicodeString( &uniValueName,L"other_access");
    status = ZwQueryValueKey( hProcessRulesKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
    if( !NT_SUCCESS( status ))
    {
        KdPrint(("query value key(other_access) failed!\n"));
        gb_process_config_other_allow = TRUE;
    }
    else
    {
        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        if( *(UINT32 *)pKeyValuePartialInfor->Data == 1 )
            gb_process_config_other_allow = TRUE;
        else
            gb_process_config_other_allow = FALSE;
    }


    status = ZwQueryKey( hProcessRulesKey,
                         KeyFullInformation,
                         &RetInfor,
                         sizeof( RetInfor ),
                         &retLength );
    if( !NT_SUCCESS( status ) ){
        KdPrint(( "QueryKeyfullinfor failed!\n"));
        return status;
    }
    pKeyFullInfor = ( PKEY_FULL_INFORMATION )RetInfor;
    subKeys = pKeyFullInfor->SubKeys;
    
    for( i = 0;i < subKeys; i++)
    {
        HANDLE  hKey;

        RtlZeroMemory( &RetInfor,sizeof(RetInfor));
        status = ZwEnumerateKey( hProcessRulesKey,
                                      i,
                                      KeyBasicInformation,
                                      &RetInfor,
                                      sizeof( RetInfor ),
                                      &retLength);
        if( !NT_SUCCESS( status ) ){
            KdPrint(("Enumerate value key failed!--%d\n",i));
            continue;
        }
        pKeyBasicInfor = (PKEY_BASIC_INFORMATION)RetInfor;
        uniKeyName.Length = uniKeyName.MaximumLength = (USHORT)pKeyBasicInfor->NameLength;
        uniKeyName.Buffer = pKeyBasicInfor->Name;
        UnicodeStringToUint32( &uniKeyName,&crcProcessPath );
        
        InitializeObjectAttributes( &KeyObjAttr,
                                &uniKeyName,
                                OBJ_KERNEL_HANDLE,
                                hProcessRulesKey,
                                NULL);
        status = ZwCreateKey( &hKey,
                                KEY_ALL_ACCESS,
                                &KeyObjAttr,
                                0,
                                NULL,
                                0,
                                NULL);
        if( !NT_SUCCESS( status ) ){
            KdPrint(("create hKey failed!--%d\n",i));
            continue;
        }
        
        RtlInitUnicodeString( &uniValueName,L"rule");
        status = ZwQueryValueKey( hKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
        if( !NT_SUCCESS( status ))
        {
            KdPrint(("query value key failed!--%d\n",i));
            continue;
        }

        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        rule = *(UINT32 *)pKeyValuePartialInfor->Data;
        
        ZwClose( hKey );
        hKey = NULL;

        KdPrint(("crcProcessPath = 0x%x,rule = %x\n",crcProcessPath,rule ));
        add_process_rule( crcProcessPath,rule );

    }

    ZwClose( hProcessRulesKey );
    ZwClose( hCactiKey );

    gb_enable_process_monitor = TRUE;

    return STATUS_SUCCESS;

}

NTSTATUS
wall_load_ip_config()
/*++
功能说明：载入IP规则

参数说明：无

返回值：成功返回STATUS_SUCCESS

--*/
{
    NTSTATUS                status;
    HANDLE                  hCactiKey = 0,hIpRulesKey = 0;
    OBJECT_ATTRIBUTES       KeyObjAttr;
    UNICODE_STRING          RegDirectory;
    ULONG                   i;
    UCHAR                   RetInfor[ sizeof( KEY_FULL_INFORMATION ) + 88 ];//NOTICE!
    PKEY_FULL_INFORMATION   pKeyFullInfor;
    PKEY_BASIC_INFORMATION  pKeyBasicInfor;
    PKEY_VALUE_PARTIAL_INFORMATION pKeyValuePartialInfor;
    PKEY_VALUE_FULL_INFORMATION    pKeyValueFullInfor;
    ULONG                   retLength = 0;
    ULONG                   subKeys = 0,KeyValues = 0;
    UNICODE_STRING          uniKeyName;
    UNICODE_STRING          uniValueName;
    UINT32                  crcIpRuleName;
    UINT32                  rule;
    ip_rules_elem           elem = {0};

    LOG("into\n");

    init_ip_rules();

    RtlInitUnicodeString( &RegDirectory,CACTIWALL_REG_DIRECTORY );
    InitializeObjectAttributes( &KeyObjAttr,
                                &RegDirectory,
                                OBJ_KERNEL_HANDLE,
                                0,
                                NULL);
    status = ZwCreateKey( &hCactiKey,
                          KEY_ALL_ACCESS,
                          &KeyObjAttr,
                          0,
                          NULL,
                          0,
                          NULL);
    if( !NT_SUCCESS( status ) ){
        KdPrint(("Create key 1 failed!\n"));
        return status;
    }

    RtlInitUnicodeString( &RegDirectory,L"iprules" );
    InitializeObjectAttributes( &KeyObjAttr,
                                &RegDirectory,
                                OBJ_KERNEL_HANDLE,
                                hCactiKey,
                                NULL);
    status = ZwCreateKey( &hIpRulesKey,
                          KEY_ALL_ACCESS,
                          &KeyObjAttr,
                          0,
                          NULL,
                          0,
                          NULL);
    if( !NT_SUCCESS( status ) ){
        KdPrint(("Create key 2 failed!\n"));
        return status;
    }

    RtlInitUnicodeString( &uniValueName,L"other_access");
    status = ZwQueryValueKey( hIpRulesKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
    if( !NT_SUCCESS( status ))
    {
        KdPrint(("query value key(other_access) failed!\n"));
        gb_ip_config_other_allow = TRUE;
    }
    else
    {
        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        if( *(UINT32 *)pKeyValuePartialInfor->Data == 0 )
            gb_ip_config_other_allow = FALSE;
        else
            gb_ip_config_other_allow = TRUE;
        KdPrint(("ip_config:other_access = %x\n",gb_ip_config_other_allow ));
    }


    status = ZwQueryKey( hIpRulesKey,
                         KeyFullInformation,
                         &RetInfor,
                         sizeof( RetInfor ),
                         &retLength );
    if( !NT_SUCCESS( status ) ){
        KdPrint(( "QueryKeyfullinfor failed!\n"));
        return status;
    }
    pKeyFullInfor = ( PKEY_FULL_INFORMATION )RetInfor;
    subKeys = pKeyFullInfor->SubKeys;
    
    for( i = 0;i < subKeys; i++)
    {
        HANDLE  hKey = NULL;
        pip_rules_elem ipRulesElem = NULL;

        RtlZeroMemory( &RetInfor,sizeof(RetInfor));
        status = ZwEnumerateKey( hIpRulesKey,
                                      i,
                                      KeyBasicInformation,
                                      &RetInfor,
                                      sizeof( RetInfor ),
                                      &retLength);
        if( !NT_SUCCESS( status ) ){
            KdPrint(("Enumerate value key failed!--%d\n",i));
            continue;
        }
        pKeyBasicInfor = (PKEY_BASIC_INFORMATION)RetInfor;
        uniKeyName.Length = uniKeyName.MaximumLength = (USHORT)pKeyBasicInfor->NameLength;
        uniKeyName.Buffer = pKeyBasicInfor->Name;
        UnicodeStringToUint32( &uniKeyName,&crcIpRuleName );
        
        InitializeObjectAttributes( &KeyObjAttr,
                                &uniKeyName,
                                OBJ_KERNEL_HANDLE,
                                hIpRulesKey,
                                NULL);
        status = ZwCreateKey( &hKey,
                                KEY_ALL_ACCESS,
                                &KeyObjAttr,
                                0,
                                NULL,
                                0,
                                NULL);
        if( !NT_SUCCESS( status ) ){
            KdPrint(("create hKey failed!--%d\n",i));
            continue;
        }

        ipRulesElem = &elem;
        RtlZeroMemory( ipRulesElem,sizeof(ip_rules_elem));
        
        RtlInitUnicodeString( &uniValueName,L"rule");
        status = ZwQueryValueKey( hKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
        if( !NT_SUCCESS( status ))
        {
            KdPrint(("query value key failed!--%d\n",i));
            my_ex_free_pool( ipRulesElem );
            continue;
        }

        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        rule = *(UINT32 *)pKeyValuePartialInfor->Data;
        
        ipRulesElem->crc_rule_name = crcIpRuleName;
        ipRulesElem->rule.u32 = rule;
        
        //根据rule的相关位设置加载相应字段

        if( ipRulesElem->rule.Bits.local_addr_type != AnyAddr )
        {
            //读入地址1
            RtlInitUnicodeString( &uniValueName,L"local_addr");
            status = ZwQueryValueKey( hKey,
                                      &uniValueName,
                                      KeyValuePartialInformation,
                                      &RetInfor,
                                      sizeof( RetInfor ),
                                      &retLength );
            if( !NT_SUCCESS( status ))
            {
                KdPrint(("query value key failed!(local_addr)\n"));
            }
            else
            {
                pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
                ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
                ipRulesElem->local_addr = *(UINT32 *)pKeyValuePartialInfor->Data;

            }

            if( ipRulesElem->rule.Bits.local_addr_type == RangeAddr )
            {
                //读入地址2
                RtlInitUnicodeString( &uniValueName,L"local_addr2");
                status = ZwQueryValueKey( hKey,
                                          &uniValueName,
                                          KeyValuePartialInformation,
                                          &RetInfor,
                                          sizeof( RetInfor ),
                                          &retLength );
                if( !NT_SUCCESS( status ))
                {
                    KdPrint(("query value key failed!(local_addr)\n"));
                }
                else
                {
                    pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
                    ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
                    ipRulesElem->local_addr2 = *(UINT32 *)pKeyValuePartialInfor->Data;
                }
            }
        }//end if local_addr

        if( ipRulesElem->rule.Bits.remote_addr_type != AnyAddr )
        {
            //读入地址1
            RtlInitUnicodeString( &uniValueName,L"remote_addr");
            status = ZwQueryValueKey( hKey,
                                      &uniValueName,
                                      KeyValuePartialInformation,
                                      &RetInfor,
                                      sizeof( RetInfor ),
                                      &retLength );
            if( !NT_SUCCESS( status ))
            {
                KdPrint(("query value key failed!(local_addr)\n"));
            }
            else
            {
                pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
                ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
                ipRulesElem->remote_addr = *(UINT32 *)pKeyValuePartialInfor->Data;
            }
            if( ipRulesElem->rule.Bits.remote_addr_type == RangeAddr )
            {
                //读入地址2
                RtlInitUnicodeString( &uniValueName,L"remote_addr2");
                status = ZwQueryValueKey( hKey,
                                          &uniValueName,
                                          KeyValuePartialInformation,
                                          &RetInfor,
                                          sizeof( RetInfor ),
                                          &retLength );
                if( !NT_SUCCESS( status ))
                {
                    KdPrint(("query value key failed!(local_addr)\n"));
                }
                else
                {
                    pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
                    ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
                    ipRulesElem->remote_addr2 = *(UINT32 *)pKeyValuePartialInfor->Data;
                }
            }
        } //end if remote_addr

        if( ipRulesElem->rule.Bits.local_port_type != AnyAddr )
        {
            //读入端口1
            RtlInitUnicodeString( &uniValueName,L"local_port");
            status = ZwQueryValueKey( hKey,
                                      &uniValueName,
                                      KeyValuePartialInformation,
                                      &RetInfor,
                                      sizeof( RetInfor ),
                                      &retLength );
            if( !NT_SUCCESS( status ))
            {
                KdPrint(("query value key failed!(local_addr)\n"));
            }
            else
            {
                pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
                ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
                ipRulesElem->local_port = *(UINT16 *)pKeyValuePartialInfor->Data;
            }

            if( ipRulesElem->rule.Bits.local_port_type == RangeAddr )
            {
                //读入端口2
                RtlInitUnicodeString( &uniValueName,L"local_port2");
                status = ZwQueryValueKey( hKey,
                                          &uniValueName,
                                          KeyValuePartialInformation,
                                          &RetInfor,
                                          sizeof( RetInfor ),
                                          &retLength );
                if( !NT_SUCCESS( status ))
                {
                    KdPrint(("query value key failed!(local_addr)\n"));
                }
                else
                {
                    pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
                    ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
                    ipRulesElem->local_port2 = *(UINT16 *)pKeyValuePartialInfor->Data;
                }
            }
        }//end if local_port

        if( ipRulesElem->rule.Bits.remote_port_type != AnyAddr )
        {
            //读入端口1
            RtlInitUnicodeString( &uniValueName,L"remote_port");
            status = ZwQueryValueKey( hKey,
                                      &uniValueName,
                                      KeyValuePartialInformation,
                                      &RetInfor,
                                      sizeof( RetInfor ),
                                      &retLength );
            if( !NT_SUCCESS( status ))
            {
                KdPrint(("query value key failed!(local_addr)\n"));
            }
            else
            {
                pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
                ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
                ipRulesElem->remote_port = *(UINT16 *)pKeyValuePartialInfor->Data;
            }

            if( ipRulesElem->rule.Bits.remote_port_type == RangeAddr )
            {
                //读入端口2
                RtlInitUnicodeString( &uniValueName,L"remote_port2");
                status = ZwQueryValueKey( hKey,
                                          &uniValueName,
                                          KeyValuePartialInformation,
                                          &RetInfor,
                                          sizeof( RetInfor ),
                                          &retLength );
                if( !NT_SUCCESS( status ))
                {
                    KdPrint(("query value key failed!(local_addr)\n"));
                }
                else
                {
                    pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
                    ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
                    ipRulesElem->remote_port2 = *(UINT16 *)pKeyValuePartialInfor->Data;
                }
            }
        }//end if remote_port


        ZwClose( hKey );
        hKey = NULL;

        KdPrint(("crcIpRulename = 0x%x\n\
            rule = 0x%x\n\
            local_addr=0x%x\n\
            local_addr2=0x%x\n\
            remote_addr=0x%x\n\
            remote_addr2=0x%x\n\
            local_port=0x%x\n\
            local_port2=0x%x\n\
            remote_port=0x%x\n\
            remote_port2=0x%x\n",
            ipRulesElem->crc_rule_name,
            ipRulesElem->rule.u32,
            ipRulesElem->local_addr,
            ipRulesElem->local_addr2,
            ipRulesElem->remote_addr,
            ipRulesElem->remote_addr2,
            ipRulesElem->local_port,
            ipRulesElem->local_port2,
            ipRulesElem->remote_port,
            ipRulesElem->remote_port2 ));
        add_ip_rule( ipRulesElem );
        ipRulesElem = NULL;

    }//end for enum ip rules sub key

    ZwClose( hIpRulesKey );
    ZwClose( hCactiKey );

    gb_enable_ip_monitor = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS wall_load_dns_config()
/*++
--*/
{
    
    NTSTATUS                status;
    HANDLE                  hCactiKey = 0,hDnsRulesKey = 0;
    OBJECT_ATTRIBUTES       KeyObjAttr;
    UNICODE_STRING          RegDirectory;
    ULONG                   i;
    UCHAR                   RetInfor[ sizeof( KEY_FULL_INFORMATION ) + 88 ];//NOTICE!
    PKEY_FULL_INFORMATION   pKeyFullInfor;
    PKEY_BASIC_INFORMATION  pKeyBasicInfor;
    PKEY_VALUE_PARTIAL_INFORMATION pKeyValuePartialInfor;
    PKEY_VALUE_FULL_INFORMATION    pKeyValueFullInfor;
    ULONG                   retLength = 0;
    ULONG                   subKeys = 0,KeyValues = 0;
    UNICODE_STRING          uniKeyName;
    UNICODE_STRING          uniValueName;
    UINT32                  crcDnsRuleName;
    UINT32                  rule;
    BOOLEAN                 bAllow = TRUE;

    LOG("into\n");

    InitDnsRules();

    RtlInitUnicodeString( &RegDirectory,CACTIWALL_REG_DIRECTORY );
    InitializeObjectAttributes( &KeyObjAttr,
                                &RegDirectory,
                                OBJ_KERNEL_HANDLE,
                                0,
                                NULL);
    status = ZwCreateKey( &hCactiKey,
                          KEY_ALL_ACCESS,
                          &KeyObjAttr,
                          0,
                          NULL,
                          0,
                          NULL);
    if( !NT_SUCCESS( status ) ){
        KdPrint(("Create key 1 failed!\n"));
        return status;
    }

    RtlInitUnicodeString( &RegDirectory,L"dnsrules" );
    InitializeObjectAttributes( &KeyObjAttr,
                                &RegDirectory,
                                OBJ_KERNEL_HANDLE,
                                hCactiKey,
                                NULL);
    status = ZwCreateKey( &hDnsRulesKey,
                          KEY_ALL_ACCESS,
                          &KeyObjAttr,
                          0,
                          NULL,
                          0,
                          NULL);
    if( !NT_SUCCESS( status ) ){
        KdPrint(("Create key 2 failed!\n"));
        return status;
    }

    RtlInitUnicodeString( &uniValueName,L"other_access");
    status = ZwQueryValueKey( hDnsRulesKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
    if( !NT_SUCCESS( status ))
    {
        KdPrint(("query value key(other_access) failed!\n"));
        gb_dns_config_other_allow = TRUE;
    }
    else
    {
        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        if( *(UINT32 *)pKeyValuePartialInfor->Data == 0 )
            gb_dns_config_other_allow = FALSE;
        else
            gb_dns_config_other_allow = TRUE;
        KdPrint(("dns_config:other_access = %x\n",gb_dns_config_other_allow ));
    }


    status = ZwQueryKey( hDnsRulesKey,
                         KeyFullInformation,
                         &RetInfor,
                         sizeof( RetInfor ),
                         &retLength );
    if( !NT_SUCCESS( status ) ){
        KdPrint(( "QueryKeyfullinfor failed!\n"));
        return status;
    }
    pKeyFullInfor = ( PKEY_FULL_INFORMATION )RetInfor;
    subKeys = pKeyFullInfor->SubKeys;
    
    for( i = 0;i < subKeys; i++)
    {
        HANDLE  hKey = NULL;

        RtlZeroMemory( &RetInfor,sizeof(RetInfor));
        status = ZwEnumerateKey( hDnsRulesKey,
                                      i,
                                      KeyBasicInformation,
                                      &RetInfor,
                                      sizeof( RetInfor ),
                                      &retLength);
        if( !NT_SUCCESS( status ) ){
            KdPrint(("Enumerate value key failed!--%d\n",i));
            continue;
        }
        pKeyBasicInfor = (PKEY_BASIC_INFORMATION)RetInfor;
        uniKeyName.Length = uniKeyName.MaximumLength = (USHORT)pKeyBasicInfor->NameLength;
        uniKeyName.Buffer = pKeyBasicInfor->Name;
        UnicodeStringToUint32( &uniKeyName,&crcDnsRuleName );
        
        InitializeObjectAttributes( &KeyObjAttr,
                                &uniKeyName,
                                OBJ_KERNEL_HANDLE,
                                hDnsRulesKey,
                                NULL);
        status = ZwCreateKey( &hKey,
                                KEY_ALL_ACCESS,
                                &KeyObjAttr,
                                0,
                                NULL,
                                0,
                                NULL);
        if( !NT_SUCCESS( status ) ){
            KdPrint(("create hKey failed!--%d\n",i));
            continue;
        }

        
        RtlInitUnicodeString( &uniValueName,L"rule");
        status = ZwQueryValueKey( hKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
        if( !NT_SUCCESS( status ))
        {
            KdPrint(("query value key failed!--%d\n",i));
            continue;
        }

        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_DWORD );
        rule = *(UINT32 *)pKeyValuePartialInfor->Data;
        if( rule & DNS_RULE_FLAG_ALLOW_ACCESS )
            bAllow = TRUE;
        else
            bAllow = FALSE;

        RtlZeroMemory( &RetInfor,sizeof(RetInfor));
        RtlInitUnicodeString( &uniValueName,L"name");
        status = ZwQueryValueKey( hKey,
                                  &uniValueName,
                                  KeyValuePartialInformation,
                                  &RetInfor,
                                  sizeof( RetInfor ),
                                  &retLength );
        if( !NT_SUCCESS( status ))
        {
            KdPrint(("query value key failed!--%d\n",i));
            continue;
        }

        pKeyValuePartialInfor = (PKEY_VALUE_PARTIAL_INFORMATION)RetInfor;
        ASSERT( pKeyValuePartialInfor->Type == REG_SZ );
        
        KdPrint(("Add dns:%ws\n",pKeyValuePartialInfor->Data));
        if( pKeyValuePartialInfor->DataLength + sizeof(WCHAR)
              + sizeof( KEY_VALUE_PARTIAL_INFORMATION) >sizeof( RetInfor))
        {
            KdPrint(("the dns name is too long!\n"));
            continue;
        }
        AddDnsRule( (PWCHAR)pKeyValuePartialInfor->Data,
                    pKeyValuePartialInfor->DataLength + sizeof(WCHAR),
                    bAllow,
                    crcDnsRuleName );

    }//end for

    gb_enable_dns_monitor = TRUE;

    return STATUS_SUCCESS;
}

VOID    wall_unload_process_config()
/*++
--*/
{
    LOG("into\n");

    gb_enable_process_monitor = FALSE;

    return;
}

VOID    wall_unload_ip_config()
/*++
--*/
{
    LOG("into\n");

    gb_enable_ip_monitor = FALSE;

    clear_ip_rules_list();

    return;
}

VOID    wall_unload_dns_config()
/*++
--*/
{
    LOG("into\n");

    gb_enable_dns_monitor = FALSE;

    ClearDnsRulesList();

    return;
}

VOID    wall_load_config()
/*++
功能描述：加载配置数据

参数说明：无

返回值说明：无返回值
--*/
{
    NTSTATUS    status;

    LOG("into\n");

    wall_load_global_config();

    if( gb_enable_process_monitor )
        wall_load_process_config();

    if( gb_enable_ip_monitor )
        wall_load_ip_config();

    if( gb_enable_dns_monitor )
        wall_load_dns_config();
    
}

VOID    wall_unload_config()
/*++
功能描述：卸载配置数据，释放资源

参数说明：无

返回值说明：无返回值
--*/
{
    NTSTATUS    status;

    LOG("into\n");


    if( gb_enable_process_monitor )
        wall_unload_process_config();

    if( gb_enable_ip_monitor )
        wall_unload_ip_config();

    if( gb_enable_dns_monitor)
        wall_unload_dns_config();
    
}


BOOLEAN
wall_is_process_traffic_permit( IN pwall_pended_packet packet )
/*++
功能描述：判断一个packet是否符合进程规则的放行条件

参数说明：
    packet:指向被判定的packet结构

返回值说明：符合返回TRUE，否则返回FALSE
--*/
{
    NTSTATUS                status = STATUS_SUCCESS;
    UINT32                  rule;
    
    LOG("into\n");

    //if( packet->direction == FWP_DIRECTION_OUTBOUND )
        KdPrint(( "remote addr:%x\nlocal addr:%x\n",packet->ipv4RemoteAddr,packet->ipv4LocalAddr));
    status = get_process_rule( packet->crcProcessPath,&rule );
    if( status == STATUS_SUCCESS )
    {
        if(rule & PROCESS_RULE_FLAG_ALLOW_ACCESS )
        {
            KdPrint(("return true\n"));
            return TRUE;
        }
        else 
        {
            KdPrint(("return false\n"));
            return FALSE;
        }
    }

    KdPrint(("return %x\n",gb_process_config_other_allow ));
    return gb_process_config_other_allow;
}

BOOLEAN
wall_is_ip_traffic_permit( IN pwall_pended_packet packet )
/*++
功能描述：判断一个packet是否符合IP规则的放行条件

参数说明：
    packet:指向被判定的packet结构

返回值说明：符合返回TRUE，否则返回FALSE
--*/
{
    extern ip_rules_list    gIpRulesList;
    PLIST_ENTRY             list = NULL;
    BOOLEAN                 bMatched = FALSE;

    LOG("into\n");

    KdPrint(("remote_addr:%x\nLocalAddr:%x\nRemotePort:%x\nLocalPort:%x\nProtocol:%x\ndirection:%x\n",
        packet->ipv4RemoteAddr,
        packet->ipv4LocalAddr,
        packet->remotePort,
        packet->localPort,
        packet->protocol,
        packet->direction));
    for( list = gIpRulesList.list.Flink;
        list != &gIpRulesList.list;
        list = list->Flink)
    {
        pip_rules_elem  rule = (pip_rules_elem)list;

        if(rule->rule.Bits.direction != RulesDirectionAny )
        {
            if( rule->rule.Bits.direction == RulesDirectionUp && 
                packet->direction != FWP_DIRECTION_OUTBOUND )continue;
            if( rule->rule.Bits.direction == RulesDirectionDown && 
                packet->direction != FWP_DIRECTION_INBOUND )continue;

        }

        if( rule->rule.Bits.local_addr_type == UniqueAddr && 
            rule->local_addr != *(PUINT32)packet->localAddr.byteArray16 )
            continue;

        if( rule->rule.Bits.local_addr_type == RangeAddr && 
            (rule->local_addr > *(PUINT32)packet->localAddr.byteArray16  || 
             rule->local_addr2 < *(PUINT32)packet->localAddr.byteArray16))
            continue;

        if( rule->rule.Bits.remote_addr_type == UniqueAddr && 
            rule->remote_addr != *(PUINT32)packet->remoteAddr.byteArray16 )
            continue;

        if( rule->rule.Bits.remote_addr_type == RangeAddr && 
            (rule->remote_addr > *(PUINT32)packet->remoteAddr.byteArray16  || 
             rule->remote_addr2 < *(PUINT32)packet->remoteAddr.byteArray16))
            continue;

        if( rule->rule.Bits.protocol_type != RulesProtocolAny)
        {
            if(rule->rule.Bits.protocol_type != packet->protocol )
                continue;

            if( packet->protocol == IPPROTO_TCP || packet->protocol==IPPROTO_UDP)
            {
                if( rule->rule.Bits.local_port_type == UniqueAddr && 
                    rule->local_port != packet->localPort )
                    continue;

                if( rule->rule.Bits.local_port_type == RangeAddr && 
                    (rule->local_port > packet->localPort  || 
                     rule->local_port2 < packet->localPort))
                    continue;

                if( rule->rule.Bits.remote_port_type == UniqueAddr && 
                    rule->remote_port != packet->remotePort )
                    continue;

                if( rule->rule.Bits.remote_port_type == RangeAddr && 
                    (rule->remote_port > packet->remotePort  || 
                     rule->remote_port2 < packet->remotePort))
                    continue;
            }//end if tcp || udp

            if( packet->protocol == IPPROTO_ICMP )
            {
                if( rule->rule.Bits.icmp_type != 0x1f )
                {
                    if(rule->rule.Bits.icmp_type != packet->icmpType )
                        continue;

                    if( rule->rule.Bits.icmp_code != 0x1f && 
                        rule->rule.Bits.icmp_code != packet->icmpCode )
                        continue;
                }
            }//end if icmp

        }//end if processType any

        bMatched = TRUE;

        if( rule->rule.Bits.access == 0 )
        {
            KdPrint(("return false\n"));
            return FALSE;
        }
    }

    if( bMatched )
    {
        KdPrint(("return true\n"));
        return TRUE;
    }
    else
    {
        KdPrint(("return %x\n",gb_ip_config_other_allow));
        return gb_ip_config_other_allow;
    }

}

BOOLEAN
wall_is_dns_traffic_permit( IN pwall_pended_packet packet )
/*++
功能描述：判断一个packet是否符合DNS则的放行条件

参数说明：
    packet:指向被判定的packet结构

返回值说明：符合返回TRUE，否则返回FALSE
--*/
{
    extern DNS_RULES_LIST   gDnsRulesList;
    PNET_BUFFER_LIST        netBufferList = NULL;
    PNET_BUFFER             netBuffer = NULL;
    PMDL                    mdl = NULL;
    PBYTE                   va = NULL,dnsName = NULL;
    ULONG                   dataLength = 0,count = 0,offset=0;
    PBYTE                   udpDataBuffer = NULL;
    UNICODE_STRING          uniDnsName = {0};
    ANSI_STRING             ansiDnsName = {0};
    ULONG                   bytesCopied = 0;
    ULONG                   len = 0;
    PLIST_ENTRY             list = NULL;
    BOOLEAN                 bMatched = FALSE;
    int                     i = 0,j = 0;

    LOG("into\n");
    ASSERT( packet != NULL );

    if( packet->protocol != IPPROTO_UDP || 
        packet->remotePort != RtlUshortByteSwap(53) )return TRUE;//53为DNS解析所用端口号

    ASSERT( packet->type == WALL_DATA_PACKET && packet->netBufferList != NULL);

    //从NET_BUFFER_LIST结构中提取UDP包数据

    netBufferList = packet->netBufferList;
    netBuffer = NET_BUFFER_LIST_FIRST_NB( netBufferList );
    mdl = NET_BUFFER_FIRST_MDL( netBuffer );
    dataLength = NET_BUFFER_DATA_LENGTH( netBuffer );
    offset = NET_BUFFER_DATA_OFFSET( netBuffer );
    KdPrint(("data length of net_buffer list is %d\n",dataLength ));
    udpDataBuffer = (PBYTE)my_ex_allocate_pool( dataLength );
    if( udpDataBuffer == NULL)
    {
        KdPrint(("memory allocated failed! return true!\n"));
        return gb_dns_config_other_allow;
    }

    for(bytesCopied = 0;
        mdl != NULL;
        mdl = mdl->Next )
    {
        va = (PBYTE)MmGetMdlVirtualAddress( mdl );
        count = MmGetMdlByteCount( mdl );

        if( offset >= count ){
            offset -= count;
            continue;
        }

        len = count - offset > dataLength ? dataLength:count-offset ;
        if( len == 0 )break;

        RtlCopyMemory( udpDataBuffer + bytesCopied,
                        va + offset,
                        len );
        bytesCopied += len;
        dataLength -= len;
        offset = 0;
    }//end for 
    ASSERT( dataLength == 0 );
    KdPrint(("udpDataBuffer = 0x%x,bytesCopied = %d\n",udpDataBuffer,bytesCopied ));

    //从UDP数据报中提取所查询的域名
    //udp header:8 bytes,the first 6 records of dns packet:12 bytes
    //offset of dns name:20 bytes

    for( i = 20;udpDataBuffer[i] != 0; )
    {
        for( j = i + 1;j < i + udpDataBuffer[i]+1;j++)
        {
            //转换为小写
            if( udpDataBuffer[j] >='A' && udpDataBuffer[j] <= 'Z')
                udpDataBuffer[j] = udpDataBuffer[j]-'A' + 'a';
        }
        udpDataBuffer[i] = '.';
        i = j;
    }
    dnsName = udpDataBuffer + 21;

    //转换为UNICODE_STRING
    ansiDnsName.Buffer = dnsName;
    ansiDnsName.Length = ansiDnsName.MaximumLength = strlen( dnsName) +1;
    
    uniDnsName.MaximumLength = (USHORT)RtlAnsiStringToUnicodeSize( &ansiDnsName );
    uniDnsName.Buffer = (PWCHAR)my_ex_allocate_pool( uniDnsName.MaximumLength);
    if( uniDnsName.Buffer == NULL )
    {
        KdPrint(("Memory allocated failed!(unicode buffer)\n"));
        return gb_dns_config_other_allow;
    }
    RtlZeroMemory( uniDnsName.Buffer,uniDnsName.MaximumLength );
    KdPrint(("ansi_string = %s\n",ansiDnsName.Buffer ));
    RtlAnsiStringToUnicodeString( &uniDnsName,&ansiDnsName,FALSE );

    my_ex_free_pool( udpDataBuffer );
    udpDataBuffer = NULL;
    ansiDnsName.MaximumLength = ansiDnsName.Length = 0;
    ansiDnsName.Buffer = NULL;

    KdPrint(("addr:%x\nwsz = %ws\n",&uniDnsName,uniDnsName.Buffer ));
    
    //匹配规则
    bMatched = FALSE;
    for( list = gDnsRulesList.list.Flink;
        list != &gDnsRulesList.list;
        list = list->Flink)
    {
        PDNS_RULES_ELEM  rule = (PDNS_RULES_ELEM)list;
        
        if( NULL != wcsstr(uniDnsName.Buffer,rule->dnsName->str.Buffer))
        {
            bMatched = TRUE;
            if( rule->rule & DNS_RULE_FLAG_ALLOW_ACCESS )
                continue;
            else
                break;
        }
    }

    my_ex_free_pool( uniDnsName.Buffer );
    uniDnsName.Buffer = NULL;
    uniDnsName.Length = uniDnsName.MaximumLength = 0;

    if( bMatched )
    {
        if( list == &gDnsRulesList.list )
        {
            KdPrint(("return true\n"));
            return TRUE;
        }
        else 
        {
            KdPrint(("return false\n"));
            return FALSE;
        }
    }
    else
    {
        KdPrint(("return other_allow:%x\n",gb_dns_config_other_allow));
        return gb_dns_config_other_allow;
    }

}

NTSTATUS
wall_block_all( BOOLEAN b_block_all )
/*++
功能描述：设置阻塞所有连接

参数说明：

    b_block_all:为TRUE则设置阻塞所有连接，否则此功能无效。

返回值：成功返回STATUS_SUCCESS,否则返回STATUS_UNSUCCESSFUL
    
--*/
{
    LOG("into\n");

    gb_block_all = b_block_all;
    KdPrint(("gb_block_all = %d\n",gb_block_all ));

    return STATUS_SUCCESS;
}

///////////////////////////函数定义结束//////////////////////////////////////

                                                                                                                                                                                                                                                                                                                                                               /*
BUG LIST
1:  wall_allocate_and_init_pended_packet  line:943

*/