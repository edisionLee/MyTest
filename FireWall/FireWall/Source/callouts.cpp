
#include "callouts.h"
#include "wall.h"
#include "memtrace.h"


extern HANDLE					g_inject_handle;
extern pwall_connect_list		g_connect_list;
extern pwall_packet_list		g_packet_list;

extern VOID wall_inspect_wall_packets ( PVOID context );

extern NTSTATUS wall_run_my_process ( my_process ToyMyProcess, PVOID context );

void NTAPI wall_ale_connect_classify ( IN const FWPS_INCOMING_VALUES* in_fixed_values,
   IN const FWPS_INCOMING_METADATA_VALUES* in_meta_values,
   IN OUT void* layer_data,
   IN const void* classify_context,
   IN const FWPS_FILTER* filter,
   IN UINT64 flow_context,
   OUT FWPS_CLASSIFY_OUT* classify_out
   )
/*++

注意：此回调的Irql <= DISPATCH_LEVEL!!!!!
--*/
{
    NTSTATUS						status = STATUS_SUCCESS;
    pwall_pended_packet				pended_connect = NULL;
    BOOLEAN							b_wake_up = FALSE;
	ADDRESS_FAMILY				    address_family = AF_UNSPEC;
	UNICODE_STRING					dev_name = { 0 }, dos_name = {0};
	WCHAR							buffer[MAX_PATH_LEN] = L"";
    pmy_unicode_string				log_data = NULL;
	FWPS_PACKET_INJECTION_STATE		state = FWPS_PACKET_NOT_INJECTED;
	FWP_DIRECTION					packet_direction = FWP_DIRECTION_INBOUND;
	KIRQL							irql, irql2;
	LIST_ENTRY*						listEntry = NULL;
	BOOLEAN							authComplete = FALSE;

    LOG("into\n");

    if( !( classify_out->rights & FWPS_RIGHT_ACTION_WRITE ) )	{
        KdPrint( ("write right not set!\n") );
        return;
    }

     if( NULL != layer_data )	{
         state = FwpsQueryPacketInjectionState( g_inject_handle, layer_data, NULL );
		 if (FWPS_PACKET_INJECTED_BY_SELF == state || FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF == state )	{
             classify_out->actionType = FWP_ACTION_PERMIT;
             goto exit;
         }
     }

    address_family = get_address_family_for_layer( in_fixed_values->layerId );

	if( !is_ale_reauthorize( in_fixed_values ) )	{
        pended_connect = wall_allocate_and_init_pended_packet( in_fixed_values,
                                                    in_meta_values,
                                                    address_family,
                                                    layer_data,
                                                    WALL_CONNECT_PACKET,
                                                    FWP_DIRECTION_OUTBOUND );
        if( NULL == pended_connect )	{
            classify_out->actionType = FWP_ACTION_BLOCK;
            classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            goto exit;
        }

        ASSERT( FWPS_IS_METADATA_FIELD_PRESENT ( in_meta_values, FWPS_METADATA_FIELD_COMPLETION_HANDLE ) );

        status = FwpsPendOperation0 ( in_meta_values->completionHandle, &pended_connect->completion_context );

        if ( !NT_SUCCESS( status ) )	{
            classify_out->actionType = FWP_ACTION_BLOCK;
            classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            goto exit;
        }

        b_wake_up = IsListEmpty ( &g_packet_list->list ) && IsListEmpty ( &g_connect_list->list );

        ExInterlockedInsertTailList ( &g_connect_list->list ,&pended_connect->list, &g_connect_list->lock );
        pended_connect = NULL;

        if( b_wake_up )	{
            run_my_process( wall_inspect_wall_packets, NULL );
        }

        classify_out->actionType = FWP_ACTION_BLOCK;
        classify_out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    }
    else	{//reauth

        LOG("1\n");

        ASSERT(FWPS_IS_METADATA_FIELD_PRESENT( in_meta_values, FWPS_METADATA_FIELD_PACKET_DIRECTION ) );
        packet_direction = in_meta_values->packetDirection;

		if ( FWP_DIRECTION_OUTBOUND == packet_direction )	{
           
            
            LOG("2\n");
            KeAcquireSpinLock( &g_connect_list->lock, &irql );
            LOG("22\n");
            for (listEntry = g_connect_list->list.Flink; listEntry != ( PLIST_ENTRY )g_connect_list; )	{   
                pended_connect = (pwall_pended_packet)listEntry;
                listEntry = listEntry->Flink;

                if (is_matching_connect_packet( in_fixed_values,
                     address_family,
                     packet_direction,
                     pended_connect
                  ) && ( 0 != pended_connect->auth_connect_decision ) )	{

					ASSERT(( FWP_ACTION_PERMIT == pended_connect->auth_connect_decision ) ||
						( FWP_ACTION_BLOCK == pended_connect->auth_connect_decision ) );
					LOG("3\n");
                    classify_out->actionType = pended_connect->auth_connect_decision;
                    if( classify_out->actionType == FWP_ACTION_BLOCK )	{
                        classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
                        classify_out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
                    }

                    RemoveEntryList( &pended_connect->list );
               
                    if (/*!gDriverUnloading &&*/
						(NULL != pended_connect->net_buffer_list) && ( FWP_ACTION_PERMIT == pended_connect->auth_connect_decision ))	{
                  
                        pended_connect->type = WALL_DATA_PACKET;
                        LOG("4\n");
                        KeAcquireSpinLock ( &g_packet_list->lock, &irql2 );

                        b_wake_up = IsListEmpty ( &g_packet_list->list ) && IsListEmpty ( &g_connect_list->list );

                        InsertTailList( &g_packet_list->list, &pended_connect->list );
                        pended_connect = NULL; // ownership transferred

                        KeReleaseSpinLock( &g_packet_list->lock, irql2 );

                        if ( b_wake_up )	{
                            run_my_process( wall_inspect_wall_packets, NULL );
                        }
                    }//end if permit

                    authComplete = TRUE;
                    break;
                }//end if match
            }//end if for

            KeReleaseSpinLock( &g_connect_list->lock, irql );
            if ( authComplete )	{
                 LOG("5\n");
                goto exit;
            }
            else  {
                pended_connect = NULL;
            }
        }//end if outbound

        classify_out->actionType = FWP_ACTION_BLOCK;
        classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        classify_out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    }
exit:
    if( NULL != pended_connect )	{
        LOG("free packet\n");
        wall_free_pended_packet( pended_connect );
        pended_connect = NULL;
    }

	if ( FWP_ACTION_PERMIT == classify_out->actionType )	{
        RtlInitUnicodeString ( &dev_name, ( PWCHAR )in_meta_values->processPath->data );
        RtlInitEmptyUnicodeString ( &dos_name, buffer, MAX_PATH_LEN * sizeof( WCHAR ) );
		log_data = ( pmy_unicode_string )my_ex_allocate_pool(sizeof(my_unicode_string) + in_meta_values->processPath->size );
        if( NULL != log_data )	{
            log_data->str.Buffer = log_data->buffer;
            log_data->str.MaximumLength = ( USHORT )in_meta_values->processPath->size;
            status = device_path_to_dos_path ( &dev_name, &dos_name );
            if( NT_SUCCESS( status ) )
            {
                RtlCopyUnicodeString( ( PUNICODE_STRING )log_data, &dos_name );
            }
            else	{
                RtlCopyUnicodeString( ( PUNICODE_STRING )log_data, &dev_name );
            }
            KdPrint( ("log_data:%wZ\n", log_data ) );

            run_my_process ( wall_write_connect_log_data, log_data );
            log_data = NULL;
        }
        
    }
    return;
}

NTSTATUS NTAPI wall_ale_connect_notify ( IN FWPS_CALLOUT_NOTIFY_TYPE  notify_type,
    IN const GUID  *filter_key,
    IN const FWPS_FILTER  *filter
    )
{
    LOG("into\n");

    return STATUS_SUCCESS;
}

VOID NTAPI wall_ale_connect_flow_delete( IN UINT16  layer_id,
    IN UINT32  callout_id,
    IN UINT64  flow_context
    )
{
    LOG("into\n");

    return;
}

void NTAPI wall_ale_recv_accept_classify( IN const FWPS_INCOMING_VALUES* in_fixed_values,
   IN const FWPS_INCOMING_METADATA_VALUES* in_meta_values,
   IN OUT void* layer_data,
   IN const void* classify_context,
   IN const FWPS_FILTER* filter,
   IN UINT64 flow_context,
   OUT FWPS_CLASSIFY_OUT* classify_out
   )
/*++
--*/
{
    NTSTATUS							status = STATUS_SUCCESS;
	UNICODE_STRING						dev_name = { 0 }, dos_name = {0};
    WCHAR								buffer[MAX_PATH_LEN] = L"";
    pmy_unicode_string					log_data = NULL;
    pwall_pended_packet					pended_recv = NULL;
    BOOLEAN								b_wake_up = FALSE;
    ADDRESS_FAMILY						address_family = AF_UNSPEC;
	FWPS_PACKET_INJECTION_STATE			state = FWPS_PACKET_NOT_INJECTED;
	FWP_DIRECTION						packet_direction = FWP_DIRECTION_OUTBOUND;
	KIRQL								irql, irql2;


    LOG("into\n");


    if( !( classify_out->rights & FWPS_RIGHT_ACTION_WRITE ) )	{
        KdPrint( ("write right not set!\n") );
        return;
    }

    if( NULL != layer_data )	{
        
        state = FwpsQueryPacketInjectionState( g_inject_handle, layer_data, NULL);
        KdPrint( ("inject state:%x\n", state ) );
        if( FWPS_PACKET_INJECTED_BY_SELF == state || FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF == state )	{
            classify_out->actionType = FWP_ACTION_PERMIT;
            KdPrint(("inject by self\n"));
            goto exit;
        }
    }
	address_family = get_address_family_for_layer( in_fixed_values->layerId );

    if( !is_ale_reauthorize( in_fixed_values ) )	{
        pended_recv = wall_allocate_and_init_pended_packet( in_fixed_values,
                                                    in_meta_values,
                                                    address_family,
                                                    layer_data,
                                                    WALL_DATA_PACKET,
                                                    FWP_DIRECTION_INBOUND );
        if( NULL == pended_recv )	{
            classify_out->actionType = FWP_ACTION_BLOCK;
            classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            goto exit;
        }

        ASSERT( FWPS_IS_METADATA_FIELD_PRESENT( in_meta_values, FWPS_METADATA_FIELD_COMPLETION_HANDLE ) );

        status = FwpsPendOperation0( in_meta_values->completionHandle, &pended_recv->completion_context );

        if ( !NT_SUCCESS(status) )	{
            classify_out->actionType = FWP_ACTION_BLOCK;
            classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            classify_out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            goto exit;
        }

        b_wake_up = IsListEmpty( &g_packet_list->list ) && IsListEmpty( &g_connect_list->list );

        ExInterlockedInsertTailList( &g_packet_list->list, &pended_recv->list, &g_packet_list->lock );
        pended_recv = NULL;

        if( b_wake_up )	{
            run_my_process( wall_inspect_wall_packets, NULL );
        }

        classify_out->actionType = FWP_ACTION_BLOCK;
        classify_out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
    else	{//reauth
        KdPrint(("recv reauth!\n"));
        classify_out->actionType = FWP_ACTION_BLOCK;
        classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        classify_out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    }


exit:
    if( FWP_ACTION_PERMIT == classify_out->actionType )	{
        RtlInitUnicodeString( &dev_name, (PWCHAR)in_meta_values->processPath->data );
        RtlInitEmptyUnicodeString( &dos_name, buffer, MAX_PATH_LEN * sizeof(WCHAR));
        log_data = ( pmy_unicode_string ) my_ex_allocate_pool( sizeof( my_unicode_string) + in_meta_values->processPath->size);
        if( NULL != log_data)	{
            log_data->str.Buffer = log_data->buffer;
            log_data->str.MaximumLength = ( USHORT ) in_meta_values->processPath->size;
            status = device_path_to_dos_path( &dev_name, &dos_name );
            if( NT_SUCCESS( status ))	{
                RtlCopyUnicodeString( (PUNICODE_STRING)log_data, &dos_name );
			}
			else	{
                RtlCopyUnicodeString( (PUNICODE_STRING)log_data, &dev_name );
            }
            run_my_process( wall_write_connect_log_data, log_data );
            log_data = NULL;
        }
        
    }
    return;
}


NTSTATUS NTAPI wall_ale_recv_accept_notify ( IN FWPS_CALLOUT_NOTIFY_TYPE  notify_type,
    IN const GUID  *filter_key,
    IN const FWPS_FILTER  *filter
    )
/*++
--*/
{
    LOG("into\n");

    return STATUS_SUCCESS;
}


VOID NTAPI wall_ale_recv_accept_flow_delete(IN UINT16  layer_id,
    IN UINT32  callout_id,
    IN UINT64  flow_context
    )
/*++
--*/
{
    LOG("into\n");

    return;
}
