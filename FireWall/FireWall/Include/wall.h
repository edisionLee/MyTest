#pragma once

typedef enum _wall_pended_packet_type
{
    WALL_CONNECT_PACKET,
    WALL_DATA_PACKET,
    WALL_REAUTH_PACKET
} wall_packet_type;

typedef struct _wall_pended_packet
{
    LIST_ENTRY				list;

    ADDRESS_FAMILY			address_family;
	wall_packet_type		type;
    FWP_DIRECTION			direction;

    UINT32					auth_connect_decision;
    HANDLE					completion_context;
    UINT32					crc_process_path;
    //
    // Common fields for inbound and outbound traffic.
    //
    UINT8					protocol;
    NET_BUFFER_LIST*		net_buffer_list;
    COMPARTMENT_ID			compartment_id;
    union	{
       FWP_BYTE_ARRAY16		local_addr;
       UINT32				ipv4_local_addr;
    };
    union	{
       UINT16				local_port;
       UINT16				icmp_type;
    };
	union	{
       UINT16				remote_port;
       UINT16				icmp_code;
    };

    //
    // Data fields for outbound packet re-injection.
    //
    UINT64					endpoint_handle;
	union	{
       FWP_BYTE_ARRAY16		remote_addr;
       UINT32				ipv4_remote_addr;
    };

    SCOPE_ID				remote_scope_id;
    WSACMSGHDR*				control_data;
    ULONG					control_data_length;

    //
    // Data fields for inbound packet re-injection.
    //
    BOOLEAN					ip_sec_protected;
    ULONG					nbl_offset;
    UINT32					ip_header_size;
    UINT32					transport_header_size;
    IF_INDEX				interface_index;
    IF_INDEX				sub_interface_iIndex;

}wall_pended_packet, *pwall_pended_packet;

typedef struct _wall_connect_list
{
    LIST_ENTRY		list;
    KSPIN_LOCK		lock;
}wall_connect_list, wall_packet_list, *pwall_connect_list, *pwall_packet_list;

NTSTATUS RegisterCalloutForLayer ( IN const GUID* layer_key,
   IN const GUID* callout_key,
   IN FWPS_CALLOUT_CLASSIFY_FN classify_fn,
   IN FWPS_CALLOUT_NOTIFY_FN notify_fn,
   IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flow_delete_notify_fn,
   OUT UINT32* callout_id,
   OUT UINT64* filter_id
   );

NTSTATUS wall_register_callouts () ;

NTSTATUS wall_un_register_callouts () ;

VOID wall_write_connect_log_data ( IN PVOID data ) ;

NTSTATUS wall_create_connect_list ();

NTSTATUS wall_create_packet_list ();

VOID wall_destroy_connect_list ();

VOID wall_destroy_packet_list();

NTSTATUS wall_create_injection_handle();

NTSTATUS wall_destroy_injection_handle ();

wall_pended_packet* wall_allocate_and_init_pended_packet ( IN const FWPS_INCOMING_VALUES0* in_fixed_values,
   IN const FWPS_INCOMING_METADATA_VALUES0* in_meta_values,
   IN ADDRESS_FAMILY address_family,
   IN OUT void* layer_data,
   IN wall_packet_type packet_type,
   IN FWP_DIRECTION packet_direction
   );

VOID wall_free_pended_packet( IN pwall_pended_packet packet );

VOID wall_inspect_wall_packets ( IN PVOID Context );

BOOLEAN is_matching_connect_packet( IN const FWPS_INCOMING_VALUES0* in_fixed_values,
   IN ADDRESS_FAMILY address_family,
   IN FWP_DIRECTION direction,
   IN wall_pended_packet* pended_packet
   );

ADDRESS_FAMILY get_address_family_for_layer ( IN UINT16 layer_id );

VOID wall_load_global_config ();

NTSTATUS wall_load_process_config ();

NTSTATUS wall_load_ip_config ();

NTSTATUS wall_load_dns_config();

VOID wall_unload_process_config ();

VOID wall_unload_ip_config ();

VOID wall_unload_dns_config ();

VOID wall_load_config();
VOID wall_unload_config();

BOOLEAN wall_is_process_traffic_permit( IN pwall_pended_packet packet );

BOOLEAN wall_is_ip_traffic_permit( IN pwall_pended_packet packet );

BOOLEAN wall_is_dns_traffic_permit( IN pwall_pended_packet packet );

NTSTATUS wall_block_all( BOOLEAN b_block_all );
