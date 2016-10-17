#pragma once

#include "common.h"

// {6812FC83-7D3E-499a-A012-55E0D85F348B}
DEFINE_GUID ( WALL_ALE_AUTH_CONNECT_CALLOUT_V4, 
			0x6812fc83, 
			0x7d3e,
			0x499a,
			0xa0, 0x12, 0x55, 0xe0, 0xd8, 0x5f, 0x34, 0x8b
			);

// {B438CEAE-FF2A-484f-9CB8-F425A288594C}
DEFINE_GUID ( WALL_ALE_AUTH_RECV_ACCEPT_CALLOUT_V4, 
			0xb438ceae, 
			0xff2a, 
			0x484f, 
			0x9c, 0xb8, 0xf4, 0x25, 0xa2, 0x88, 0x59, 0x4c
			);

void NTAPI wall_ale_connect_classify ( IN const FWPS_INCOMING_VALUES* in_fixed_values,
	IN const FWPS_INCOMING_METADATA_VALUES* in_meta_values,
	IN OUT void* layer_data,
	IN const void* classify_context,
	IN const FWPS_FILTER* filter,
	IN UINT64 flow_context,
	OUT FWPS_CLASSIFY_OUT* classify_out
	);


NTSTATUS NTAPI wall_ale_connect_notify ( IN FWPS_CALLOUT_NOTIFY_TYPE  notify_type,
	IN const GUID  *filter_key,
	IN const FWPS_FILTER  *filter
    );



VOID NTAPI wall_ale_connect_flow_delete ( IN UINT16  layer_id,
    IN UINT32  callout_id,
    IN UINT64  flow_context
    );

void NTAPI wall_ale_recv_accept_classify ( IN const FWPS_INCOMING_VALUES* in_fixed_values,
   IN const FWPS_INCOMING_METADATA_VALUES* in_meta_values,
   IN OUT void* layer_data,
   IN const void* classify_context,
   IN const FWPS_FILTER* filter,
   IN UINT64 flow_context,
   OUT FWPS_CLASSIFY_OUT* classify_out
   );


NTSTATUS NTAPI wall_ale_recv_accept_notify ( IN FWPS_CALLOUT_NOTIFY_TYPE  notify_type,
    IN const GUID  *filter_key,
    IN const FWPS_FILTER  *filter
    );

VOID  NTAPI wall_ale_recv_accept_flow_delete ( IN UINT16  layer_id,
    IN UINT32  callout_id,
    IN UINT64  flow_context
    );










                                                                                                                                                                                                                                                                                                                                                    