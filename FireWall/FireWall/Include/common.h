#pragma once

#include<ndis.h>
#include<ntddk.h>
#include<fwpmk.h>
#include<limits.h>
#include "memtrace.h"

#pragma warning(disable:28197)

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include "fwpsk.h"

#pragma warning(pop)

#define INITGUID
#include <guiddef.h>

#if 1
#define LOG(x) \
    KdPrint(("%s(%d).%s:%s",__FILE__,__LINE__,__FUNCTION__,(x)))
#else
#define LOG(X) 
#endif

#define DEVICE_NAME			L"\\Device\\Wall_Device"
#define DEVICE_DOSNAME		L"\\DosDevices\\Wall_Device"

#define MAX_PATH_LEN		256

#define CACTIWALL_REG_DIRECTORY		L"\\REGISTRY\\Machine\\Software\\lzcj\\CactiWall"

#define DELAY_ONE_MICROSECOND		( -10 )
#define DELAY_ONE_MILLISECOND		( DELAY_ONE_MICROSECOND * 1000 )
#define DELAY_ONE_SECOND		( DELAY_ONE_MILLISECOND * 1000 )

typedef VOID		( *my_process )( PVOID context );

typedef struct _my_unicode_string	{
    UNICODE_STRING		str;
    WCHAR				buffer[1];
}my_unicode_string, *pmy_unicode_string;

typedef  struct  _worker_thread		{
    LIST_ENTRY		list;
    HANDLE			thread_id;
    KEVENT			thread_event;
    KSPIN_LOCK		spinLock;
}worker_thread, *pworker_thread;

typedef struct _worker_process_node		{
    LIST_ENTRY		list;
    KEVENT			process_event;
    my_process		routine_address;
    PVOID			context;
}worker_process_node, *pworker_process_node;

typedef struct _volume_link_item	{
    WCHAR		volume_letter;
    UINT32		crc_mapped_dev_name;  //crc hash value of the device name mapped by VolumeLetter
}volume_link_item, *pvolume_link_item;

NTSTATUS get_local_time ( OUT PTIME_FIELDS  local_time );

VOID create_volume_link_table ();

NTSTATUS device_path_to_dos_path ( IN PUNICODE_STRING device_path, OUT PUNICODE_STRING dos_path );

UINT32 hash_unicode_string ( IN PUNICODE_STRING s );

NTSTATUS unicode_string_to_uint32 ( IN PUNICODE_STRING str, OUT UINT32 *result );

NTSTATUS create_worker_thread ();

VOID destroy_worker_thread ();

NTSTATUS run_my_process ( IN my_process to_my_process, PVOID context);

__inline void get_flags_indexes_for_layer ( IN UINT16 layer_id, OUT UINT* flags_index );

BOOLEAN is_ale_reauthorize( IN const FWPS_INCOMING_VALUES0* in_fixed_values );
