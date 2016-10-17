#pragma once

#include<ntddk.h>

#define MEM_TAG			'WALL'


#define MEM_MAGIC		'WALL'

#if DBG
typedef struct _mem_node {
    ULONG					magic;
	struct _mem_node		*next;
	struct _mem_node		*prev;
    ULONG					size;
    const char				*file;
    ULONG					line;
    PVOID					data[];
}mem_node, *pmem_node;

PVOID   dbg_ex_allocate_pool( IN ULONG size, IN const char *file, IN ULONG line );
VOID    dbg_ex_free_pool( IN PVOID ptr );
VOID    dbg_mem_trace_init();
BOOLEAN dbg_is_mem_leak();

#define my_ex_allocate_pool(_x_) dbg_ex_allocate_pool( (_x_), __FILE__, __LINE__ )
#define my_ex_free_pool(_x_) dbg_ex_free_pool( (_x_) )
#else
#define my_ex_allocate_pool(_x_) ExAllocatePoolWithTag(NonPagedPool,(_x_),MEM_TAG)
#define my_ex_free_pool(_x_) ExFreePool((_x_))
#endif





                                                                                                                                                                                                                                