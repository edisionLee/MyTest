#include"common.h"
#include "rules.h"

process_rules_table gProcessRulesTable={0};
ip_rules_list       gIpRulesList = {0};
DNS_RULES_LIST      gDnsRulesList = {0};

NTSTATUS
init_process_rules()
/*++
--*/
{
    LOG("into\n");

    RtlZeroMemory( &gProcessRulesTable,sizeof(process_rules_table ));

    return STATUS_SUCCESS;
}

NTSTATUS
add_process_rule( IN UINT32 crc_path,IN UINT32 rule )
/*++
--*/
{
    UINT8   xorsum = 0;
    UINT32  key,i;

    LOG("into\n");

    if( gProcessRulesTable.count >= MAX_PROCESS_RULES_NUM )
        return STATUS_PROCESS_RULES_FULL;

    if ( is_process_rule_exist( crc_path ))
        return STATUS_PROCESS_RULES_EXISTED;

    if( crc_path == 0 )crc_path = ZERO_CRC_VALUE;
    key = crc_path;

    for( i = 0;i < 32;i++)
    {
        xorsum ^= key & 0xff;
        key >>= 1;
    }

    for( i = xorsum;;i = (i + 1 ) % MAX_PROCESS_RULES_NUM )
    {
        if( gProcessRulesTable.rules[i].crc_path == 0 )
            break;
    }
    gProcessRulesTable.rules[i].crc_path = crc_path;
    gProcessRulesTable.rules[i].rule = rule;
    gProcessRulesTable.count++;

    return STATUS_SUCCESS;
}

NTSTATUS
delete_process_rule( IN UINT32 crc_path )
/*++
--*/
{
    UINT8   xorsum = 0;
    UINT32  key,i;

    LOG("into\n");

    if( gProcessRulesTable.count == 0 )
        return STATUS_PROCESS_RULES_EMPTY;

    if( !is_process_rule_exist( crc_path ) )
        return STATUS_PROCESS_RULES_NOT_EXISTED;

    if( crc_path == 0 )crc_path = ZERO_CRC_VALUE;
    key = crc_path;

    for( i = 0;i < 32;i++)
    {
        xorsum ^= key & 0xff;
        key >>= 1;
    }

    for( i = xorsum;;i = (i + 1 ) % MAX_PROCESS_RULES_NUM )
    {
        if( gProcessRulesTable.rules[i].crc_path == crc_path )
            break;
    }
    gProcessRulesTable.rules[i].crc_path = 0;
    gProcessRulesTable.rules[i].rule = 0;
    gProcessRulesTable.count--;

    return STATUS_SUCCESS;
}

NTSTATUS
get_process_rule( IN UINT32 crc_path, IN OUT UINT32 *rule )
/*++
--*/
{
    UINT8   xorsum = 0;
    UINT32  key,i;

    LOG("into\n");

    if( gProcessRulesTable.count == 0 )
        return STATUS_PROCESS_RULES_EMPTY;

    if( !is_process_rule_exist( crc_path ) )
        return STATUS_PROCESS_RULES_NOT_EXISTED;

    if( crc_path == 0 )crc_path = ZERO_CRC_VALUE;
    key = crc_path;

    for( i = 0;i < 32;i++)
    {
        xorsum ^= key & 0xff;
        key >>= 1;
    }

    for( i = xorsum;;i = (i + 1 ) % MAX_PROCESS_RULES_NUM )
    {
        if( gProcessRulesTable.rules[i].crc_path == crc_path )
            break;
    }
    
    *rule = gProcessRulesTable.rules[i].rule;

    return STATUS_SUCCESS;
}

BOOLEAN
is_process_rule_exist( IN UINT32 crc_path )
/*++
--*/
{
    UINT8   xorsum = 0;
    UINT32  key,i;

    LOG("into\n");

    if( crc_path == 0 )crc_path = ZERO_CRC_VALUE;
    key = crc_path;

    for( i = 0;i < 32;i++)
    {
        xorsum ^= key & 0xff;
        key >>= 1;
    }

    for( i = xorsum;;)
    {
        if( gProcessRulesTable.rules[i].crc_path == crc_path)
            return TRUE;
        if( gProcessRulesTable.rules[i].crc_path == 0 )
            return FALSE;

        i = (i + 1 ) % MAX_PROCESS_RULES_NUM;
        if( i == xorsum )break;
    }

    return FALSE;
}

NTSTATUS
init_ip_rules()
/*++
--*/
{
    LOG("into\n");

    RtlZeroMemory( &gIpRulesList,sizeof( gIpRulesList) );

    InitializeListHead( &gIpRulesList.list );
    KeInitializeSpinLock( &gIpRulesList.lock );
    gIpRulesList.count = 0;

    return STATUS_SUCCESS;
}

NTSTATUS
add_ip_rule( IN pip_rules_elem elem )
/*++
--*/
{
    pip_rules_elem rule = NULL;

    LOG("into\n");

    rule = my_ex_allocate_pool( sizeof( ip_rules_elem ));
    ASSERT( rule != NULL );
    RtlZeroMemory( rule,sizeof(ip_rules_elem));
    *rule = *elem;

    if( rule->rule.Bits.remote_addr_type == AnyAddr ||
        rule->rule.Bits.remote_addr_type == RangeAddr ||
        rule->rule.Bits.local_addr_type == AnyAddr ||
        rule->rule.Bits.local_addr_type == RangeAddr ||
        rule->rule.Bits.remote_port_type == AnyAddr ||
        rule->rule.Bits.remote_port_type == RangeAddr ||
        rule->rule.Bits.local_port_type == AnyAddr ||
        rule->rule.Bits.local_port_type == RangeAddr )
    {
        ExInterlockedInsertHeadList( &gIpRulesList.list,
                                    &rule->list,
                                    &gIpRulesList.lock );
    }
    else
    {
        ExInterlockedInsertTailList( &gIpRulesList.list,
                                    &rule->list,
                                    &gIpRulesList.lock );

    }
    
    InterlockedIncrement( &gIpRulesList.count );

    return STATUS_SUCCESS;
}

NTSTATUS
delete_ip_rule( IN pip_rules_elem rule )
/*++
--*/
{
    KIRQL       oldIrql;
    BOOLEAN     bSuccess;

    LOG("into\n");

    KeAcquireSpinLock( &gIpRulesList.lock,&oldIrql );
    bSuccess = RemoveEntryList( &rule->list );
    KeReleaseSpinLock( &gIpRulesList.lock,oldIrql );

    if( bSuccess )
    {
        my_ex_free_pool( rule );
        rule = NULL;
        InterlockedDecrement( &gIpRulesList.count );

        return STATUS_SUCCESS;
    }
    else
    {
        return STATUS_UNSUCCESSFUL;
    }
}


NTSTATUS
delete_ip_rule_by_crc_name( IN UINT32 crc_name )
/*++
--*/
{
    PLIST_ENTRY list = NULL;

    for( list = gIpRulesList.list.Flink;
         list != &gIpRulesList.list;
         list = list->Flink )
    {
        if( ((pip_rules_elem)list)->crc_rule_name == crc_name )
            break;
    }

    if( list != &gIpRulesList.list )
    {
        return delete_ip_rule( (pip_rules_elem)list );
    }
    else
    {
        return STATUS_IP_RULES_NOT_EXISTED;
    }
}


NTSTATUS
get_ip_rule_by_crc_name( IN UINT32 crc_name,IN OUT pip_rules_elem *rule )
/*++
--*/
{
    PLIST_ENTRY list = NULL;

    for( list = gIpRulesList.list.Flink;
         list != &gIpRulesList.list;
         list = list->Flink )
    {
        if( ((pip_rules_elem)list)->crc_rule_name == crc_name )
            break;
    }

    if( list != &gIpRulesList.list )
    {
        *rule = (pip_rules_elem)list;
        return STATUS_SUCCESS;
    }
    else
    {
        *rule = NULL;
        return STATUS_IP_RULES_NOT_EXISTED;
    }
}


BOOLEAN
is_ip_rule_exist( IN UINT32 crc_name )
/*++
--*/
{
    PLIST_ENTRY list = NULL;

    for( list = gIpRulesList.list.Flink;
         list != &gIpRulesList.list;
         list = list->Flink )
    {
        if( ((pip_rules_elem)list)->crc_rule_name == crc_name )
            break;
    }

    if( list != &gIpRulesList.list )
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

VOID    clear_ip_rules_list()
/*++
--*/
{
    PLIST_ENTRY list = NULL;

    LOG("into\n");

    while( (list = ExInterlockedRemoveHeadList( &gIpRulesList.list,&gIpRulesList.lock))
        != NULL )
    {
        my_ex_free_pool( list );
        list = NULL;
        InterlockedDecrement( &gIpRulesList.count );

    }
    ASSERT( IsListEmpty( &gIpRulesList.list ));
    ASSERT( gIpRulesList.count == 0 );

    return;
}



NTSTATUS
InitDnsRules()
/*++
--*/
{
    LOG("into\n");

    RtlZeroMemory( &gDnsRulesList,sizeof( gDnsRulesList) );

    InitializeListHead( &gDnsRulesList.list );
    KeInitializeSpinLock( &gDnsRulesList.lock );
    gDnsRulesList.count = 0;

    return STATUS_SUCCESS;

}

NTSTATUS
AddDnsRule( IN WCHAR dnsName[],IN ULONG Length,IN BOOLEAN bAllow ,IN UINT32 crc_name )
/*++

NOTE:dnsName为以0结尾的字符串，Length是其长度,单位字节，包括结尾0
--*/
{
    PDNS_RULES_ELEM rule = NULL;

    LOG("into\n");

    rule = my_ex_allocate_pool( sizeof( DNS_RULES_ELEM ));
    ASSERT( rule != NULL );
    RtlZeroMemory( rule,sizeof(DNS_RULES_ELEM));

    rule->crc_rule_name = crc_name;
    if( bAllow )
        rule->rule |= DNS_RULE_FLAG_ALLOW_ACCESS;
    rule->dnsName = (pmy_unicode_string)my_ex_allocate_pool( sizeof(my_unicode_string)+Length );
    ASSERT( rule->dnsName != NULL );
    RtlCopyMemory( rule->dnsName->buffer,dnsName,Length );
    rule->dnsName->str.Buffer = rule->dnsName->buffer;
    rule->dnsName->str.Length = 
        rule->dnsName->str.MaximumLength = (USHORT)Length;

    ExInterlockedInsertHeadList( &gDnsRulesList.list,
                                &rule->list,
                                &gDnsRulesList.lock );

    InterlockedIncrement( &gDnsRulesList.count );

    return STATUS_SUCCESS;
}

NTSTATUS
DeleteDnsRule( IN PDNS_RULES_ELEM rule )
/*++
--*/
{
    KIRQL       oldIrql;
    BOOLEAN     bSuccess;

    LOG("into\n");

    KeAcquireSpinLock( &gIpRulesList.lock,&oldIrql );
    bSuccess = RemoveEntryList( &rule->list );
    KeReleaseSpinLock( &gIpRulesList.lock,oldIrql );

    if( bSuccess )
    {
        if( rule->dnsName != NULL )
        {
            my_ex_free_pool( rule->dnsName );
            rule->dnsName = NULL;
        }
        my_ex_free_pool( rule );
        rule = NULL;
        InterlockedDecrement( &gDnsRulesList.count );

        return STATUS_SUCCESS;
    }
    else
    {
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS
DeleteDnsRuleByCrcName( IN UINT32 crc_name )
/*++
--*/
{
    PLIST_ENTRY list = NULL;

    for( list = gDnsRulesList.list.Flink;
         list != &gDnsRulesList.list;
         list = list->Flink )
    {
        if( ((PDNS_RULES_ELEM)list)->crc_rule_name == crc_name )
            break;
    }

    if( list != &gDnsRulesList.list )
    {
        return DeleteDnsRule( (PDNS_RULES_ELEM)list );
    }
    else
    {
        return STATUS_DNS_RULES_NOT_EXISTED;
    }
}

NTSTATUS
GetDnsRuleByCrcName( IN UINT32 crc_name,IN OUT PDNS_RULES_ELEM *rule )
/*++
--*/
{
    PLIST_ENTRY list = NULL;

    for( list = gDnsRulesList.list.Flink;
         list != &gDnsRulesList.list;
         list = list->Flink )
    {
        if( ((PDNS_RULES_ELEM)list)->crc_rule_name == crc_name )
            break;
    }

    if( list != &gDnsRulesList.list )
    {
        *rule = (PDNS_RULES_ELEM)list;
        return STATUS_SUCCESS;
    }
    else
    {
        *rule = NULL;
        return STATUS_DNS_RULES_NOT_EXISTED;
    }
}

BOOLEAN
IsDnsRuleExist( IN UINT32 crc_name )
/*++
--*/
{
    PLIST_ENTRY list = NULL;

    for( list = gDnsRulesList.list.Flink;
         list != &gDnsRulesList.list;
         list = list->Flink )
    {
        if( ((PDNS_RULES_ELEM)list)->crc_rule_name == crc_name )
            break;
    }

    if( list != &gDnsRulesList.list )
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

VOID
ClearDnsRulesList()
/*++
--*/
{
    PLIST_ENTRY list = NULL;

    LOG("into\n");

    while( (list = ExInterlockedRemoveHeadList( &gDnsRulesList.list,&gDnsRulesList.lock))
        != NULL )
    {
        if(((PDNS_RULES_ELEM)list)->dnsName != NULL )
        {
            my_ex_free_pool( ((PDNS_RULES_ELEM)list)->dnsName);
            ((PDNS_RULES_ELEM)list)->dnsName = NULL;
        }
        my_ex_free_pool( list );
        list = NULL;
        InterlockedDecrement( &gDnsRulesList.count );
    }
    ASSERT( IsListEmpty( &gDnsRulesList.list ));
    ASSERT( gDnsRulesList.count == 0 );

    return;
}
                                                                                                                                                                                                                                                                                                                                                                              