#pragma once

#include<ntddk.h>


#define ZERO_CRC_VALUE		( 0x87326698 );



////////////////////////////////进程规则声明/////////////////////////////////

#define MAX_PROCESS_RULES_NUM		255


#define STATUS_PROCESS_RULES_FULL				( 0x60000001L )
#define STATUS_PROCESS_RULES_EXISTED			( 0x60000002L )
#define STATUS_PROCESS_RULES_EMPTY				( 0x60000003L )
#define STATUS_PROCESS_RULES_NOT_EXISTED		( 0x60000004L )

typedef struct _process_rules_elem
{
    UINT32		crc_path;
    UINT32		rule;      //32位值，各个位的功能参看下边的宏定义
}process_rules_elem, *pprocess_rules_elem;

#define PROCESS_RULE_FLAG_ALLOW_ACCESS		( (UINT32)( 1<<0 ) )


typedef struct _process_rules_table
{
    UINT8                count;
    process_rules_elem  rules[ MAX_PROCESS_RULES_NUM ];
}process_rules_table, *pprocess_rules_table;

NTSTATUS init_process_rules();

NTSTATUS add_process_rule( IN UINT32 crc_path, IN UINT32 rule );

NTSTATUS delete_process_rule( IN UINT32 crc_path );

NTSTATUS get_process_rule( IN UINT32 crc_path, IN OUT UINT32 *rule );

BOOLEAN is_process_rule_exist( IN UINT32 crc_path );

/////////////////////////////////////////////////////////////////////////////



//////////////////////////////IP规则声明/////////////////////////////////////



#define STATUS_IP_RULES_FULL			( 0x60000001L )
#define STATUS_IP_RULES_EXISTED			( 0x60000002L )
#define STATUS_IP_RULES_EMPTY			( 0x60000003L )
#define STATUS_IP_RULES_NOT_EXISTED		( 0x60000004L )

enum
{
    AnyAddr=0,
    UniqueAddr,
    RangeAddr,
    UnknownAddr
};

enum
{
    RulesDirectionAny=0,
    RulesDirectionUp,
    RulesDirectionDown,
    RulesDirectionUnknown
};

enum
{
    RulesProtocolAny = 0
};

typedef struct _ip_rules_elem
{
    LIST_ENTRY					list;

    UINT32						crc_rule_name;   //IP规则名称的32位crc值（对应注册表中相应的项）
    
    union	{
			     UINT32			u32;
				 struct	{
					 UINT32		remote_addr_type : 2;  //取值为AnyAddr,UniqueAddr,RangeAddr
					 UINT32		local_addr_type : 2;   //取值为AnyAddr,UniqueAddr,RangeAddr
					 UINT32		remote_port_type : 2;  //取值为AnyAddr,UniqueAddr,RangeAddr
					 UINT32		local_port_type : 2;   //取值为AnyAddr,UniqueAddr,RangeAddr
					 UINT32		protocol_type : 8;//网络协议类型
					 UINT32		direction : 2;//00：任意方向 01：上行  10:下行  11：未定义
					 UINT32		access : 1;//是否允许访问，1为允许
					 UINT32		icmp_type : 5;
					 UINT32		icmp_code : 5;
					 UINT32		reserved : 3;
				 }Bits;
	}rule;

    UINT32						local_addr;
    UINT32						local_addr2;
    UINT32						remote_addr;
    UINT32						remote_addr2;
    UINT16						local_port;
    UINT16						local_port2;
    UINT16						remote_port;
	UINT16						remote_port2;

}ip_rules_elem, *pip_rules_elem;

typedef struct _ip_rules_list
{
    LIST_ENTRY          list;
    LONG                count;
    KSPIN_LOCK          lock;
}ip_rules_list, *pip_rules_list;

NTSTATUS init_ip_rules();

NTSTATUS add_ip_rule( IN pip_rules_elem elem );

NTSTATUS delete_ip_rule( IN pip_rules_elem rule );

NTSTATUS delete_ip_rule_by_crc_name( IN UINT32 crc_name );

NTSTATUS get_ip_rule_by_crc_name( IN UINT32 crc_name, IN OUT pip_rules_elem *rule );

BOOLEAN is_ip_rule_exist( IN UINT32 crc_name );

VOID clear_ip_rules_list();


///////////////////////////////END///////////////////////////////////////////




////////////////////////////////DNS规则声明/////////////////////////////////


#define STATUS_DNS_RULES_FULL \
        (0x60000001L)
#define STATUS_DNS_RULES_EXISTED \
        (0x60000002L)
#define STATUS_DNS_RULES_EMPTY \
        (0x60000003L)
#define STATUS_DNS_RULES_NOT_EXISTED \
        (0x60000004L)

typedef struct _DNS_RULES_ELEM
{
    LIST_ENTRY          list;
    UINT32              crc_rule_name;
    pmy_unicode_string  dnsName;
    UINT32              rule;      //32位值，各个位的功能参看下边的宏定义
}DNS_RULES_ELEM,*PDNS_RULES_ELEM;

#define DNS_RULE_FLAG_ALLOW_ACCESS  ((UINT32)(1<<0))


typedef struct _DNS_RULES_LIST
{
    LIST_ENTRY          list;
    LONG                count;
    KSPIN_LOCK          lock;
}DNS_RULES_LIST,*PDNS_RULES_LIST;

NTSTATUS
InitDnsRules();

NTSTATUS
AddDnsRule( IN WCHAR dnsName[],IN ULONG Length,IN BOOLEAN bAllow,IN UINT32 crc_name );

NTSTATUS
DeleteDnsRule( IN PDNS_RULES_ELEM rule );

NTSTATUS
DeleteDnsRuleByCrcName( IN UINT32 crc_name );

NTSTATUS
GetDnsRuleByCrcName( IN UINT32 crc_name,IN OUT PDNS_RULES_ELEM *rule );

BOOLEAN
IsDnsRuleExist( IN UINT32 crc_name );

VOID
ClearDnsRulesList();                                                                                                                                                                                                                                                                                                                                                                                                                                                                        