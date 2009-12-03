#ifndef _HVM_RK_DA_ADDRESSMANAGER_H
#define _HVM_RK_DA_ADDRESSMANAGER_H


extern "C"
{
	#include <ntddk.h>
};

#define NTOSKRNL_PAGE						0x80400000
#define LARGE_PAGE_SIZE					0x00400000
#define HIGHEST_USER_ADDRESS				0x7FFF0000
#define LOWEST_ADDRESS_IN_LARGE_PAGE_RANGE  0X80000000
#define HIGHEST_ADDRESS_IN_LARGE_PAGE_RANGE	0x9FFFFFFF

#define PROCESS_PAGE_DIR_BASE                  0xC0300000
#define PROCESS_PAGE_TABLE_BASE                0xC0000000
#define PTE_OFFSET								12
#define PDE_OFFSET								22
#define MAX_NUMBER_OF_HOOKED_BYTES				16
#define MAX_NUMBER_OF_HOOKED_PAGES				256
#define NUM_HASH_BITS_PAGE						12 //32 - log10(MAX_NUMBER_OF_HOOKED_PAGES) / log10(2)
#define NUM_HASH_BITS_BYTE						8  //12 - log2(MAX_NUMBER_OF_HOOKED_BYTES_SMALL_PAGE)

#pragma pack(1)

//SSDT Table
typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	PVOID	ServiceTableBase;
	PULONG	ServiceCounterTableBase;
	ULONG	NumberOfService;
	ULONG	ParamTableBase;
}SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

#pragma pack()

extern "C"
{
	__declspec(dllimport) SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
};

#endif