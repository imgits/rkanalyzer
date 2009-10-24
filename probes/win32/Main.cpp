/*
    BitVisor Probe For Windows.
    Report Windows Kernel Structure Address to VMM.
    Writtern By Tyrael.
*/

extern "C"
{
	#include <ntddk.h>
};
	
#include "types.h"

struct guest_win_kernel_objects{
	virt_t pSDT;
	virt_t pSSDT;
	unsigned long int NumberOfService;
	virt_t pIDT;
	virt_t pKernelCodeStart;
	virt_t pKernelCodeEnd;
};

//////////////////
//              //
//  PROTOTYPES  //
//              //
//////////////////
extern "C" NTSTATUS    DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath );
VOID DriverUnload( IN PDRIVER_OBJECT DriverObject );

///////////////
//          //
//  Globals  //
//          //
///////////////
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

////////////////////
//                //
//  DriverUnload  //
//                //
////////////////////
VOID DriverUnload( IN PDRIVER_OBJECT DriverObject )
{
    DbgPrint( "[BVWinProbe]Unloaded.\n");
}

////////////////////
//                //
//  Driver Entry  //
//                //
////////////////////
extern "C"
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{
	
	DriverObject->DriverUnload = DriverUnload;
	
    DbgPrint( "[BVWinProbe]Start.\n" );
    
    char *pcallname = "rk_win_init";
    struct guest_win_kernel_objects win_ko;
    
    win_ko.pSDT = (virt_t)&KeServiceDescriptorTable;
    win_ko.pSSDT = (virt_t)KeServiceDescriptorTable.ServiceTableBase;
    win_ko.NumberOfService = (unsigned long int)KeServiceDescriptorTable.NumberOfService;
    win_ko.pIDT = 0;
    win_ko.pKernelCodeStart = 0;
    win_ko.pKernelCodeEnd = 0;
    
    DbgPrint("pSDT = 0x%lX\n", win_ko.pSDT);
    DbgPrint("pSSDT = 0x%lX\n", win_ko.pSSDT);
    
    PVOID pointer_win_ko = &win_ko;
    
    __asm
    {
    	push ebx
    	push eax
    	mov ebx, pcallname
    	mov eax, 0
    	
    	_emit 0x0F        // VMCALL
        _emit 0x01
        _emit 0xC1
        
    	mov ebx, pointer_win_ko
    	
    	_emit 0x0F        // VMCALL
        _emit 0x01
        _emit 0xC1
        
        pop eax
       	pop ebx
    }
    
    return STATUS_SUCCESS;
}