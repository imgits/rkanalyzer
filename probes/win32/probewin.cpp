/*
    RKAnalyzer Probe For Windows.
    Report Windows Kernel Structure Address to VMM.
    Writtern By Tyrael.
*/

extern "C"
{
	#include <ntddk.h>
};

#include "probewin.h"
#include "types.h"

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
    DbgPrint( "[rkanalyzer_probe_win32]Unloaded.\n");
}

VOID ParseNTDLLExportTable( )
{
	
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
	
    DbgPrint( "[rkanalyzer_probe_win32]Start.\n" );
    
    char *pcallname = "rk_win_init";
    struct guest_win_kernel_objects win_ko;
    
    win_ko.pSDT = (virt_t)&KeServiceDescriptorTable;
    win_ko.pSSDT = (virt_t)KeServiceDescriptorTable.ServiceTableBase;
    win_ko.NumberOfService = (unsigned long int)KeServiceDescriptorTable.NumberOfService;
    win_ko.pIDT = 0;
    win_ko.pKernelCodeStart = 0;
    win_ko.pKernelCodeEnd = 0;
    
    DbgPrint("[rkanalyzer_probe_win32]pSDT = 0x%lX\n", win_ko.pSDT);
    DbgPrint("[rkanalyzer_probe_win32]pSSDT = 0x%lX\n", win_ko.pSSDT);
    
    PVOID pointer_win_ko = &win_ko;
 
 /*   
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
    
*/
    
    DbgPrint( "[rkanalyzer_probe_win32]Done.\n" );
    
    return STATUS_SUCCESS;
}