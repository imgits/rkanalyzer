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

// ntddk.h in XP DDK don't have this func declared. copied from 2003 DDK.
extern "C" NTSYSAPI NTSTATUS
NTAPI
ZwCreateSection (
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
    );

////////////////////
//                //
//  DriverUnload  //
//                //
////////////////////
VOID DriverUnload( IN PDRIVER_OBJECT DriverObject )
{
    DbgPrint( "[rkanalyzer_probe_win32]Unloaded.\n");
}

///
/// Map the ntdll.dll to nonpagedpool for analyze. should be freed explictly after use
///
PVOID MapNTDLLToNonPagedPool()
{
	UNICODE_STRING dllName;
	HANDLE hSection, hFile;
    SECTION_IMAGE_INFORMATION sii;
    PVOID BaseAddress = NULL;
    PVOID pNTDLLMaped = NULL;
    SIZE_T size=0;

	RtlInitUnicodeString(&dllName, L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntdll.dll");
    OBJECT_ATTRIBUTES oa = {sizeof oa, 0, &dllName, OBJ_CASE_INSENSITIVE};

    IO_STATUS_BLOCK iosb;

    ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

    oa.ObjectName = 0;
    
    ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_EXECUTE, SEC_IMAGE, hFile);
    
    ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE); 
    
    ZwClose(hFile);
    
    pNTDLLMaped = ExAllocatePool(NonPagedPool, size);
    if(pNTDLLMaped != NULL)
    {
    	RtlCopyMemory(pNTDLLMaped, BaseAddress, size);
    }

	ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
    ZwClose(hSection);

	return pNTDLLMaped;
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
    struct guest_win_kernel_objects *pwin_ko = NULL;
    PVOID pNTDLLMaped = NULL;
    
    if((pwin_ko = (struct guest_win_kernel_objects *)ExAllocatePool(NonPagedPool, sizeof(struct guest_win_kernel_objects))) == NULL)
    {
    	DbgPrint( "[rkanalyzer_probe_win32]Insufficient Resources.Init Failed.\n" );
    	return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    pwin_ko->pSDT = (virt_t)&KeServiceDescriptorTable;
    pwin_ko->pSSDT = (virt_t)KeServiceDescriptorTable.ServiceTableBase;
    pwin_ko->NumberOfService = (unsigned long int)KeServiceDescriptorTable.NumberOfService;
    pwin_ko->pIDT = 0;
    pwin_ko->pKernelCodeStart = 0;
    pwin_ko->pKernelCodeEnd = 0;
    
    pNTDLLMaped = MapNTDLLToNonPagedPool();
    pwin_ko->pNTDLLMaped = (virt_t)pNTDLLMaped;
    
    DbgPrint("[rkanalyzer_probe_win32]pSDT = 0x%lX\n", pwin_ko->pSDT);
    DbgPrint("[rkanalyzer_probe_win32]pSSDT = 0x%lX\n", pwin_ko->pSSDT);
    DbgPrint("[rkanalyzer_probe_win32]NumberOfService = %d\n", pwin_ko->NumberOfService);
    
 
 
    __asm
    {
    	push ebx
    	push eax
    	mov ebx, pcallname
    	mov eax, 0
    	
    	_emit 0x0F        // VMCALL
        _emit 0x01
        _emit 0xC1
        
    	mov ebx, pwin_ko
    	
    	_emit 0x0F        // VMCALL
        _emit 0x01
        _emit 0xC1
        
        pop eax
       	pop ebx
    }
    
    
    if(pNTDLLMaped != NULL)
    {
		ExFreePool(pNTDLLMaped);
	}
	
	ExFreePool(pwin_ko);
	
    DbgPrint( "[rkanalyzer_probe_win32]Done.\n" );
    
    return STATUS_SUCCESS;
}