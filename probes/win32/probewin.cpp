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

extern "C" NTSTATUS
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

VOID ParseNTDLLExportTable( )
{
	UNICODE_STRING dllName;
	HANDLE hThread, hSection, hFile, hMod;
    SECTION_IMAGE_INFORMATION sii;
    IMAGE_DOS_HEADER* dosheader;
    IMAGE_OPTIONAL_HEADER* opthdr;
    IMAGE_EXPORT_DIRECTORY* pExportTable;
    DWORD* arrayOfFunctionAddresses;
    DWORD* arrayOfFunctionNames;
    WORD* arrayOfFunctionOrdinals;
    DWORD functionOrdinal;
    DWORD Base, x, functionAddress;
    char* functionName;
    STRING ntFunctionName;
    PVOID BaseAddress = NULL;
    SIZE_T size=0;

	RtlInitUnicodeString(&dllName, L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntdll.dll");
    OBJECT_ATTRIBUTES oa = {sizeof oa, 0, &dllName, OBJ_CASE_INSENSITIVE};

    IO_STATUS_BLOCK iosb;

    //_asm int 3;
    ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

    oa.ObjectName = 0;
    
    ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_EXECUTE, SEC_IMAGE, hFile);
    
    ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE); 
    
    ZwClose(hFile);
    
    hMod = BaseAddress;
    
    dosheader = (IMAGE_DOS_HEADER *)hMod;
    
    opthdr =(IMAGE_OPTIONAL_HEADER *) ((BYTE*)hMod+dosheader->e_lfanew+24);

    pExportTable =(IMAGE_EXPORT_DIRECTORY*)((BYTE*) hMod + opthdr->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress);

    // now we can get the exported functions, but note we convert from RVA to address
    arrayOfFunctionAddresses = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfFunctions);

    arrayOfFunctionNames = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfNames);

    arrayOfFunctionOrdinals = (WORD*)( (BYTE*)hMod + pExportTable->AddressOfNameOrdinals);

    Base = pExportTable->Base;

    for(x = 0; x < pExportTable->NumberOfFunctions; x++)
    {
        functionName = (char*)( (BYTE*)hMod + arrayOfFunctionNames[x]);

        RtlInitString(&ntFunctionName, functionName);

        functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1; // always need to add base, -1 as array counts from 0
        // this is the funny bit.  you would expect the function pointer to simply be arrayOfFunctionAddresses[x]
        // oh no thats too simple.  it is actually arrayOfFunctionAddresses[functionOrdinal]!!
        functionAddress = (DWORD)( (BYTE*)hMod + arrayOfFunctionAddresses[functionOrdinal]);
        
        // DbgPrint("0x%lx, %s\n", functionAddress, functionName);
        
        // dump the SSDT index
        if((*functionName == 'N') && (*(functionName + 1) == 't'))
        {
        	DbgPrint("[%d]%s\n", *((WORD*)(functionAddress+1)), functionName);
        }
    }

	ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
    ZwClose(hSection);

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
    DbgPrint("[rkanalyzer_probe_win32]NumberOfService = %d\n", win_ko.NumberOfService);
    
    PVOID pointer_win_ko = &win_ko;
 
 	ParseNTDLLExportTable();
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