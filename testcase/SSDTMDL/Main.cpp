////////////////////
//                //
//  Driver Entry  //
//                //
////////////////////

#include "AddressManager.h"

#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)


#define HOOK_SYSCALL(_Function, _Hook, _Orig, _OrigType, _MappedSystemCallTable) \
       _Orig = (_OrigType) InterlockedExchange( (PLONG) &_MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)


#define UNHOOK_SYSCALL(_Function, _Orig, _MappedSystemCallTable) \
       InterlockedExchange( (PLONG) &_MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Orig)


typedef NTSTATUS(*NT_RESTORE_KEY)(
IN HANDLE KeyHandle, IN HANDLE FileHandle, IN ULONG RestoreOption
);

extern "C"
NTKERNELAPI NTSTATUS ZwRestoreKey(
IN HANDLE KeyHandle, IN HANDLE FileHandle, IN ULONG RestoreOption
); 

typedef unsigned long int DWORD;

NT_RESTORE_KEY RealNtRestoreKey;


NTSTATUS
HookedNtRestoreKey(
                   IN HANDLE               KeyHandle,
                   IN HANDLE               FileHandle,
                   IN ULONG                RestoreOption 
                   )
{
    return RealNtRestoreKey(
                            KeyHandle,
                            FileHandle,
                            RestoreOption
                            );
}

void HookSSDT()
{
    PMDL pMdlSystemCall = NULL;
    DWORD * MappedSystemCallTable = 0;
       pMdlSystemCall = IoAllocateMdl(
                                   KeServiceDescriptorTable.ServiceTableBase,
                                   KeServiceDescriptorTable.NumberOfService*4, 
                                   0,
                                   0,
                                   NULL
                                   );
       if(!pMdlSystemCall)
          return;

       MmBuildMdlForNonPagedPool(pMdlSystemCall);

    MappedSystemCallTable=(DWORD *)MmMapLockedPages(pMdlSystemCall, KernelMode);

    HOOK_SYSCALL(
                 ZwRestoreKey,
                 HookedNtRestoreKey,
                 RealNtRestoreKey,
                 NT_RESTORE_KEY,
                 MappedSystemCallTable
                 );

    
    IoFreeMdl(pMdlSystemCall);

    return;
}

void UnhookSSDT()
{
    PMDL pMdlSystemCall = NULL;
    DWORD * MappedSystemCallTable = NULL;
       pMdlSystemCall = IoAllocateMdl(
                                   KeServiceDescriptorTable.ServiceTableBase,
                                   KeServiceDescriptorTable.NumberOfService*4, 
                                   0,
                                   0,
                                   NULL
                                   );
       if(!pMdlSystemCall)
          return;

       MmBuildMdlForNonPagedPool(pMdlSystemCall);

    
    MappedSystemCallTable = (DWORD *)MmMapLockedPages(pMdlSystemCall, KernelMode);

    UNHOOK_SYSCALL(
                   ZwRestoreKey,
                   RealNtRestoreKey,
                   MappedSystemCallTable
                   );
    
    IoFreeMdl(pMdlSystemCall);

}


VOID DriverUnload( IN PDRIVER_OBJECT DriverObject )
{
}


extern "C"
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{
    DriverObject->DriverUnload = DriverUnload;

    HookSSDT();
    UnhookSSDT();

    return STATUS_SUCCESS;
}
