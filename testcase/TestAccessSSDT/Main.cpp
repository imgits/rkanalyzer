////////////////////
//                //
//  Driver Entry  //
//                //
////////////////////

#include "AddressManager.h"

#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
	
#define HOOK_SYSCALL(_Function, _Hook, _Orig, _OrigType, _SSDT) \
       _Orig = (_OrigType) InterlockedExchange( (PLONG)(_SSDT + 4 * SYSCALL_INDEX(_Function)), (LONG) _Hook)

#define UNHOOK_SYSCALL(_Function, _Orig, _SSDT) \
       InterlockedExchange( (PLONG)(_SSDT + 4 * SYSCALL_INDEX(_Function)), (LONG) _Orig)
    
typedef NTSTATUS(*NT_RESTORE_KEY)(
IN HANDLE KeyHandle, IN HANDLE FileHandle, IN ULONG RestoreOption
);

extern "C"
NTKERNELAPI NTSTATUS ZwRestoreKey(
IN HANDLE KeyHandle, IN HANDLE FileHandle, IN ULONG RestoreOption
); 

typedef unsigned long int DWORD;

LONG RealNtRestoreKey;

NTSTATUS
HookedNtRestoreKey(
                   IN HANDLE               KeyHandle,
                   IN HANDLE               FileHandle,
                   IN ULONG                RestoreOption 
                   )
{
    return ((NT_RESTORE_KEY)RealNtRestoreKey)(
                            KeyHandle,
                            FileHandle,
                            RestoreOption
                            );
}

VOID DriverUnload( IN PDRIVER_OBJECT DriverObject )
{
}


extern "C"
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{

    KSPIN_LOCK spinLock;
    KIRQL oldIrql;

    PLONG ssdt = (PLONG)KeServiceDescriptorTable.ServiceTableBase;
    LONG index = SYSCALL_INDEX(ZwRestoreKey);    
    DriverObject->DriverUnload = DriverUnload;

 __asm{
    push eax
    cli
         mov  eax,cr0
    and  eax,not 10000h
    mov  cr0,eax
    sti
    pop eax
  }
    //KeAcquireSpinLock(&spinLock, &oldIrql);
    
    DbgPrint("ssdt = %lx\n", ssdt);
    DbgPrint("ZwRestoreKey Index = %d\n", index );
    RealNtRestoreKey = (*(PLONG)(ssdt+ index ));
    DbgPrint("%lx\n", RealNtRestoreKey );
    InterlockedExchange((PLONG)(ssdt+ index ), (LONG)HookedNtRestoreKey);
    DbgPrint("%lx\n", *(PLONG)(ssdt+ index ));
    InterlockedExchange((PLONG)(ssdt+ index ), (LONG)RealNtRestoreKey);
    DbgPrint("%lx\n", *(PLONG)(ssdt+ index ));
    DbgPrint("%lx\n", ZwRestoreKey);
    
    //KeReleaseSpinLock(&spinLock, oldIrql);

  __asm{ 
    push eax
    cli
          mov  eax,cr0
    or   eax,10000h
    mov  cr0,eax
    sti
    pop eax
  }

    return STATUS_SUCCESS;
}
