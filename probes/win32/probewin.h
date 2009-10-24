#ifndef __PROBE_WIN_H
#define __PROBE_WIN_H

extern "C"
{
	#include <ntddk.h>
};

#include "types.h"

typedef USHORT WORD;

typedef struct _SECTION_IMAGE_INFORMATION {
PVOID EntryPoint; 
ULONG StackZeroBits; 
ULONG StackReserved; 
ULONG StackCommit; 
ULONG ImageSubsystem; 
WORD SubsystemVersionLow; 
WORD SubsystemVersionHigh; 
ULONG Unknown1; 
ULONG ImageCharacteristics; 
ULONG ImageMachineType; 
ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

struct guest_win_kernel_objects{
	virt_t pSDT;
	virt_t pSSDT;
	unsigned long int NumberOfService;
	virt_t pIDT;
	virt_t pKernelCodeStart;
	virt_t pKernelCodeEnd;
};

#endif