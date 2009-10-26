#ifndef __PROBE_WIN_H
#define __PROBE_WIN_H

extern "C"
{
	#include <ntddk.h>
};

#include "types.h"

#define SEC_IMAGE 0x01000000
#define rk_struct_win_offset(type, member) (size_t)(&((type *)0)->member)

typedef USHORT WORD;
typedef ULONG DWORD;
typedef UCHAR BYTE;

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

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    u16   e_magic;                     // Magic number
    u16   e_cblp;                      // Bytes on last page of file
    u16   e_cp;                        // Pages in file
    u16   e_crlc;                      // Relocations
    u16   e_cparhdr;                   // Size of header in paragraphs
    u16   e_minalloc;                  // Minimum extra paragraphs needed
    u16   e_maxalloc;                  // Maximum extra paragraphs needed
    u16   e_ss;                        // Initial (relative) SS value
    u16   e_sp;                        // Initial SP value
    u16   e_csum;                      // Checksum
    u16   e_ip;                        // Initial IP value
    u16   e_cs;                        // Initial (relative) CS value
    u16   e_lfarlc;                    // File address of relocation table
    u16   e_ovno;                      // Overlay number
    u16   e_res[4];                    // Reserved u16s
    u16   e_oemid;                     // OEM identifier (for e_oeminfo)
    u16   e_oeminfo;                   // OEM information; e_oemid specific
    u16   e_res2[10];                  // Reserved u16s
    ulong   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    u16    Machine;
    u16    NumberOfSections;
    ulong   TimeDateStamp;
    ulong   PointerToSymbolTable;
    ulong   NumberOfSymbols;
    u16    SizeOfOptionalHeader;
    u16    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ulong   VirtualAddress;
    ulong   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    u16    Magic;
    u8    MajorLinkerVersion;
    u8    MinorLinkerVersion;
    ulong   SizeOfCode;
    ulong   SizeOfInitializedData;
    ulong   SizeOfUninitializedData;
    ulong   AddressOfEntryPoint;
    ulong   BaseOfCode;
    ulong   BaseOfData;

    //
    // NT additional fields.
    //

    ulong   ImageBase;
    ulong   SectionAlignment;
    ulong   FileAlignment;
    u16    MajorOperatingSystemVersion;
    u16    MinorOperatingSystemVersion;
    u16    MajorImageVersion;
    u16    MinorImageVersion;
    u16    MajorSubsystemVersion;
    u16    MinorSubsystemVersion;
    ulong   Win32VersionValue;
    ulong   SizeOfImage;
    ulong   SizeOfHeaders;
    ulong   CheckSum;
    u16    Subsystem;
    u16    DllCharacteristics;
    ulong   SizeOfStackReserve;
    ulong   SizeOfStackCommit;
    ulong   SizeOfHeapReserve;
    ulong   SizeOfHeapCommit;
    ulong   LoaderFlags;
    ulong   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
    ulong Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ulong   Characteristics;
    ulong   TimeDateStamp;
    u16    MajorVersion;
    u16    MinorVersion;
    ulong   Name;
    ulong   Base;
    ulong   NumberOfFunctions;
    ulong   NumberOfNames;
    ulong   AddressOfFunctions;     // RVA from base of image
    ulong   AddressOfNames;         // RVA from base of image
    ulong   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

struct guest_win_kernel_objects{
	virt_t pSDT;
	virt_t pSSDT;
	unsigned long int NumberOfService;
	virt_t pIDT;
	virt_t pKernelCodeStart;
	virt_t pKernelCodeEnd;
	virt_t pNTDLLMaped;
};

#endif