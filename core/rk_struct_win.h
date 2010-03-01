#ifndef _RK_STRUCT_WIN_H
#define _RK_STRUCT_WIN_H

#include "types.h"
#include "list.h"

#define rk_struct_win_offset(type, member) (size_t)(&((type *)0)->member)
#define CURRENT_THREAD_OFFSET_IN_KPCR 0x124
#define SWAP_CONTEXT_ENTRY_OFFSET_IN_KERNEL 0x3A9CC
#define PSLOADEDMODULELIST_OFFSET_IN_KERNEL 0xaf988

#define WIN_KERNEL_BASE			0x80800000
#define WIN_KERNEL_BSP_STARTUP_EIP	(WIN_KERNEL_BASE + 0x2211fc)
#define WIN_KERNEL_AP_STARTUP_EIP	(WIN_KERNEL_BASE + 0x2211fc)

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
    u32   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    u16    Machine;
    u16    NumberOfSections;
    u32   TimeDateStamp;
    u32   PointerToSymbolTable;
    u32   NumberOfSymbols;
    u16    SizeOfOptionalHeader;
    u16    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    u32   VirtualAddress;
    u32   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    u16    Magic;
    u8    MajorLinkerVersion;
    u8    MinorLinkerVersion;
    u32   SizeOfCode;
    u32   SizeOfInitializedData;
    u32   SizeOfUninitializedData;
    u32   AddressOfEntryPoint;
    u32   BaseOfCode;
    u32   BaseOfData;

    //
    // NT additional fields.
    //

    u32   ImageBase;
    u32   SectionAlignment;
    u32   FileAlignment;
    u16    MajorOperatingSystemVersion;
    u16    MinorOperatingSystemVersion;
    u16    MajorImageVersion;
    u16    MinorImageVersion;
    u16    MajorSubsystemVersion;
    u16    MinorSubsystemVersion;
    u32   Win32VersionValue;
    u32   SizeOfImage;
    u32   SizeOfHeaders;
    u32   CheckSum;
    u16    Subsystem;
    u16    DllCharacteristics;
    u32   SizeOfStackReserve;
    u32   SizeOfStackCommit;
    u32   SizeOfHeapReserve;
    u32   SizeOfHeapCommit;
    u32   LoaderFlags;
    u32   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
    u32 Signature;
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
    u32   Characteristics;
    u32   TimeDateStamp;
    u16    MajorVersion;
    u16    MinorVersion;
    u32   Name;
    u32   Base;
    u32   NumberOfFunctions;
    u32   NumberOfNames;
    u32   AddressOfFunctions;     // RVA from base of image
    u32   AddressOfNames;         // RVA from base of image
    u32   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((u32_PTR)ntheader +                                              \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

//
// Section header format.
//

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    u8    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            u32   PhysicalAddress;
            u32   VirtualSize;
    } Misc;
    u32   VirtualAddress;
    u32   SizeOfRawData;
    u32   PointerToRawData;
    u32   PointerToRelocations;
    u32   PointerToLinenumbers;
    u16    NumberOfRelocations;
    u16    NumberOfLinenumbers;
    u32   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

//
// Section characteristics.
//
//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  //
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  //
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  //
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  //
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  //
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  //
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  //
// Unused                                    0x00F00000
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.

typedef struct _LIST_ENTRY32 {
	u32 Flink;
	u32 Blink;
} LIST_ENTRY32;

typedef struct _UNICODE_STRING32 {
	u16 Length;
	u16 MaximumLength;
	u32 Buffer;
} UNICODE_STRING32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	u32 DllBase;
	u32 EntryPoint;
	u32 SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	u32 Flags;
	u16 LoadCount;
	u16 TlsIndex;
	union {
		LIST_ENTRY32 HashLinks;
		struct {
			u32 SectionPointer;
			u32 CheckSum;
		};
	};
	union {
		struct {
			u32 TimeDataStamp;
		};
		struct {
			u32 LoadedImports;
		};
	};
} LDR_DATA_TABLE_ENTRY32;

#endif
