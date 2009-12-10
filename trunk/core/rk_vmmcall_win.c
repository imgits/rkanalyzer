/*
	Changlog:
	2009.7.22	First Ver. Base Functions
*/

#include "asm.h"
#include "current.h"
#include "initfunc.h"
#include "cpu_mmu.h"
#include "mm.h"
#include "panic.h"
#include "pcpu.h"
#include "printf.h"
#include "string.h"
#include "vmmcall.h"
#include "list.h"
#include "rk_main.h"
#include "rk_struct_win.h"

#ifdef RK_ANALYZER

#define FUNCTION_NAME_MAXLEN 100

struct guest_win_kernel_objects{
	virt_t pSDT;
	virt_t pSSDT;
	unsigned long int NumberOfService;
	virt_t pIDT;
	virt_t pKernelCodeStart;
	virt_t pKernelCodeEnd;
	virt_t pNTDLLMaped;
};

struct guest_win_kernel_export_function{
	LIST1_DEFINE (struct guest_win_kernel_export_function);
	virt_t entrypoint;
	char name[FUNCTION_NAME_MAXLEN];
};

struct guest_win_pe_section{
	LIST1_DEFINE (struct guest_win_pe_section);
	virt_t va;
	ulong size;
	ulong characteristics;
	char name[FUNCTION_NAME_MAXLEN];
};

struct guest_win_kernel_objects win_ko;

static LIST1_DEFINE_HEAD (struct guest_win_kernel_export_function, list_win_kernel_export_functions);
static LIST1_DEFINE_HEAD (struct guest_win_kernel_export_function, list_win_kernel_ssdt_entries);
static LIST1_DEFINE_HEAD (struct guest_win_pe_section, list_win_pe_sections);

/*

static bool rk_win_getentryaddrbyname(const char *name, virt_t *pEntrypoint)
{
	struct guest_win_kernel_export_function *func;

	LIST1_FOREACH (list_win_kernel_export_functions, func) {
		if(strcmp(func->name, name) == 0){
			*pEntrypoint = func->entrypoint;
			return true;
		}
	}

	return false;
}

static void rk_win_setdebugregister()
{
	virt_t pObCreateObject;
	ulong dr7;

	if (rk_win_getentryaddrbyname("ObCreateObject", &pObCreateObject)) {
		asm volatile ("mov %0, %%db0" : : "a"(pObCreateObject));
		asm_rddr7(&dr7);
		dr7 |= 0x2;	//DR7.G0 = 1
		dr7 &= 0xFFFCFFFF;	//DR7.R/W0 = 00;
		asm volatile ("mov %0, %%db7" : : "a"(dr7));
	}
}

*/


static void rk_win_readfromguest()
{
	//Parse the PE Section
	//Dump all exported functions.
	int i,j;
	int step = 0;
	int err = 0;
	ulong pebase = 0;
	ulong buf = 0;
	ulong pNTHeader = 0;
	u16 shortbuf = 0;
	ulong addr = 0;
	ulong addr_2 = 0;
	int namelen = 0;
	IMAGE_EXPORT_DIRECTORY Export;
	char strbuf[FUNCTION_NAME_MAXLEN];
	unsigned char* buf_2 = (unsigned char*)&Export;
	bool succeed = false;
	struct guest_win_kernel_export_function *function;
	struct guest_win_pe_section *section;
	ulong addr_section_header = 0;
	u16 numberOfSections = 0;
	IMAGE_SECTION_HEADER section_header;
	unsigned char* p_section_header = (unsigned char*)&section_header;
	u8 sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];

	//Scan for Ntoskrnl base
	pebase = 0x80000000;
	while(pebase < 0xa0000000){
		if(read_linearaddr_l(pebase, &buf) == VMMERR_SUCCESS){
			if(buf == 0x00905A4D){
				//Found 'MZ'
				//Test if the ImageSize is bigger than 0x150000
				addr = pebase + rk_struct_win_offset(IMAGE_DOS_HEADER, e_lfanew);
				if(read_linearaddr_l(addr, &buf) == VMMERR_SUCCESS){
					addr = pebase + buf + rk_struct_win_offset(IMAGE_NT_HEADERS, 
						OptionalHeader.SizeOfImage);
					if(read_linearaddr_l(addr, &buf) == VMMERR_SUCCESS){
						if(buf >= 0x150000){
							break;
						}
					}
				}
			}
		}
		pebase = pebase >> PAGESIZE_SHIFT;
		pebase ++;
		pebase = pebase << PAGESIZE_SHIFT;
	}

	if(pebase >= 0xa0000000){
		goto init_failed;
	}
	step ++;

	printf("KernelBase = %lX\n", pebase);

	//buf = pNTHeader
	addr = pebase + rk_struct_win_offset(IMAGE_DOS_HEADER, e_lfanew);
	err = read_linearaddr_l(addr, &buf);
	if (err != VMMERR_SUCCESS)
		goto init_failed;
	buf += pebase;
	pNTHeader = buf;
	step ++;

	printf("NtHeader = %lX\n", buf);
		
	//buf = pExportDirectory
	addr = buf + rk_struct_win_offset(IMAGE_NT_HEADERS, 
			OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	err = read_linearaddr_l(addr, &buf);
	if (err != VMMERR_SUCCESS)
		goto init_failed;
	buf += pebase;	
	step ++;

	printf("pExportDirectory = %lX\n", buf);
	
	for (i = 0; i < sizeof(IMAGE_EXPORT_DIRECTORY); i++) {
		if (read_linearaddr_b (buf + i, buf_2 + i)
		    != VMMERR_SUCCESS)
			goto init_failed;
	}
	step ++;

	printf("Export.Name = %lX\n", Export.Name);

	//name
	buf = Export.Name + pebase;
	for (i = 0; i < sizeof(strbuf); i++) {
		if (read_linearaddr_b (buf + i, strbuf + i)
		    != VMMERR_SUCCESS)
			goto init_failed;
		if(strbuf[i] == 0)
			break;
	}
	printf("FileName: %s\n", strbuf);
	printf("Number of Functions: %ld\n", Export.NumberOfFunctions);
	printf("Number of Names: %ld\n",Export.NumberOfNames);

	//Sections
	//numberofSections
	addr = pNTHeader + rk_struct_win_offset(IMAGE_NT_HEADERS, 
			FileHeader.NumberOfSections);
	err = read_linearaddr_w(addr, &shortbuf);
	if (err != VMMERR_SUCCESS)
		goto init_failed;
	numberOfSections = shortbuf;
	step ++;
	//addr_section_header = p_IMAGE_FIRST_SECTION;
	addr = pNTHeader + rk_struct_win_offset(IMAGE_NT_HEADERS, 
			FileHeader.SizeOfOptionalHeader);
	err = read_linearaddr_w(addr, &shortbuf);
	if (err != VMMERR_SUCCESS)
		goto init_failed;
	addr_section_header = pNTHeader + rk_struct_win_offset( IMAGE_NT_HEADERS, OptionalHeader ) + shortbuf;
	for (j = 0; j < numberOfSections; j++) {
		for (i = 0; i < sizeof(IMAGE_SECTION_HEADER); i++) {
			if (read_linearaddr_b (addr_section_header + i, p_section_header + i)
		    	!= VMMERR_SUCCESS)
				goto init_failed;
		}
		addr_section_header += sizeof(IMAGE_SECTION_HEADER);
		memcpy(sectionName, section_header.Name, sizeof(u8) * IMAGE_SIZEOF_SHORT_NAME);
		sectionName[IMAGE_SIZEOF_SHORT_NAME] = 0;
		printf("Section Name = %s, VA = 0x%lX, SIZE = %ld bytes, Flags = 0x%lX\n", sectionName, 
			section_header.VirtualAddress, section_header.SizeOfRawData, section_header.Characteristics);

		section = alloc(sizeof(struct guest_win_pe_section));
		section->va = pebase + section_header.VirtualAddress;
		section->size = section_header.SizeOfRawData;
		namelen = (strlen(strbuf) > (FUNCTION_NAME_MAXLEN - IMAGE_SIZEOF_SHORT_NAME - 2) ?
			  (FUNCTION_NAME_MAXLEN - IMAGE_SIZEOF_SHORT_NAME - 2) :strlen(strbuf));
		memcpy(section->name, strbuf, sizeof(char) * namelen);
		section->name[namelen] = ':';
		memcpy((section->name + namelen + 1), sectionName, sizeof(char) * (IMAGE_SIZEOF_SHORT_NAME + 1));
		section->name[namelen + IMAGE_SIZEOF_SHORT_NAME + 1] = 0;		//NULL Terminate It
		section->characteristics = section_header.Characteristics;

		LIST1_ADD (list_win_pe_sections, section);
	}
	step ++;

	//Dump the functions
	//FIXME:各种越界问题
	for(i = 0; i < Export.NumberOfNames; i++){

		succeed = true;

		//Function Ordinals
		addr = pebase + Export.AddressOfNameOrdinals + i * sizeof(u16);
		if(read_linearaddr_w(addr, &shortbuf) != VMMERR_SUCCESS){
			continue;
		}

		//Function Entry Point
		addr = pebase + Export.AddressOfFunctions + (shortbuf + Export.Base - 1) * sizeof(ulong);
		if(read_linearaddr_l(addr, &buf) != VMMERR_SUCCESS){
			continue;
		}
		buf += pebase;

		//Function Name
		addr = pebase + Export.AddressOfNames + i * sizeof(ulong);
		if(read_linearaddr_l(addr, &addr_2) != VMMERR_SUCCESS){
			continue;
		}
		addr = pebase + addr_2;
		for (j = 0; j < sizeof(strbuf); j++) {
			if (read_linearaddr_b (addr + j, strbuf + j)
		    		!= VMMERR_SUCCESS){
				succeed = false;
				break;
			}
			if(strbuf[j] == 0){
				succeed = true;
				break;
			}
		}

		if(succeed){
			function = alloc(sizeof(struct guest_win_kernel_export_function));
			function->entrypoint = buf;

			namelen = (strlen(strbuf) > FUNCTION_NAME_MAXLEN ? FUNCTION_NAME_MAXLEN : strlen(strbuf));
			memcpy(function->name, strbuf, sizeof(char) * namelen);
			function->name[namelen - 1] = 0;			//NULL Terminate It

			LIST1_ADD (list_win_kernel_export_functions, function);
			//printf("Name : %s, Entry : 0x%lX\n", strbuf, function->entrypoint);
		}
	}


	printf("[RKAnalyzer]Get Export Table Succeed...\n");

	return;

init_failed:
	printf("[RKAnalyzer]Get Export Table Failed!, step = %d, buf= %lX, addr= %lX, err = %d\n", step, buf, addr, err);
	return;
}

static void rk_win_fill_ssdt_entries(ulong pNTDLLMaped){
	
	//Try reading .edata section from ntdll.dll...dirty hack but no other method
	//Parse the PE Section
	//Dump all exported functions.
	int i,j;
	int step = 0;
	int err = 0;
	ulong pebase = pNTDLLMaped;
	ulong buf = 0;
	u16 shortbuf = 0;
	ulong addr = 0;
	ulong addr_2 = 0;
	ulong ordinalbase = 0;
	int namelen = 0;
	IMAGE_EXPORT_DIRECTORY Export;
	char strbuf[FUNCTION_NAME_MAXLEN];
	unsigned char* buf_2 = (unsigned char*)&Export;
	unsigned char cbuf;
	bool succeed = false;
	struct guest_win_kernel_export_function *ssdtentry;
	
	printf("[RKAnalyzer]Get SSDT Table Indices From Export Table Of Ntdll.dll...\n");
	printf("NTDLL Mapped Base = %lX\n", pebase);

	//buf = pNTHeader
	addr = pebase + rk_struct_win_offset(IMAGE_DOS_HEADER, e_lfanew);
	err = read_linearaddr_l(addr, &buf);
	if (err != VMMERR_SUCCESS)
		goto init_failed;
	buf += pebase;
	step ++;

	printf("NtHeader = %lX\n", buf);
		
	//buf = pExportDirectory
	addr = buf + rk_struct_win_offset(IMAGE_NT_HEADERS, 
			OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	err = read_linearaddr_l(addr, &buf);
	if (err != VMMERR_SUCCESS)
		goto init_failed;
	buf += pebase;	
	step ++;

	printf("pExportDirectory = %lX\n", buf);
	
	for (i = 0; i < sizeof(IMAGE_EXPORT_DIRECTORY); i++) {
		if (read_linearaddr_b (buf + i, buf_2 + i)
		    != VMMERR_SUCCESS)
			goto init_failed;
	}
	step ++;

	printf("Export.Name = %lX\n", Export.Name);

	//name
	buf = Export.Name + pebase;
	for (i = 0; i < sizeof(strbuf); i++) {
		if (read_linearaddr_b (buf + i, strbuf + i)
		    != VMMERR_SUCCESS)
			goto init_failed;
		if(strbuf[i] == 0)
			break;
	}

	step ++;

	printf("FileName: %s\n", strbuf);
	printf("Number of Functions: %ld\n", Export.NumberOfFunctions);
	printf("Number of Names: %ld\n",Export.NumberOfNames);
	printf("Base: %ld\n", Export.Base);

	//Dump the functions
	//FIXME:各种越界问题
	for(i = 0; i < Export.NumberOfNames; i++){

		succeed = true;

		//Function Ordinals
		addr = pebase + Export.AddressOfNameOrdinals + i * sizeof(u16);
		if(read_linearaddr_w(addr, &shortbuf) != VMMERR_SUCCESS){
			continue;
		}

		//Function Entry Point
		addr = pebase + Export.AddressOfFunctions + (shortbuf + Export.Base - 1) * sizeof(ulong);
		if(read_linearaddr_l(addr, &buf) != VMMERR_SUCCESS){
			continue;
		}
		buf += pebase;

		//Function Name
		addr = pebase + Export.AddressOfNames + i * sizeof(ulong);
		if(read_linearaddr_l(addr, &addr_2) != VMMERR_SUCCESS){
			continue;
		}
		addr = pebase + addr_2;
		for (j = 0; j < sizeof(strbuf); j++) {
			if (read_linearaddr_b (addr + j, strbuf + j)
		    		!= VMMERR_SUCCESS){
				succeed = false;
				break;
			}
			if(strbuf[j] == 0){
				succeed = true;
				break;
			}
		}

		// printf("Name : %s, Entry : %lX\n", strbuf, buf);

		if(succeed){
			if(strbuf[0] == 'Z' && strbuf[1] == 'w'){
				if((err = read_linearaddr_b(buf, &cbuf)) == VMMERR_SUCCESS){
					if(cbuf == 0xb8){
						addr = buf + 1;
						if(read_linearaddr_w(addr, &shortbuf) == VMMERR_SUCCESS){
							//shortbuf = SSDT entry index
							ssdtentry = alloc(sizeof(struct guest_win_kernel_export_function));
							ssdtentry->entrypoint = win_ko.pSSDT + sizeof(ulong) * shortbuf;

							namelen = ((strlen(strbuf) + 1) > FUNCTION_NAME_MAXLEN ? FUNCTION_NAME_MAXLEN : strlen(strbuf) + 1);
							strbuf[0] = 'N';
							strbuf[1] = 't';
							memcpy(ssdtentry->name, strbuf, sizeof(char) * namelen);
							ssdtentry->name[namelen - 1] = 0;			//NULL Terminate It
			
							LIST1_ADD (list_win_kernel_ssdt_entries, ssdtentry);
							//printf("Index : %d, Name : %s, Entry : 0x%lX\n", shortbuf, strbuf, ssdtentry->entrypoint);
						}
					}
				}
			}
		}
	}


	printf("[RKAnalyzer]Get SSDT Table Succeed...\n");

	return;

init_failed:
	printf("[RKAnalyzer]Get SSDT Table Failed!, step = %d, buf= %lX, addr= %lX, err = %d\n", step, buf, addr, err);
	return;
}

static void mmprotect_callback_win_ssdt(struct mm_protected_area *mmarea, virt_t addr)
{
	struct guest_win_kernel_export_function *func;
	virt_t equivaladdr;

	printf("[RKAnalyzer][SSDT]Access Violation at 0x%lX\n", addr);

	if(mmarea->referarea == NULL){
		LIST1_FOREACH (list_win_kernel_ssdt_entries, func) {
			if((addr >= func->entrypoint) && ((addr - func->entrypoint) <= 3)){
				printf("[RKAnalyzer][SSDT]Access Violation at %s\n", func->name);	
				break;
			}
		}
	}else{
		equivaladdr = addr - mmarea->startaddr + mmarea->referarea->startaddr;
		LIST1_FOREACH (list_win_kernel_ssdt_entries, func) {
			if((equivaladdr >= func->entrypoint) && ((equivaladdr - func->entrypoint) <= 3)){
				printf("[RKAnalyzer][SSDT]Access Violation at %s\n", func->name);
				break;	
			}
		}
	}

	return;
}

static void mmprotect_callback_win_pereadonly(struct mm_protected_area *mmarea, virt_t addr)
{
	printf("[RKAnalyzer][PEReadOnly]Access Violation at 0x%lX\n", addr);
}

static void rk_win_protectpereadonlysections()
{
	struct guest_win_pe_section *section;

	LIST1_FOREACH (list_win_pe_sections, section) {
		if((section->characteristics & 0x80000000) == 0) {
			printf("[RKAnalyzer]Protecting Readonly Section %s, VA = 0x%lX, VA_END = 0x%lX, SIZE = 0x%lX bytes\n", section->name, 
			section->va, section->va + section->size - 1, section->size);
			
			if(!rk_protect_mmarea(section->va, section->va + section->size, "PEReadOnly", mmprotect_callback_win_pereadonly, NULL)){
				printf("[RKAnalyzer]Failed Adding MM Area...\n");
			}
		}
	}
}

static void dump_ko(void)
{
	printf("[RKAnalyzer]Kernel Objects Dump:\n");
	printf("[RKAnalyzer]pSDT = 0x%lX\n", win_ko.pSDT);
	printf("[RKAnalyzer]pSSDT = 0x%lX\n", win_ko.pSSDT);
	printf("[RKAnalyzer]NumberOfService = %ld\n", win_ko.NumberOfService);
	printf("[RKAnalyzer]pIDT = 0x%lX\n", win_ko.pIDT);
	printf("[RKAnalyzer]pKernelCodeStart = 0x%lX\n", win_ko.pKernelCodeStart);
	printf("[RKAnalyzer]pKernelCodeEnd = 0x%lX\n", win_ko.pKernelCodeEnd);
	printf("[RKAnalyzer]pNTDLLMaped = 0x%lX\n", win_ko.pNTDLLMaped);
}

static void rk_win_init(void)
{
	//Get Windows Kernel Address From guest
	int i;
	ulong  rbx;
	virt_t base;
	unsigned char* buf = (unsigned char*)&win_ko;
	
	current->vmctl.read_general_reg (GENERAL_REG_RBX, &rbx);
	base = (virt_t)rbx;

	for (i = 0; i < sizeof(struct guest_win_kernel_objects); i++) {
		if (read_linearaddr_b (base + i, buf + i)
		    != VMMERR_SUCCESS)
			goto init_failed;
	}

	dump_ko();
	rk_win_readfromguest();
	rk_win_fill_ssdt_entries(win_ko.pNTDLLMaped);
	rk_win_protectpereadonlysections();

	if(!rk_protect_mmarea(win_ko.pSSDT, win_ko.pSSDT + 4 * win_ko.NumberOfService - 1,"SSDT", mmprotect_callback_win_ssdt, NULL)){
		printf("[RKAnalyzer]Failed Adding MM Area...\n");
	}
	
	return;
	
init_failed:
	memset(&win_ko, 0, sizeof(struct guest_win_kernel_objects));
	printf("[RKAnalyzer]Get Kernel Information Failed!\n");
	return;
}

static void
vmmcall_rk_win_init (void)
{
	vmmcall_register ("rk_win_init", rk_win_init);
	memset(&win_ko, 0, sizeof(struct guest_win_kernel_objects));

	LIST1_HEAD_INIT (list_win_kernel_export_functions);
	LIST1_HEAD_INIT (list_win_kernel_ssdt_entries);
	LIST1_HEAD_INIT (list_win_pe_sections);
	printf("Windows Kernel Symbol Lists Initialized...\n");
}

INITFUNC ("vmmcal0", vmmcall_rk_win_init);

#endif
