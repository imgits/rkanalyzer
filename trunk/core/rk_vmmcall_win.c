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
};

struct guest_win_kernel_export_function{
	LIST1_DEFINE (struct guest_win_kernel_export_function);
	virt_t entrypoint;
	char name[FUNCTION_NAME_MAXLEN];
};

struct guest_win_kernel_objects win_ko;

static LIST1_DEFINE_HEAD (struct guest_win_kernel_export_function, list_win_kernel_export_functions);
static LIST1_DEFINE_HEAD (struct guest_win_kernel_export_function, list_win_kernel_ssdt_entries);

// This functions are useless, just keep for reference on how to parse a PE file section in memory
/*

static void rk_win_readfromguest()
{
	//Parse the PE Section
	//Dump all exported functions.
	int i,j;
	int step = 0;
	int err = 0;
	ulong pebase = 0;
	ulong buf = 0;
	u16 shortbuf = 0;
	ulong addr = 0;
	ulong addr_2 = 0;
	int namelen = 0;
	IMAGE_EXPORT_DIRECTORY Export;
	char strbuf[FUNCTION_NAME_MAXLEN];
	unsigned char* buf_2 = (unsigned char*)&Export;
	bool succeed = false;
	struct guest_win_kernel_export_function *function;
	
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
		addr = pebase + Export.AddressOfFunctions + shortbuf * sizeof(ulong);
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
			
			LIST1_ADD (list_win_kernel_export_functions, function);

		}
	}


	printf("[RKAnalyzer]Get Export Table Succeed...\n");

	return;

init_failed:
	printf("[RKAnalyzer]Get Export Table Failed!, step = %d, buf= %lX, addr= %lX, err = %d\n", step, buf, addr, err);
	return;
}

static void rk_win_fill_ssdt_entries(){
	
	//Try reading .edata section from ntdll.dll...dirty hack but no other method
	//Parse the PE Section
	//Dump all exported functions.
	int i,j;
	int step = 0;
	int err = 0;
	ulong pebase = 0;
	ulong buf = 0;
	u16 shortbuf = 0;
	ulong addr = 0;
	ulong addr_2 = 0;
	int namelen = 0;
	IMAGE_EXPORT_DIRECTORY Export;
	char strbuf[FUNCTION_NAME_MAXLEN];
	unsigned char* buf_2 = (unsigned char*)&Export;
	unsigned char cbuf;
	bool succeed = false;
	struct guest_win_kernel_export_function *ssdtentry;
	
	//Scan for ntdll base
	pebase = 0x80000000;
	while(pebase > 0){
		step = 0;
		succeed = true;
		if(read_linearaddr_l(pebase, &buf) == VMMERR_SUCCESS){
			if(buf == 0x00905A4D){
				//Found 'MZ'
				//Test if the ImageSize is bigger than 0x80000
				addr = pebase + rk_struct_win_offset(IMAGE_DOS_HEADER, e_lfanew);
				if((err = read_linearaddr_l(addr, &buf)) == VMMERR_SUCCESS){
					//buf = pExportDirectory
					addr = pebase + buf + rk_struct_win_offset(IMAGE_NT_HEADERS, 
						OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
					if((err = read_linearaddr_l(addr, &buf)) == VMMERR_SUCCESS){
						buf += pebase;

						for (i = 0; i < sizeof(IMAGE_EXPORT_DIRECTORY); i++) {
							if ((err = read_linearaddr_b (buf + i, buf_2 + i))
							    != VMMERR_SUCCESS){
								printf("Failed at 2, reason : %d\n", err);
								succeed = false;
								break;
							}
						}

						if(!succeed)
							goto nextcircle;
				
						step++;

						//name
						buf = Export.Name + pebase;
						for (i = 0; i < sizeof(strbuf); i++) {
							if ((err = read_linearaddr_b (buf + i, strbuf + i))
							    != VMMERR_SUCCESS){
								printf("Failed at 3, reason : %d\n", err);
								succeed = false;
								break;
							}
							if(strbuf[i] == 0)
								break;
						}
				
						if(!succeed)
							goto nextcircle;
				
						step++;
				
						printf("%s\n", strbuf);

						//Check if name = "ntdll.dll"
						if(strcmp(strbuf, "ntdll.dll") == 0){
							break;
						}
					}
					else{
						printf("Failed at 1, reason : %d\n", err);
					}
				}
				else{
					printf("Failed at 0, reason : %d\n", err);
				}
			}
		}

nextcircle:
		pebase = pebase >> PAGESIZE_SHIFT;
		pebase --;
		pebase = pebase << PAGESIZE_SHIFT;
	}

	if(pebase <= 0){
		goto init_failed;
	}
	step ++;

	printf("FileName: %s\n", strbuf);
	printf("Number of Functions: %ld\n", Export.NumberOfFunctions);
	printf("Number of Names: %ld\n",Export.NumberOfNames);

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
		addr = pebase + Export.AddressOfFunctions + shortbuf * sizeof(ulong);
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

		printf("Name : %s, Entry : %lX\n", strbuf, buf);

		if(succeed){
			if(strbuf[0] == 'N' && strbuf[1] == 't'){
				if((err = read_linearaddr_b(buf, &cbuf)) == VMMERR_SUCCESS){
					if(cbuf == 0xb8){
						addr = buf;
						if(read_linearaddr_l(addr, &buf) == VMMERR_SUCCESS){
							//buf = SSDT entry index
							ssdtentry = alloc(sizeof(struct guest_win_kernel_export_function));
							ssdtentry->entrypoint = win_ko.pSSDT + sizeof(ulong) * buf;

							namelen = (strlen(strbuf) > FUNCTION_NAME_MAXLEN ? FUNCTION_NAME_MAXLEN : strlen(strbuf));
							memcpy(ssdtentry->name, strbuf, sizeof(char) * namelen);
			
							LIST1_ADD (list_win_kernel_ssdt_entries, ssdtentry);
							printf("Index : %d, Name : %s\n", buf, strbuf);
						}
						else{
							printf("Failed 6, err = %d\n", err);
						}
					}
					else{
						printf("Failed 5, cbuf = %x\n", cbuf);
					}
				}
				else{
					printf("Failed 4, err = %d\n", err);
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

*/

static void mmprotect_callback_win_ssdt(struct mm_protected_area *mmarea, virt_t addr)
{

	printf("[RKAnalyzer][SSDT]Access Violation at 0x%lX\n", addr);

	return;
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

	if(!rk_protect_mmarea(win_ko.pSSDT, win_ko.pSSDT + 4 * win_ko.NumberOfService,"SSDT", mmprotect_callback_win_ssdt)){
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

}

INITFUNC ("vmmcal0", vmmcall_rk_win_init);

#endif
