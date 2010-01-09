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
#include "rk_nx.h"
#include "rk_struct_win.h"
#include "cpu.h"

#ifdef RK_ANALYZER

#define NAME_MAXLEN 256
#define MAX_OBJTYPENAME_LENGTH 100

#define PROPERTY_CALLERADDR 0
#define PROPERTY_POOLTYPE 1
#define PROPERTY_ALLOCSIZE 2
#define PROPERTY_TAG 3
#define PROPERTY_ALLOCADDR 4
#define KERNEL_HEAP_PROPERTYS_COUNT 5

#define CALL_LIST_WARN_COUNT	20

struct guest_win_pe_section{
	LIST1_DEFINE (struct guest_win_pe_section);
	virt_t va;
	ulong size;
	ulong characteristics;
	char name[NAME_MAXLEN];
};

struct guest_win_pe_symbol{
	LIST1_DEFINE (struct guest_win_pe_symbol);
	ulong va;
	char name[NAME_MAXLEN];
};

struct guest_win_pe{
	LIST1_DEFINE (struct guest_win_pe);
	LIST1_DEFINE_HEAD (struct guest_win_pe_section, list_sections);
	LIST1_DEFINE_HEAD (struct guest_win_pe_symbol, list_data_symbols);
	LIST1_DEFINE_HEAD (struct guest_win_pe_symbol, list_code_symbols);
	ulong imagebase;
	ulong size;
	char name[NAME_MAXLEN];
};

/*
	OS Dependent Structures. Put here for convienience
*/
struct guest_win_exallocatepoolwithtag_call_info{
	LIST1_DEFINE (struct guest_win_exallocatepoolwithtag_call_info);
	ulong retaddr;
	ulong param_pooltype;
	ulong param_numberofbytes;
	ulong param_tag;
	ulong retval;
};

struct guest_win_exallocatepoolwithtag_call_info_stack{
	LIST1_DEFINE (struct guest_win_exallocatepoolwithtag_call_info_stack);
	LIST1_DEFINE_HEAD (struct guest_win_exallocatepoolwithtag_call_info, call_info_stack_in_thread);
	ulong kthread_addr;
};

static volatile ulong kernelbase;
static struct guest_win_pe kernel_pe;
static spinlock_t call_info_access_lock;
static volatile ulong call_info_list_watchdog;
static volatile ulong call_info_list_current_count;
static spinlock_t call_info_watchdog_lock;

static LIST1_DEFINE_HEAD (struct guest_win_pe, list_legal_pes);
static LIST1_DEFINE_HEAD (struct guest_win_pe, list_illegal_pes);
static LIST1_DEFINE_HEAD (struct guest_win_exallocatepoolwithtag_call_info_stack, list_call_info);	//call info stack for ExAllocatePoolWithTag in Windows

static inline void init_pe_struct(struct guest_win_pe *p_pe)
{
	LIST1_HEAD_INIT(p_pe->list_sections);
	LIST1_HEAD_INIT(p_pe->list_data_symbols);
	LIST1_HEAD_INIT(p_pe->list_code_symbols);
	memset(p_pe->name, 0, sizeof(char) * NAME_MAXLEN);
}

static void rk_win_call_info_check_watchdog(bool increment)
{
	ulong temp;
	
	spinlock_lock(&call_info_watchdog_lock);
	if(increment){
		call_info_list_current_count++;
		if(call_info_list_current_count > call_info_list_watchdog){
			temp = call_info_list_current_count;
			call_info_list_watchdog = call_info_list_current_count;
			spinlock_unlock(&call_info_watchdog_lock);
			printf("[RKAnalyzer][Watchdog]Call Info List Count Too Much. Current Count %ld.\n", temp);
		}
		else
		{
			spinlock_unlock(&call_info_watchdog_lock);
		}
	}
	else{
		if(call_info_list_current_count == 0){
			spinlock_unlock(&call_info_watchdog_lock);
			printf("[RKAnalyzer][Watchdog]Call Info List Count Fall Below 0.\n");
		}
		else{
			call_info_list_current_count--;
			spinlock_unlock(&call_info_watchdog_lock);
		}
	}
}

static bool rk_win_getentryaddrbyname(const char *name, virt_t *pEntrypoint)
{
	struct guest_win_pe_symbol *func;

	LIST1_FOREACH (kernel_pe.list_code_symbols, func) {
		if(strcmp(func->name, (char *)name) == 0){
			*pEntrypoint = func->va;
			return true;
		}
	}

	return false;
}

static bool rk_win_is_system_code(virt_t inst_addr)
{
	struct guest_win_pe_section *section;

	LIST1_FOREACH (kernel_pe.list_sections, section) {
		if(((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) && 
			(inst_addr >= section->va) && (inst_addr <= (section->va + section->size - 1)))
		{
			return true;
		}
	}

	return false;
}

static bool rk_win_is_code_in_pe(struct guest_win_pe *p_pe, virt_t inst_addr)
{
	struct guest_win_pe_section *section;

	LIST1_FOREACH (p_pe->list_sections, section) {
		if(((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) && 
			(inst_addr >= section->va) && (inst_addr <= (section->va + section->size - 1)))
		{
			return true;
		}
	}

	return false;
}

static bool rk_win_is_code_in_legal_pe_list(virt_t inst_addr)
{
	struct guest_win_pe_section *section;
	struct guest_win_pe *pe;

	LIST1_FOREACH (list_legal_pes, pe){
		LIST1_FOREACH (pe->list_sections, section) {
			if(((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) && 
				(inst_addr >= section->va) && (inst_addr <= (section->va + section->size - 1)))
			{
				return true;
			}
		}
	}

	return false;
}

static bool rk_win_is_code_in_illegal_pe_list(virt_t inst_addr)
{
	struct guest_win_pe_section *section;
	struct guest_win_pe *pe;

	LIST1_FOREACH (list_illegal_pes, pe){
		LIST1_FOREACH (pe->list_sections, section) {
			if(((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) && 
				(inst_addr >= section->va) && (inst_addr <= (section->va + section->size - 1)))
			{
				return true;
			}
		}
	}

	return false;
}

static ulong rk_win_get_current_kthread_addr()
{
	ulong kpcr;
	ulong retval = 0;
	
	current->vmctl.read_sreg_base(SREG_FS, &kpcr);
	
	if (read_linearaddr_l (kpcr + CURRENT_THREAD_OFFSET_IN_KPCR, &retval) != VMMERR_SUCCESS){
			printf("error reading kpcr.kthread");
	}
	
	return retval;
}

static struct guest_win_exallocatepoolwithtag_call_info* rk_win_get_call_info_by_kthread_addr(ulong kthread_addr, bool pop)
{
	struct guest_win_exallocatepoolwithtag_call_info_stack* call_info_stack;
	struct guest_win_exallocatepoolwithtag_call_info_stack* call_info_stack_n;
	struct guest_win_exallocatepoolwithtag_call_info* call_info;
	
	spinlock_lock(&call_info_access_lock);
	LIST1_FOREACH_DELETABLE(list_call_info, call_info_stack, call_info_stack_n){
		if(call_info_stack->kthread_addr == kthread_addr){
			if(LIST1_EMPTY(call_info_stack->call_info_stack_in_thread)){
				call_info = NULL;
				LIST1_DEL(list_call_info, call_info_stack);
				free(call_info_stack);
			}
			else{
				call_info = LIST1_POP(call_info_stack->call_info_stack_in_thread);
				if(pop){
					if(LIST1_EMPTY(call_info_stack->call_info_stack_in_thread)){
						LIST1_DEL(list_call_info, call_info_stack);
						free(call_info_stack);
					}
				}
				else{
					//not pop, push it back
					LIST1_PUSH(call_info_stack->call_info_stack_in_thread, call_info);
				}
			}
			spinlock_unlock(&call_info_access_lock);
			return call_info;
		}
	}
	
	spinlock_unlock(&call_info_access_lock);
	return NULL;
}

static void rk_win_add_call_info_by_kthread_addr(ulong kthread_addr, struct guest_win_exallocatepoolwithtag_call_info* call_info){

	struct guest_win_exallocatepoolwithtag_call_info_stack* call_info_stack;
	
	spinlock_lock(&call_info_access_lock);
	LIST1_FOREACH(list_call_info, call_info_stack){
		if(call_info_stack->kthread_addr == kthread_addr){
			LIST1_PUSH(call_info_stack->call_info_stack_in_thread, call_info);
			spinlock_unlock(&call_info_access_lock);
			return;
		}
	}
	
	call_info_stack = alloc(sizeof(struct guest_win_exallocatepoolwithtag_call_info_stack));
	call_info_stack->kthread_addr = kthread_addr;
	LIST1_HEAD_INIT(call_info_stack->call_info_stack_in_thread);
	LIST1_PUSH(call_info_stack->call_info_stack_in_thread, call_info);
	LIST1_ADD(list_call_info, call_info_stack);
	
	spinlock_unlock(&call_info_access_lock);
}

//Use DR0 and DR2, DR3 here.
static void rk_win_setdebugregister()
{
	virt_t pCallEntry;
	virt_t pCallEntry_2;
	virt_t res;
	ulong dr7;
	struct rk_tf_state *p_rk_tf = current->vmctl.get_struct_rk_tf();

	if (rk_win_getentryaddrbyname("ExAllocatePoolWithTag", &pCallEntry) && 
	rk_win_getentryaddrbyname("ExFreePoolWithTag", &pCallEntry_2) && (kernelbase != 0)) {
		asm volatile ("mov %%db0, %0" : "=r"(res));
		p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR0;
		p_rk_tf->dr0_shadow = res;
		asm volatile ("mov %0, %%db0" : : "r"(pCallEntry));
		asm volatile ("mov %%db2, %0" : "=r"(res));
		p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR2;
		p_rk_tf->dr2_shadow = res;
		asm volatile ("mov %0, %%db2" : : "r"(pCallEntry_2));
		asm volatile ("mov %%db3, %0" : "=r"(res));
		p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR3;
		p_rk_tf->dr2_shadow = res;
		asm volatile ("mov %0, %%db3" : : "r"(kernelbase + SWAP_CONTEXT_ENTRY_OFFSET_IN_KERNEL));
		asm_vmread(VMCS_GUEST_DR7, &dr7);
		p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR7;
		p_rk_tf->dr7_shadow = dr7;
		dr7 |= 0x2;	//DR7.G0 = 1
		dr7 |= 0x20;	//DR7.G2 = 1
		dr7 |= 0x80;	//DR7.G3 = 1
		dr7 &= 0x00F0FFFF;	//DR7.R/W0 = 00, DR7.LEN0 = 00; DR7.R/W2 = 00, DR7.LEN2 = 00; DR7.R/W3 = 00, DR7.LEN3 = 00
		asm_vmwrite(VMCS_GUEST_DR7, dr7);
		printf("Debug Register Set. DR0 = 0x%lx, DR2 = 0x%lx, DR3 = 0x%lx, DR7 =  0x%lx\n", 
			pCallEntry, pCallEntry_2, kernelbase + SWAP_CONTEXT_ENTRY_OFFSET_IN_KERNEL, dr7);
	}
}

static void rk_win_set_dr1_to_virt(virt_t addr)
{
	virt_t res;
	ulong dr7;
	struct rk_tf_state *p_rk_tf = current->vmctl.get_struct_rk_tf();

	asm volatile ("mov %%db1, %0" : "=r"(res));
	p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR1;
	p_rk_tf->dr1_shadow = res;
	asm volatile ("mov %0, %%db1" : : "r"(addr));
	asm_vmread(VMCS_GUEST_DR7, &dr7);
	dr7 |= 0x8;	//DR7.G1 = 1
	dr7 &= 0xFF0FFFFF;	//DR7.R/W1 = 00, DR7.LEN1 = 00;
	asm_vmwrite(VMCS_GUEST_DR7, dr7);
	//printf("Debug Register Set. DR1 = 0x%lx, DR7 =  0x%lx\n", addr, dr7);
}

static void rk_win_remove_dr1()
{
	ulong dr7;
	struct rk_tf_state *p_rk_tf = current->vmctl.get_struct_rk_tf();

	p_rk_tf->dr_shadow_flag &= (~(DR_SHADOW_DR1));
	asm volatile ("mov %0, %%db1" : : "r"(p_rk_tf->dr1_shadow));
	asm_vmread(VMCS_GUEST_DR7, &dr7);
	dr7 &= (~(0x8));	//DR7.G1 = 0
	asm_vmwrite(VMCS_GUEST_DR7, dr7);
	//printf("Debug Register 1 Removed.\n");
}

static bool mmprotect_callback_win_pereadonly(struct mm_protected_area *mmarea, virt_t addr, bool display)
{
	if(display)
	{
		printf("[RKAnalyzer][PEReadOnly]Access Violation at 0x%lX\n", addr);
	}
	
	return true;
}

static bool mmprotect_callback_win_kernelheap(struct mm_protected_area *mmarea, virt_t addr, bool display)
{
	ulong ip;

	if(display)
	{
		current->vmctl.read_ip(&ip);
		
		if(!(rk_win_is_system_code(ip)))
		{
			dbgprint("[RKAnalyzer][KernelHeap]Access Violation at 0x%lX, eip = 0x%lX\n", addr, ip);
			if(mmarea->varange->properties != NULL){
				dbgprint("[RKAnalyzer][KernelHeap]Heap Info: Allocer = 0x%lX, Type = 0x%lX, Tag = 0x%lX, Size = 0x%lX\n", 
					mmarea->varange->properties[PROPERTY_CALLERADDR], mmarea->varange->properties[PROPERTY_POOLTYPE], 
					mmarea->varange->properties[PROPERTY_TAG], mmarea->varange->properties[PROPERTY_ALLOCSIZE]);
			}
			return true;
		}
		
	}
	
	if(is_debug()){
		return true;
	}
	else{
		return false;
	}
}

static bool mmcode_callback_general (struct mm_code_varange* mmvarange, virt_t addr, bool display)
{
	return true;
}

static void rk_win_dr_dispatch(int debug_num)
{
	ulong esp, eax, ppool, edi, esi;
//	struct guest_win_obcreateobject_call_info call_info;
	struct guest_win_exallocatepoolwithtag_call_info call_info;
	struct guest_win_exallocatepoolwithtag_call_info *exalloc_call_info;
	ulong properties[10];
	struct rk_tf_state *p_rk_tf = current->vmctl.get_struct_rk_tf();

	switch(debug_num){
	case 0:
		//ObCreateObject
/*
		printf("ObCreateObject Hit!\n");
		// Current Stack:
		// +0x24 Object(DWORD) 
		// +0x20 NonPagedPoolCharge(DWORD) 
		// +0x1C PagedPoolCharge(DWORD) 
		// +0x18 ObjectBodySize(DWORD) 
		// +0x14 ParseContext(DWORD) 
		// +0x10 OwnerShipMode(CCHAR) 
		// +0xC ObjectAttributes(DWORD) 
		// +0x8 ObjectType(DWORD) 
		// +0x4 ProbeMode(CCHAR) 
		// +0 address(DWORD) <- esp
		current->vmctl.read_general_reg( GENERAL_REG_RSP, &esp);
		if (read_linearaddr_l (esp, &(call_info.retaddr)) != VMMERR_SUCCESS){
			printf("error on 0x0");
		}
		if (read_linearaddr_l (esp + 0x18 , &(call_info.param_objbodysize)) != VMMERR_SUCCESS){
			printf("error on 0x18");
		}
		if (read_linearaddr_l (esp + 0x24, &(call_info.param_ppobj)) != VMMERR_SUCCESS){
			printf("error on 0x24");
		}
		printf("Call Info: Caller=0x%lx, ObjBodySize=0x%lx, PPObj=0x%lx\n", call_info.retaddr, call_info.param_objbodysize, call_info.param_ppobj);
*/

		//ExAllocatePoolWithTag
		// Current Stack:
		// +0xC Tag(DWORD) 
		// +0x8 NumberOfBytes(DWORD) 
		// +0x4 PoolType(DWORD) 
		// +0 address(DWORD) <- esp
		current->vmctl.read_general_reg( GENERAL_REG_RSP, &esp);
		if (read_linearaddr_l (esp, &(call_info.retaddr)) != VMMERR_SUCCESS){
			printf("error on 0x0");
		}
		if (read_linearaddr_l (esp + 0x4 , &(call_info.param_pooltype)) != VMMERR_SUCCESS){
			printf("error on 0x4");
		}
		if (read_linearaddr_l (esp + 0x8, &(call_info.param_numberofbytes)) != VMMERR_SUCCESS){
			printf("error on 0x8");
		}
		if (read_linearaddr_l (esp + 0xC, &(call_info.param_tag)) != VMMERR_SUCCESS){
			printf("error on 0xC");
		}
		if (rk_win_is_system_code(call_info.retaddr)){

			exalloc_call_info = alloc(sizeof(struct guest_win_exallocatepoolwithtag_call_info));
			if(exalloc_call_info != NULL){
				exalloc_call_info->retaddr = call_info.retaddr;
				exalloc_call_info->param_pooltype = call_info.param_pooltype;
				exalloc_call_info->param_numberofbytes = call_info.param_numberofbytes;
				exalloc_call_info->param_tag = call_info.param_tag;
				
				rk_win_add_call_info_by_kthread_addr(rk_win_get_current_kthread_addr(), exalloc_call_info);

				rk_win_call_info_check_watchdog(true);
				
				//Set DR1 to the retaddr. clear interrupts to disable thread switch
				//Because in exception handlers, they won't call ExAllocate functions. so it is garuanteend to obtain the return value
				rk_win_set_dr1_to_virt(call_info.retaddr);
			}
		}
		break;
	case 1:
		current->vmctl.read_general_reg( GENERAL_REG_RAX, &eax);
		
		exalloc_call_info = rk_win_get_call_info_by_kthread_addr(rk_win_get_current_kthread_addr(), true);
		if(exalloc_call_info == NULL){
			printf("Strange Status. Return Addr of ExAllocatePoolWithTag not monitored but hit.\n");
		}
		else{
			exalloc_call_info->retval = eax;
			
			if((exalloc_call_info->retval != 0) && (exalloc_call_info->param_tag == (0x636f7250 | 0x80000000))){
				//printf("[CPU %d]Call Info: Caller=0x%lx, PoolType=0x%lx, NumberOfBytes=0x%lx, Tag=0x%lX, RetVal=0x%lX\n", get_cpu_id(), 
				//exalloc_call_info->retaddr, exalloc_call_info->param_pooltype, exalloc_call_info->param_numberofbytes, 
				//exalloc_call_info->param_tag, exalloc_call_info->retval);

				//Add it to protection list
				properties[PROPERTY_CALLERADDR] = exalloc_call_info->retaddr;
				properties[PROPERTY_POOLTYPE] = exalloc_call_info->param_pooltype;
				properties[PROPERTY_ALLOCSIZE] = exalloc_call_info->param_numberofbytes;
				properties[PROPERTY_TAG] = exalloc_call_info->param_tag;
				properties[PROPERTY_ALLOCADDR] = exalloc_call_info->retval;
			
				rk_protect_mmarea(exalloc_call_info->retval, exalloc_call_info->retval + exalloc_call_info->param_numberofbytes - 1, 
				"KRNLHEAP", mmprotect_callback_win_kernelheap, properties, KERNEL_HEAP_PROPERTYS_COUNT);
			}
			free(exalloc_call_info);
			
			rk_win_call_info_check_watchdog(false);
		}
		//If there are still calls in the stack, set dr1 to the top of the stack.
		exalloc_call_info = rk_win_get_call_info_by_kthread_addr(rk_win_get_current_kthread_addr(), false);
		if(exalloc_call_info == NULL){
			rk_win_remove_dr1();
		}
		else{
			rk_win_set_dr1_to_virt(exalloc_call_info->retaddr);
		}
		break;
	case 2:
		//ExFreePoolWithTag
		// Current Stack:
		// +0x8 Tag(DWORD) 
		// +0x4 PPool(DWORD) 
		// +0 address(DWORD) <- esp
		current->vmctl.read_general_reg( GENERAL_REG_RSP, &esp);
		if (read_linearaddr_l (esp + 0x4 , &(ppool)) != VMMERR_SUCCESS){
			printf("error on 0x4");
		}
		
		if(rk_unprotect_mmarea(ppool, 0)){
			//printf("[CPU %d]Unprotect OK: Pool = 0x%lX\n", get_cpu_id(), ppool);
		}
		
		break;
	case 3:
		//SwapContext
		// edi - Address of previous thread
		// esi - Address of next thread
		current->vmctl.read_general_reg( GENERAL_REG_RDI, &edi);
		current->vmctl.read_general_reg( GENERAL_REG_RSI, &esi);
		
		exalloc_call_info = rk_win_get_call_info_by_kthread_addr(esi, false);
		if(exalloc_call_info == NULL){
			//Switched to a thread not monitored
			rk_win_remove_dr1();
		}
		else{
			rk_win_set_dr1_to_virt(exalloc_call_info->retaddr);
			//printf("[CPU %d]Switch To:Caller = 0x%lX\n", get_cpu_id(), exalloc_call_info->retaddr);
		}
		break;
	default:
		break;
	}

	//Set the EFLAGS.RF = 1 to avoid recursion
	p_rk_tf->should_set_rf_befor_entry = true;
}

//scankernel = true -> scan kernel, ignore, hint_addr
//scankernel = false -> scan for PE, from hint_addr to lower space
static bool rk_win_readfromguest(struct guest_win_pe *p_pe, bool scankernel, virt_t hint_addr)
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
	char strbuf[NAME_MAXLEN];
	unsigned char* buf_2 = (unsigned char*)&Export;
	bool succeed = false;
	struct guest_win_pe_symbol *function;
	struct guest_win_pe_section *section;
	ulong addr_section_header = 0;
	u16 numberOfSections = 0;
	IMAGE_SECTION_HEADER section_header;
	unsigned char* p_section_header = (unsigned char*)&section_header;
	u8 sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
	
	if(p_pe == NULL)
	{
		return false;
	}

	//Scan for Ntoskrnl base
	if(scankernel){
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
	}
	else{
		pebase = (hint_addr >> PAGESIZE_SHIFT) << PAGESIZE_SHIFT;	//PE Always load at page aligned addr
		while(pebase >= 0x80000000){
			if(read_linearaddr_l(pebase, &buf) == VMMERR_SUCCESS){
				if(buf == 0x00905A4D){
					//Found 'MZ'
					//TODO: Test 'PE' Flag
					break;
				}
			}
			pebase = pebase >> PAGESIZE_SHIFT;
			pebase --;
			pebase = pebase << PAGESIZE_SHIFT;
		}

		if(pebase < 0x80000000){
			goto init_failed;
		}
		step ++;
	}

	if(scankernel)
	{
		kernelbase = pebase;
	}

	//buf = pNTHeader
	addr = pebase + rk_struct_win_offset(IMAGE_DOS_HEADER, e_lfanew);
	err = read_linearaddr_l(addr, &buf);
	if (err != VMMERR_SUCCESS)
		goto init_failed;
	buf += pebase;
	pNTHeader = buf;
	step ++;
	
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
		//printf("Section Name = %s, VA = 0x%X, SIZE = %d bytes, Flags = 0x%X\n", sectionName, 
		//	section_header.VirtualAddress, section_header.SizeOfRawData, section_header.Characteristics);

		section = alloc(sizeof(struct guest_win_pe_section));
		section->va = pebase + section_header.VirtualAddress;
		section->size = section_header.SizeOfRawData;
		memcpy(section->name, sectionName, sizeof(u8) * IMAGE_SIZEOF_SHORT_NAME);
		section->name[IMAGE_SIZEOF_SHORT_NAME] = 0;
		section->characteristics = section_header.Characteristics;

		LIST1_ADD (p_pe->list_sections, section);
	}
	step ++;
	
	if((!scankernel) && (!rk_win_is_code_in_pe(p_pe, hint_addr)))
	{
		//It's a fake PE!!!!!!!
		return false;
	}
	
	printf("Hint = %lX, Base = %lX\n", hint_addr, pebase);
	
	if(scankernel)
	{
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
			if ((err = read_linearaddr_b (buf + i, buf_2 + i))
				!= VMMERR_SUCCESS)
				goto init_failed;
		}
		step ++;

		printf("Export.Name = %X\n", Export.Name);

		//name
		buf = Export.Name + pebase;
		for (i = 0; i < sizeof(strbuf); i++) {
			if ((err = read_linearaddr_b (buf + i, strbuf + i))
				!= VMMERR_SUCCESS)
				goto init_failed;
			if(strbuf[i] == 0)
				break;
		}
		printf("FileName: %s\n", strbuf);
		printf("Number of Functions: %d\n", Export.NumberOfFunctions);
		printf("Number of Names: %d\n",Export.NumberOfNames);

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
			addr = pebase + Export.AddressOfFunctions + (shortbuf + Export.Base - 1) * sizeof(u32);
			if(read_linearaddr_l(addr, &buf) != VMMERR_SUCCESS){
				continue;
			}
			buf += pebase;

			//Function Name
			addr = pebase + Export.AddressOfNames + i * sizeof(u32);
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
				function = alloc(sizeof(struct guest_win_pe_symbol));
				function->va = buf;

				namelen = (strlen(strbuf) > (NAME_MAXLEN - 1) ? (NAME_MAXLEN - 1) : strlen(strbuf));
				memcpy(function->name, strbuf, sizeof(char) * namelen);
				function->name[namelen] = 0;			//NULL Terminate It

				LIST1_ADD (p_pe->list_code_symbols, function);
				//printf("Name : %s, Entry : 0x%lX\n", function->name, function->entrypoint);
			}
		}


		printf("[RKAnalyzer]Get Export Table Succeed...\n");
	}

	return true;

init_failed:
	printf("[RKAnalyzer]Fail To Read PE!, step = %d, buf= %lX, addr= %lX, err = %d\n", step, buf, addr, err);
	return false;
}

static void rk_win_protectpereadonlysections(struct guest_win_pe *p_pe)
{
	struct guest_win_pe_section *section;

	if(p_pe == NULL){
		return;
	}

	LIST1_FOREACH (p_pe->list_sections, section) {
		if((section->characteristics & IMAGE_SCN_MEM_WRITE) == 0) {
			printf("[RKAnalyzer]Protecting Readonly Section %s, VA = 0x%lX, VA_END = 0x%lX, SIZE = 0x%lX bytes\n", section->name, 
			section->va, section->va + section->size - 1, section->size);
			
			if(!rk_protect_mmarea(section->va, section->va + section->size - 1, "PEReadOnly", mmprotect_callback_win_pereadonly, NULL, 0))
			{
				printf("[RKAnalyzer]Failed Adding MM Area...\n");
			}
		}
	}
}

static enum rk_code_type rk_win_unknown_code_check_dispatch(virt_t addr)
{
	struct guest_win_pe_section *section;
	
	if(rk_win_is_code_in_legal_pe_list(addr)){
		return RK_CODE_LEGAL;
	}
	
	if(rk_win_is_code_in_illegal_pe_list(addr)){
		return RK_CODE_ILLEGAL;
	}
	
	struct guest_win_pe *new_pe = alloc(sizeof(struct guest_win_pe));
	init_pe_struct(new_pe);
	if(rk_win_readfromguest(new_pe, false, addr))
	{
		LIST1_ADD(list_illegal_pes, new_pe);
		//rk_win_protectpereadonlysections(new_pe);
		LIST1_FOREACH (new_pe->list_sections, section) {
			if((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
				rk_add_code_mmvarange_nolock(false, section->va, section->va + section->size - 1, mmcode_callback_general);
		}
	}
	else{
		free(new_pe);
		
		//Add as a scratch
		rk_add_code_mmvarange_nolock(false, addr, addr, mmcode_callback_general);
	}
	
	return RK_CODE_ILLEGAL;
}

void rk_win_os_dep_setter(void)
{	
	os_dep.dr_dispatcher = rk_win_dr_dispatch;
	os_dep.va_kernel_start = 0x80000000;
	os_dep.unknown_code_check_dispatcher = rk_win_unknown_code_check_dispatch;
}

bool rk_win_init_global(virt_t base)
{
	int i;
	struct guest_win_pe_section *section;
	
	if(!rk_try_setup_global(rk_win_os_dep_setter)){
		return true;
	}

	printf("[RKAnalyzer]Setup Memory Areas To Protect...\n");


	rk_win_readfromguest(&kernel_pe, true, 0);
	LIST1_ADD(list_legal_pes, &kernel_pe);
	rk_win_protectpereadonlysections(&kernel_pe);
	
	LIST1_FOREACH (kernel_pe.list_sections, section) {
		if((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
			rk_add_code_mmvarange_nolock(true, section->va, section->va + section->size - 1, mmcode_callback_general);
	}
	
	printf("[RKAnalyzer]Global Initialized on CPU %d.\n", get_cpu_id());
	
	return true;
	
init_failed:
	printf("[RKAnalyzer]Get Kernel Information Failed!\n");
	return false;
}

bool rk_win_init_per_vcpu(void)
{
	if(!rk_try_setup_per_vcpu()){
		return true;
	}

	//rk_win_setdebugregister();
	printf("[RKAnalyzer]CPU %d Initialized.\n", get_cpu_id());
	
	return true;
}

static void rk_win_init(void)
{
	//Get Windows Kernel Address From guest
	ulong  rbx;
	virt_t base;
	
	current->vmctl.read_general_reg (GENERAL_REG_RBX, &rbx);
	base = (virt_t)rbx;

	if(!(rk_win_init_global(base))){
		return;
	}
	
	if(!(rk_win_init_per_vcpu())){
		return;
	}
}

static void
vmmcall_rk_win_init (void)
{
	vmmcall_register ("rk_win_init", rk_win_init);
	kernelbase = 0;
	call_info_list_watchdog = CALL_LIST_WARN_COUNT;
	call_info_list_current_count = 0;
	init_pe_struct(&kernel_pe);

	LIST1_HEAD_INIT (list_legal_pes);
	LIST1_HEAD_INIT (list_illegal_pes);
	LIST1_HEAD_INIT (list_call_info);
	spinlock_init(&call_info_access_lock);
	spinlock_init(&call_info_watchdog_lock);
	printf("RKAnalyzer Windows Module Initialized...\n");
}

INITFUNC ("vmmcal0", vmmcall_rk_win_init);

#endif
