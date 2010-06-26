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
#include "desc.h"

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
	ulong va;	//absolute va, not rva
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
	char fullname[NAME_MAXLEN];
	bool legal;
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

struct guest_win_pe_base_filter{
	LIST1_DEFINE (struct guest_win_pe_base_filter);
	ulong imagebase;
};

static volatile ulong kernelbase;
static struct guest_win_pe kernel_pe;
static spinlock_t call_info_access_lock;
static volatile ulong call_info_list_watchdog;
static volatile ulong call_info_list_current_count;
static spinlock_t call_info_watchdog_lock;
static spinlock_t global_init_lock;

static LIST1_DEFINE_HEAD (struct guest_win_pe, list_pes);
static LIST1_DEFINE_HEAD (struct guest_win_pe_base_filter, list_pe_base_filter);
static LIST1_DEFINE_HEAD (struct guest_win_exallocatepoolwithtag_call_info_stack, list_call_info);	//call info stack for ExAllocatePoolWithTag in Windows

static void rk_win_init(void);
static bool rk_win_check_for_kernel(void);

static bool
guest64 (void)
{
	u64 efer = 0;

	current->vmctl.read_msr (MSR_IA32_EFER, &efer);
	if (efer & MSR_IA32_EFER_LMA_BIT)
		return true;
	return false;
}

static inline void init_pe_struct(struct guest_win_pe *p_pe)
{
	LIST1_HEAD_INIT(p_pe->list_sections);
	LIST1_HEAD_INIT(p_pe->list_data_symbols);
	LIST1_HEAD_INIT(p_pe->list_code_symbols);
	memset(p_pe->name, 0, sizeof(char) * NAME_MAXLEN);
	memset(p_pe->fullname, 0, sizeof(char) * NAME_MAXLEN);
}

static void rk_win_call_info_check_watchdog(bool increment)
{
	ulong temp = 0;
	
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
	struct guest_win_pe_symbol *func = NULL;

	LIST1_FOREACH (kernel_pe.list_code_symbols, func) {
		if(strcmp(func->name, (char *)name) == 0){
			*pEntrypoint = func->va;
			return true;
		}
	}

	return false;
}

static struct guest_win_pe_symbol* rk_win_getsymbolbyentry_precise(virt_t pEntrypoint)
{
	struct guest_win_pe_symbol *func = NULL;

	LIST1_FOREACH (kernel_pe.list_code_symbols, func) {
		if(pEntrypoint == func->va){
			return func;
		}
	}

	return NULL;
}

static struct guest_win_pe_symbol* rk_win_getsymbolbyentry(virt_t pEntrypoint)
{
	struct guest_win_pe_symbol *func = NULL;
	struct guest_win_pe_symbol *ret_func = NULL;
	ulong diff = 0xFFFFFFFF;

	LIST1_FOREACH (kernel_pe.list_code_symbols, func) {
		if(pEntrypoint >= func->va){
			if((pEntrypoint - func->va) < diff){
				diff = (pEntrypoint - func->va);
				ret_func = func;
			}
		}
	}

	return ret_func;
}

static bool rk_win_is_system_code(virt_t inst_addr)
{
	struct guest_win_pe_section *section = NULL;

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
	struct guest_win_pe_section *section = NULL;

	LIST1_FOREACH (p_pe->list_sections, section) {
		if(((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) && 
			(inst_addr >= section->va) && (inst_addr <= (section->va + section->size - 1)))
		{
			return true;
		}
	}

	return false;
}

static struct guest_win_pe* rk_win_get_pe_from_code_addr(virt_t inst_addr)
{
	struct guest_win_pe_section *section = NULL;
	struct guest_win_pe *pe = NULL;
	
	LIST1_FOREACH (list_pes, pe){
		LIST1_FOREACH (pe->list_sections, section) {
			if(((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) && 
				(inst_addr >= section->va) && (inst_addr <= (section->va + section->size - 1)))
			{
				return pe;
			}
		}
	}
	
	return NULL;
}

static bool rk_win_fill_ldr_data(virt_t baseaddr, LDR_DATA_TABLE_ENTRY32 *ldr_data)
{
	unsigned char *p_buf = NULL;
	LIST_ENTRY32 current_entry;
	u32 head_addr = 0;
	LDR_DATA_TABLE_ENTRY32 current_ldr_data;
	ulong addr = 0, addr2 = 0;
	int i = 0;
	int err = 0;
	
	memset(&current_entry, 0, sizeof(LIST_ENTRY32));
	memset(&current_ldr_data, 0, sizeof(LDR_DATA_TABLE_ENTRY32));
	
	addr = kernelbase + PSLOADEDMODULELIST_OFFSET_IN_KERNEL;
	p_buf = (unsigned char *)&current_entry;
	for (i = 0; i < sizeof(LIST_ENTRY32); i++) {
			if ((err = read_linearaddr_b (addr + i, p_buf + i))
				!= VMMERR_SUCCESS)
				goto failed;
	}
	
	head_addr = addr;
	addr = current_entry.Flink;
	while(addr != head_addr){
		p_buf = (unsigned char *)&current_ldr_data;
		addr2 = addr - rk_struct_win_offset(LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
		for (i = 0; i < sizeof(LDR_DATA_TABLE_ENTRY32); i++) {
			if ((err = read_linearaddr_b (addr2 + i, p_buf + i))
				!= VMMERR_SUCCESS)
				goto failed;
		}
		
		if((current_ldr_data.DllBase <= baseaddr) && ((current_ldr_data.DllBase + current_ldr_data.SizeOfImage) > baseaddr)){
			//found;
			memcpy(ldr_data, p_buf, sizeof(LDR_DATA_TABLE_ENTRY32));
			return true;
		}
		
		addr = current_ldr_data.InLoadOrderLinks.Flink;
	}
	
failed:
	return false;
}

static bool rk_win_is_addr_in_idt(virt_t addr, ulong *entry_index)
{
	int err = 0;
	ulong idt_base = 0, idt_limit = 0;
	ulong gdt_base = 0, gdt_limit = 0, gdt_offset = 0;
	ulong ldt_accessright = 0;
	ulong current_offset = 0, current_index = 0;
	struct gatedesc32 idt_desc32;
	struct segdesc gdt_desc32;
	bool is_guest_64 = false;
	size_t idt_entry_size = 0;
	
	memset(&idt_desc32, 0, sizeof(struct gatedesc32));
	memset(&gdt_desc32, 0, sizeof(struct segdesc));
	is_guest_64 = guest64();
	idt_entry_size = (is_guest_64 ? 16 : 8);
	current->vmctl.read_idtr(&idt_base, &idt_limit);
	current_index = 0;
	
	for(current_offset = 0;current_offset < idt_limit;current_offset += idt_entry_size, current_index++){
		if(is_guest_64){
			//TODO:Handle IA-32e Guest
		}
		else{
			if ((err = read_linearaddr_q (idt_base + current_offset, &idt_desc32)) == VMMERR_SUCCESS){
				if((idt_desc32.sel & 0x4) == 0){
					//GDT
					current->vmctl.read_gdtr(&gdt_base, &gdt_limit);
				}
				else{
					//LDT
					asm_vmread(VMCS_GUEST_LDTR_BASE, &gdt_base);
					asm_vmread(VMCS_GUEST_LDTR_LIMIT, &gdt_limit);
					asm_vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS, &ldt_accessright);
					if((ldt_accessright & 0x10000) != 0){
						continue;
					}
				}
				
				gdt_offset = (idt_desc32.sel >> 3) * 8;
				if(gdt_offset < gdt_limit){
					if ((err = read_linearaddr_q (gdt_base + gdt_offset, &gdt_desc32)) == VMMERR_SUCCESS){
						if((((SEGDESC_BASE(gdt_desc32)) + (idt_desc32.offset_31_16 << 16) + idt_desc32.offset_15_0) == addr) &&
							(((idt_desc32.offset_31_16 << 16) + idt_desc32.offset_15_0) < ((gdt_desc32.limit_19_16 << 16) + gdt_desc32.limit_15_0))){
							if(entry_index != NULL)
								*entry_index = current_index;
							return true;
						}
					}
				}
			}
		}
	}
	
	return false;
}

static ulong rk_win_get_current_kthread_addr()
{
	ulong kpcr = 0;
	ulong retval = 0;
	
	current->vmctl.read_sreg_base(SREG_FS, &kpcr);
	
	if (read_linearaddr_l (kpcr + CURRENT_THREAD_OFFSET_IN_KPCR, &retval) != VMMERR_SUCCESS){
			printf("error reading kpcr.kthread");
	}
	
	return retval;
}

static struct guest_win_exallocatepoolwithtag_call_info* rk_win_get_call_info_by_kthread_addr(ulong kthread_addr, bool pop)
{
	struct guest_win_exallocatepoolwithtag_call_info_stack* call_info_stack = NULL;
	struct guest_win_exallocatepoolwithtag_call_info_stack* call_info_stack_n = NULL;
	struct guest_win_exallocatepoolwithtag_call_info* call_info = NULL;
	
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

	struct guest_win_exallocatepoolwithtag_call_info_stack* call_info_stack = NULL;
	
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

static void rk_win_set_dr_to_virt(int debug_num, virt_t addr)
{
	virt_t res = 0;
	ulong dr7 = 0;
	ulong dr7_or_mask = 0;
	ulong dr7_and_mask = 0;
	struct rk_tf_state *p_rk_tf = current->vmctl.get_struct_rk_tf();
	
	switch(debug_num){
	case 0:
		if((p_rk_tf->dr_shadow_flag & DR_SHADOW_DR0) == 0){
			asm volatile ("mov %%db0, %0" : "=r"(res));
			p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR0;
			p_rk_tf->dr0_shadow = res;
		}
		asm volatile ("mov %0, %%db0" : : "r"(addr));
		dr7_or_mask = 0x2;
		dr7_and_mask = 0xFFF0FFFF;
		break;
	case 1:
		if((p_rk_tf->dr_shadow_flag & DR_SHADOW_DR1) == 0){
			asm volatile ("mov %%db1, %0" : "=r"(res));
			p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR1;
			p_rk_tf->dr1_shadow = res;
		}
		asm volatile ("mov %0, %%db1" : : "r"(addr));
		dr7_or_mask = 0x8;
		dr7_and_mask = 0xFF0FFFFF;
		break;
	case 2:
		if((p_rk_tf->dr_shadow_flag & DR_SHADOW_DR2) == 0){
			asm volatile ("mov %%db2, %0" : "=r"(res));
			p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR2;
			p_rk_tf->dr2_shadow = res;
		}
		asm volatile ("mov %0, %%db2" : : "r"(addr));
		dr7_or_mask = 0x20;
		dr7_and_mask = 0xF0FFFFFF;
		break;
	case 3:
		if((p_rk_tf->dr_shadow_flag & DR_SHADOW_DR3) == 0){
			asm volatile ("mov %%db3, %0" : "=r"(res));
			p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR3;
			p_rk_tf->dr3_shadow = res;
		}
		asm volatile ("mov %0, %%db3" : : "r"(addr));
		dr7_or_mask = 0x80;
		dr7_and_mask = 0x0FFFFFFF;
		break;
	default:
		return;
	}

	asm_vmread(VMCS_GUEST_DR7, &dr7);
	if((p_rk_tf->dr_shadow_flag & DR_SHADOW_DR7) == 0){
		p_rk_tf->dr_shadow_flag |= DR_SHADOW_DR7;
		p_rk_tf->dr7_shadow = dr7;
	}
	dr7 |= dr7_or_mask;		//DR7.GX = 1
	dr7 &= dr7_and_mask;	//DR7.R/WX = 00, DR7.LENX = 00;
	asm_vmwrite(VMCS_GUEST_DR7, dr7);
	//printf("Debug Register Set. DR1 = 0x%lx, DR7 =  0x%lx\n", addr, dr7);
}

static void rk_win_remove_dr(int debug_num)
{
	ulong dr7 = 0;
	ulong dr7_nor_mask = 0;
	struct rk_tf_state *p_rk_tf = current->vmctl.get_struct_rk_tf();
	
	switch(debug_num){
	case 0:
		p_rk_tf->dr_shadow_flag &= (~(DR_SHADOW_DR0));
		asm volatile ("mov %0, %%db0" : : "r"(p_rk_tf->dr0_shadow));
		dr7_nor_mask = 0x2;
		break;
	case 1:
		p_rk_tf->dr_shadow_flag &= (~(DR_SHADOW_DR1));
		asm volatile ("mov %0, %%db1" : : "r"(p_rk_tf->dr1_shadow));
		dr7_nor_mask = 0x8;
		break;
	case 2:
		p_rk_tf->dr_shadow_flag &= (~(DR_SHADOW_DR2));
		asm volatile ("mov %0, %%db2" : : "r"(p_rk_tf->dr2_shadow));
		dr7_nor_mask = 0x20;
		break;
	case 3:
		p_rk_tf->dr_shadow_flag &= (~(DR_SHADOW_DR3));
		asm volatile ("mov %0, %%db3" : : "r"(p_rk_tf->dr3_shadow));
		dr7_nor_mask = 0x80;
		break;
	default:
		return;
	}

	asm_vmread(VMCS_GUEST_DR7, &dr7);
	dr7 &= (~(dr7_nor_mask));	//DR7.GX = 0
	asm_vmwrite(VMCS_GUEST_DR7, dr7);
}

//Use DR0 and DR2, DR3 here.
static void rk_win_setdebugregister()
{
	virt_t pCallEntry = 0;
	virt_t pCallEntry_2 = 0;
	ulong dr7 = 0;

	printf("[CPU%d]%d, %d, %lX\n", get_cpu_id(), rk_win_getentryaddrbyname("ExAllocatePoolWithTag", &pCallEntry), rk_win_getentryaddrbyname("ExFreePoolWithTag", &pCallEntry_2), kernelbase);

	if (rk_win_getentryaddrbyname("ExAllocatePoolWithTag", &pCallEntry) && 
	rk_win_getentryaddrbyname("ExFreePoolWithTag", &pCallEntry_2) && (kernelbase != 0)) {
		rk_win_set_dr_to_virt(0, pCallEntry);
		rk_win_set_dr_to_virt(2, pCallEntry_2);
		rk_win_set_dr_to_virt(3, (kernelbase + SWAP_CONTEXT_ENTRY_OFFSET_IN_KERNEL));
		asm_vmread(VMCS_GUEST_DR7, &dr7);
		printf("[CPU%d]Debug Register Set. DR0 = 0x%lx, DR2 = 0x%lx, DR3 = 0x%lx, DR7 =  0x%lx\n", 
			get_cpu_id(), pCallEntry, pCallEntry_2, kernelbase + SWAP_CONTEXT_ENTRY_OFFSET_IN_KERNEL, dr7);
	}
}

static bool mmprotect_callback_win_pereadonly(struct mm_protected_area *mmarea, virt_t addr, bool display)
{
	if(display)
	{
		printf("[CPU%d][RKAnalyzer][PEReadOnly]Access Violation at 0x%lX\n", get_cpu_id(), addr);
	}
	
	return true;
}

static bool mmprotect_callback_win_kernelheap(struct mm_protected_area *mmarea, virt_t addr, bool display)
{
	ulong ip = 0;

	if(display)
	{
		current->vmctl.read_ip(&ip);
		
		if(!(rk_win_is_system_code(ip)))
		{
			if(mmarea->varange->properties != NULL){
				dbgprint("[CPU%d][RKAnalyzer][KernelHeap]Access Violation at 0x%lX+0x%lX\n", get_cpu_id(), 
				mmarea->varange->properties[PROPERTY_ALLOCADDR], addr - mmarea->varange->properties[PROPERTY_ALLOCADDR]);
				dbgprint("[CPU%d][RKAnalyzer][KernelHeap]Heap Info: Allocer = 0x%lX, Type = 0x%lX, Tag = 0x%lX, Size = 0x%lX\n", get_cpu_id(), 
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

static void rk_win_dr_dispatch_detectboot(int debug_num)
{
	bool kernelfound = false;
	struct rk_tf_state *p_rk_tf = current->vmctl.get_struct_rk_tf();
	
	switch(debug_num){
	case 0:
	case 1:
		//So we have the instruction at the address we expected executed
		//But we don't know if it is the kernel!
		//We scan for the PE of the kernel to make sure.
		
		printf("Hit on CPU%d", get_cpu_id());
		kernelfound = rk_win_check_for_kernel();
		if(kernelfound){
			//OK, the kernel has already been booted.
			//We can initialized everything
			rk_win_remove_dr(0);
			rk_win_remove_dr(1);
			
			//Get a lock here to do global initialize
			spinlock_lock(&global_init_lock);
			rk_win_init();
			spinlock_unlock(&global_init_lock);
		}
		break;
	default:
		break;
	}
	
	p_rk_tf->should_set_rf_befor_entry = true;
}

static void rk_win_dr_dispatch(int debug_num)
{
	ulong esp = 0, eax = 0, ppool = 0, edi = 0, esi = 0;
//	struct guest_win_obcreateobject_call_info call_info;
	struct guest_win_exallocatepoolwithtag_call_info call_info;
	struct guest_win_exallocatepoolwithtag_call_info *exalloc_call_info;
	ulong properties[10];
	struct rk_tf_state *p_rk_tf = current->vmctl.get_struct_rk_tf();

	memset(&call_info, 0, sizeof(struct guest_win_exallocatepoolwithtag_call_info));
	memset(properties, 0, sizeof(ulong) * 10);

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
				rk_win_set_dr_to_virt(1, call_info.retaddr);
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
			
			if((exalloc_call_info->retval != 0) /*&& (exalloc_call_info->param_tag == (0x636f7250 | 0x80000000))*/){
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
			rk_win_remove_dr(1);
		}
		else{
			rk_win_set_dr_to_virt(1, exalloc_call_info->retaddr);
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
			rk_win_remove_dr(1);
		}
		else{
			rk_win_set_dr_to_virt(1, exalloc_call_info->retaddr);
			//printf("[CPU %d]Switch To:Caller = 0x%lX\n", get_cpu_id(), exalloc_call_info->retaddr);
		}
		break;
	default:
		break;
	}

	//Set the EFLAGS.RF = 1 to avoid recursion
	p_rk_tf->should_set_rf_befor_entry = true;
}

static void rk_win_build_pe_base_filter()
{
	//Parse the PE Section
	//Dump all exported functions.
	ulong pebase = 0;
	ulong buf = 0;
	struct guest_win_pe_base_filter *p_pe_base_filter = NULL;
	
	//Try Find in PsLoadedModuleList First
	unsigned char *p_buf = NULL;
	LIST_ENTRY32 current_entry;
	u32 head_addr = 0;
	LDR_DATA_TABLE_ENTRY32 current_ldr_data;
	ulong addr = 0, addr2 = 0;
	int i = 0;
	int err = 0;
	
	memset(&current_entry, 0, sizeof(LIST_ENTRY32));
	memset(&current_ldr_data, 0, sizeof(LDR_DATA_TABLE_ENTRY32));
	
	addr = kernelbase + PSLOADEDMODULELIST_OFFSET_IN_KERNEL;
	p_buf = (unsigned char *)&current_entry;
	for (i = 0; i < sizeof(LIST_ENTRY32); i++) {
			if ((err = read_linearaddr_b (addr + i, p_buf + i))
				!= VMMERR_SUCCESS)
				goto nextstep;
	}
	
	head_addr = addr;
	addr = current_entry.Flink;
	while(addr != head_addr){
		p_buf = (unsigned char *)&current_ldr_data;
		addr2 = addr - rk_struct_win_offset(LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
		for (i = 0; i < sizeof(LDR_DATA_TABLE_ENTRY32); i++) {
			if ((err = read_linearaddr_b (addr2 + i, p_buf + i))
				!= VMMERR_SUCCESS)
				goto nextstep;
		}
		
		p_pe_base_filter = alloc(sizeof(struct guest_win_pe_base_filter));
		p_pe_base_filter->imagebase = current_ldr_data.DllBase;
		LIST1_ADD(list_pe_base_filter, p_pe_base_filter);
				
		addr = current_ldr_data.InLoadOrderLinks.Flink;
	}
	
nextstep:

	//Scan Kernel Memory for additional
	//Scan for 'MZ' on page start
	pebase = 0x80000000;
	while(pebase <= ((0xFFFFFFFF >> PAGESIZE_SHIFT) << PAGESIZE_SHIFT)){
		if(read_linearaddr_l(pebase, &buf) == VMMERR_SUCCESS){
			if(buf == 0x00905A4D){
				//Found 'MZ'
				p_pe_base_filter = alloc(sizeof(struct guest_win_pe_base_filter));
				p_pe_base_filter->imagebase = pebase;
				LIST1_ADD(list_pe_base_filter, p_pe_base_filter);
			}
		}
		
		if(pebase >= ((0xFFFFFFFF >> PAGESIZE_SHIFT) << PAGESIZE_SHIFT)){
			break;
		}
		
		pebase = pebase >> PAGESIZE_SHIFT;
		pebase ++;
		pebase = pebase << PAGESIZE_SHIFT;
	}
}

static bool rk_win_check_for_kernel()
{
	ulong pebase = 0;
	ulong buf = 0;
	ulong addr = 0;
	
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
		return false;
	}
	
	return true;
}

//scankernel = true -> scan kernel, ignore, hint_addr
//scankernel = false -> scan for PE, from hint_addr to lower space
static bool rk_win_readfromguest(struct guest_win_pe *p_pe, bool scankernel, virt_t hint_addr)
{
	//Parse the PE Section
	//Dump all exported functions.
	int i = 0,j = 0;
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
	struct guest_win_pe_symbol *function = NULL;
	struct guest_win_pe_section *section = NULL;
	ulong addr_section_header = 0;
	u16 numberOfSections = 0;
	IMAGE_SECTION_HEADER section_header;
	unsigned char* p_section_header = (unsigned char*)&section_header;
	u8 sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
	LDR_DATA_TABLE_ENTRY32 ldr_data;
	
	memset(&Export, 0, sizeof(IMAGE_EXPORT_DIRECTORY));
	memset(&section_header, 0, sizeof(IMAGE_SECTION_HEADER));
	memset(&ldr_data, 0, sizeof(LDR_DATA_TABLE_ENTRY32));
	memset(strbuf, 0, sizeof(char) * NAME_MAXLEN);
	memset(sectionName, 0, sizeof(char) * (IMAGE_SIZEOF_SHORT_NAME + 1));
	
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
		//TODO: Scan in PsLoadedModuleList First before search in memory
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
	
	p_pe->imagebase = pebase;

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

		//printf("pExportDirectory = %lX\n", buf);
	
		for (i = 0; i < sizeof(IMAGE_EXPORT_DIRECTORY); i++) {
			if ((err = read_linearaddr_b (buf + i, buf_2 + i))
				!= VMMERR_SUCCESS)
				goto init_failed;
		}
		step ++;

		//printf("Export.Name = %X\n", Export.Name);

		//name
		buf = Export.Name + pebase;
		for (i = 0; i < sizeof(strbuf); i++) {
			if ((err = read_linearaddr_b (buf + i, strbuf + i))
				!= VMMERR_SUCCESS)
				goto init_failed;
			if(strbuf[i] == 0)
				break;
		}
		//printf("FileName: %s\n", strbuf);
		//printf("Number of Functions: %d\n", Export.NumberOfFunctions);
		//printf("Number of Names: %d\n",Export.NumberOfNames);

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
		//printf("[RKAnalyzer]Get Export Table Succeed...\n");
	}
	
	if(rk_win_fill_ldr_data(p_pe->imagebase, &ldr_data)){
		p_pe->size = ldr_data.SizeOfImage;
		namelen = (ldr_data.FullDllName.Length > (NAME_MAXLEN - 1) ? (NAME_MAXLEN - 1) : ldr_data.FullDllName.Length);
		namelen = namelen >> 1;
		for (j = 0; j < namelen; j++) {
			if ((err = read_linearaddr_b (ldr_data.FullDllName.Buffer + j * 2, (unsigned char *)(p_pe->fullname) + j))
					!= VMMERR_SUCCESS){
				break;
			}
		}
		p_pe->fullname[namelen] = 0;
		
		namelen = (ldr_data.BaseDllName.Length > (NAME_MAXLEN - 1) ? (NAME_MAXLEN - 1) : ldr_data.BaseDllName.Length);
		namelen = namelen >> 1;
		for (j = 0; j < namelen; j++) {
			if (read_linearaddr_b (ldr_data.BaseDllName.Buffer + j * 2, (unsigned char *)(p_pe->name) + j)
					!= VMMERR_SUCCESS){
				break;
			}
		}
		p_pe->name[namelen] = 0;
	}
	
	printf("Hint = %lX, Base = %lX, FullName = %s, BaseName = %s\n", hint_addr, p_pe->imagebase, p_pe->fullname, p_pe->name);

	return true;

init_failed:
	printf("[RKAnalyzer]Fail To Read PE!, Hint = %lX, step = %d, buf= %lX, addr= %lX, err = %d\n", hint_addr, step, buf, addr, err);
	return false;
}

static void rk_win_protectpereadonlysections(struct guest_win_pe *p_pe)
{
	struct guest_win_pe_section *section = NULL;

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
	struct guest_win_pe_section *section = NULL;
	struct guest_win_pe *pe = NULL;
	struct guest_win_pe_base_filter *p_pe_base_filter = NULL;
	bool in_filter = false;
	
	if((pe = rk_win_get_pe_from_code_addr(addr)) != NULL){
		if(pe->legal)
			return RK_CODE_LEGAL;
		return RK_CODE_ILLEGAL;
	}
	
	struct guest_win_pe *new_pe = alloc(sizeof(struct guest_win_pe));
	init_pe_struct(new_pe);
	if(rk_win_readfromguest(new_pe, false, addr))
	{
		LIST1_FOREACH (list_pe_base_filter, p_pe_base_filter) {
			if(p_pe_base_filter->imagebase == new_pe->imagebase){
				in_filter = true;
				break;
			}
		}
		
		new_pe->legal = is_current_module_legal();
		LIST1_ADD(list_pes, new_pe);
		//rk_win_protectpereadonlysections(new_pe);
		
		if((!in_filter) && new_pe->legal) {
			//Add Legal Module to Filter
			p_pe_base_filter = alloc(sizeof(struct guest_win_pe_base_filter));
			p_pe_base_filter->imagebase = new_pe->imagebase;
			LIST1_ADD(list_pe_base_filter, p_pe_base_filter);
		}
		
		LIST1_FOREACH (new_pe->list_sections, section) {
			if((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
				rk_add_code_mmvarange_nolock(new_pe->legal, section->va, section->va + section->size - 1, mmcode_callback_general);
		}
		
		return (new_pe->legal ? RK_CODE_LEGAL : RK_CODE_ILLEGAL);
	}
	else{
		free(new_pe);
		
		//Add as a scratch
		rk_add_code_mmvarange_nolock(true, addr, addr, mmcode_callback_general);
		return RK_CODE_LEGAL;
	}
}

static void rk_win_switch_print_dispatch(virt_t from_ip, virt_t to_ip)
{
	//ignore hardware interrupts and exceptions
	//intercept calls to kernel
	
	//How to determine what kind of branch it is?
	//1. jmp : [from_ip] == jmp xxx
	//2. call : [from_ip] == call xxx
	//3. ret : [from_ip] = ret
	//4. iret : [from_ip] = iret
	//5. Hardware interrupt | exception : to_ip = IDT[x], [from_ip] != jmp IDT[x], [from_ip] != call IDT[x]
	//not ret or iret, [from_ip - instruction_len] != int x
	//6. Software interrupt | exception : to_ip = IDT[x], [from_ip - instruction_len] == int x

	//We only output:
	//from_ip in rootkit, to_ip in kernel
	//from_ip in kernel, to_ip in rootkit
	//branch type 1,2,3,4,6
	
	struct guest_win_pe_base_filter *p_pe_base_filter = NULL;
	struct guest_win_pe *p_from_pe, *p_to_pe = NULL;
	struct guest_win_pe_symbol *p_symbol = NULL;
	bool in_filter = false;
	ulong idt_index = 0;
	u8 inst = 0;
	int err = 0;
	
	if(rk_win_is_system_code(to_ip)){
		p_to_pe = &kernel_pe;
		p_from_pe = rk_win_get_pe_from_code_addr(from_ip);
		if(p_from_pe != NULL){
			LIST1_FOREACH (list_pe_base_filter, p_pe_base_filter) {
				if(p_pe_base_filter->imagebase == p_from_pe->imagebase){
					in_filter = true;
					break;
				}
			}
			if(in_filter)
				return;
			
			//rootkit->kernel
			
			if(rk_win_is_addr_in_idt(to_ip, &idt_index)){
				//TODO:Check More for Route 5
				return;
			}
			
			p_symbol = rk_win_getsymbolbyentry(to_ip);
			
			if(p_symbol == NULL){
				dbgprint("[CPU%d][RKAnalyzer][Rootkit->Kernel][%s+0x%lX->%s+0x%lX][%lX->%lX]\n", get_cpu_id(), 
				p_from_pe->name, from_ip - p_from_pe->imagebase, p_to_pe->name, to_ip - p_to_pe->imagebase, from_ip, to_ip);
			}
			else{
				if(p_symbol->va == to_ip){
					dbgprint("[CPU%d][RKAnalyzer][Rootkit->Kernel][%s+0x%lX->%s+%s][%lX->%lX]\n", get_cpu_id(), 
					p_from_pe->name, from_ip - p_from_pe->imagebase, p_to_pe->name, p_symbol->name, from_ip, to_ip);
				}
				else{
					dbgprint("[CPU%d][RKAnalyzer][Rootkit->Kernel][%s+0x%lX->%s+0x%lX(%s+0x%lX)][%lX->%lX]\n", get_cpu_id(), 
					p_from_pe->name, from_ip - p_from_pe->imagebase, p_to_pe->name, to_ip - p_to_pe->imagebase, p_symbol->name,
					to_ip - p_symbol->va, from_ip, to_ip);
				}
			}
		}
	}
	else{
		if(rk_win_is_system_code(from_ip)){
			p_from_pe = &kernel_pe;
			p_to_pe = rk_win_get_pe_from_code_addr(to_ip);
			if(p_to_pe != NULL){
				LIST1_FOREACH (list_pe_base_filter, p_pe_base_filter) {
					if(p_pe_base_filter->imagebase == p_to_pe->imagebase){
						in_filter = true;
						break;
					}
				}
				if(in_filter)
					return;
				
				//check if we return from interrupt(iretd)
				//if we do, we don't bother output the return.
				if ((err = read_linearaddr_b (from_ip, &inst)) == VMMERR_SUCCESS){
					if(inst == 0xCF){
						return;
					}
				}
				
				p_symbol = rk_win_getsymbolbyentry(from_ip);
								
				//kernel->rootkit
				if(p_symbol == NULL){
					dbgprint("[CPU%d][RKAnalyzer][Kernel->Rootkit][%s+0x%lX->%s+0x%lX][%lX->%lX]\n", get_cpu_id(), 
					p_from_pe->name, from_ip - p_from_pe->imagebase, p_to_pe->name, to_ip - p_to_pe->imagebase, from_ip, to_ip);
				}
				else{
					if(p_symbol->va == from_ip){
						dbgprint("[CPU%d][RKAnalyzer][Kernel->Rootkit][%s+%s->%s+0x%lX][%lX->%lX]\n", get_cpu_id(), 
						p_from_pe->name, p_symbol->name, p_to_pe->name, to_ip - p_to_pe->imagebase, from_ip, to_ip);
					}
					else{
						dbgprint("[CPU%d][RKAnalyzer][Kernel->Rootkit][%s+0x%lX(%s+0x%lX)->%s+0x%lX][%lX->%lX]\n", get_cpu_id(), 
						p_from_pe->name, from_ip - p_from_pe->imagebase, p_symbol->name,
						from_ip - p_symbol->va, p_to_pe->name, to_ip - p_to_pe->imagebase, from_ip, to_ip);
					}
				}
			}
		}
	}
}

void rk_win_os_dep_setter(void)
{	
	os_dep.dr_dispatcher = rk_win_dr_dispatch;
	os_dep.va_kernel_start = 0x80000000;
	os_dep.unknown_code_check_dispatcher = rk_win_unknown_code_check_dispatch;
	os_dep.switch_print_dispatcher = rk_win_switch_print_dispatch;
}

bool rk_win_init_global()
{
	struct guest_win_pe_section *section = NULL;
	
	if(!rk_try_setup_global(rk_win_os_dep_setter)){
		return true;
	}

	printf("[RKAnalyzer]Setup Memory Areas To Protect...\n");
	
	rk_win_readfromguest(&kernel_pe, true, 0);
	kernel_pe.legal = true;
	LIST1_ADD(list_pes, &kernel_pe);
	rk_win_protectpereadonlysections(&kernel_pe);
	
	//rk_win_build_pe_base_filter();
	
	LIST1_FOREACH (kernel_pe.list_sections, section) {
		if((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
			rk_add_code_mmvarange_nolock(true, section->va, section->va + section->size - 1, mmcode_callback_general);
	}
	
	printf("[RKAnalyzer]Global Initialized on CPU %d.\n", get_cpu_id());
	
	return true;
}

bool rk_win_init_per_vcpu(void)
{
	if(!rk_try_setup_per_vcpu()){
		return true;
	}

	rk_win_setdebugregister();
	printf("[RKAnalyzer]CPU %d Initialized.\n", get_cpu_id());
	
	return true;
}

static void rk_win_init(void)
{
	//Get Windows Kernel Address From guest
	if(!(rk_win_init_global())){
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

	LIST1_HEAD_INIT (list_pes);
	LIST1_HEAD_INIT (list_call_info);
	LIST1_HEAD_INIT (list_pe_base_filter);
	spinlock_init(&call_info_access_lock);
	spinlock_init(&call_info_watchdog_lock);
	spinlock_init(&global_init_lock);
	
	//Our Temp DR dispatcher for OS booting detect
	os_dep.dr_dispatcher_detectboot = rk_win_dr_dispatch_detectboot;
	
	printf("[RKAnalyzer]RKAnalyzer Windows Module Initialized...\n");
}

static void
rk_win_set_detect_osboot (void)
{	
	//And we use DR1
	rk_win_set_dr_to_virt(0, WIN_KERNEL_BSP_STARTUP_EIP);
	rk_win_set_dr_to_virt(1, WIN_KERNEL_AP_STARTUP_EIP);
	printf("[CPU%d][RKAnalyzer]OS Boot Detecting Setup ON...\n", get_cpu_id());
}

INITFUNC ("vmmcal0", vmmcall_rk_win_init);
INITFUNC ("vcpu1", rk_win_set_detect_osboot);

#endif
