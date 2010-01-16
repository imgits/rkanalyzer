/*
	Changlog:
	2009.7.9		First Ver. Base Operations.
*/

#include "rk_nx.h"
#include "rk_main.h"
#include "list.h"
#include "mm.h"
#include "cpu_mmu.h"
#include "initfunc.h"
#include "string.h"
#include "asm.h"
#include "printf.h"
#include "current.h"
#include "constants.h"
#include "panic.h"
#include "cpu_mmu_spt.h"

#ifdef RK_ANALYZER

static spinlock_t mm_code_area_lock;
static LIST1_DEFINE_HEAD (struct mm_code_varange, list_code_varanges);

static void
rk_nx_init_global (void)
{
	spinlock_init(&mm_code_area_lock);
	LIST1_HEAD_INIT (list_code_varanges);
	printf("MM Code Area List Initialized...\n");
}

static bool is_kernel_page(virt_t addr)
{
	if(addr >= os_dep.va_kernel_start)
		return true;
		
	return false;
}

static u16 rk_nx_rd_guest_cpl()
{
	u16 retval;
	current->vmctl.read_sreg_sel(SREG_CS, &retval);
	return (retval & 0x3);
}

void rk_nx_try_setup_global()
{

}

void rk_nx_try_setup_per_vcpu()
{
	// Test CPL see whether we are in kernel or user? (Should be in kernel)
	ulong ip;
	u64 msrdata;
	ulong debugctl;
	struct rk_tf_state *rk_tf = current->vmctl.get_struct_rk_tf();
	
	if(((os_dep.va_kernel_start >> PAGESIZE2M_SHIFT) << PAGESIZE2M_SHIFT) != os_dep.va_kernel_start){
		panic("Error Init NX: Kernel Start Not Align on 2M Page!\n");
	}
	
	//Enable NXE in MSR_IA32_EFER and set shadow before enable NX Protect
	current->vmctl.read_msr(MSR_IA32_EFER, &msrdata);
	rk_tf->guest_msr_efer_nxe = !!(msrdata & MSR_IA32_EFER_NXE_BIT);
	msrdata |= MSR_IA32_EFER_NXE_BIT;
	current->vmctl.write_msr(MSR_IA32_EFER, msrdata);
	//LBR in IA32_MSR_DEBUGCTL
	asm_vmread(VMCS_GUEST_IA32_DEBUGCTL, &debugctl);
	debugctl |= MSR_IA32_DEBUGCTL_LBR_BIT;
	asm_vmwrite(VMCS_GUEST_IA32_DEBUGCTL, debugctl);
	
	//Enable NX Protect Flag. Now IA32_EFER.NXE is shadowed
	rk_tf->nx_enable = true;
	
	current->vmctl.read_ip(&ip);
	
	rk_tf->cpl_last = rk_nx_rd_guest_cpl();
	rk_tf->current_code_legal = false;
	
	if(rk_tf->cpl_last == CPL_KERNEL)
	{
		//Flush Page Table
		spinlock_lock(&mm_code_area_lock);
		rk_tf->current_code_legal = ((os_dep.unknown_code_check_dispatcher(ip) == RK_CODE_LEGAL) ? true : false);
		spinlock_unlock(&mm_code_area_lock);
		cpu_mmu_spt_updatecr3();
	}
	else if(rk_tf->cpl_last == CPL_USER)
	{
		//Flush Page Table
		cpu_mmu_spt_updatecr3();
	}
	else
	{
		panic("Error Init NX: Unknown CPL!\n");
	}
}

static void print_switch_info()
{
	//TODO:Support more processor familys
	//Currently we only support Intel Family 06_17H
	u64 tos;
	u64 from_ip, to_ip;
	u64 perf_msr;
	ulong debugctl;
	ulong cs_base;
	
	current->vmctl.read_msr(MSR_IA32_PERF_CAPABILITIES, &perf_msr);
	perf_msr &= MSR_IA32_PERF_CAPABILITIES_LBR_MASK;
	
	//Intel Family 06_17H
	//Read MSR
	current->vmctl.read_msr(MSR_LASTBRANCH_TOS, &tos);
	tos &= 0x3;		//TOS should be from 0 to 3
	current->vmctl.read_msr(MSR_LASTBRANCH_0_FROM_IP + tos, &from_ip);
	current->vmctl.read_msr(MSR_LASTBRANCH_0_TO_LIP + tos, &to_ip);

	
	//send address to os module to process
	if(perf_msr == MSR_IA32_PERF_CAPABILITIES_LBR_32){
		current->vmctl.read_sreg_base(SREG_CS, &cs_base);
		from_ip += cs_base;
		to_ip += cs_base;
	}
	else if(perf_msr == MSR_IA32_PERF_CAPABILITIES_LBR_64LIP){
	}
	else if(perf_msr == MSR_IA32_PERF_CAPABILITIES_LBR_64EIP){
	}
	
	if(os_dep.switch_print_dispatcher != NULL){
		os_dep.switch_print_dispatcher(from_ip, to_ip);
	}
}

static bool rk_is_code_area_overlapped_with_current_ones(virt_t startaddr, virt_t endaddr, bool display)
{
	struct mm_code_varange *varange;
	
	LIST1_FOREACH (list_code_varanges, varange){
		if((startaddr >= varange->startaddr) && (startaddr <= varange->endaddr)){
			if(display){
				printf("[RKAnalyzer]Error Add Code Area[0x%lX 0x%lX]: Overlapped Memory Area[0x%lX 0x%lX]!\n", 
					startaddr, endaddr, varange->startaddr, varange->endaddr);
			}
			return true;
		}
		
		if((endaddr >= varange->startaddr) && (endaddr <= varange->endaddr)){
			if(display){
				printf("[RKAnalyzer]Error Add Code Area[0x%lX 0x%lX]: Overlapped Memory Area[0x%lX 0x%lX]!\n", 
					startaddr, endaddr, varange->startaddr, varange->endaddr);
			}
			return true;
		}
	}
	
	return false;
}

bool rk_add_code_mmvarange_nolock(bool legal, virt_t startaddr, virt_t endaddr, mmcode_callback callback_func)
{

	struct mm_code_varange *varange;

	if(startaddr > endaddr){
		printf("[RKAnalyzer]Error Add Code Area: Invalid Parameter!\n");
		return false;
	}

	if(rk_is_code_area_overlapped_with_current_ones(startaddr, endaddr, true)){
		return false;
	}

	// Create a New VA Range for original
	varange = alloc(sizeof(struct mm_code_varange));
	varange->startaddr = startaddr;
	varange->endaddr = endaddr;
	varange->callback_func = callback_func;
	varange->legal = legal;
	
	LIST1_ADD(list_code_varanges, varange);
	
	return true;
}

static bool rk_del_code_mmvarange_core(virt_t startaddr, virt_t endaddr)
{
	// Delete All Original Areas in va belongs to [startaddr endaddr]
	// Also Remove derived areas

	struct mm_code_varange *varange;
	struct mm_code_varange *varange_n;
	bool varange_found = false;

	LIST1_FOREACH_DELETABLE (list_code_varanges, varange, varange_n){
		if((varange->startaddr == startaddr) || (varange->endaddr == endaddr))
		{
			varange_found = true;
			LIST1_DEL(list_code_varanges, varange);
			break;
		}
	}

	if(!varange_found){
		return false;
	}

	//TODO:Add Support for Large Pages(4M)

	free(varange);

	return true;
}

bool rk_del_code_mmvarange(virt_t startaddr, virt_t endaddr)
{
	bool ret = false;

	spinlock_lock(&mm_code_area_lock);
	ret =  rk_del_code_mmvarange_core(startaddr, endaddr);
	spinlock_unlock(&mm_code_area_lock);

	return ret;
}

static void rk_mark_page_nx(virt_t addr)
{
	u64 pte;
	pmap_t m;
	
	pmap_open_vmm (&m, current->spt.cr3tbl_phys, current->spt.levels);
	pmap_seek (&m, addr, 1);
	pte = pmap_read(&m);
	pte = pte | PTE_NX_BIT;
	pmap_write (&m, pte, 0xFFF);
	pmap_close(&m);
}

static void rk_unmark_page_nx(virt_t addr)
{
	u64 pte;
	pmap_t m;
	
	pmap_open_vmm (&m, current->spt.cr3tbl_phys, current->spt.levels);
	pmap_seek (&m, addr, 1);
	pte = pmap_read(&m);
	pte = pte & (~PTE_NX_BIT);
	pmap_write (&m, pte, 0xFFF);
	pmap_close(&m);
}

static struct mm_code_varange* rk_check_code_type_core(virt_t virtaddr)
{

	//TODO:Add Support for Large Pages(4M)	

	struct mm_code_varange *mmvarange;

	//TODO:Add Support for Large Pages(4M)
	
	LIST1_FOREACH (list_code_varanges, mmvarange){
		if((virtaddr >= mmvarange->startaddr) && (virtaddr <= mmvarange->endaddr)){
			return mmvarange;
		}
	}

	return NULL;
}

static struct mm_code_varange* rk_check_code_type_same_page_core(virt_t virtaddr)
{

	//TODO:Add Support for Large Pages(4M)	

	struct mm_code_varange *mmvarange;

	//TODO:Add Support for Large Pages(4M)
	
	LIST1_FOREACH (list_code_varanges, mmvarange){
		if((virtaddr >= mmvarange->startaddr) && (virtaddr <= mmvarange->endaddr)){
			return mmvarange;
		}
		if((virtaddr >> PAGESIZE_SHIFT) == (mmvarange->startaddr >> PAGESIZE_SHIFT)){
			return mmvarange;
		}
		if((virtaddr >> PAGESIZE_SHIFT) == (mmvarange->endaddr >> PAGESIZE_SHIFT)){
			return mmvarange;
		}
	}

	return NULL;
}

void rk_manipulate_code_mmvarange_if_need(virt_t newvirtaddr, u64 gfns){

	struct mm_code_varange* mmvarange;
	u16 cpl_current;
	struct rk_tf_state *rk_tf = current->vmctl.get_struct_rk_tf();
	cpl_current = rk_nx_rd_guest_cpl();
	
	//We don't handle Kernel<->User switch here
	//If switch happen with page not present, we load it and mark nx, 
	//so switch would be delayed to rk_check_code_mmarea on next VM Entry
	
	//Route:
	//1.CPL_LAST = KERNEL, newvirtaddr in userland : mark Page[newvirtaddr].NX = 1
	//2.CPL_LAST = KERNEL, newvirtaddr in kernel :
	//2(a). current_code_legal = true
	//2(a)_1. newvirtaddr is legal : mark Page[newvirtaddr].NX = 0
	//2(a)_2. newvirtaddr is illegal : mark Page[newvirtaddr].NX = 1
	//2(a)_3. newvirtaddr is not known : mark Page[newvirtaddr].NX = 1, so it will be processed in rk_check_code_mmarea on next VMEntry
	//2(b). current_code_legal = false
	//2(b)_1. newvirtaddr is legal : mark Page[newvirtaddr].NX = 1
	//2(b)_2. newvirtaddr is illegal : mark Page[newvirtaddr].NX = 0
	//2(b)_3. newvirtaddr is not known : mark Page[newvirtaddr].NX = 1, so it will be processed in rk_check_code_mmarea on next VMEntry
	//3.CPL_LAST = USER, newvirtaddr in kernel : mark Page[newvirtaddr].NX = 1
	//4.CPL_LAST = USER, newvirtaddr in user : Do nothing
	
	if(cpl_current == CPL_KERNEL){
		if(is_kernel_page(newvirtaddr)){
			//Route 2
			spinlock_lock(&mm_code_area_lock);
			mmvarange = rk_check_code_type_same_page_core(newvirtaddr);
			spinlock_unlock(&mm_code_area_lock);
			
			if(rk_tf->current_code_legal){
				//Route 2(a)
				if(mmvarange == NULL){
					//Route 2(a)_3
					//printf("Route 2(a)_3, %lX, CPU[%d]\n", newvirtaddr, get_cpu_id());
					rk_mark_page_nx(newvirtaddr);
				}
				else{
					if(mmvarange->legal){
						//Route 2(a)_1
						//printf("Route 2(a)_1, %lX, CPU[%d]\n", newvirtaddr, get_cpu_id());
					}
					else{
						//Route 2(a)_2
						//printf("Route 2(a)_2, %lX, CPU[%d]\n", newvirtaddr, get_cpu_id());
						rk_mark_page_nx(newvirtaddr);
					}
				}
			}
			else{
				//Route 2(b)
				if(mmvarange == NULL){
					//Route 2(b)_3
					//printf("Route 2(b)_3, %lX, CPU[%d]\n", newvirtaddr, get_cpu_id());
					rk_mark_page_nx(newvirtaddr);
				}
				else{
					if(mmvarange->legal){
						//Route 2(b)_1
						//printf("Route 2(b)_1, %lX, CPU[%d]\n", newvirtaddr, get_cpu_id());
						rk_mark_page_nx(newvirtaddr);
					}
					else{
						//Route 2(b)_2
						//printf("Route 2(b)_2, %lX, CPU[%d]\n", newvirtaddr, get_cpu_id());
					}
				}
			}
			
		}
		else{
			//Route 1
			//printf("Route 1, %lX, CPU[%d]\n", newvirtaddr, get_cpu_id());
			rk_mark_page_nx(newvirtaddr);
		}
	}
	else{
		if(is_kernel_page(newvirtaddr)){
			//Route 3
			//printf("Route 3, %lX, CPU[%d]\n", newvirtaddr, get_cpu_id());
			rk_mark_page_nx(newvirtaddr);
		}
		else{
			//Route 4
			//printf("Route 4, %lX, CPU[%d]\n", newvirtaddr, get_cpu_id());
		}
	}
	
}


//rewrite
enum rk_nx_result rk_check_code_mmvarange(virt_t virtaddr)
{

	//TODO:Add Support for Large Pages(2M)
	//TODO:Consider 64 bit guest

	// Routes
	// 1.KERNEL->USER : KERNEL PDE NX = 1, USER PDE NX = 0, record current CPL, Open Write Protection
	//
	// 2.USER->KERNEL : KERNEL PDE NX = 1, USER PDE NX = 1, record current CPL
	// 2a.Entry to LEGAL : LEGAL PTE NX = 0 (Remember also to adjust PDE for PTE NX = 0), Close Write Protection
	// 2b.Entry to ILLEGAL : ILLEGAL PTE NX = 0 (Remember also to adjust PDE for PTE NX = 0), Open Write Protection
	// 2c.Entry to UNKNOWN : Call os_dep.unknown_code_check_dispatcher to check legal or illegal. Add to list
	// go 2a or 2b
	//
	// 3.KERNEL->KERNEL :
	// 3a.LEGAL->ILLEGAL : LEGAL PTE NX = 1, ILLEGAL PTE NX = 0, Open Write Protection (Remember also to adjust PDE for PTE NX = 0)
	// 3b.ILLEGAL->LEGAL : LEGAL PTE NX = 0, ILLEGAL PTE NX = 1, Close Write Protection
	// 3c.ANY->UNKNOWN   : Call os_dep.unknown_code_check_dispatcher to check legal or illegal. Add to list
	// 3c(1).If LEGAL->LEGAL or ILLEGAL->ILLEGAL, set new pages PTE NX = 0;
	// 3c(2).ELSE, goto 3a or 3b
	// 3d.If code_legal_known = false, then set new pages PTE NX = 0;
	//
	// Special: If code_legal_known = false in rk_tf_state, then we should set it here if we in kernel
	
	u16 cpl_current;
	struct mm_code_varange* mmvarange_code;
	bool legal;
	struct rk_tf_state *rk_tf = current->vmctl.get_struct_rk_tf();
	
	cpl_current = rk_nx_rd_guest_cpl();
	if(rk_tf->cpl_last == CPL_KERNEL)
	{
		if(cpl_current == CPL_USER)
		{
			//Route 1
			rk_tf->cpl_last = CPL_USER;
			rk_tf->disable_protect = false;
			cpu_mmu_spt_updatecr3();
			
			return RK_NX_K2U;
		}
		else if(cpl_current == CPL_KERNEL)
		{
			//Route 3

			//Route 3c
			spinlock_lock(&mm_code_area_lock);
			mmvarange_code = rk_check_code_type_core(virtaddr);
			if(mmvarange_code== NULL){
				legal = ((os_dep.unknown_code_check_dispatcher(virtaddr) == RK_CODE_LEGAL) ? true : false);
				
				if(rk_tf->current_code_legal == legal){
					//Route 3c(1)
					spinlock_unlock(&mm_code_area_lock);
					cpu_mmu_spt_updatecr3();
				
					if(legal){
						print_switch_info();
						return RK_NX_L2L;
					}
					
					print_switch_info();
					return RK_NX_IL2IL;
				}
				
				//Route 3c(2)
			}
			else{
				legal = mmvarange_code->legal;
			}
			spinlock_unlock(&mm_code_area_lock);

			if((!legal) && rk_tf->current_code_legal){
				//Route 3a
				rk_tf->current_code_legal = legal;
				rk_tf->disable_protect = false;
				cpu_mmu_spt_updatecr3();
				print_switch_info();
				return RK_NX_L2IL;
			}
			else if(legal && (!(rk_tf->current_code_legal))){
				//Route 3b
				rk_tf->current_code_legal = legal;
				rk_tf->disable_protect = true;
				cpu_mmu_spt_updatecr3();
				print_switch_info();
				return RK_NX_IL2L;
			}
			
			panic("Strange Status in rk_nx 0, %d, %d, %lX, CPU[%d]\n", legal, rk_tf->current_code_legal, virtaddr, get_cpu_id());
			return RK_NX_SYSTEM;
		}
		
		panic("Strange Status in rk_nx 1\n");
		return RK_NX_SYSTEM;
	}
	else if (rk_tf->cpl_last == CPL_USER)
	{
		if(cpl_current == CPL_KERNEL)
		{
			//Route 2
			rk_tf->cpl_last = CPL_KERNEL;
			
			spinlock_lock(&mm_code_area_lock);
			mmvarange_code = rk_check_code_type_core(virtaddr);
			if(mmvarange_code == NULL){
				legal = ((os_dep.unknown_code_check_dispatcher(virtaddr) == RK_CODE_LEGAL) ? true : false);
			}
			else{
				legal = mmvarange_code->legal;
			}
			spinlock_unlock(&mm_code_area_lock);

			rk_tf->current_code_legal = legal;
			
			if(legal){
				//Route 2a
				rk_tf->disable_protect = true;
				cpu_mmu_spt_updatecr3();
			}
			else{
				//Route 2b
				rk_tf->disable_protect = false;
				cpu_mmu_spt_updatecr3();
			}
			
			return RK_NX_U2K;
		}
		
		panic("Strange Status in rk_nx 2\n");
		return RK_NX_SYSTEM;
	}
	
	//Should never get here if DEP is not enabled in system
	panic("Strange Status in rk_nx 3\n");
	return RK_NX_SYSTEM;
}

INITFUNC("global4", rk_nx_init_global);

#endif
