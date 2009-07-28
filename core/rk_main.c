/*
	Changlog:
	2009.7.9		First Ver. Base Operations.
*/


#include "rk_main.h"
#include "list.h"
#include "mm.h"
#include "initfunc.h"
#include "string.h"
#include "asm.h"
#include "printf.h"
#include "current.h"
#include "constants.h"

#ifdef RK_ANALYZER

static LIST1_DEFINE_HEAD (struct mm_protected_area, list_mmarea);

static void
rk_init_global (void)
{
	LIST1_HEAD_INIT (list_mmarea);
	printf("MM Protect Area List Initialized...\n");
}


bool rk_protect_mmarea(virt_t startaddr, virt_t endaddr, char* areatag, mmprotect_callback callback_func)
{
	//Two Step:
	//(1) Add this area to list
	//(2) Set those pages which contain this area to WP = 0

	struct mm_protected_area *mmarea;
	int areataglen;
	ulong cr3;
	u64 pte;
	virt_t currentaddr;
	pmap_t m;

	if(startaddr > endaddr){
		printf("[RKAnalyzer]Error Add Area: Invalid Parameter!\n");
		return false;
	}

	if((rk_is_addr_protected(startaddr) == RK_PROTECTED) ||
	(rk_is_addr_protected(endaddr) == RK_PROTECTED)){
		printf("[RKAnalyzer]Error Add Area: Overlapped Memory Area!\n");
		return false;
	}

	//Step 1
	mmarea = alloc(sizeof *mmarea);
	mmarea->startaddr = startaddr;
	mmarea->endaddr = endaddr;
	mmarea->callback_func = callback_func;
	if(areatag){
		areataglen = (strlen(areatag) > AREA_TAG_MAXLEN ? AREA_TAG_MAXLEN : strlen(areatag));
		memcpy(mmarea->areatag, areatag, sizeof(char) * areataglen);
	}else{
		memset(mmarea->areatag, 0, AREA_TAG_MAXLEN);
	}
	mmarea->detailed = false;
	mmarea->detailtags = NULL;

	LIST1_ADD (list_mmarea, mmarea);
	
	//Step 2
	//FIXME : Low Performance. Should set by page.
	pmap_open_vmm (&m, current->spt.cr3tbl_phys, current->spt.levels);
	
	pmap_seek (&m, startaddr, 1);
	pte = pmap_read(&m);
	if((pte & PTE_RW_BIT) != 0){
		mmarea->page_wr_setbysystem[0] = false;
	}else{
		if(rk_is_addr_protected(startaddr) == RK_UNPROTECTED_IN_PROTECTED_AREA){
			mmarea->page_wr_setbysystem[0] = false;
		}else{
			mmarea->page_wr_setbysystem[0] = true;
		}
	}
	pte &= (~PTE_RW_BIT);
	pmap_write (&m, pte, 0xFFF);

	for(currentaddr = startaddr + 1; currentaddr < endaddr; currentaddr ++){
		pmap_seek (&m, currentaddr, 1);
		pte = pmap_read(&m) & (~PTE_RW_BIT);
		pmap_write (&m, pte, 0xFFF);
	}

	pmap_seek (&m, endaddr, 1);
	pte = pmap_read(&m);
	if((pte & PTE_RW_BIT) != 0){
		mmarea->page_wr_setbysystem[1] = false;
	}else{
		if(rk_is_addr_protected(endaddr) == RK_UNPROTECTED_IN_PROTECTED_AREA){
			mmarea->page_wr_setbysystem[1] = false;
		}else{
			mmarea->page_wr_setbysystem[1] = true;
		}
	}
	pte &= (~PTE_RW_BIT);
	pmap_write (&m, pte, 0xFFF);

	pmap_close (&m);

	return true;
	
}

enum rk_result rk_is_addr_protected(virt_t virtaddr)
{
	struct mm_protected_area *mmarea;
	
	LIST1_FOREACH (list_mmarea, mmarea) {
		if((virtaddr >= mmarea->startaddr) && (virtaddr <= mmarea->endaddr)){
			if(mmarea->page_wr_setbysystem[0])
				return RK_PROTECTED;
			else
				return RK_PROTECTED_BYSYSTEM;
		}
	}
	
	LIST1_FOREACH (list_mmarea, mmarea) {
		if(virtaddr < mmarea->startaddr){
			if((virtaddr >> PAGESIZE_SHIFT) == (mmarea->startaddr >> PAGESIZE_SHIFT)){
				if(mmarea->page_wr_setbysystem[0])
					return RK_UNPROTECTED_IN_PROTECTED_AREA;
				else
					return RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM;
			}
		}else if(virtaddr > mmarea->endaddr){
			if((virtaddr >> PAGESIZE_SHIFT) == (mmarea->endaddr >> PAGESIZE_SHIFT)){
				if(mmarea->page_wr_setbysystem[1])
					return RK_UNPROTECTED_IN_PROTECTED_AREA;
				else
					return RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM;
			}
		}
	}

	return RK_UNPROTECTED_AREA;
}

enum rk_result rk_callfunc_if_addr_protected(virt_t virtaddr)
{
	struct mm_protected_area *mmarea;
	
	LIST1_FOREACH (list_mmarea, mmarea) {
		if((virtaddr >= mmarea->startaddr) && (virtaddr <= mmarea->endaddr)){
			if(mmarea->page_wr_setbysystem[0]){
				mmarea->callback_func(mmarea, virtaddr);
				return RK_PROTECTED;
			}else{
				mmarea->callback_func(mmarea, virtaddr);
				return RK_PROTECTED_BYSYSTEM;
			}
		}
	}
	
	LIST1_FOREACH (list_mmarea, mmarea) {
		if(virtaddr < mmarea->startaddr){
			if((virtaddr >> PAGESIZE_SHIFT) == (mmarea->startaddr >> PAGESIZE_SHIFT)){
				if(mmarea->page_wr_setbysystem[0])
					return RK_UNPROTECTED_IN_PROTECTED_AREA;
				else
					return RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM;
			}
		}else if(virtaddr > mmarea->endaddr){
			if((virtaddr >> PAGESIZE_SHIFT) == (mmarea->endaddr >> PAGESIZE_SHIFT)){
				if(mmarea->page_wr_setbysystem[1])
					return RK_UNPROTECTED_IN_PROTECTED_AREA;
				else
					return RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM;
			}
		}
	}

	return RK_UNPROTECTED_AREA;
}

void rk_entry_before_tf(void)
{
	ulong cr0toshadow;	
	u64 pte;
	pmap_t m;

	current->vmctl.read_control_reg (CONTROL_REG_CR0, &cr0toshadow);
	cr0toshadow &= (~CR0_WP_BIT);
	asm_vmwrite (VMCS_CR0_READ_SHADOW, cr0toshadow);
	asm_vmwrite (VMCS_GUEST_CR0, cr0toshadow);

	//make sure the page is read-only before entry!
	pmap_open_vmm (&m, current->spt.cr3tbl_phys, current->spt.levels);
	pmap_seek (&m, current->rk_tf.addr, 1);

	pte = pmap_read(&m);
	pte &= (~PTE_RW_BIT);
	pmap_write (&m, pte, 0xFFF);
	pmap_close (&m);
}

void rk_ret_from_tf(void)
{
	ulong cr0;
	u64 pte;
	pmap_t m;
	
	printf("[RKAnalyzer]Restore CR0.WP...\n");

	//restore CR0's WP
	current->vmctl.read_control_reg (CONTROL_REG_CR0, &cr0);
	cr0 |= CR0_WP_BIT;
	asm_vmwrite (VMCS_CR0_READ_SHADOW, cr0);
	asm_vmwrite (VMCS_GUEST_CR0, cr0);

	//make sure the page is read-only after entry!
	pmap_open_vmm (&m, current->spt.cr3tbl_phys, current->spt.levels);
	pmap_seek (&m, current->rk_tf.addr, 1);

	pte = pmap_read(&m);
	pte &= (~PTE_RW_BIT);
	pmap_write (&m, pte, 0xFFF);
	pmap_close (&m);
}

INITFUNC("global4", rk_init_global);

#endif
