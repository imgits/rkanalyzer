/*
	Changlog:
	2009.7.9		First Ver. Base Operations.
*/


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

#ifdef RK_ANALYZER

static LIST1_DEFINE_HEAD (struct mm_protected_area, list_mmarea);

static void
rk_init_global (void)
{
	LIST1_HEAD_INIT (list_mmarea);
	printf("MM Protect Area List Initialized...\n");
}


bool rk_protect_mmarea(virt_t startaddr, virt_t endaddr, char* areatag, mmprotect_callback callback_func, struct mm_protected_area* referarea)
{
	//Two Step:
	//(1) Add this area to list
	//(2) Set those pages which contain this area to WP = 0

	struct mm_protected_area *mmarea;
	int areataglen;
	u64 pte, gfns;
	virt_t currentaddr, currentendaddr, nextaddr;
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

	pmap_open_vmm (&m, current->spt.cr3tbl_phys, current->spt.levels);

	currentaddr = startaddr;
	while(currentaddr <= endaddr){
		mmarea = alloc(sizeof(struct mm_protected_area));

		//TODO:Add Support for Large Pages(4M)

		//Modify Page Table
		pmap_seek (&m, currentaddr, 1);
		pte = pmap_read(&m);
		if((pte & PTE_RW_BIT) != 0){
			mmarea->page_wr_setbysystem = false;
		}else{
			if(rk_is_addr_protected(startaddr) == RK_UNPROTECTED_IN_PROTECTED_AREA){
				mmarea->page_wr_setbysystem = false;
			}else{
				mmarea->page_wr_setbysystem = true;
			}
		}
		pte = pte & (~PTE_RW_BIT);
		pmap_write (&m, pte, 0xFFF);

		gfns = (pte & PTE_ADDR_MASK64) >> PAGESIZE_SHIFT;
		currentendaddr = currentaddr | ~((0xFFFFFFFF >> PAGESIZE_SHIFT) << PAGESIZE_SHIFT);
		nextaddr = currentendaddr + 1;
		if(currentendaddr > endaddr){
			currentendaddr = endaddr;
		}

		printf("Current Addr = 0x%lX\n", currentaddr);
		printf("Current End Addr = 0x%lX\n", currentendaddr);
		printf("Next Addr = 0x%lX\n", nextaddr);

		//Set mmarea
		mmarea->startaddr = currentaddr;
		mmarea->endaddr = currentendaddr;
		mmarea->gfns = gfns;
		mmarea->callback_func = callback_func;
		mmarea->referarea = referarea;
		if(areatag){
			areataglen = (strlen(areatag) > AREA_TAG_MAXLEN ? AREA_TAG_MAXLEN : strlen(areatag));
			memcpy(mmarea->areatag, areatag, sizeof(char) * areataglen);
		}else{
			memset(mmarea->areatag, 0, AREA_TAG_MAXLEN);
		}

		LIST1_ADD (list_mmarea, mmarea);

		if(nextaddr == 0){
			break;
		}
		currentaddr = nextaddr;
	}
	
	pmap_close (&m);

	return true;
	
}

void rk_manipulate_mmarea_if_need(virt_t newvirtaddr, u64 gfns){

	//TODO:Consider the condition that a Large Page(4M) contains a Small Page(4K)

	struct mm_protected_area *mmarea_gfns;
	struct mm_protected_area *mmarea_virtaddr;
	virt_t newstartaddr;
	virt_t newendaddr;

	//Step1. Check gfns is in protect mmarea
	mmarea_gfns = rk_get_mmarea_bygfns(gfns);
	mmarea_virtaddr = rk_get_mmarea_byvirtaddr_insamepage(newvirtaddr);

	if(mmarea_gfns == NULL){
		//If the virtaddr is in protect mmarea but the gfns is not, it means that the mmarea has expired.
		//Remove it if needed.
		if(mmarea_virtaddr != NULL){
			LIST1_DEL(list_mmarea, mmarea_virtaddr);
			free(mmarea_virtaddr);
		}
		return;
	}

	//Step2. Check virtaddr is not in protect mmarea
	if(mmarea_virtaddr != NULL){
		if(mmarea_virtaddr->gfns != gfns){
			//different gfns. the memory area has been remapped since last record.
			//so we should change the mapping.delete last one and add new one.
			LIST1_DEL(list_mmarea, mmarea_virtaddr);
			free(mmarea_virtaddr);
			goto duplicate;
		}
		//same gfns. no need to add it again.
		return;
	}


duplicate:
	//Step3. Do Duplicate
	printf("Guest Tries to map protected physical page, gfns = %llX, virtaddr = %lX\n", gfns, newvirtaddr);
	newstartaddr = ((newvirtaddr >> PAGESIZE_SHIFT) << (PAGESIZE_SHIFT)) | (mmarea_gfns->startaddr & ~((0xFFFFFFFF >> PAGESIZE_SHIFT) << PAGESIZE_SHIFT));
	newendaddr = ((newvirtaddr >> PAGESIZE_SHIFT) << (PAGESIZE_SHIFT)) | (mmarea_gfns->endaddr & ~((0xFFFFFFFF >> PAGESIZE_SHIFT) << PAGESIZE_SHIFT));
	printf("Duplicate MMProtect Area, start = %lX, end = %lX\n", newstartaddr, newendaddr);
	rk_protect_mmarea(newstartaddr, newendaddr, mmarea_gfns->areatag, mmarea_gfns->callback_func, mmarea_gfns);
}

enum rk_result rk_is_addr_protected(virt_t virtaddr)
{
	struct mm_protected_area *mmarea;

	//TODO:Add Support for Large Pages(4M)

	LIST1_FOREACH (list_mmarea, mmarea) {
		if((virtaddr >= mmarea->startaddr) && (virtaddr <= mmarea->endaddr)){
			if(!mmarea->page_wr_setbysystem)
				return RK_PROTECTED;
			else
				return RK_PROTECTED_BYSYSTEM;
		}
	}
	
	LIST1_FOREACH (list_mmarea, mmarea) {
		if(virtaddr < mmarea->startaddr){
			if((virtaddr >> PAGESIZE_SHIFT) == (mmarea->startaddr >> PAGESIZE_SHIFT)){
				if(!mmarea->page_wr_setbysystem)
					return RK_UNPROTECTED_IN_PROTECTED_AREA;
				else
					return RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM;
			}
		}else if(virtaddr > mmarea->endaddr){
			if((virtaddr >> PAGESIZE_SHIFT) == (mmarea->endaddr >> PAGESIZE_SHIFT)){
				if(!mmarea->page_wr_setbysystem)
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
			if(!mmarea->page_wr_setbysystem){
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
				if(!mmarea->page_wr_setbysystem)
					return RK_UNPROTECTED_IN_PROTECTED_AREA;
				else
					return RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM;
			}
		}else if(virtaddr > mmarea->endaddr){
			if((virtaddr >> PAGESIZE_SHIFT) == (mmarea->endaddr >> PAGESIZE_SHIFT)){
				if(!mmarea->page_wr_setbysystem)
					return RK_UNPROTECTED_IN_PROTECTED_AREA;
				else
					return RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM;
			}
		}
	}

	return RK_UNPROTECTED_AREA;
}

struct mm_protected_area* rk_get_mmarea_byvirtaddr_insamepage(virt_t virtaddr){
	struct mm_protected_area *mmarea;
	
	LIST1_FOREACH (list_mmarea, mmarea) {
		if((virtaddr >= mmarea->startaddr) && (virtaddr <= mmarea->endaddr)){
			return mmarea;
		}
	}

	LIST1_FOREACH (list_mmarea, mmarea) {
		if(virtaddr < mmarea->startaddr){
			if((virtaddr >> PAGESIZE_SHIFT) == (mmarea->startaddr >> PAGESIZE_SHIFT)){
				return mmarea;
			}
		}else if(virtaddr > mmarea->endaddr){
			if((virtaddr >> PAGESIZE_SHIFT) == (mmarea->endaddr >> PAGESIZE_SHIFT)){
				return mmarea;
			}
		}
	}

	return NULL;
}

struct mm_protected_area* rk_get_mmarea_bygfns(u64 gfns){

	struct mm_protected_area *mmarea;

	LIST1_FOREACH (list_mmarea, mmarea) {
		if(mmarea->gfns == gfns){
			return mmarea;
		}
	}
	
	return NULL;
}

void rk_entry_before_tf(void)
{
	ulong cr0toshadow;	
	u64 pte;
	pmap_t m;
	ulong val;
	int err = 0;

	current->vmctl.read_control_reg (CONTROL_REG_CR0, &cr0toshadow);
	cr0toshadow &= (~CR0_WP_BIT);
	asm_vmwrite (VMCS_CR0_READ_SHADOW, cr0toshadow);
	asm_vmwrite (VMCS_GUEST_CR0, cr0toshadow);

	if((err = read_linearaddr_l(current->rk_tf.addr, &val)) == VMMERR_SUCCESS){
		printf("Value Before Modification Is : %lX\n", val);
	}else{
		printf("Value Before Modification Is Unknown. err : %d\n", err);
	}

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
	ulong ip;
	ulong val;
	int err = 0;

	// IMPORTANT:SET has_ret_from_tf to false
	current->rk_tf.has_ret_from_tf = false;

	current->vmctl.read_ip(&ip);
	
	if((err = read_linearaddr_l(current->rk_tf.addr, &val)) == VMMERR_SUCCESS){
		printf("Value After Modification Is : %lX\n", val);
	}else{
		printf("Value After Modification Is Unknown. err : %d\n", err);
	}

	printf("[RKAnalyzer]Restore CR0.WP...\n");
	printf("Current EIP is 0x%lX\n", ip);

	//restore CR0's WP
	current->vmctl.read_control_reg (CONTROL_REG_CR0, &cr0);

	printf("Current Guest CRO.WP = %d\n", !!(cr0 & CR0_WP_BIT));

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
