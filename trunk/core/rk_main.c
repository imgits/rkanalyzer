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
#include "constants.h"


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

	if(startaddr > endaddr)
	{
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
	asm_rdcr3 (&cr3);
	pmap_open_vmm (&m, cr3, PMAP_LEVELS);
	for(currentaddr = startaddr; currentaddr <= endaddr; currentaddr ++){
		pmap_seek (&m, startaddr, 1);
		pte = pmap_read(&m) & (~PTE_RW_BIT);
		pmap_write (&m, pte, 0xFFF);
	}
	pmap_close (&m);

	return true;
	
}

bool rk_is_addr_protected(virt_t virtaddr)
{
	struct mm_protected_area *mmarea;
	
	LIST1_FOREACH (list_mmarea, mmarea) {
		if((virtaddr >= mmarea->startaddr) && (virtaddr <= mmarea->endaddr)){
			return true;
		}
	}

	return false;
}

bool rk_callfunc_if_addr_protected(virt_t virtaddr)
{
		struct mm_protected_area *mmarea;
	
	LIST1_FOREACH (list_mmarea, mmarea) {
		if((virtaddr >= mmarea->startaddr) && (virtaddr <= mmarea->endaddr)){
			mmarea->callback_func(mmarea, virtaddr);
			return true;
		}
	}

	return false;
}

INITFUNC("global4", rk_init_global);
