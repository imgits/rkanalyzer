/*
	Changlog:
	2009.7.9		First Ver. Base data structs.
*/


#ifndef _RK_MAIN_H
#define _RK_MAIN_H

#include "types.h"
#include "list.h"

#ifdef RK_ANALYZER

#define AREA_TAG_MAXLEN 20

struct mm_protected_area;

typedef void (*mmprotect_callback) (struct mm_protected_area *, virt_t );

// A Protected Memory Area. The startaddr and endaddr need not to be in the same page.
struct mm_protected_area{
	LIST1_DEFINE (struct mm_protected_area);
	virt_t	startaddr;
	virt_t	endaddr;
	char		areatag[AREA_TAG_MAXLEN + 1];
	bool		detailed;
	char**	detailtags;
	mmprotect_callback callback_func;
};



bool rk_protect_mmarea(virt_t startaddr, virt_t endaddr, char* areatag, mmprotect_callback callback_func);
bool rk_is_addr_protected(virt_t virtaddr);
bool rk_callfunc_if_addr_protected(virt_t virtaddr);

#endif

#endif
