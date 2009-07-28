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

enum rk_result{
	RK_PROTECTED,
	RK_PROTECTED_BYSYSTEM,
	RK_UNPROTECTED_IN_PROTECTED_AREA,
	RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM,
	RK_UNPROTECTED_AREA,
};

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
	bool 	page_wr_setbysystem[2];			//Is the wr bit set by us or the system
							//(first and last page, as these two pages may be fragile.)
};

struct rk_tf_state{
	bool tf;					//Should run with tf? This is a once-set switch
	bool debuglog;					//debuglog
	enum rk_result rk_res;				
	virt_t	addr;					//The violation address
	u64 originalpte;				//Original PTE.we write it back after TF
};

bool rk_protect_mmarea(virt_t startaddr, virt_t endaddr, char* areatag, mmprotect_callback callback_func);
enum rk_result rk_is_addr_protected(virt_t virtaddr);
enum rk_result rk_callfunc_if_addr_protected(virt_t virtaddr);
void rk_ret_from_tf(void);
void rk_entry_before_tf(void);

#endif

#endif
