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

// A Protected Memory Area. The startaddr and endaddr must be in the same page.
struct mm_protected_area{
	LIST1_DEFINE (struct mm_protected_area);
	virt_t	startaddr;
	virt_t	endaddr;
	u64 gfns;
	char		areatag[AREA_TAG_MAXLEN + 1];
	mmprotect_callback callback_func;
	bool 	page_wr_setbysystem;			//Is the wr bit set by us or the system
	struct mm_protected_area *referarea;		//If this area is original, set this to NULL; else set it to the area copied from.
};

struct rk_tf_state{
	bool tf;					//Should run with tf? This is a once-set switch
	bool debuglog;					//debuglog
	enum rk_result rk_res;				
	virt_t	addr;					//The violation address
	u64 originalpte;				//Original PTE.we write it back after TF
};

// The startaddr and endaddr could be in different page. The function will handle it and split them to different pages.
bool rk_protect_mmarea(virt_t startaddr, virt_t endaddr, char* areatag, mmprotect_callback callback_func, struct mm_protected_area* referarea);
void rk_manipulate_mmarea_if_need(virt_t newvirtaddr, u64 gfns);

enum rk_result rk_is_addr_protected(virt_t virtaddr);
enum rk_result rk_callfunc_if_addr_protected(virt_t virtaddr);
struct mm_protected_area* rk_get_mmarea_byvirtaddr_insamepage(virt_t virtaddr);
struct mm_protected_area* rk_get_mmarea_bygfns(u64 gfns);
void rk_ret_from_tf(void);
void rk_entry_before_tf(void);

#endif

#endif
