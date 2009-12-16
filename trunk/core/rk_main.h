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
#define DR6_FLAG_BS 0x4000
#define DR6_FLAG_BD 0x2000
#define DR6_FLAG_B0 0x1
#define DR6_FLAG_B1 0x2
#define DR6_FLAG_B2 0x4
#define DR6_FLAG_B3 0x8
#define DR_SHADOW_DR0 0x1
#define DR_SHADOW_DR1 0x2
#define DR_SHADOW_DR2 0x4
#define DR_SHADOW_DR3 0x8
#define DR_SHADOW_DR6 0x40
#define DR_SHADOW_DR7 0x80

enum rk_result{
	RK_PROTECTED,
	RK_PROTECTED_BYSYSTEM,
	RK_UNPROTECTED_IN_PROTECTED_AREA,
	RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM,
	RK_UNPROTECTED_AREA,
};

struct mm_protected_area;

typedef void (*mmprotect_callback) (struct mm_protected_area *, virt_t );
typedef void (*debugreg_dispatch) (int);

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
	bool has_ret_from_tf;				//Set this flag after return from tf. Clear it before the next entry.
	bool other_interrput_during_tf;			//Other Interrupt During TF;
	virt_t	addr;					//The violation address
	u64 originalpte;				//Original PTE.we write it back after TF
	ulong init_pending_count;			//Is there a init 
	bool shouldreportvalue;				//Should Report Value Before and After Modification?
	bool if_flag;					//Is IF Flag Set when enter Single Stepping
	bool should_set_rf_befor_entry;			//Should we set EFLAGS.RF = 1 before entry? This has nothing to do with tf state, but keep it here 								//for the DR Monitor
	ulong dr_shadow_flag;				//Is Debug Register Shadowed? Each bit reflect one register shadow flag;
	ulong dr0_shadow;				//DR shadows
	ulong dr1_shadow;
	ulong dr2_shadow;
	ulong dr3_shadow;
	ulong dr6_shadow;
	ulong dr7_shadow;
};

extern bool has_setup;				//Has the module been initialized?
extern debugreg_dispatch dr_dispatcher;		//Dispatch Routine for Debug Register Monitor

// The startaddr and endaddr could be in different page. The function will handle it and split them to different pages.
bool rk_protect_mmarea(virt_t startaddr, virt_t endaddr, char* areatag, mmprotect_callback callback_func, struct mm_protected_area* referarea);
void rk_manipulate_mmarea_if_need(virt_t newvirtaddr, u64 gfns);

enum rk_result rk_is_addr_protected(virt_t virtaddr);
enum rk_result rk_callfunc_if_addr_protected(virt_t virtaddr);
struct mm_protected_area* rk_get_mmarea_byvirtaddr_insamepage(virt_t virtaddr);
struct mm_protected_area* rk_get_mmarea_original_bygfns(u64 gfns);
void rk_ret_from_tf(void);
void rk_entry_before_tf(void);
bool rk_try_setup(void);

#endif

#endif
