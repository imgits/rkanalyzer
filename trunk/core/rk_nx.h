#ifndef _RK_NX_H
#define _RK_NX_H

#include "types.h"
#include "list.h"
#include "spinlock.h"

#ifdef RK_ANALYZER

#ifndef CPU_MMU_SPT_USE_PAE
#error Need PAE for NX Protection
#endif

//NB: We will not use hash table to store these code areas. simply use list.
//At most there could be 100 areas and don't worth such effort to implement a hashtable
//
//Note we don't have derived pages for code pages. All executed pages are original.
//Those mapped pages would not be legal, though.

enum rk_code_type{
	RK_CODE_LEGAL,
	RK_CODE_ILLEGAL,
};

enum rk_nx_result{
	RK_NX_K2U,
	RK_NX_U2K,
	RK_NX_L2IL,
	RK_NX_IL2L,
	RK_NX_L2L,
	RK_NX_IL2IL,
	RK_NX_INIT,
	RK_NX_SYSTEM,		//NX Caused by system, should report
};

struct mm_code_varange;

typedef enum rk_code_type (*unknown_code_check_dispatch) (virt_t);
typedef bool (*mmcode_callback) (struct mm_code_varange*, virt_t, bool display);

// A Protected Virtual Address Range. It contains protected areas, only original ones, which are divided into pages
struct mm_code_varange{
	LIST1_DEFINE (struct mm_code_varange);
	virt_t startaddr;
	virt_t endaddr;
	mmcode_callback callback_func;
	bool legal;							//Only valid for original code area. All derived is ILLEGAL!!!!!!!
};

// Following Function for NX Protections
bool rk_del_code_mmvarange(virt_t startaddr, virt_t endaddr);
void rk_manipulate_code_mmvarange_if_need(virt_t newvirtaddr, u64 gfns);
//Only Call in unknown_code_check_dispatch
bool rk_add_code_mmvarange_nolock(bool legal, virt_t startaddr, virt_t endaddr, mmcode_callback callback_func);

//Called When Encounting NX. All branches are processed in this function
//Including: LEGAL<->UNLEGAL, ANY->UNKNOWN, USER<->KERNEL
enum rk_nx_result rk_check_code_mmvarange(virt_t addr);

void rk_nx_try_setup_global();			//Initialized NX Protection
void rk_nx_try_setup_per_vcpu();		//For each cpu

#endif

#endif
