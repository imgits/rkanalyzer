/*
	Changlog:
	2009.7.9		First Ver. Base data structs.
*/


#ifndef _RK_MAIN_H
#define _RK_MAIN_H

#include "types.h"
#include "list.h"
#include "spinlock.h"
#include "rk_nx.h"

#ifdef RK_ANALYZER

//#define RK_ANALYZER_NO_USER_TRACE 1

#define AREA_TAG_MAXLEN 20
#define PROPERTY_MAX 10
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

#define CPL_KERNEL	0
#define CPL_USER	3
#define CPL_KERNEL_EXEC_USER_PAGE	0xF

#ifdef __x86_64__
#define MAX_VA		0xFFFFFFFFFFFFFFFFULL
#else
#define MAX_VA		0xFFFFFFFFUL
#endif

enum rk_result{
	RK_PROTECTED,
	RK_PROTECTED_BYSYSTEM,
	RK_UNPROTECTED_IN_PROTECTED_AREA,
	RK_UNPROTECTED_IN_PROTECTED_AREA_BYSYSTEM,
	RK_UNPROTECTED_AREA,
};

struct mm_protected_area;

//area, virtual address that violation occur
//display, if display is false, then no message should be print out
//bool = true: the access is invalid
//bool = false: the access is valid, bypass it
typedef bool (*mmprotect_callback) (struct mm_protected_area *, virt_t, bool display);
typedef void (*debugreg_dispatch) (int);
typedef void (*os_dependent_setter) (void);

// A Protected Memory Area. The startaddr and endaddr must be in the same page.
struct mm_protected_area{
	LIST2_DEFINE (struct mm_protected_area, forpage);
	LIST2_DEFINE (struct mm_protected_area, forvarange);
	virt_t startaddr;
	virt_t endaddr;
	struct mm_protected_page *page;			//The page that this area belongs to
	struct mm_protected_varange *varange;	//The VA Range that this area belongs to
};

// A Protected Virtual Address Range. It contains protected areas, only original ones, which are divided into pages
struct mm_protected_varange{
	LIST1_DEFINE (struct mm_protected_varange);
	LIST2_DEFINE_HEAD (areas_in_varange, struct mm_protected_area, forvarange);

	virt_t startaddr;
	virt_t endaddr;
	char areatag[AREA_TAG_MAXLEN + 1];
	mmprotect_callback callback_func;
	ulong properties[PROPERTY_MAX];			//properties
};

struct mm_protected_page_samegfns_list;

struct mm_protected_page_derived{
	LIST1_DEFINE (struct mm_protected_page_derived);
	ulong	pfn;								//Page Frame Number; this should never changed after initialized
	struct mm_protected_page_samegfns_list *list_belong;			//The List this derived page belong to
	bool 	page_wr_setbysystem;						//Is the wr bit set by us or the system
};

// A Protected Page. It may contain many protected areas.
struct mm_protected_page{
	LIST1_DEFINE (struct mm_protected_page);
	LIST2_DEFINE_HEAD (areas_in_page, struct mm_protected_area, forpage);	//areas list; when this list is empty, we delete this page from our list
										//and restore the W/R flag according to whether it had been set by system
	ulong	pfn;								//Page Frame Number; this should never changed after initialized
	struct mm_protected_page_samegfns_list *list_belong;			//The List this derived page belong to
	bool 	page_wr_setbysystem;						//Is the wr bit set by us or the system
};

struct mm_protected_page_samegfns_list{
	LIST1_DEFINE_HEAD (struct mm_protected_page_derived, pages_of_samegfns_derived);
	LIST1_DEFINE_HEAD (struct mm_protected_page, pages_of_samegfns_original);
	u64 gfns;								//physical mem frame number
};

/*
	state per vcpu.
	We store all variables that differs in each vcpu here.
*/
struct rk_tf_state{
	bool initialized;
	spinlock_t init_lock;
	
	bool tf;							//Should run with tf? This is a once-set switch
	bool dont_pass_db;					//Should Inhibit #DB pass to guest?
	virt_t	addr;						//The violation address
	ulong originalval;					//Original Value
	ulong last_eip;						//EIP before the instruction
	bool shouldreportvalue;				//Should Report Value Before and After Modification?
	bool has_modify_if_flag;			//Did we modified if flag when enter single stepping?
	
	bool should_set_rf_befor_entry;		//Should we set EFLAGS.RF = 1 before entry? This has nothing to do with tf state, but keep it here
										//for the DR Monitor
	ulong dr_shadow_flag;				//Is Debug Register Shadowed? Each bit reflect one register shadow flag;
	ulong dr0_shadow;					//DR shadows
	ulong dr1_shadow;
	ulong dr2_shadow;
	ulong dr3_shadow;
	ulong dr6_shadow;
	ulong dr7_shadow;
	
	bool nx_enable;						//NX Protection Enabled?
	bool current_code_legal;			//Are we currently executing legal code? Only valid for kernel(CPL = 0)
	u16 cpl_last;						//The CPL of last switch
	bool disable_protect;				//Should Disable Protection? so W/R bit won't be set
	bool guest_msr_efer_nxe;			//Is NXE of MSR_IA32_EFER in guest set? This is used for shadow,lalala
	bool guest_msr_debugctl_lbr;		//Guest Last Branch Record Set?
};

struct os_dependent{
	ulong va_kernel_start;				//Kernel Page Start Virtual Address
	debugreg_dispatch dr_dispatcher;		//Dispatch Routine for Debug Register Monitor
	debugreg_dispatch dr_dispatcher_detectboot;		//Dispatch Routine for Debug Register Monitor
	
	//Dispatch Routine for Unknown code check.
	//NB: DO NOT CALL ANY FUNCTION OF rk_nx.h IN THIS FUNCTION!!!!!!!!!!
	unknown_code_check_dispatch unknown_code_check_dispatcher;
	switch_print switch_print_dispatcher;
	
};

extern volatile struct os_dependent os_dep;
extern volatile bool rk_has_setup;				//Has the module been initialized?

// The startaddr and endaddr could be in different page. The function will handle it and split them to different pages.
bool rk_protect_mmarea(virt_t startaddr, virt_t endaddr, char* areatag, mmprotect_callback callback_func, ulong *properties, int properties_count);
bool rk_unprotect_mmarea(virt_t startaddr, virt_t endaddr);
void rk_manipulate_mmarea_if_need(virt_t newvirtaddr, u64 gfns);

enum rk_result rk_callfunc_if_addr_protected(virt_t virtaddr, bool display);
void rk_ret_from_tf(bool was_instruction_carried_out);
void rk_entry_before_tf(void);

// Common Routines
bool rk_try_setup_global(os_dependent_setter os_dep_setter);
bool rk_try_setup_per_vcpu(void);

void toogle_current_module_legal(void);
bool is_current_module_legal(void);

void toogle_debug_print(void);
bool is_debug(void);
int dbgprint(const char *format, ...)
	__attribute__ ((format (printf, 1, 2)));
	
#endif

#endif
