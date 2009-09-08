/*
	Changlog:
	2009.7.22	First Ver. Base Functions
*/

#include "asm.h"
#include "current.h"
#include "initfunc.h"
#include "cpu_mmu.h"
#include "mm.h"
#include "panic.h"
#include "pcpu.h"
#include "printf.h"
#include "string.h"
#include "vmmcall.h"
#include "rk_main.h"

#ifdef RK_ANALYZER

struct guest_win_kernel_objects{
	virt_t pSDT;
	virt_t pSSDT;
	unsigned long int NumberOfService;
	virt_t pIDT;
	virt_t pKernelCodeStart;
	virt_t pKernelCodeEnd;
};

struct guest_win_kernel_objects win_ko;

static void rk_win_readfromguest()
{
	//Parse the PE Section
	//Dump all exported functions.
	
}

static void mmprotect_callback_win_ssdt(struct mm_protected_area *mmarea, virt_t addr)
{
	printf("[RKAnalyzer][SSDT]Access Violation at 0x%lX\n", addr);
	return;
}

static void dump_ko(void)
{
	printf("[RKAnalyzer]Kernel Objects Dump:\n");
	printf("[RKAnalyzer]pSDT = 0x%lX\n", win_ko.pSDT);
	printf("[RKAnalyzer]pSSDT = 0x%lX\n", win_ko.pSSDT);
	printf("[RKAnalyzer]NumberOfService = %ld\n", win_ko.NumberOfService);
	printf("[RKAnalyzer]pIDT = 0x%lX\n", win_ko.pIDT);
	printf("[RKAnalyzer]pKernelCodeStart = 0x%lX\n", win_ko.pKernelCodeStart);
	printf("[RKAnalyzer]pKernelCodeEnd = 0x%lX\n", win_ko.pKernelCodeEnd);
}

static void rk_win_init(void)
{
	//Get Windows Kernel Address From guest
	int i;
	ulong  rbx;
	virt_t base;
	unsigned char* buf = (unsigned char*)&win_ko;
	
	current->vmctl.read_general_reg (GENERAL_REG_RBX, &rbx);
	base = (virt_t)rbx;

	for (i = 0; i < sizeof(struct guest_win_kernel_objects); i++) {
		if (read_linearaddr_b (base + i, buf + i)
		    != VMMERR_SUCCESS)
			goto init_failed;
	}

	dump_ko();

	if(!rk_protect_mmarea(win_ko.pSSDT, win_ko.pSSDT + 4 * win_ko.NumberOfService,"SSDT", mmprotect_callback_win_ssdt)){
		printf("[RKAnalyzer]Failed Adding MM Area...\n");
	}
	
	return;
	
init_failed:
	memset(&win_ko, 0, sizeof(struct guest_win_kernel_objects));
	printf("[RKAnalyzer]Get Kernel Information Failed!\n");
	return;
}

static void
vmmcall_rk_win_init (void)
{
	vmmcall_register ("rk_win_init", rk_win_init);
	memset(&win_ko, 0, sizeof(struct guest_win_kernel_objects));

}

INITFUNC ("vmmcal0", vmmcall_rk_win_init);

#endif
