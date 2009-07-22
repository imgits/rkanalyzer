/*
	Changlog:
	2009.7.22	First Ver. Base Functions
*/

#include "asm.h"
#include "assert.h"
#include "config.h"
#include "current.h"
#include "initfunc.h"
#include "main.h"
#include "mm.h"
#include "panic.h"
#include "pcpu.h"
#include "printf.h"
#include "sleep.h"
#include "string.h"
#include "vmmcall.h"

struct guest_win_kernel_objects{
	virt_t pSDT;
	virt_t pSSDT;
	virt_t pIDT;
	virt_t pKernelCodeStart;
	virt_t pKernelCodeEnd;
};

static void rk_win_init(void)
{
	//Get Windows Kernel Address From guest
	ulong  rbx;
	virt_t base;
	
	current->vmctl.read_general_reg (GENERAL_REG_RBX, &rbx);
	base = (virt_t)rbx;
}

static void
vmmcall_rk_win_init (void)
{
	vmmcall_register ("rk_win_init", rk_win_init);
}

INITFUNC ("vmmcal0", vmmcall_rk_win_init);