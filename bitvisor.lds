ENTRY(entry)
virt = 0x40100000;
phys = 0x00100000;
PHDRS {
	hdrs PT_PHDR PHDRS AT (phys);
	all PT_LOAD;
}
SECTIONS {
	. = virt;
	head = .;
	. = virt + SIZEOF_HEADERS;
	.text : AT (phys + (code - head)) {
		code = .;
		*(.entry)
		*(.text)
	} :all
	.data : AT (phys + (data - head)) {
		data = .;
		*(.data)
		. = ALIGN (8);
                __initfunc_start = .;
                *(.initfunc)
                __initfunc_end = .;
	/* }
	.bss : AT (phys + (bss - head)) { */
		bss = .;
		*(.bss)
		*(COMMON)
	}
	end = .;
	/DISCARD/ : {
		*(.gomi)
	}
}
