PWD := $(shell pwd)
include $(CONFIG)

CONSTANTS-$(CONFIG_SHADOW_UHCI) += -DENABLE_USB_RW_API
CONSTANTS-$(CONFIG_HANDLE_USBMSC) += -DHANDLE_USBMSC
CONSTANTS-$(CONFIG_HANDLE_USBHUB) += -DHANDLE_USBHUB
CONSTANTS-$(CONFIG_PS2KBD_F10USB) += -DF10USBTEST
CONSTANTS-$(CONFIG_PS2KBD_F12USB) += -DF12UHCIFRAME

OBJS-$(CONFIG_SHADOW_UHCI) += $(patsubst %.c,%.o,$(wildcard uhci*.c))
OBJS-$(CONFIG_SHADOW_EHCI) += $(patsubst %.c,%.o,$(wildcard ehci*.c))
OBJS-$(CONFIG_HANDLE_USBMSC) += usb_mscd.o
OBJS-$(CONFIG_HANDLE_USBHUB) += usb_hub.o
OBJS-1	 = $(filter-out $(OBJS-0), $(OBJS))

TARGET	 = driver.o
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))
HEADERS += $(wildcard *.h)
CFLAGS  += $(CONSTANTS-1) -I$(PWD) -DENABLE_DPRINTF

$(TARGET): $(OBJS-1) $(CONFIG)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJS-1)

$(OBJS-1): $(HEADERS) $(CONFIG)
