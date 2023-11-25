KERNEL = /lib/modules/$(shell uname -r)/build

obj-m += nice-driver.o
nice-driver-objs = main.o hooks.o utils.o ioctl-handlers.o
ccflags-y += -Wno-declaration-after-statement

all:
	${MAKE} -C ${KERNEL} M=$(PWD) modules

clean:
	${MAKE} -C ${KERNEL} M=$(PWD) clean

test:
	rmmod nice-driver
	make
	dmesg -C
	insmod nice-driver.ko
