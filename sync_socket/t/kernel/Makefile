EXTRA_CFLAGS = $(DEFINES)

obj-m = kserver.o ss_kserver.o ss_kclient.o

ss_kserver-objs = \
	sync_kserver.o

ss_kclient-objs = \
	sync_kclient.o \
	../../../tempesta_fw/addr.o

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
