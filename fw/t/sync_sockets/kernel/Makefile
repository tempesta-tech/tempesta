EXTRA_CFLAGS = $(DEFINES) -I$(src)/../../..

obj-m = kserver.o ss_kserver.o ss_kclient.o

ss_kserver-objs = \
	sync_kserver.o \
	../../../sock.o

ss_kclient-objs = \
	sync_kclient.o \
	../../../addr.o

all:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
