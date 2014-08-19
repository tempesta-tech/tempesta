EXTRA_CFLAGS = $(DEFINES)

obj-m = kserver.o sync_kserver.o

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
