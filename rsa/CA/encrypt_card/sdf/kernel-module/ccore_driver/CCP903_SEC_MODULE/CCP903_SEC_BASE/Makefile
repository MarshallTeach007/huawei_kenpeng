
DRV_SDF = 
DRV_CCP903H = 

TARGET := PCIE_CCP903T
obj-m = $(TARGET).o
$(TARGET)-objs = jr.o  ccp903_sec.o job.o ccp903_cards.o compate_interface.o ccp903_common.o ccp903_dbg.o

ifdef DRV_SDF
EXTRA_CFLAGS += -DBAR_CONFIG_IN_COS
endif

INC := -I/$(PWD)/INCLUDE

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) $(INC) modules
	#make -C /lib/modules/4.15.0-041500-generic/build M=$(shell pwd) $(INC) modules
	#make -C $(KERNEL_SRC) M=$(shell pwd) $(INC) modules  
	#make -C /home/zjjin/work/ccfc9000ta/linux-3.4.106.ccore.r1 M=$(shell pwd) modules ARCH=powerpc
clean: 
	rm -rf *.a *.o *.ko *.mod.c *.mod.o modules.* Mod* 

