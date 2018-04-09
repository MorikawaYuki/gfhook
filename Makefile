CONFIG_MODULE_SING=n
obj-m += gf_hook.o  
all:     
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules  
clean:     
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
