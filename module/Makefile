obj-m += firewall.o
firewall-objs := hw4secws.o RuleTable.o LogDevice.o PacketFilter.o ConnectionTable.o ProxyDevice.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean