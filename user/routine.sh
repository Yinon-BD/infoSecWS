sudo dmesg -c
clear
sudo sysctl net.ipv4.ip_forward=1
cd ~/infoSecWS/module
sudo rmmod firewall
make clean
make
sudo insmod ./firewall.ko
cd ../user
make clean
make
sudo ./load_rules.sh
sudo ./show_rules.sh
