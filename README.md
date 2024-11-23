# InfoSec Workshop HW2:

In order to insert the module into the kernel write in bash:
```
cd module
make
sudo insmod hw2secws.ko
```

In order to run the user space program:
```
cd user
gcc packetCounter.c
./a.out
```

To remove the module from kernel:
sudo rmmod hw2secws
make clean (in module folder to remove the *o *ko files)