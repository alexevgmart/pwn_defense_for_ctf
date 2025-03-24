#!/bin/bash

rm user;
gcc user.c -o user;
rmmod read_and_write;
make clean;
make;
insmod read_and_write.ko target_file=chall server_monitor=user;
#insmod read_and_write.ko target_file=test server_monitor=user;
./user 192.168.0.137 9001;
