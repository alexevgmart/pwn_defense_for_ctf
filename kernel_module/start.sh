#!/bin/bash

gcc user.c -o user;
rmmod read_and_write;
make clean;
make;
insmod read_and_write.ko target_file=chall server_monitor=user;
./user;
