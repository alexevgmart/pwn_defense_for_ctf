#!/bin/bash

clear
gcc -c -fPIC strings.c -o strings.o
gcc -c -fPIC formats.c -o formats.o
gcc -c -fPIC malloc_and_free.c -o malloc_and_free.o
gcc -c -fPIC main.c -o main.o
gcc -shared -fPIC malloc_and_free.o formats.o strings.o main.o -o libcapture.so
rm malloc_and_free.o formats.o strings.o main.o

file_name="$1"

if [[ "$file_name" == *.c ]]; then
    gcc "$file_name" -o "${file_name%.c}"
    file_name="${file_name%.c}"
fi

LD_PRELOAD=./libcapture.so "./$file_name"

# set environment LD_PRELOAD ./libcapture.so (для pwndbg)