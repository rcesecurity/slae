#!/bin/bash

echo '[+] Compiling with GCC ... '
gcc $1.c -o $1 -fno-stack-protector -z execstack -m32

echo '[+] Done!'
