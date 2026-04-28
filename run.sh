#!/bin/bash
set -e

gcc test.c malloc.c -ldl -o test
./test