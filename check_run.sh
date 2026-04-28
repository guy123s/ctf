#!/bin/bash
set -e

gcc self_check.c malloc.c -ldl -o self_check
./self_check