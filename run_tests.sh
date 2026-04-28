#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

declare -A DESC
DESC[1]="data leakage after free"
DESC[2]="heap overflow corrupts neighbor"
DESC[3]="double-free detection"
DESC[4]="stale data on realloc"
DESC[5]="header corruption → wrong pool"
DESC[6]="use-after-free"
DESC[7]="off-by-one canary"
DESC[8]="heap scan for secrets"
DESC[9]="free(stack_ptr) injection"
DESC[10]="allocation size confusion"
DESC[11]="header metadata exposure"
DESC[12]="freed memory still readable"
DESC[13]="heap grooming overflow"
DESC[14]="alignment"
DESC[15]="deterministic address prediction"
DESC[16]="allocator memory leak"
DESC[17]="header bit-flip bypass"
DESC[18]="fake chunk forgery"
DESC[19]="pool boundary overflow"
DESC[20]="ASLR / heap randomization"

TOTAL=0
PASS=0
FAILED_LIST=""

for test in tests/test*.c; do
    name=$(basename "$test" .c)
    num="${name#test}"
    desc="${DESC[$num]:-?}"

    if ! gcc "$test" malloc.c -ldl -o "tests/$name" 2>/dev/null; then
        printf "${YELLOW}[ERR ]${RESET}  %-8s - %s\n" "$name" "$desc"
        continue
    fi

    TOTAL=$((TOTAL + 1))
    if "tests/$name" >/dev/null 2>&1; then
        printf "${GREEN}[PASS]${RESET}  %-8s - %s\n" "$name" "$desc"
        PASS=$((PASS + 1))
    else
        printf "${RED}[FAIL]${RESET}  %-8s - %s\n" "$name" "$desc"
        FAILED_LIST="$FAILED_LIST $num"
    fi
done

echo ""
printf '%0.s─' {1..50}; echo ""
printf "${BOLD}Score: $PASS/$TOTAL${RESET}"
if [ -n "$FAILED_LIST" ]; then
    printf "   Failed:$FAILED_LIST"
fi
echo ""
