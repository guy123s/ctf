#include <stdio.h>
#include <stdlib.h>
int main(){

    int *a = (int*)malloc(sizeof(int) * 10);
    free(a);
    return 0;
}