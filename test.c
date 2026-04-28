#include <stdio.h>
#include <stdlib.h>
int main(){
    int *a = (int*)malloc(sizeof(int) * 10);
    int *b = (int*)malloc(sizeof(int) * 10);
    a[10] = 5;
    if(b[0] == 5){
        printf("won\n");
    } 
    else{
        printf("lost\n");
    }
    return 0;
}