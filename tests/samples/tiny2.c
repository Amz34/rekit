#include <stdio.h>
static int add(int a,int b){return a+b;}
static int sub(int a,int b){return a-b;}
static int mul(int a,int b){return a*b;}
int main(void){printf("%d %d %d\n", add(1,2), sub(3,1), mul(2,5)); return 0;}
