#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{

    int i = 0;
    const int * p1 = &i;
    int* p2 = NULL;
    printf("i = %d \n",*p1);
    memcpy(&p2, &p1,sizeof(p1));
    *p2 = 2;
    printf("i = %d \n",*p2);
    printf("i = %d \n",*p1);

    return 0;
}