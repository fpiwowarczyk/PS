#include <time.h>
#include <stdio.h>
time_t t;
int main()
{
    t= clock();
    printf( "Czas %ld",clock());

}