#include <stdio.h>
#include "time.h"
#include "stdint.h"

int64_t number1=0;
int64_t number2=0;
int64_t number3=1;
int64_t result;
double duration;
clock_t start,stop;

main(){
    start = clock();
    for(number1;number1<50;number1++){

        for(number2;number2<2;number2++){
            result = number1*number2*number3;
        } 

    }
    stop  = clock();
    duration = (double)(stop-start)/CLOCKS_PER_SEC/100*1000;
    printf("duration is: %f",duration);
}
