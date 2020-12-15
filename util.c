#include <stdio.h>

void log(char* string){
    FILE* f;
    f = fopen("log.txt","a");
    fprintf(f,string);
    fclose(f);
}