#include <ncurses.h>

#include <locale.h>

#include <stdio.h>
#include <string.h>

int main(void){
    char string[10];
    memset(string, '\0', 10);
    char a='1';
    char b='2';
    char c='3';
    fprintf(string, "%c%c%c", a, b, c);
    printf(string);
}