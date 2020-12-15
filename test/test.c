#include <ncurses.h>

#include <locale.h>

#include <stdio.h>

int main(void){

//init_pair(short index,short foreground,short background)初始化颜色索引

//attron(COLOR_PAIR(索引号)|属性)

    setlocale(LC_ALL,"");

    initscr();//初始化

    box(stdscr,ACS_VLINE,ACS_HLINE);//画边框

    if (!has_colors()||start_color()==ERR){

    endwin();

    printf("终端不支持颜色\n");

    return 0;

    }

    init_pair(1,COLOR_GREEN,COLOR_BLACK);

    init_pair(2,COLOR_RED,COLOR_BLACK);

    init_pair(3,COLOR_WHITE,COLOR_BLUE);

    int i=0;

    for (i=1;i<=3;i++){

        attron(COLOR_PAIR(i));

        move(i,10);

        printw("hello,world:%d",i);

    }

    for (i=1;i<=3;i++){

        attron(COLOR_PAIR(i)|A_UNDERLINE);

        move(i+5,10);

        printw("hello,world:%d",i);

    }

    refresh();//刷新屏幕

    getch();//等待按键

    endwin();//结束
}