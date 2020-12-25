#pragma once
#include "util.h"

void initCurses();
int scrollMenu(WINDOW **devices, int count);
WINDOW **drawDevices(int start_row, int start_col, int count, pcap_if_t *devices);
void deleteMenus(WINDOW **items, int count);
WINDOW **drawMenu();
void drawMenuBar();