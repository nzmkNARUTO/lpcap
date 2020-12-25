#pragma once
#include "util.h"

void initCurses();
int scrollDevices(WINDOW **devices, int count);
WINDOW **drawDevices(int start_row, int start_col, int count, pcap_if_t *devices);
void deleteDevices(WINDOW **items, int count);
WINDOW **drawPacket(int count, pNode packet);