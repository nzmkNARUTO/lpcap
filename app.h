void initCurses();
int scrollDevices(WINDOW **devices, int count);
WINDOW **drawMenu(int start_row, int start_col, int count, pcap_if_t *devices);