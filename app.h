void init_curses();
int scroll_devices(WINDOW **devices, int count);
WINDOW **draw_menu(int start_row, int start_col, int count, pcap_if_t *devices);