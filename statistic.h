#pragma once

/**
 * @brief Set the Time
 * 
 */
void setTime();

/**
 * @brief statistic a new packet
 * 
 * @param length packet length
 * @param type packet type
 */
void newPacket(int length, int type);

/**
 * @brief show statistic information
 * 
 * @param statistic_window the window to show info
 */
void showInfo(WINDOW *statistic_window);