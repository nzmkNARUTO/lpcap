#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

/**
 * @brief Create a Socket object
 *
 * @return int socket ID
 */
int createSocket();

/**
 * @brief capture a packet
 * store in buffer
 * @param sock from which sock to capture packet
 * @param buffer the char buffer to store data
 * @param maxsize the max size of buffer
 * @return int packet length
 */
int capturePacket(int sock, char* buffer, int maxsize);