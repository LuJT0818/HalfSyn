#include <stdio.h>
#include <libnet.h>

#define SRC_PORT 40000

libnet_t* send_init(void);

void str2addr(libnet_t* net, uint32_t* src, uint32_t* dst, char *argv[]);

void make_packet(libnet_t* net, uint32_t src, uint32_t dst, uint16_t port);

void send_packet(libnet_t* net);