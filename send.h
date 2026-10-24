#ifndef SEND_H
#define SEND_H

#include <stdint.h>
#include <libnet.h>

#define SRC_PORT 40000

libnet_t *send_init(void);

int str2addr(libnet_t *net, uint32_t *src, uint32_t *dst, char *argv[]);

int make_packet(libnet_t *net, uint32_t src, uint32_t dst, uint16_t port);

int send_packet(libnet_t *net);

#endif /* SEND_H */
