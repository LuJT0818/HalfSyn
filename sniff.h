#ifndef SNIFF_H
#define SNIFF_H

#include <pcap.h>

/* 打开网卡并设置过滤器，失败返回 NULL。 */
pcap_t *sniff_init(const char *device, const char *filter_exp);

/* 等待一个 TCP 响应并打印 SYN/RST/ACK。
 * 收到返回 0，超时或出错返回 -1；不关闭 handle。
 */
int sniff_packet(pcap_t *handle);

#endif /* SNIFF_H */
