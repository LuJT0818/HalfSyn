#include "send.h"

#include <stdio.h>
#include <stdlib.h>

libnet_t *send_init(void)
{
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *net = libnet_init(LIBNET_RAW4, NULL, errbuf);

    if (net == NULL)
        fprintf(stderr, "libnet_init: %s\n", errbuf);

    return net;
}

int str2addr(libnet_t *net, uint32_t *src, uint32_t *dst, char *argv[])
{
    *src = libnet_name2addr4(net, argv[1], LIBNET_DONT_RESOLVE);
    *dst = libnet_name2addr4(net, argv[2], LIBNET_DONT_RESOLVE);

    if (*src == (uint32_t)-1 || *dst == (uint32_t)-1) {
        fprintf(stderr, "IP 地址无效：%s / %s\n", argv[1], argv[2]);
        return -1;
    }

    return 0;
}

int make_packet(libnet_t *net, uint32_t src, uint32_t dst, uint16_t port)
{
    if (libnet_build_tcp(
            SRC_PORT,            /* 源端口 */
            port,                /* 用户指定的目标端口 */
            12345,               /* SEQ */
            0,                   /* ACK */
            TH_SYN,              /* SYN 标志 */
            64240,               /* 窗口大小 */
            0,                   /* 自动计算校验和 */
            0,                   /* 紧急指针 */
            LIBNET_TCP_H,        /* TCP 总长：20 字节 */
            NULL, 0,             /* 无数据 */
            net, 0) == -1) {
        fprintf(stderr, "libnet_build_tcp: %s\n", libnet_geterror(net));
        return -1;
    }

    if (libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H,
            0,                   /* 服务字段 */
            1,                   /* IP 标识 */
            0,                   /* 分片字段 */
            64,                  /* TTL */
            IPPROTO_TCP,
            0,                   /* 自动计算校验和 */
            src, dst,
            NULL, 0,
            net, 0) == -1) {
        fprintf(stderr, "libnet_build_ipv4: %s\n", libnet_geterror(net));
        return -1;
    }

    return 0;
}

int send_packet(libnet_t *net)
{
    if (libnet_write(net) == -1) {
        fprintf(stderr, "libnet_write: %s\n", libnet_geterror(net));
        return -1;
    }

    return 0;
}
