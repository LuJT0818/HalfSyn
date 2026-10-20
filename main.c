#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>

int main(void)
{
    char errbuf[LIBNET_ERRBUF_SIZE];

    /* 初始化 IPv4 原始套接字，需要 root 权限 */
    libnet_t *net = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (net == NULL) {
        fprintf(stderr, "初始化失败：%s\n", errbuf);
        return 1;
    }

    /* 改成你自己的实验服务器地址和端口 */
    uint32_t dst_ip = libnet_name2addr4(
        net, "192.168.1.100", LIBNET_DONT_RESOLVE
    );
    uint32_t src_ip = libnet_get_ipaddr4(net);

    if (dst_ip == (uint32_t)-1 || src_ip == (uint32_t)-1)
        goto error;

    /* 先构造 TCP 头 */
    if (libnet_build_tcp(
            40000,          /* 本机源端口 */
            80,             /* 服务器目标端口 */
            12345,          /* 序列号 SEQ */
            0,              /* ACK：首次 SYN 不确认任何数据 */
            TH_SYN,         /* 只设置 SYN 标志 */
            64240,          /* 接收窗口大小 */
            0,              /* 校验和：由 Libnet 自动计算 */
            0,              /* 紧急指针 */
            LIBNET_TCP_H,   /* TCP 头长度，无选项和数据 */
            NULL, 0,        /* 不携带数据 */
            net, 0
        ) == -1)
        goto error;

    /* 再构造 IPv4 头，把 TCP 包装进去 */
    if (libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H,
            0,              /* 服务类型 */
            1,              /* IP 标识 */
            0,              /* 分片字段 */
            64,             /* TTL */
            IPPROTO_TCP,
            0,              /* IP 校验和自动计算 */
            src_ip,
            dst_ip,
            NULL, 0,
            net, 0
        ) == -1)
        goto error;

    /* 发送 */
    int bytes = libnet_write(net);
    if (bytes == -1)
        goto error;

    printf("已发送 SYN，共 %d 字节\n", bytes);
    libnet_destroy(net);
    return 0;

error:
    fprintf(stderr, "失败：%s\n", libnet_geterror(net));
    libnet_destroy(net);
    return 1;
}