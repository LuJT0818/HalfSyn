#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "sniff.h"
#include "send.h"

/* 参数检查：成功返回 1，失败返回 0 */
// gcc -Wall -Wextra -O2 main.c send.c sniff.c -o main -lnet -lpcap
// (本地测试)打开端口: python3 -m http.server 8000 --bind 127.0.0.1
// sudo ./main 127.0.0.1 127.0.0.1 5000
// 查看本机 IP 和出口网卡：ip -4 -brief addr show

/* 根据本机 IPv4 地址查找对应网卡名，找不到返回 NULL */
static const char *device_from_ip(const char *ip)
{
    static char name[IFNAMSIZ];
    struct ifaddrs *ifs, *ifa;
    struct in_addr want;

    if (inet_pton(AF_INET, ip, &want) != 1)
        return NULL;

    if (getifaddrs(&ifs) != 0)
        return NULL;

    for (ifa = ifs; ifa != NULL; ifa = ifa->ifa_next) {
        if (!(ifa->ifa_flags & IFF_UP) ||
            ifa->ifa_addr == NULL ||
            ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr ==
            want.s_addr) {
            snprintf(name, sizeof(name), "%s", ifa->ifa_name);
            freeifaddrs(ifs);
            return name;
        }
    }

    freeifaddrs(ifs);
    return NULL;
}
static int check(int argc, char *argv[], uint16_t *port)
{
    /* argv[1]：源 IP
     * argv[2]：目标 IP
     * argv[3]：目标端口
     * argv[4]：可选，抓包网卡（默认 lo）
     */
    if (argc != 4 && argc != 5) {
        printf("用法：%s <源IP> <目标IP> <目标端口> [网卡名]\n", argv[0]);
        return 0;
    }

    char *end;
    long value = strtol(argv[3], &end, 10);

    if (end == argv[3] || *end != '\0' ||
        value < 1 || value > 65535) {
        fprintf(stderr, "端口必须是 1～65535 的整数\n");
        return 0;
    }

    *port = (uint16_t)value;
    return 1;
}

int main(int argc, char *argv[])
{
    uint32_t src = 0, dst = 0;
    uint16_t port = 0;
    const char *device;
    char filter[512];
    pcap_t *handle = NULL;
    libnet_t *net = NULL;
    int ret = 1;

    if (!check(argc, argv, &port))
        return 1;

    device = (argc == 5) ? argv[4] : device_from_ip(argv[1]);
    if (device == NULL) {
        fprintf(stderr, "找不到源 IP %s 对应的网卡，请手动指定\n", argv[1]);
        return 1;
    }

    /* 只接收“从目标端口返回给扫描源端口 40000”的响应，
     * 避免把自己的 SYN 也抓进来。
     */
    snprintf(filter, sizeof(filter),
                   "tcp and src host %s and dst host %s "
                   "and src port %u and dst port %u",
                   argv[2], argv[1], (unsigned)port, SRC_PORT);

    /* 先打开抓包并装好过滤器，再发 SYN。
     * 这样目标响应再快，报文也已经进入抓包缓冲区，不会漏掉。
     */
    handle = sniff_init(device, filter);
    if (handle == NULL)
        return 1;

    net = send_init();
    if (net == NULL) {
        pcap_close(handle);
        return 1;
    }

    str2addr(net, &src, &dst, argv);
    make_packet(net, src, dst, port);
    send_packet(net);
    printf("已发送 SYN：%s:%d -> %s:%u，等待响应...\n",
           argv[1], SRC_PORT, argv[2], (unsigned)port);

    /* 等待并解析响应，打印 SYN / RST / ACK 标志 */
    if (sniff_packet(handle) == 0)
        ret = 0;
    return ret;
}
