#include "sniff.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define SNAP_LEN            65535
#define READ_TIMEOUT_MS     100
#define CAPTURE_TIMEOUT_SEC 3

/* 解析 TCP 报文并打印 SYN / RST / ACK 标志 */
static void got_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    (void) header;
    const struct ip *ip = (const struct ip *)(packet + 14);
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + 14 + ip->ip_hl * 4);
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));

    printf("%s:%u -> %s:%u\n", src, ntohs(tcp->th_sport), dst, ntohs(tcp->th_dport));
    printf(" [SYN=%d  RST=%d  ACK=%d]", !!(tcp->th_flags & TH_SYN), !!(tcp->th_flags & TH_RST), !!(tcp->th_flags & TH_ACK));

    if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
        printf("  => SYN+ACK：端口开放\n");
    else if (tcp->th_flags & TH_RST)
        printf("  => RST：端口关闭\n");
}

pcap_t *sniff_init(const char *device, const char *filter_exp){
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    pcap_t *handle = pcap_open_live(device, SNAP_LEN, 0, READ_TIMEOUT_MS, errbuf);
    /* 设置过滤器 */
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) goto error;
    if (pcap_setfilter(handle, &fp) != 0) goto error;
    /* 非阻塞读取，配合下面的简单轮询实现超时 */
    if (pcap_setnonblock(handle, 1, errbuf) == -1) goto error;

    pcap_freecode(&fp);
    return handle;

error:
    pcap_freecode(&fp);
    pcap_close(handle);
    return NULL;
}

int sniff_packet(pcap_t *handle)
{
    time_t deadline = time(NULL) + CAPTURE_TIMEOUT_SEC;

    while (time(NULL) < deadline) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        if(pcap_next_ex(handle, &header, &packet)){
            got_packet(header, packet);
            return 0;
        }
        usleep(10000);  /* 没有报文时等 10 ms，避免忙等 */
    }
    printf("超时：没有收到响应\n");
    return -1;
}
