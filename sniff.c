#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
// 每抓到数据包，pcap自动调用该回调函数
// 编译命令：g++ -o sniffer Sniffer.cpp -lpcap
void print_hex(const u_char *data, size_t len){
    printf("0x00: ");
    for (size_t i = 0; i < len; i++){
        printf("%02x ", data[i]);
        if ((i+1) % 16 == 0)
            printf("\n0x%02lx: ", i+1);
    }
    printf("\n");
}
void print_payload(const u_char *data, int len){
    for (int i = 0; i < len; i++){
        unsigned char c = data[i];
        if (c >= 32 && c < 127) putchar(c);
        else if (c == '\n') putchar('\n');
        // else printf("\\x%02x", c);
    }
    fflush(stdout);
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    // 解析数据包以太网帧 + ip数据报
    const struct ether_header *eth = (const struct ether_header *)packet;
    const struct ip *ip_hdr = (const struct ip *)(packet + 14);
    const struct tcphdr *tcp_hdr = (const struct tcphdr *)(packet + 14 + 20);

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip_hdr->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst, sizeof(dst));

    int payload_len = header->caplen - 14 - 20 - tcp_hdr->doff * 4;
    if (payload_len <= 0) return;
    const u_char *payload = packet + 14 + 20 + tcp_hdr->doff * 4;

    // printf("Got a packet, the packet length is %u bytes\n", header->caplen);
    printf("[%s -> %s]\n", src, dst);
    // print_hex(packet, header->caplen);
    print_payload(payload, payload_len);

    printf("-------------\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    // 1.两台特定主机之间的 ICMP 报文
    // char filter_exp[] = "icmp && (host 10.0.9.5 || host 10.0.9.6)";
    // 2. 目标端口范围 10‑100 的 TCP 报文
    // char filter_exp[] = "tcp && (port >= 10 && port <= 100)";
    // 3. Telnet 报文, 端口为23
    char filter_exp[] = "tcp && dst port 23";

    bpf_u_int32 net;

    // 打开网卡会话，把eth3修改为自己的网卡（br‑xxxx）
    handle = pcap_open_live("br-a91f707f420b", BUFSIZ, 1, 1000, errbuf);

    // 编译BPF过滤表达式
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // 循环捕获数据包，‑1代表无限抓包
    pcap_loop(handle, -1, got_packet, NULL);
    
    pcap_close(handle);
    return 0;
}
