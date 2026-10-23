#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "sniff.h"
#include "send.h"

u_int check(int argc, char *argv[], u_int *port){
    /* argv[1]：源 IP
     * argv[2]：目标 IP
     * argv[3]：目标端口
     * argv[4]：可选，抓包网卡（默认按源 IP 自动选择）
     */
    if (argc != 4 && argc != 5) {
        printf("用法：%s <源IP> <目标IP> <目标端口> [网卡名]\n", argv[0]);
        return 0;
    }

    /* 将端口字符串转为整数，并检查范围 */
    char *end;
    *port = strtol(argv[3], &end, 10);
    if (end == argv[3] || *end != '\0' ||
        *port < 1 || *port > 65535) {
        fprintf(stderr, "端口必须是 1～65535 的整数\n");
        return 0;
    }
}

int main(int argc, char *argv[])
{
    uint32_t src = 0, dst = 0;
    u_int port = 0;
    if (!check(argc, argv, &port)) return 1;

    
    libnet_t* net = send_init();
    str2addr(net, &src, &dst, argv);
    

    make_packet(net, src, dst, port);
    send_packet(net);
    printf("success\n");
}
