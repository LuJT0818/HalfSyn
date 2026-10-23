# HalfSyn

TCP 半连接（SYN）端口扫描示例：发送 SYN 后，用 libpcap 抓取并解析
目标返回的 SYN+ACK / RST，从而判断端口是否开放。

## 文件

- `main.c`：参数处理、构造并发送 SYN、输出扫描结果
- `sniff.h` / `sniff.c`：抓包模块，封装 libpcap，解析以太网 + IPv4 + TCP

## 编译

```sh
gcc -Wall -Wextra -O2 main.c sniff.c -o main -lnet -lpcap
```

## 运行

```sh
sudo ./main <源IP> <目标IP> <目标端口> [网卡名]
```

例如：

```sh
sudo ./main 192.168.1.10 192.168.1.20 80
sudo ./main 192.168.1.10 192.168.1.20 80 eth0
```

- 需要 root 权限，或给程序授予 `CAP_NET_RAW` 能力（libnet 与 libpcap 都需要）。
- 源 IP 应填写本机地址；不指定网卡时，程序会根据源 IP 自动选择网卡。
- 先启动抓包再发送 SYN，避免响应过快导致漏包。
- 输出结果：收到 `SYN+ACK` 表示端口开放；收到 `RST` 表示端口关闭；
  超时通常表示端口被防火墙过滤或主机不可达。
