# libpcap 抓包与解析教程

本文以 Linux + C 为例，讲清 libpcap 从**选择网卡 → 打开设备 → 设置过滤器 → 抓包 → 解析链路层/IP/TCP → 关闭**的完整流程。文末有一个可直接编译运行的完整例子，也适合改造成 TCP 半连接扫描器的接收模块。

> 环境：Ubuntu/Debian，libpcap 1.9+，gcc。
> 安装开发包：`sudo apt install libpcap-dev`
> 头文件：`#include <pcap.h>`
> 链接选项：`-lpcap`

---

## 目录

1. [整体流程](#1-整体流程)
2. [核心数据结构](#2-核心数据结构)
3. [常用函数详解](#3-常用函数详解)
4. [BPF 过滤表达式](#4-bpf-过滤表达式)
5. [数据包解析](#5-数据包解析)
6. [完整示例](#6-完整示例)
7. [编译、权限与运行](#7-编译权限与运行)
8. [常见问题](#8-常见问题)
9. [函数速查表](#9-函数速查表)

---

## 1. 整体流程

```text
① 找到网卡            pcap_findalldevs / pcap_freealldevs
        │
② 打开网卡            pcap_open_live
        │             或 pcap_create + 若干 set_* + pcap_activate
        ▼
③ 查看链路层类型      pcap_datalink
        │
④ 编译并安装过滤器    pcap_compile → pcap_setfilter → pcap_freecode
        │
⑤ 循环抓包            pcap_loop / pcap_dispatch / pcap_next_ex
        │
⑥ 解析报文            以太网头 → IPv4 头 → TCP 头（自己写代码）
        │
⑦ 统计、关闭          pcap_stats / pcap_close
```

最常用的“最小组合”其实只有 6 个函数：

```c
pcap_open_live()
pcap_compile()
pcap_setfilter()
pcap_freecode()
pcap_next_ex()      /* 或 pcap_loop() */
pcap_close()
```

### 一个重要顺序

如果是“先发请求，再等响应”的程序（例如 SYN 扫描），一定要**先打开抓包设备并装好过滤器，再发送请求**：

```c
handle = pcap_open_live(...);   /* 先开始抓包 */
pcap_setfilter(...);
send_syn();                     /* 再发包 */
pcap_next_ex(...);              /* 收响应 */
```

否则响应可能在抓包启动之前就已经到达，造成漏包。

---

## 2. 核心数据结构

### 2.1 `pcap_t`

抓包句柄，内部细节不公开，相当于 `FILE *`：

```c
typedef struct pcap pcap_t;
```

所有抓包 API 都要围绕它工作。一个句柄同一时间只应由一个线程使用。

### 2.2 `pcap_if_t` 和 `pcap_addr_t`

`pcap_findalldevs()` 返回的网卡链表节点：

```c
struct pcap_if {
    struct pcap_if *next;
    char *name;                 /* 网卡名，传给 pcap_open_live() */
    char *description;          /* 文字描述，可能为 NULL */
    struct pcap_addr *addresses;
    bpf_u_int32 flags;          /* PCAP_IF_LOOPBACK / PCAP_IF_UP 等 */
};

struct pcap_addr {
    struct pcap_addr *next;
    struct sockaddr *addr;      /* IP 地址 */
    struct sockaddr *netmask;   /* 子网掩码 */
    struct sockaddr *broadaddr; /* 广播地址，可能为 NULL */
    struct sockaddr *dstaddr;   /* 点对点对端地址，可能为 NULL */
};
```

常用标志位：

```c
PCAP_IF_LOOPBACK   0x00000001
PCAP_IF_UP         0x00000002
PCAP_IF_RUNNING    0x00000004
```

### 2.3 `struct pcap_pkthdr`

每抓到一包，libpcap 都会给出这个头部信息：

```c
struct pcap_pkthdr {
    struct timeval ts;      /* 抓包时间戳 */
    bpf_u_int32 caplen;     /* 实际抓到的字节数 */
    bpf_u_int32 len;        /* 报文在链路上的原始长度 */
};
```

重点区分：

- `caplen`：你真正拿到的字节数，**解析时的边界检查必须用它**。
- `len`：报文原始长度。如果 `caplen < len`，说明被 `snaplen` 截断了。
- `ts`：时间戳，`ts.tv_sec` 和 `ts.tv_usec`。

### 2.4 `struct bpf_program`

编译后的 BPF 过滤程序：

```c
struct bpf_program {
    u_int bf_len;           /* 指令条数 */
    struct bpf_insn *bf_insns;  /* 指令数组 */
};
```

通常不直接操作它，交给 `pcap_compile()`、`pcap_setfilter()`、`pcap_freecode()` 即可。

### 2.5 `pcap_handler`

`pcap_loop()` 和 `pcap_dispatch()` 使用的回调类型：

```c
typedef void (*pcap_handler)(u_char *user,
                             const struct pcap_pkthdr *h,
                             const u_char *bytes);
```

- `user`：调用 `pcap_loop()` 时传入的自定义指针。
- `h`：报文头（时间戳、长度）。
- `bytes`：报文内容，从**链路层头**开始。

### 2.6 `struct pcap_stat`

抓包统计信息：

```c
struct pcap_stat {
    u_int ps_recv;      /* 收到的报文数 */
    u_int ps_drop;      /* 因缓冲区满等被丢弃的报文数 */
    u_int ps_ifdrop;    /* 网卡层丢弃数，部分平台不支持 */
};
```

`ps_drop` 持续增长通常说明抓包跟不上流量，需要加大缓冲区或收紧过滤器。

---

## 3. 常用函数详解

### 3.1 设备发现与网络信息

#### `pcap_findalldevs`

```c
int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
```

功能：列出所有可抓包的网卡，成功返回 `0`，失败返回 `-1` 并填写 `errbuf`。

参数：

- `alldevsp`：输出参数，指向分配好的 `pcap_if_t` 链表头。
- `errbuf`：至少 `PCAP_ERRBUF_SIZE` 字节的错误缓冲区。

示例：

```c
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;
    pcap_if_t *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    for (d = alldevs; d != NULL; d = d->next) {
        printf("%s", d->name);
        if (d->description != NULL)
            printf("  (%s)", d->description);
        printf("\n");

        for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
            if (a->addr != NULL && a->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                printf("    IPv4: %s\n", ip);
            }
        }
    }

    pcap_freealldevs(alldevs);
    return 0;
}
```

#### `pcap_freealldevs`

```c
void pcap_freealldevs(pcap_if_t *alldevs);
```

功能：释放 `pcap_findalldevs()` 分配的链表。没有返回值。

#### `pcap_lookupnet`

```c
int pcap_lookupnet(const char *device,
                   bpf_u_int32 *netp,
                   bpf_u_int32 *maskp,
                   char *errbuf);
```

功能：取得指定网卡的网络号和掩码，主要用于 `pcap_compile()` 的 `netmask` 参数。

- `netp`、`maskp`：输出参数，网络字节序。
- 成功返回 `0`，失败返回 `-1`。
- 不知道掩码时可以用 `PCAP_NETMASK_UNKNOWN`。

```c
bpf_u_int32 net = 0;
bpf_u_int32 mask = PCAP_NETMASK_UNKNOWN;

if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
    /* 不影响简单 host/port 过滤，继续用 PCAP_NETMASK_UNKNOWN */
}
```

#### `pcap_lookupdev`（已废弃）

```c
char *pcap_lookupdev(char *errbuf);
```

老代码常见，但已废弃，且不线程安全。新代码请使用 `pcap_findalldevs()` 取第一块网卡，或让用户显式指定。

#### `pcap_lib_version`

```c
const char *pcap_lib_version(void);
```

返回 libpcap 版本字符串，调试时很有用：

```c
printf("%s\n", pcap_lib_version());
```

---

### 3.2 打开与关闭设备

#### `pcap_open_live`

```c
pcap_t *pcap_open_live(const char *device,
                       int snaplen,
                       int promisc,
                       int to_ms,
                       char *errbuf);
```

功能：打开网卡开始抓包。成功返回句柄，失败返回 `NULL`。

参数：

| 参数 | 含义 |
|---|---|
| `device` | 网卡名，如 `eth0`、`enp0s3`、`lo`、`any` |
| `snaplen` | 每包最多抓多少字节，常用 `65535` |
| `promisc` | 非 0 表示混杂模式，抓本网段所有帧；扫描器一般用 `0` |
| `to_ms` | 读超时，单位毫秒；`0` 的行为依赖平台，可能一直阻塞 |
| `errbuf` | 失败原因，至少 `PCAP_ERRBUF_SIZE` 字节 |

```c
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle = pcap_open_live("enp0s3", 65535, 0, 100, errbuf);

if (handle == NULL) {
    fprintf(stderr, "pcap_open_live: %s\n", errbuf);
    return 1;
}
```

注意：`snaplen` 太小会截断报文；解析时如果 `caplen < len`，只能解析已抓到的部分。

#### `pcap_create` + 配置函数 + `pcap_activate`

```c
pcap_t *pcap_create(const char *device, char *errbuf);

int pcap_set_snaplen(pcap_t *p, int snaplen);
int pcap_set_promisc(pcap_t *p, int promisc);
int pcap_set_timeout(pcap_t *p, int to_ms);
int pcap_set_immediate_mode(pcap_t *p, int immediate);
int pcap_set_buffer_size(pcap_t *p, int size);
int pcap_activate(pcap_t *p);
```

这是更现代、更灵活的打开方式：

1. `pcap_create()` 创建未激活句柄。
2. 在激活前调用各个 `pcap_set_*()`。
3. 最后 `pcap_activate()` 真正打开设备。

`pcap_activate()` 返回值：

- `0`：成功。
- `> 0`：成功但有警告（例如不支持混杂模式）。
- `< 0`：失败，可用 `pcap_statustostr()` 和 `pcap_geterr()` 查看。

```c
pcap_t *handle = pcap_create(dev, errbuf);
if (handle == NULL) {
    fprintf(stderr, "pcap_create: %s\n", errbuf);
    return NULL;
}

if (pcap_set_snaplen(handle, 65535) < 0 ||
    pcap_set_promisc(handle, 0) < 0 ||
    pcap_set_timeout(handle, 100) < 0) {
    fprintf(stderr, "配置抓包参数失败: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return NULL;
}

/* 低延迟：有包就尽快交给应用，适合“发一个包等一个响应”的扫描器 */
pcap_set_immediate_mode(handle, 1);

int rc = pcap_activate(handle);
if (rc < 0) {
    fprintf(stderr, "pcap_activate: %s (%s)\n",
            pcap_statustostr(rc), pcap_geterr(handle));
    pcap_close(handle);
    return NULL;
}
if (rc > 0) {
    fprintf(stderr, "警告: %s\n", pcap_statustostr(rc));
}
```

几个配置函数：

| 函数 | 作用 |
|---|---|
| `pcap_set_snaplen()` | 设置抓包长度 |
| `pcap_set_promisc()` | 设置混杂模式 |
| `pcap_set_timeout()` | 设置读超时（毫秒） |
| `pcap_set_immediate_mode()` | 关闭缓冲，尽快交付报文 |
| `pcap_set_buffer_size()` | 设置内核抓包缓冲区字节数 |

这些函数都必须在 `pcap_activate()` 之前调用，否则可能返回 `PCAP_ERROR_ACTIVATED`。

#### `pcap_open_offline`

```c
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
```

功能：打开一个 `.pcap` / `.pcapng` 文件，后续用同样的 `pcap_next_ex()` 读取。

```c
pcap_t *handle = pcap_open_offline("demo.pcap", errbuf);
if (handle == NULL) {
    fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
    return 1;
}

struct pcap_pkthdr *hdr;
const u_char *pkt;
int rc;
while ((rc = pcap_next_ex(handle, &hdr, &pkt)) == 1) {
    /* 解析 pkt */
}
/* rc == PCAP_ERROR_BREAK(-2) 表示正常读到文件末尾 */
pcap_close(handle);
```

#### `pcap_close`

```c
void pcap_close(pcap_t *p);
```

关闭句柄，释放资源。所有打开成功的 `pcap_t *` 最后都要关闭。

---

### 3.3 过滤器：编译、安装、释放

过滤器的作用是让内核只把匹配的报文交给用户态，既减少拷贝，也避免解析无关流量。

#### `pcap_compile`

```c
int pcap_compile(pcap_t *p,
                 struct bpf_program *fp,
                 const char *str,
                 int optimize,
                 bpf_u_int32 netmask);
```

功能：把人类可读的过滤表达式编译成 BPF 指令。

- `p`：已激活的抓包句柄。
- `fp`：输出，编译结果。
- `str`：过滤表达式，如 `"tcp and port 80"`。
- `optimize`：一般传 `1`。
- `netmask`：`pcap_lookupnet()` 得到的掩码；不知道就传 `PCAP_NETMASK_UNKNOWN`。

成功返回 `0`，失败返回 `-1`，错误用 `pcap_geterr(p)` 获取。

#### `pcap_setfilter`

```c
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
```

功能：把编译好的过滤器安装到抓包句柄。成功返回 `0`，失败返回 `-1`。

#### `pcap_freecode`

```c
void pcap_freecode(struct bpf_program *fp);
```

功能：释放 `pcap_compile()` 分配的内存。`pcap_setfilter()` 成功后就可以释放，不需要等到抓包结束。

完整写法：

```c
bpf_u_int32 net = 0;
bpf_u_int32 mask = PCAP_NETMASK_UNKNOWN;
struct bpf_program fp;
const char *filter = "tcp and src host 192.168.1.20 and dst port 40000";

pcap_lookupnet(dev, &net, &mask, errbuf);  /* 失败也不影响 host/port 过滤 */

if (pcap_compile(handle, &fp, filter, 1, mask) == -1) {
    fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
}

if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
    pcap_freecode(&fp);
    pcap_close(handle);
    return 1;
}

pcap_freecode(&fp);
```

#### `pcap_offline_filter`

```c
int pcap_offline_filter(const struct bpf_program *fp,
                        const struct pcap_pkthdr *h,
                        const u_char *pkt);
```

功能：对单个已经抓到的报文应用过滤器，匹配返回非 0。适合“抓包时不方便加过滤，事后筛选”的场景。

---

### 3.4 抓包：三种常用方式

#### 方式一：`pcap_next_ex`（推荐）

```c
int pcap_next_ex(pcap_t *p,
                 struct pcap_pkthdr **pkt_header,
                 const u_char **pkt_data);
```

功能：取下一包，并通过输出参数返回报文头和报文数据。

返回值：

| 返回值 | 含义 |
|---|---|
| `1` | 成功取到一包 |
| `0` | 读超时；非阻塞模式下表示当前没有报文 |
| `-1` (`PCAP_ERROR`) | 读取出错，用 `pcap_geterr()` 查看 |
| `-2` (`PCAP_ERROR_BREAK`) | 离线文件读到末尾 |

示例：

```c
struct pcap_pkthdr *hdr;
const u_char *pkt;
int rc;

while ((rc = pcap_next_ex(handle, &hdr, &pkt)) == 1) {
    printf("caplen=%u len=%u\n", hdr->caplen, hdr->len);
    /* 解析 pkt，长度为 hdr->caplen */
}

if (rc == -1)
    fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(handle));
```

注意：`hdr` 和 `pkt` 指向 libpcap 内部缓冲区，**下一次调用后就可能失效**。需要保存就自己 `memcpy`。

#### 方式二：`pcap_loop` + 回调

```c
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
```

功能：循环抓包，每抓一包调用一次 `callback`。

- `cnt`：最多处理多少包；一般用 `-1` 表示一直抓到出错或 `pcap_breakloop()`。
- `callback`：`pcap_handler` 类型回调。
- `user`：原样传给回调的自定义指针，可放上下文结构体。

返回值：

- `0`：处理完 `cnt` 个包。
- `-2`：被 `pcap_breakloop()` 打断。
- 其他负数：出错。

示例：

```c
static void got_packet(u_char *user,
                       const struct pcap_pkthdr *hdr,
                       const u_char *pkt)
{
    int *count = (int *)user;

    (*count)++;
    printf("第 %d 包，caplen=%u\n", *count, hdr->caplen);
    /* 解析 pkt */
}

int count = 0;
int rc = pcap_loop(handle, -1, got_packet, (u_char *)&count);

if (rc == -1)
    fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(handle));
```

#### 方式三：`pcap_dispatch`

```c
int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
```

和 `pcap_loop()` 类似，但只处理“当前这一批”报文，处理完就返回，不保证凑满 `cnt` 个。

- 返回本次处理的报文数。
- 返回 `0` 表示超时或当前没有报文。
- 返回负数表示错误或被 `pcap_breakloop()` 打断。

适合放在 `poll()` / `select()` 事件循环里使用：

```c
int n = pcap_dispatch(handle, 10, got_packet, (u_char *)&ctx);
if (n < 0)
    fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(handle));
```

#### `pcap_next`

```c
const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
```

功能：取下一包并返回数据指针，失败或超时返回 `NULL`。

缺点：无法区分“超时”和“出错”，也不适合非阻塞模式。新代码建议用 `pcap_next_ex()`。

#### `pcap_breakloop`

```c
void pcap_breakloop(pcap_t *p);
```

功能：让正在运行的 `pcap_loop()` / `pcap_dispatch()` 尽快返回，返回值为 `PCAP_ERROR_BREAK(-2)`。

常见用途：信号处理函数中停止抓包：

```c
#include <signal.h>

static pcap_t *g_handle;

static void on_sigint(int sig)
{
    (void)sig;
    pcap_breakloop(g_handle);
}

signal(SIGINT, on_sigint);
```

注意：`pcap_breakloop()` 只是设置一个标志，不会立即从回调中强行退出；当前回调执行完后循环才结束。

#### 非阻塞 + `poll`：精确控制超时

```c
int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf);
int pcap_get_selectable_fd(pcap_t *p);
```

- `pcap_setnonblock(handle, 1, errbuf)`：设为非阻塞。没有报文时，`pcap_next_ex()` 返回 `0` 而不是阻塞。
- `pcap_get_selectable_fd(handle)`：取得可用于 `select()` / `poll()` 的文件描述符；返回 `-1` 表示该设备不支持。

组合用法：

```c
if (pcap_setnonblock(handle, 1, errbuf) == -1) {
    fprintf(stderr, "pcap_setnonblock: %s\n", errbuf);
}

int fd = pcap_get_selectable_fd(handle);
if (fd < 0) {
    fprintf(stderr, "该设备不支持 poll\n");
}

struct pollfd pfd;
pfd.fd = fd;
pfd.events = POLLIN;
pfd.revents = 0;

int ret = poll(&pfd, 1, 3000);   /* 最多等 3000 ms */
if (ret > 0) {
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;

    while ((rc = pcap_next_ex(handle, &hdr, &pkt)) == 1) {
        /* 解析 */
    }
} else if (ret == 0) {
    /* 超时 */
}
```

注意：非阻塞模式下不要用 `pcap_loop()` / `pcap_next()`，它们不适合这种用法；用 `pcap_next_ex()` 或 `pcap_dispatch()`。

#### `pcap_stats`

```c
int pcap_stats(pcap_t *p, struct pcap_stat *ps);
```

功能：取抓包统计，成功返回 `0`，失败返回 `-1`。

```c
struct pcap_stat st;
if (pcap_stats(handle, &st) == 0) {
    printf("recv=%u drop=%u ifdrop=%u\n",
           st.ps_recv, st.ps_drop, st.ps_ifdrop);
}
```

#### `pcap_setdirection`（可选）

```c
int pcap_setdirection(pcap_t *p, pcap_direction_t d);
```

只抓某个方向：

```c
typedef enum {
    PCAP_D_INOUT = 0,   /* 双向，默认 */
    PCAP_D_IN,          /* 只收进入本机的 */
    PCAP_D_OUT          /* 只收本机发出的 */
} pcap_direction_t;
```

不是所有平台/设备都支持，失败返回 `-1`。用 `any` 设备时尤其可能不支持。

---

### 3.5 错误处理

#### `pcap_geterr`

```c
char *pcap_geterr(pcap_t *p);
```

返回该句柄最近一次错误的字符串。返回的是内部缓冲区，**不要 free**，下一次调用可能被覆盖。

```c
if (pcap_setfilter(handle, &fp) == -1)
    fprintf(stderr, "setfilter: %s\n", pcap_geterr(handle));
```

#### `pcap_perror`

```c
void pcap_perror(pcap_t *p, const char *prefix);
```

直接把最近错误打印到标准错误：

```c
pcap_perror(handle, "pcap_setfilter");
```

#### `pcap_statustostr`

```c
const char *pcap_statustostr(int status);
```

把 `pcap_activate()` 等函数返回的负数错误码转成文字，例如 `PCAP_ERROR_PERM_DENIED` → `"Permission denied"`。

#### `pcap_strerror`

```c
const char *pcap_strerror(int error);
```

类似 `strerror()`，但由 libpcap 提供，跨平台更一致。

---

### 3.6 保存和读取 pcap 文件

#### `pcap_dump_open`

```c
pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);
```

根据已打开的抓包句柄创建 `.pcap` 文件。失败返回 `NULL`，用 `pcap_geterr(p)` 查原因。

#### `pcap_dump`

```c
void pcap_dump(u_char *user,
               const struct pcap_pkthdr *h,
               const u_char *sp);
```

把一包写入文件。第一个参数本质上是 `pcap_dumper_t *`，需要强制转换：

```c
static void dump_cb(u_char *user,
                    const struct pcap_pkthdr *hdr,
                    const u_char *pkt)
{
    pcap_dump(user, hdr, pkt);   /* user 就是 dumper */
}

pcap_dumper_t *dumper = pcap_dump_open(handle, "out.pcap");
if (dumper == NULL) {
    fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(handle));
}

pcap_loop(handle, 100, dump_cb, (u_char *)dumper);
pcap_dump_close(dumper);
```

#### `pcap_dump_flush` / `pcap_dump_close`

```c
int pcap_dump_flush(pcap_dumper_t *p);
void pcap_dump_close(pcap_dumper_t *p);
```

`pcap_dump_flush()` 把用户态缓冲刷到文件；`pcap_dump_close()` 关闭文件。

#### `pcap_open_offline`

已在 3.2 介绍。读取保存文件时，`pcap_next_ex()` 最后返回 `-2` 表示 EOF。

---

### 3.7 发包（可选）

libpcap 也能发送原始帧，但更常见的是用 libnet 构造 TCP/IP 包。这里只列接口：

```c
int pcap_inject(pcap_t *p, const void *buf, size_t size);
int pcap_sendpacket(pcap_t *p, const u_char *buf, int size);
```

- 发送的是**完整链路层帧**，不是裸 IP 包。
- `pcap_inject()` 成功返回发送字节数，失败返回 `-1`。
- `pcap_sendpacket()` 成功返回 `0`，失败返回 `-1`。
- 都需要 root 或 `CAP_NET_RAW`。

### 3.8 辅助函数

#### `pcap_datalink` / 名称转换

```c
int pcap_datalink(pcap_t *p);
const char *pcap_datalink_val_to_name(int dlt);
const char *pcap_datalink_val_to_description(int dlt);
```

`pcap_datalink()` 返回链路层类型，如 `DLT_EN10MB`；后两个函数把数值转成可读名称。名称函数可能返回 `NULL`。

```c
int dlt = pcap_datalink(handle);
printf("dlt=%d (%s)\n", dlt, pcap_datalink_val_to_name(dlt));
```

#### `pcap_getnonblock`

```c
int pcap_getnonblock(pcap_t *p, char *errbuf);
```

查询当前是否为非阻塞模式：返回 `1` 表示非阻塞，`0` 表示阻塞，`-1` 表示出错。

#### `pcap_open_dead`

```c
pcap_t *pcap_open_dead(int linktype, int snaplen);
```

创建一个不真正抓包的“死”句柄，只用于 `pcap_compile()` 测试过滤表达式或离线处理。用它测试过滤器不需要 root：

```c
pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
struct bpf_program fp;

if (dead == NULL)
    return 1;

if (pcap_compile(dead, &fp, "tcp and port 80", 1,
                 PCAP_NETMASK_UNKNOWN) == 0) {
    printf("filter OK\n");
    pcap_freecode(&fp);
} else {
    printf("filter error\n");
}
pcap_close(dead);
```

---

## 4. BPF 过滤表达式

过滤器在**内核**执行，写得好可以显著降低用户态负担。

### 4.1 常用表达式

```text
ip                              # 所有 IPv4
ip6                             # 所有 IPv6
tcp                             # TCP（libpcap 1.9 主要匹配 IPv4）
udp                             # UDP（同上）
host 192.168.1.10               # 源或目的主机
src host 192.168.1.10           # 只匹配源主机
dst host 192.168.1.10           # 只匹配目的主机
net 192.168.1.0/24              # 网段
port 80                         # 源或目的端口（TCP/UDP 等）
tcp port 80                     # TCP 的 80 端口
src port 80                     # 源端口 80
dst port 40000                  # 目的端口 40000
portrange 1-1024                # 端口范围
not arp                         # 排除 ARP
```

组合：

```text
tcp and src host 192.168.1.20 and dst host 192.168.1.10
    and src port 80 and dst port 40000
```

这正好可以用来只接收“被扫描主机从目标端口返回给扫描源端口”的报文。

### 4.2 TCP 标志位过滤

BPF 支持 `tcp[tcpflags]` 和符号名：

```text
tcp[tcpflags] & tcp-syn != 0
tcp[tcpflags] & tcp-ack != 0
tcp[tcpflags] & tcp-rst != 0
tcp[tcpflags] & tcp-fin != 0
tcp[tcpflags] & (tcp-syn | tcp-ack) == (tcp-syn | tcp-ack)
```

含义：

- 第 1 条：SYN 置位。
- 第 5 条：SYN 和 ACK 同时置位，即 SYN+ACK。
- 想抓 RST：`tcp[tcpflags] & tcp-rst != 0`。

也可以直接写字节偏移，效果相同：

```text
(tcp[13] & 0x02) != 0                # SYN
(tcp[13] & 0x12) == 0x12             # SYN+ACK
(tcp[13] & 0x04) != 0                # RST
```

> libpcap 1.9 的 `tcp` / `udp` 简写主要针对 IPv4。分析 IPv6 时可以改用 `ip6` 配合协议号，或使用更新版本的 libpcap。

### 4.3 VLAN 注意事项

普通以太网 BPF 的 `tcp` 检查的是 EtherType `0x0800`。带 802.1Q VLAN 标签的帧 EtherType 是 `0x8100`，所以：

```text
vlan and tcp port 80
```

`vlan` 关键字会让后续表达式的偏移自动调整。解析报文时也要相应跳过 4 字节 VLAN 头。

### 4.4 测试过滤表达式

在写进程序之前，可以先用 tcpdump 验证：

```sh
sudo tcpdump -i enp0s3 -d 'tcp and port 80'
sudo tcpdump -i enp0s3 -nn 'tcp[tcpflags] & tcp-syn != 0'
```

`-d` 会打印编译后的 BPF 指令，能快速发现语法问题。

---

## 5. 数据包解析

libpcap 只负责把链路层帧交给你，**不负责解析 IP/TCP**。解析要自己写。

### 5.1 先看链路层类型

```c
int dlt = pcap_datalink(handle);
printf("%s\n", pcap_datalink_val_to_name(dlt));
```

常见值：

| 值 | 含义 | 链路层头长度 |
|---|---|---|
| `DLT_EN10MB` | 以太网 | 14 字节 |
| `DLT_LINUX_SLL` | Linux `any` 设备 | 16 字节 |
| `DLT_RAW` | 裸 IP，无链路层头 | 0 |
| `DLT_NULL` / `DLT_LOOP` | 部分系统的回环 | 4 字节 |

**不要假设一定是以太网。** 特别是使用 `any` 设备时，通常是 `DLT_LINUX_SLL`。

### 5.2 以太网头

```text
偏移  长度  字段
0     6     目的 MAC
6     6     源 MAC
12    2     EtherType
14    ...   负载
```

EtherType：

```text
0x0800  IPv4
0x86DD  IPv6
0x0806  ARP
0x8100  802.1Q VLAN
```

带 VLAN 时：

```text
12-13 0x8100
14-15 TCI
16-17 内层 EtherType
18... 负载
```

### 5.3 IPv4 头

```text
偏移  长度  字段
0     1    版本(高 4 位) + 首部长度(低 4 位)
1     1    TOS
2     2    总长度
4     2    标识
6     2    标志 + 分片偏移
8     1    TTL
9     1    协议（6 = TCP）
10    2    首部校验和
12    4    源 IP
16    4    目的 IP
20    ...  选项（如果有）
```

要点：

- 首部长度 = `(ip[0] & 0x0f) * 4`，最小 20。
- 总长度 = `(ip[2] << 8) | ip[3]`。
- 协议字段 `ip[9]` 为 `IPPROTO_TCP` 时才是 TCP。
- 分片偏移 `((ip[6] & 0x1f) << 8) | ip[7]`，非 0 表示不是首片，没有 TCP 头。

### 5.4 TCP 头

```text
偏移  长度  字段
0     2    源端口
2     2    目的端口
4     4    序列号
8     4    确认号
12    1    数据偏移(高 4 位) + 保留位
13    1    标志位
14    2    窗口
16    2    校验和
18    2    紧急指针
20    ...  TCP 选项
```

标志位：

```text
0x01 FIN
0x02 SYN
0x04 RST
0x08 PSH
0x10 ACK
0x20 URG
0x40 ECE
0x80 CWR
```

TCP 头长度 = `(tcp[12] >> 4) * 4`，最小 20。

### 5.5 解析时的注意事项

1. **用 `caplen` 做边界检查**，不要用 `len`。`len` 是线上长度，可能大于实际拿到的数据。
2. **不要假设 IP/TCP 头是 20 字节**，要按 IHL / data offset 计算。
3. **注意字节序**：端口、序列号、确认号是网络字节序，打印时用 `ntohs()` / `ntohl()`；IP 地址用 `inet_ntop()`。
4. **结构体强转有对齐风险**。`struct ip` / `struct tcphdr` 直接强转在 x86 上通常没事，但在 ARM 等平台可能因未对齐访问出问题。跨平台代码建议按字节读取，或使用 `memcpy`。
5. **校验和可能“看起来不对”**。抓本机发出的包时，网卡校验和卸载可能让校验和字段尚未填写；不要因为校验和不对就丢弃报文。
6. **分片**：非首片没有 TCP 头，必须跳过。

### 5.6 解析代码

支持以太网（含 VLAN）和 Linux SLL：

```c
#include <pcap.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

/* 返回 IP 头在帧中的偏移；无法识别返回 0 */
static size_t l3_offset(int dlt, const u_char *pkt, uint32_t caplen,
                        uint16_t *ethertype)
{
    size_t off;

    if (dlt == DLT_EN10MB) {
        if (caplen < 14)
            return 0;
        *ethertype = (uint16_t)((pkt[12] << 8) | pkt[13]);
        off = 14;

        while (*ethertype == 0x8100) {       /* 跳过 VLAN 标签 */
            if (caplen < off + 4)
                return 0;
            *ethertype = (uint16_t)((pkt[off + 2] << 8) | pkt[off + 3]);
            off += 4;
        }
        return off;
    }

    if (dlt == DLT_LINUX_SLL) {              /* "any" 设备 */
        if (caplen < 16)
            return 0;
        *ethertype = (uint16_t)((pkt[14] << 8) | pkt[15]);
        return 16;
    }

    return 0;
}

/* 成功返回 0；地址和端口保持网络字节序 */
static int parse_tcp(const struct pcap_pkthdr *hdr, const u_char *pkt, int dlt,
                     uint32_t *src_ip, uint32_t *dst_ip,
                     uint16_t *sport, uint16_t *dport, uint8_t *flags)
{
    uint16_t ethertype = 0;
    size_t off = l3_offset(dlt, pkt, hdr->caplen, &ethertype);
    const u_char *ip;
    const u_char *tcp;
    size_t ihl;
    size_t thl;
    uint16_t frag;

    if (off == 0 || ethertype != 0x0800)     /* 只处理 IPv4 */
        return -1;
    if (hdr->caplen < off + 20)
        return -1;

    ip = pkt + off;
    if ((ip[0] >> 4) != 4 || ip[9] != IPPROTO_TCP)
        return -1;

    ihl = (size_t)(ip[0] & 0x0f) * 4;
    if (ihl < 20 || hdr->caplen < off + ihl + 20)
        return -1;

    frag = (uint16_t)((ip[6] << 8) | ip[7]);
    if ((frag & 0x1fff) != 0)                /* 非首分片 */
        return -1;

    tcp = ip + ihl;
    thl = (size_t)(tcp[12] >> 4) * 4;
    if (thl < 20 || hdr->caplen < off + ihl + thl)
        return -1;

    memcpy(src_ip, ip + 12, 4);
    memcpy(dst_ip, ip + 16, 4);
    memcpy(sport, tcp, 2);
    memcpy(dport, tcp + 2, 2);
    *flags = tcp[13];
    return 0;
}
```

---

## 6. 完整示例

功能：

- 打开指定网卡，安装 BPF 过滤器；
- 用非阻塞 + `poll` 实现总超时；
- 用 `pcap_next_ex` 逐包读取；
- 解析以太网 / VLAN / SLL + IPv4 + TCP，打印五元组和 TCP 标志；
- 打印抓包统计。

```c
#include <pcap.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* 返回 IP 头在帧中的偏移；无法识别时返回 0 */
static size_t l3_offset(int dlt, const u_char *pkt, uint32_t caplen,
                        uint16_t *ethertype)
{
    size_t off;

    if (dlt == DLT_EN10MB) {
        if (caplen < 14)
            return 0;
        *ethertype = (uint16_t)((pkt[12] << 8) | pkt[13]);
        off = 14;
        while (*ethertype == 0x8100) {       /* 跳过 802.1Q VLAN 标签 */
            if (caplen < off + 4)
                return 0;
            *ethertype = (uint16_t)((pkt[off + 2] << 8) | pkt[off + 3]);
            off += 4;
        }
        return off;
    }

    if (dlt == DLT_LINUX_SLL) {              /* pcap 的 "any" 设备 */
        if (caplen < 16)
            return 0;
        *ethertype = (uint16_t)((pkt[14] << 8) | pkt[15]);
        return 16;
    }

    return 0;
}

/* 解析 IPv4 + TCP，成功返回 0；地址/端口保持网络字节序 */
static int parse_tcp(const struct pcap_pkthdr *hdr, const u_char *pkt, int dlt,
                     uint32_t *src_ip, uint32_t *dst_ip,
                     uint16_t *sport, uint16_t *dport, uint8_t *flags)
{
    uint16_t ethertype = 0;
    size_t off = l3_offset(dlt, pkt, hdr->caplen, &ethertype);
    const u_char *ip;
    const u_char *tcp;
    size_t ihl;
    size_t thl;
    uint16_t frag;

    if (off == 0 || ethertype != 0x0800)     /* 只处理 IPv4 */
        return -1;
    if (hdr->caplen < off + 20)
        return -1;

    ip = pkt + off;
    if ((ip[0] >> 4) != 4 || ip[9] != IPPROTO_TCP)
        return -1;

    ihl = (size_t)(ip[0] & 0x0f) * 4;
    if (ihl < 20 || hdr->caplen < off + ihl + 20)
        return -1;

    frag = (uint16_t)((ip[6] << 8) | ip[7]);
    if ((frag & 0x1fff) != 0)                /* 非首分片没有 TCP 头 */
        return -1;

    tcp = ip + ihl;
    thl = (size_t)(tcp[12] >> 4) * 4;
    if (thl < 20 || hdr->caplen < off + ihl + thl)
        return -1;

    memcpy(src_ip, ip + 12, 4);
    memcpy(dst_ip, ip + 16, 4);
    memcpy(sport, tcp, 2);
    memcpy(dport, tcp + 2, 2);
    *flags = tcp[13];
    return 0;
}

static const char *flag_name(uint8_t f)
{
    if ((f & 0x12) == 0x12) return "SYN+ACK";
    if ((f & 0x14) == 0x14) return "RST+ACK";
    if (f & 0x04) return "RST";
    if (f & 0x02) return "SYN";
    if (f & 0x01) return "FIN";
    if (f & 0x10) return "ACK";
    return "-";
}

int main(int argc, char **argv)
{
    const char *dev;
    const char *filter;
    int timeout_ms = 3000;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = PCAP_NETMASK_UNKNOWN;
    struct bpf_program fp;
    pcap_t *handle;
    int dlt;
    int fd;
    long long deadline;
    int matched = 0;
    struct pcap_stat stat;

    if (argc < 3) {
        fprintf(stderr, "用法：%s <网卡> <BPF过滤表达式> [超时毫秒]\n", argv[0]);
        return 1;
    }
    dev = argv[1];
    filter = argv[2];
    if (argc > 3)
        timeout_ms = atoi(argv[3]);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        net = 0;
        mask = PCAP_NETMASK_UNKNOWN;
    }

    handle = pcap_open_live(dev, 65535, 0, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter, 1, mask) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp);

    dlt = pcap_datalink(handle);
    printf("网卡：%s\n", dev);
    printf("链路层：%s\n", pcap_datalink_val_to_name(dlt));
    printf("过滤规则：%s\n", filter);

    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "pcap_setnonblock: %s\n", errbuf);
        pcap_close(handle);
        return 1;
    }

    fd = pcap_get_selectable_fd(handle);
    if (fd < 0) {
        fprintf(stderr, "该平台不支持 selectable fd\n");
        pcap_close(handle);
        return 1;
    }

    deadline = now_ms() + timeout_ms;
    while (!matched) {
        struct pollfd pfd;
        long long remain = deadline - now_ms();
        int failed = 0;
        int ret;

        if (remain <= 0)
            break;

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        ret = poll(&pfd, 1, (int)remain);
        if (ret == 0)
            break;
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }

        /* poll 报告可读后，把当前缓冲区里的报文全部取完 */
        for (;;) {
            struct pcap_pkthdr *hdr;
            const u_char *pkt;
            uint32_t src_ip, dst_ip;
            uint16_t sport, dport;
            uint8_t flags;
            char src[INET_ADDRSTRLEN];
            char dst[INET_ADDRSTRLEN];
            int rc;

            rc = pcap_next_ex(handle, &hdr, &pkt);
            if (rc == 0)
                break;                      /* 暂时没有更多报文 */
            if (rc == -1) {
                fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(handle));
                failed = 1;
                break;
            }
            if (rc == -2) {                 /* 离线文件读到结尾 */
                failed = 1;
                break;
            }

            if (parse_tcp(hdr, pkt, dlt,
                          &src_ip, &dst_ip, &sport, &dport, &flags) == -1)
                continue;

            inet_ntop(AF_INET, &src_ip, src, sizeof(src));
            inet_ntop(AF_INET, &dst_ip, dst, sizeof(dst));
            printf("%s:%u -> %s:%u  flags=0x%02x (%s)  caplen=%u len=%u\n",
                   src, ntohs(sport), dst, ntohs(dport),
                   flags, flag_name(flags), hdr->caplen, hdr->len);
            matched = 1;
            break;
        }

        if (failed)
            break;
    }

    if (!matched)
        printf("%d ms 内没有捕获到匹配报文\n", timeout_ms);

    (void)net;
    if (pcap_stats(handle, &stat) == 0)
        printf("统计：recv=%u drop=%u ifdrop=%u\n",
               stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);

    pcap_close(handle);
    return 0;
}
```

编译运行：

```sh
gcc -Wall -Wextra -O2 pcap_demo.c -o pcap_demo -lpcap
sudo ./pcap_demo enp0s3 'tcp and port 80' 3000
```

如果程序用于 TCP 半连接扫描，过滤器可以写成只接收目标返回给扫描源端口：

```text
tcp and src host 192.168.1.20 and dst host 192.168.1.10
    and src port 80 and dst port 40000
```

判定逻辑：

```text
flags 同时含 SYN 和 ACK   → 端口开放
flags 含 RST              → 端口关闭
超时                      → 未响应（可能被过滤）
```

---

## 7. 编译、权限与运行

### 7.1 编译

```sh
gcc -Wall -Wextra -O2 sniffer.c -o sniffer -lpcap
```

用 pkg-config 更通用：

```sh
gcc -Wall -Wextra -O2 sniffer.c -o sniffer $(pkg-config --cflags --libs libpcap)
```

如果工程拆成多个 `.c` 文件，把所有 `.c` 都写在命令里，**头文件不需要出现在命令中**：

```sh
gcc main.c send.c sniff.c -o scanner -lnet -lpcap
```

### 7.2 权限

抓包需要 `CAP_NET_RAW`（发送原始包也需要）。三种常用方式：

```sh
# 方式 1：直接 sudo
sudo ./sniffer

# 方式 2：给二进制加能力（推荐调试时使用）
sudo setcap cap_net_raw,cap_net_admin=eip ./sniffer
./sniffer

# 查看能力
getcap ./sniffer
```

注意：重新编译后文件能力可能丢失，需要重新 `setcap`。

容器中运行：

```sh
docker run --rm --net=host \
    --cap-add=NET_RAW --cap-add=NET_ADMIN \
    -v "$PWD:/work" -w /work ubuntu:22.04 ./sniffer
```

### 7.3 权限错误的表现

```text
pcap_open_live: enp0s3: You don't have permission to capture on that device
(socket: Operation not permitted)
```

或者 `pcap_activate()` 返回 `PCAP_ERROR_PERM_DENIED`。优先检查权限，而不是怀疑过滤器。

---

## 8. 常见问题

### 8.1 `pcap_open_live` 返回 NULL

- 网卡名写错：先用 `pcap_findalldevs()` 或 `ip -brief addr` 查看。
- 权限不足：用 sudo 或 `setcap`。
- 设备不存在/未启用。

### 8.2 `pcap_compile` 失败

```text
pcap_compile: can't parse filter expression: syntax error
```

- 表达式拼写错误，注意 `and` / `or` / `not`。
- 括号不匹配。
- VLAN 场景忘了 `vlan`。
- 先用 `tcpdump -d '表达式'` 验证。

### 8.3 抓不到包

- 网卡选错。
- 过滤器太严；先去掉过滤器，用 `tcp and port ...` 逐级放宽。
- 方向问题：只抓了 IN 或 OUT；用 `pcap_setdirection(handle, PCAP_D_INOUT)`。
- 没有流量；先 `ping` 或用 `tcpdump` 确认。
- 在虚拟机/容器里，抓包接口可能不是你以为的那块。

### 8.4 解析出来是乱码

- 链路层类型不是以太网。先打印 `pcap_datalink()`。
- 使用了 `any` 设备，帧头是 16 字节 SLL，不是 14 字节以太网。
- 没处理 VLAN 标签。
- 没按 IHL / data offset 计算头长度。
- 越界读取；检查 `caplen`。

### 8.5 `caplen < len`

抓包被 `snaplen` 截断。把 `snaplen` 调大（如 `65535` 或更大），但注意解析时只能访问 `caplen` 范围内的数据。

### 8.6 超时不准 / `pcap_next_ex` 一直阻塞

- `pcap_open_live` 的 `to_ms` 在部分平台不可靠。
- 需要精确超时：`pcap_setnonblock(handle, 1, errbuf)` + `pcap_get_selectable_fd()` + `poll()`，如第 6 节示例。
- 需要低延迟：`pcap_set_immediate_mode(handle, 1)`。

### 8.7 丢包

```c
struct pcap_stat st;
pcap_stats(handle, &st);
printf("drop=%u\n", st.ps_drop);
```

`ps_drop` 持续增长时：

- 收紧 BPF 过滤器，减少进入用户态的报文。
- 增大 `pcap_set_buffer_size()`。
- 减少回调中的耗时操作，或把处理放到其他线程。
- 提高 `snaplen` 反而可能增加拷贝量，按需设置。

### 8.8 VLAN 流量抓不到

过滤器改成：

```text
vlan and tcp port 80
```

解析时跳过 4 字节 VLAN 头（第 5 节代码已处理）。

### 8.9 抓本机发出的包校验和不对

网卡校验和卸载（checksum offload）会导致抓包时校验和字段尚未填写。不要依赖抓包结果判断校验和是否正确。

### 8.10 `pcap_loop` 无法退出

- 在信号处理函数里调用 `pcap_breakloop(handle)`。
- 或在回调里设置 `volatile sig_atomic_t` 标志，然后调用 `pcap_breakloop()`。
- 注意 `pcap_breakloop()` 不会立即终止正在执行的回调。

### 8.11 多线程

一个 `pcap_t` 不要同时被多个线程读写。常见做法是每个线程一个句柄，或一个抓包线程 + 队列分发给工作线程。

---

## 9. 函数速查表

| 阶段 | 函数 | 成功返回值 | 主要用途 |
|---|---|---|---|
| 设备 | `pcap_findalldevs` | `0` | 列出网卡 |
| 设备 | `pcap_freealldevs` | 无 | 释放网卡链表 |
| 设备 | `pcap_lookupnet` | `0` | 取网络号/掩码 |
| 打开 | `pcap_open_live` | 句柄 | 简单打开网卡 |
| 打开 | `pcap_create` | 句柄 | 分步配置后打开 |
| 打开 | `pcap_activate` | `0`（`>0` 警告） | 激活句柄 |
| 打开 | `pcap_open_offline` | 句柄 | 读取 pcap 文件 |
| 打开 | `pcap_close` | 无 | 关闭句柄 |
| 过滤 | `pcap_compile` | `0` | 编译 BPF |
| 过滤 | `pcap_setfilter` | `0` | 安装 BPF |
| 过滤 | `pcap_freecode` | 无 | 释放编译结果 |
| 过滤 | `pcap_offline_filter` | 非 0 匹配 | 对单包应用过滤 |
| 抓包 | `pcap_next_ex` | `1` | 取下一包（推荐） |
| 抓包 | `pcap_next` | 指针 | 取下一包（不推荐） |
| 抓包 | `pcap_loop` | `0` / `-2` | 回调循环 |
| 抓包 | `pcap_dispatch` | 处理包数 | 处理一批 |
| 抓包 | `pcap_breakloop` | 无 | 停止循环 |
| 抓包 | `pcap_setnonblock` | `0` | 非阻塞 |
| 抓包 | `pcap_get_selectable_fd` | fd / `-1` | 配合 poll/select |
| 统计 | `pcap_stats` | `0` | 收包/丢包统计 |
| 方向 | `pcap_setdirection` | `0` | 只收 IN/OUT |
| 保存 | `pcap_dump_open` | dumper | 打开 pcap 文件写 |
| 保存 | `pcap_dump` | 无 | 写一包 |
| 保存 | `pcap_dump_close` | 无 | 关闭写文件 |
| 错误 | `pcap_geterr` | 字符串 | 最近错误 |
| 错误 | `pcap_perror` | 无 | 打印错误 |
| 错误 | `pcap_statustostr` | 字符串 | 状态码转文字 |
| 信息 | `pcap_datalink` | DLT_* | 链路层类型 |
| 信息 | `pcap_lib_version` | 字符串 | libpcap 版本 |

---

## 附：一句话记住抓包流程

```text
找网卡 → 开设备 → 看链路层 → 编译并安装过滤器
      → pcap_next_ex / pcap_loop 收包
      → 从链路层头开始，按偏移解析 IP/TCP
      → 释放过滤器、关闭句柄
```

写扫描器时再记住两点：

1. **先开抓包，再发 SYN**，避免响应先到而漏包。
2. 用 `caplen` 做边界检查，用 `ntohs` / `ntohl` 处理网络字节序。
