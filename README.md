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

## Libnet操作教程

这是一份 **Linux 下 Libnet 入门教程**，重点讲 TCP SYN 发包会用到的函数，再补充 UDP 和 Ethernet 构包接口。

这里的“完整定义”指**完整函数原型、参数、返回值和调用示例**，不展开库内部实现。函数原型已按官方头文件核对，省略了用于符号导出的 `LIBNET_API` 宏；你本机安装版本以其头文件为准。[官方函数声明](https://github.com/libnet/libnet/blob/master/include/libnet/libnet-functions.h)

---

### 1. 先理解 Libnet 的工作流程

Libnet 主要帮助程序**构造并发送网络报文**。你的项目中，用 Libnet 发包，用 Libpcap 接收和分析响应。

发送一个 TCP SYN 的典型流程：

```text
libnet_init()             初始化，得到上下文 net
       ↓
libnet_name2addr4()       将源/目标 IP 字符串转换成数值
       ↓
libnet_build_tcp()        构造 TCP 头
       ↓
libnet_build_ipv4()       构造 IPv4 头
       ↓
libnet_write()            发送
       ↓
需要继续发送？
       ├── 修改已有协议块：再次调用 build，传入原 ptag
       ├── 构造新报文：libnet_clear_packet() 后重新构造
       └── 原样重发：直接再次 libnet_write()
       ↓
libnet_destroy()          关闭并释放资源
```

**构造顺序是从内层到外层，而实际报文排列是从外层到内层：**

```text
函数调用顺序：TCP → IPv4 → Ethernet（仅链路层模式需要）

实际报文结构：
┌──────────────┬──────────┬─────────┬──────────┐
│ Ethernet 头  │ IPv4 头  │ TCP 头  │ 应用数据 │
└──────────────┴──────────┴─────────┴──────────┘
```

这是 Libnet 协议块组装的要求。[官方使用说明](https://github.com/libnet/libnet/blob/master/doc/MIGRATION.md)

---

### 2. 先认识两个核心类型

```c
libnet_t *net;
```

`net` 是 **Libnet 上下文**，保存发包所需的信息，例如底层发送资源、已构造的协议块和错误信息。后续大部分函数都要传入它。

```c
libnet_ptag_t tcp_tag;
```

`ptag` 是**协议块标识**，用于找到之前构造的某个头部。

```c
/* 最后一个参数为 0：新建 TCP 协议块 */
tcp_tag = libnet_build_tcp(..., net, 0);

/* 最后一个参数为原来的 tcp_tag：修改该协议块 */
tcp_tag = libnet_build_tcp(..., net, tcp_tag);
```

构造成功返回协议块标识，失败返回 `-1`。**ptag 不是端口号，也不是 TCP 序列号。**

---

### 3. 初始化与地址处理

#### **① `libnet_init()`：初始化**

完整原型：

```c
libnet_t *libnet_init(
    int injection_type,
    const char *device,
    char *err_buf
);
```

| 参数 | 含义 |
|---|---|
| `injection_type` | 发包模式 |
| `device` | 网卡名称或 `NULL` |
| `err_buf` | 初始化失败时保存错误信息 |

常用模式：

| 模式 | 构造范围 | 适用场景 |
|---|---|---|
| `LIBNET_RAW4` | IPv4 头及其内部协议 | 你目前的 TCP SYN 实验 |
| `LIBNET_LINK` | 包括 Ethernet 等链路层头部 | 需要自己指定 MAC 地址 |
| `LIBNET_RAW6` | IPv6 及其内部协议 | IPv6 实验 |

返回值：成功返回上下文指针，失败返回 `NULL`。

```c
char errbuf[LIBNET_ERRBUF_SIZE];

libnet_t *net = libnet_init(
    LIBNET_RAW4,
    NULL,
    errbuf
);

if (net == NULL) {
    fprintf(stderr, "初始化失败：%s\n", errbuf);
    return 1;
}
```

在 Linux 的 RAW4 模式下，实际出口由内核路由决定。不要把 `device` 参数理解成对所有模式都能强制绑定出口。链路层模式则通常明确指定网卡：

```c
libnet_t *net = libnet_init(
    LIBNET_LINK,
    "enp0s3",
    errbuf
);
```

初始化原始发包环境通常需要 root 或相应权限。

#### **② `libnet_name2addr4()`：字符串转 IPv4 地址**

完整原型：

```c
uint32_t libnet_name2addr4(
    libnet_t *l,
    const char *host_name,
    uint8_t use_name
);
```

| 参数 | 含义 |
|---|---|
| `l` | Libnet 上下文 |
| `host_name` | IPv4 字符串，或允许解析时的主机名 |
| `use_name` | 是否允许域名解析 |

模式：

```c
LIBNET_DONT_RESOLVE   /* 不进行 DNS 查询 */
LIBNET_RESOLVE        /* 允许 DNS 查询 */
```

返回值：成功返回**网络字节序**的 IPv4 地址，失败返回 `(uint32_t)-1`。

```c
uint32_t dst_ip = libnet_name2addr4(
    net,
    "127.0.0.1",
    LIBNET_DONT_RESOLVE
);

if (dst_ip == (uint32_t)-1) {
    fprintf(stderr, "地址转换失败\n");
}
```

转换结果直接传给 `libnet_build_ipv4()`，**不要再次调用 `htonl()`**。

#### **③ `libnet_addr2name4()`：IPv4 地址转字符串**

完整原型：

```c
char *libnet_addr2name4(
    uint32_t in,
    uint8_t use_name
);
```

- `in`：网络字节序的 IPv4 地址。
- `use_name`：是否尝试反向名称解析。
- 返回值：可读的地址或名称字符串。

```c
printf("目标地址：%s\n",
       libnet_addr2name4(dst_ip, LIBNET_DONT_RESOLVE));
```

返回的字符串不需要你 `free()`。这个接口不是可重入接口，避免在同一个表达式中多次调用并依赖各次结果同时保留；多线程或需要独立缓冲区时，可使用标准的 `inet_ntop()`。

#### **④ `libnet_get_ipaddr4()`：获取上下文对应设备的 IPv4 地址**

完整原型：

```c
uint32_t libnet_get_ipaddr4(
    libnet_t *l
);
```

返回值：成功返回网络字节序 IPv4 地址，失败返回 `(uint32_t)-1`。

```c
uint32_t src_ip = libnet_get_ipaddr4(net);

if (src_ip != (uint32_t)-1) {
    printf("本机地址：%s\n",
           libnet_addr2name4(src_ip, LIBNET_DONT_RESOLVE));
}
```

**它不接受目标地址，因此不能保证返回“通往某个目标时应该使用的源 IP”。** 你的虚拟机有多个网卡，学习阶段可以像之前一样手动指定源地址。

---

### **4. 构造 TCP 和 IPv4 报文**

#### **⑤ `libnet_build_tcp()`：构造或修改 TCP 协议块**

完整原型：

```c
libnet_ptag_t libnet_build_tcp(
    uint16_t sp,
    uint16_t dp,
    uint32_t seq,
    uint32_t ack,
    uint8_t control,
    uint16_t win,
    uint16_t sum,
    uint16_t urg,
    uint16_t len,
    const uint8_t *payload,
    uint32_t payload_s,
    libnet_t *l,
    libnet_ptag_t ptag
);
```

| 参数 | 含义 | SYN 示例 |
|---|---|---|
| `sp` | 源端口 | `40000` |
| `dp` | 目标端口 | `8000` |
| `seq` | 序列号 | `12345` |
| `ack` | 确认号；ACK 标志未设置时无确认意义 | `0` |
| `control` | TCP 标志组合 | `TH_SYN` |
| `win` | 通告接收窗口 | `64240` |
| `sum` | TCP 校验和，`0` 表示自动计算 | `0` |
| `urg` | 紧急指针 | `0` |
| `len` | TCP 总长度，含头、选项和数据 | `LIBNET_TCP_H` |
| `payload` | 数据指针 | `NULL` |
| `payload_s` | 数据长度 | `0` |
| `l` | 上下文 | `net` |
| `ptag` | `0` 新建，已有标识则修改 | `0` |

返回值：成功返回协议块标识，失败返回 `-1`。

```c
libnet_ptag_t tcp_tag = libnet_build_tcp(
    40000, 8000,
    12345, 0,
    TH_SYN,
    64240,
    0, 0,
    LIBNET_TCP_H,
    NULL, 0,
    net, 0
);
```

常用 TCP 标志：

| 写法 | 含义 |
|---|---|
| `TH_SYN` | 发起连接 |
| `TH_ACK` | 确认 |
| `TH_RST` | 重置连接 |
| `TH_FIN` | 结束发送方向 |
| `TH_PSH` | PSH 标志 |

多个标志使用按位或：

```c
TH_SYN | TH_ACK
TH_RST | TH_ACK
TH_PSH | TH_ACK
```

注意：**仅改变标志并不构成有效 TCP 交互，序列号和确认号也必须与当前状态匹配。**

如果 TCP 携带数据：

```c
const uint8_t data[] = "hello";
uint32_t data_len = sizeof(data) - 1;  /* 不发送结尾的 '\0' */

libnet_ptag_t tag = libnet_build_tcp(
    40000, 8000,
    12346, 90001,
    TH_PSH | TH_ACK,
    64240,
    0, 0,
    LIBNET_TCP_H + data_len,
    data, data_len,
    net, 0
);
```

这是构包示例，**不代表发送前已经存在有效连接**。

#### **⑥ `libnet_build_ipv4()`：构造或修改 IPv4 协议块**

完整原型：

```c
libnet_ptag_t libnet_build_ipv4(
    uint16_t ip_len,
    uint8_t tos,
    uint16_t id,
    uint16_t frag,
    uint8_t ttl,
    uint8_t prot,
    uint16_t sum,
    uint32_t src,
    uint32_t dst,
    const uint8_t *payload,
    uint32_t payload_s,
    libnet_t *l,
    libnet_ptag_t ptag
);
```

| 参数 | 含义 | SYN 示例 |
|---|---|---|
| `ip_len` | 整个 IPv4 包的长度 | `20 + 20` |
| `tos` | 服务字段 | `0` |
| `id` | IP 标识 | `1` |
| `frag` | 分片标志与偏移 | `0` |
| `ttl` | 生存时间 | `64` |
| `prot` | 上层协议 | `IPPROTO_TCP` |
| `sum` | 校验和，通常设 `0` | `0` |
| `src` | 网络字节序源地址 | `src_ip` |
| `dst` | 网络字节序目标地址 | `dst_ip` |
| `payload` | 直接附加的额外数据 | `NULL` |
| `payload_s` | 额外数据长度 | `0` |
| `l` | 上下文 | `net` |
| `ptag` | 新建或修改标识 | `0` |

返回值：成功返回协议块标识，失败返回 `-1`。

```c
libnet_ptag_t ip_tag = libnet_build_ipv4(
    LIBNET_IPV4_H + LIBNET_TCP_H,
    0, 1, 0,
    64,
    IPPROTO_TCP,
    0,
    src_ip, dst_ip,
    NULL, 0,
    net, 0
);
```

如果已经调用 `libnet_build_tcp()`，TCP 协议块已经存在于上下文中，**不需要再通过 IPv4 的 `payload` 参数把同一份 TCP 内容重复传入**。

长度关系：

```text
无选项、无数据：
TCP 总长 = 20
IPv4 总长 = 20 + 20 = 40

无选项、携带 5 字节数据：
TCP 总长 = 20 + 5 = 25
IPv4 总长 = 20 + 25 = 45
```

这里端口、序列号、长度等普通数值参数使用主机字节序；源/目标 IPv4 地址使用网络字节序。IPv4 地址在库实现中直接赋值，不应根据部分旧注释再做额外字节序转换。[IPv4 构造实现](https://github.com/libnet/libnet/blob/master/src/libnet_build_ip.c)

---

### **5. 发送、错误处理与资源释放**

#### **⑦ `libnet_write()`：发送当前报文**

完整原型：

```c
int libnet_write(
    libnet_t *l
);
```

返回值：成功返回发送字节数，失败返回 `-1`。

```c
int bytes = libnet_write(net);

if (bytes == -1) {
    fprintf(stderr, "发送失败：%s\n", libnet_geterror(net));
} else {
    printf("已发送 %d 字节\n", bytes);
}
```

它不会自动清空当前协议块，所以可以原样重发：

```c
libnet_write(net);
libnet_write(net);
```

**返回成功只说明底层发送调用成功，不说明目标收到，更不说明端口开放。** 这些结论要靠响应报文判断。

#### **⑧ `libnet_geterror()`：读取错误信息**

完整原型：

```c
char *libnet_geterror(
    libnet_t *l
);
```

示例：

```c
if (tcp_tag == -1) {
    fprintf(stderr, "%s\n", libnet_geterror(net));
}
```

注意两个错误来源：

```c
/* 初始化失败：使用 errbuf */
net = libnet_init(LIBNET_RAW4, NULL, errbuf);

/* 初始化成功后的操作失败：使用上下文错误信息 */
libnet_geterror(net);
```

初始化失败时没有有效上下文，不要调用 `libnet_geterror(NULL)`。返回的错误字符串也不需要自行释放。

#### **⑨ `libnet_clear_packet()`：清空当前报文**

完整原型：

```c
void libnet_clear_packet(
    libnet_t *l
);
```

作用：释放当前上下文中的所有协议块，但保留上下文本身，可继续构包发送。

```c
/* 第一个包已经发完 */
libnet_write(net);

/* 清空旧报文，准备构造一个新包 */
libnet_clear_packet(net);

tcp_tag = 0;
ip_tag = 0;

/* 随后重新 build TCP、build IPv4、write */
```

**清空之后，原有 ptag 就失效了。** 将保存标识的变量重置为 `0`，避免误用。

#### **⑩ `libnet_destroy()`：关闭并释放整个上下文**

完整原型：

```c
void libnet_destroy(
    libnet_t *l
);
```

示例：

```c
libnet_destroy(net);
net = NULL;
```

它会释放上下文关联资源，包括仍存在的协议块，因此结束程序前通常不必再先调用 `libnet_clear_packet()`。

两者区别：

| 函数 | 清理范围 | 后续能否继续用原上下文 |
|---|---|---|
| `libnet_clear_packet()` | 当前报文协议块 | 可以 |
| `libnet_destroy()` | 整个上下文 | 不可以 |

---

### **6. 怎样修改报文并再次发送**

假设之前保存了 `tcp_tag`，现在想把目标端口从 `8000` 改成 `8001`：

```c
/* 传入原 tcp_tag，修改原来的 TCP 协议块 */
libnet_ptag_t updated = libnet_build_tcp(
    40000, 8001,
    12345, 0,
    TH_SYN,
    64240,
    0, 0,
    LIBNET_TCP_H,
    NULL, 0,
    net, tcp_tag
);

if (updated == -1) {
    fprintf(stderr, "修改失败：%s\n", libnet_geterror(net));
} else {
    tcp_tag = updated;
    libnet_write(net);
}
```

这里只有端口变化，报文总长度没变，所以不必更新 IPv4 总长度。

如果数据长度变化，则需要同步更新：

```text
TCP len
TCP payload_s
IPv4 ip_len
```

对你目前的扫描项目，也可以采用更容易理解的方式：

```text
每扫描一个新端口：
清空报文 → 构造 TCP → 构造 IPv4 → 发送
```

---

### **7. 其他常用辅助函数**

#### **⑪ `libnet_seed_prand()` 与 `libnet_get_prand()`：伪随机数**

完整原型：

```c
int libnet_seed_prand(
    libnet_t *l
);

uint32_t libnet_get_prand(
    int mod
);
```

`libnet_seed_prand()` 初始化伪随机数生成器，成功返回 `1`，失败返回 `-1`。

`libnet_get_prand()` 根据模式返回伪随机数：

| 模式 | 范围 |
|---|---|
| `LIBNET_PR8` | 0～255 |
| `LIBNET_PRu16` | 0～65535 |
| `LIBNET_PRu32` | 0～4294967295 |

使用示例：

```c
if (libnet_seed_prand(net) == -1) {
    fprintf(stderr, "随机数初始化失败：%s\n",
            libnet_geterror(net));
} else {
    uint32_t seq = libnet_get_prand(LIBNET_PRu32);

    uint16_t source_port = (uint16_t)(
        49152 + libnet_get_prand(LIBNET_PRu16) % 16384
    );

    printf("源端口=%u，序列号=%u\n",
           (unsigned)source_port,
           (unsigned)seq);
}
```

初始化通常做一次，不必每发一个包都初始化。这是伪随机接口，不应当作安全随机数生成器。

#### **⑫ `libnet_toggle_checksum()`：控制自动校验和**

完整原型：

```c
int libnet_toggle_checksum(
    libnet_t *l,
    libnet_ptag_t ptag,
    int mode
);
```

| 参数 | 含义 |
|---|---|
| `l` | 上下文 |
| `ptag` | 需要控制的协议块 |
| `mode` | `LIBNET_ON` 或 `LIBNET_OFF` |

返回值：成功为 `1`，失败为 `-1`。

```c
/* 启用 TCP 协议块的自动校验和 */
int result = libnet_toggle_checksum(
    net,
    tcp_tag,
    LIBNET_ON
);
```

通常在构包时把 `sum` 设为 `0` 即可，不必额外调用。Linux RAW4 发包还会涉及内核对 IPv4 头校验和的处理，不能把“关闭库内自动计算”理解成内核一定不会修改它。

---

### **8. 扩展了解：UDP 与 Ethernet 构包**

#### **⑬ `libnet_build_udp()`：构造 UDP 协议块**

完整原型：

```c
libnet_ptag_t libnet_build_udp(
    uint16_t sp,
    uint16_t dp,
    uint16_t len,
    uint16_t sum,
    const uint8_t *payload,
    uint32_t payload_s,
    libnet_t *l,
    libnet_ptag_t ptag
);
```

| 参数 | 含义 |
|---|---|
| `sp`、`dp` | 源端口、目标端口 |
| `len` | UDP 头与数据总长度 |
| `sum` | 校验和，`0` 表示交给库计算 |
| `payload`、`payload_s` | 数据及长度 |
| `l`、`ptag` | 上下文与协议块标识 |

返回值同其他构包函数：成功为 ptag，失败为 `-1`。

```c
/* 使用干净的上下文，避免混入之前的 TCP 协议块 */
libnet_clear_packet(net);

const uint8_t message[] = "hello";
uint32_t size = sizeof(message) - 1;

libnet_ptag_t udp_tag = libnet_build_udp(
    40000, 8000,
    LIBNET_UDP_H + size,
    0,
    message, size,
    net, 0
);
```

随后构造 IPv4 头时应使用：

```c
prot   = IPPROTO_UDP;
ip_len = LIBNET_IPV4_H + LIBNET_UDP_H + size;
```

#### **⑭ `libnet_build_ethernet()`：构造 Ethernet 头**

完整原型：

```c
libnet_ptag_t libnet_build_ethernet(
    const uint8_t *dst,
    const uint8_t *src,
    uint16_t type,
    const uint8_t *payload,
    uint32_t payload_s,
    libnet_t *l,
    libnet_ptag_t ptag
);
```

| 参数 | 含义 |
|---|---|
| `dst` | 目的 MAC，6 字节 |
| `src` | 源 MAC，6 字节 |
| `type` | 上层类型，IPv4 为 `ETHERTYPE_IP` |
| `payload`、`payload_s` | 直接附加的数据及长度 |
| `l`、`ptag` | 上下文与协议块标识 |

它用于 `LIBNET_LINK` 模式，不需要加到你当前的 RAW4 示例中。

调用示例，假设 `link_net` 是链路层上下文，并且已构造好 TCP 和 IPv4：

```c
uint8_t src_mac[6] = {
    0x08, 0x00, 0x27, 0xdc, 0xc2, 0x2c
};

/* 仅演示格式，实际应替换为正确的下一跳 MAC */
uint8_t dst_mac[6] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01
};

libnet_ptag_t eth_tag = libnet_build_ethernet(
    dst_mac,
    src_mac,
    ETHERTYPE_IP,
    NULL, 0,
    link_net, 0
);
```

目的 MAC 通常是：

- 目标在同一链路：目标机器的 MAC。
- 目标经过路由器到达：下一跳路由器的 MAC。

因此，链路层发包还要处理下一跳和地址解析。你当前阶段先使用 RAW4 更方便。

---

### **9. 一个完整的 SYN 发包示例**

下面将最重要的流程放在一起，仍然使用本机 `127.0.0.1:8000`。其他片段用于查阅，这段可以单独保存为 `send_syn.c`：

```c
#include <stdio.h>
#include <stdint.h>
#include <libnet.h>

int main(void)
{
    char errbuf[LIBNET_ERRBUF_SIZE];

    /* 1. 初始化 IPv4 原始发包环境 */
    libnet_t *net = libnet_init(LIBNET_RAW4, NULL, errbuf);

    if (net == NULL) {
        fprintf(stderr, "初始化失败：%s\n", errbuf);
        return 1;
    }

    /* 2. 转换地址：结果已经是网络字节序 */
    uint32_t src = libnet_name2addr4(
        net, "127.0.0.1", LIBNET_DONT_RESOLVE
    );

    uint32_t dst = libnet_name2addr4(
        net, "127.0.0.1", LIBNET_DONT_RESOLVE
    );

    if (src == (uint32_t)-1 || dst == (uint32_t)-1) {
        fprintf(stderr, "地址转换失败\n");
        libnet_destroy(net);
        return 1;
    }

    /* 3. 构造 TCP 头 */
    libnet_ptag_t tcp_tag = libnet_build_tcp(
        40000, 8000,          /* 源端口、目标端口 */
        12345, 0,             /* 序列号、确认号 */
        TH_SYN,               /* SYN */
        64240,                /* 接收窗口 */
        0, 0,                 /* 自动校验和、紧急指针 */
        LIBNET_TCP_H,         /* 无选项、无数据 */
        NULL, 0,
        net, 0
    );

    if (tcp_tag == -1)
        goto error;

    /* 4. 构造外层 IPv4 头 */
    libnet_ptag_t ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H,
        0, 1, 0,              /* 服务字段、标识、分片 */
        64, IPPROTO_TCP,      /* TTL、上层协议 */
        0,                    /* 校验和 */
        src, dst,
        NULL, 0,
        net, 0
    );

    if (ip_tag == -1)
        goto error;

    /* 5. 发送 */
    int bytes = libnet_write(net);

    if (bytes == -1)
        goto error;

    printf("已发送 SYN，共 %d 字节\n", bytes);

    /* 6. 结束时释放整个上下文 */
    libnet_destroy(net);
    return 0;

error:
    fprintf(stderr, "操作失败：%s\n", libnet_geterror(net));
    libnet_destroy(net);
    return 1;
}
```

安装和编译：

```bash
sudo apt-get install build-essential libnet1-dev

gcc -Wall -Wextra send_syn.c -o send_syn -lnet
```

先启动测试服务：

```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

另开终端抓包：

```bash
sudo tcpdump -i lo -nn -S 'tcp port 8000'
```

最后运行：

```bash
sudo ./send_syn
```

你现在优先掌握这六个调用就足够继续开发：

```text
libnet_init()
libnet_name2addr4()
libnet_build_tcp()
libnet_build_ipv4()
libnet_write()
libnet_destroy()
```

再加上 `libnet_geterror()` 做错误提示、`libnet_clear_packet()` 支持多次构包，就能完成扫描程序的发包部分。