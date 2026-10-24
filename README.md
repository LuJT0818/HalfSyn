# HalfSyn

TCP 半连接（SYN）端口扫描示例：libnet 发送 SYN 后，用 libpcap 抓取并解析
目标返回的 SYN+ACK / RST，从而判断端口是否开放。

## 文件

- `main.c`：参数处理、构造并发送 SYN、输出扫描结果
- `send.h` / `send.c` : 发送模块，封装 libnet, 指定源ip地址，并向目标ip地址和目标端口发送SYN数据包
- `sniff.h` / `sniff.c`：抓包模块，封装 libpcap，解析以太网 + IPv4 + TCP，返回嗅探结果
- `app.py`: 前端界面

## 编译与运行

### 1、通过MakeFile
用户可直接通过`make`命令来启动程序，我们在`MakeFile`为用户封装好了`c`文件和`py`文件的编译、授权和运行指令。
```sh
# 编译 C 程序，并确保 main 有抓包权限
make
# 编译 + 授权 + 启动 app.py
make run
# make run 的别名
make start
# 清理编译产物
make clean
```
### 2、手动执行
若用户选择手动执行，步骤如下：
```sh
# 1 编译.c文件
gcc -Wall -Wextra -O2 main.c sniff.c send.c -o main -lnet -lpcap

# 2.1 直接后端运行查看
sudo ./main <源IP> <目标IP> <目标端口>
# 例 (本地测试)打开端口
python3 -m http.server 8000 --bind 127.0.0.1
sudo ./main 127.0.0.1 127.0.0.1 8000

# 2.2 前端运行
# 给 main 增加抓包权限
sudo setcap cap_net_raw,cap_net_admin=eip ./main
getcap ./main
# 如果setcap成功，则无需root运行
sudo python3 app.py
```


- 需要 root 权限，或给程序授予 `CAP_NET_RAW` 能力（libnet 与 libpcap 都需要）。
- 源 IP 应填写本机地址，程序会根据源 IP 自动选择网卡。
- 输出结果：收到 `SYN+ACK` 表示端口开放；收到 `RST` 表示端口关闭；
  超时通常表示端口被防火墙过滤或主机不可达。

