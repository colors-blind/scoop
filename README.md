# Scoop

原始代码来源于书籍 《Building Open Source Network Security Tools: Components and Techniques》

这是一个很轻量的网络抓包示例工具，主要用来演示怎么用 `libpcap` 抓取网卡上的流量，并按协议做基础解析输出。


项目里当前能识别和打印的内容包括：

- 以太网帧里的 IPv4 / ARP
- IPv4 里的 TCP / UDP / ICMP
- 可选十六进制输出
- 可选流式十六进制打印模式

## 这个项目是干什么的

简单说，它就是一个简单的抓包小工具：

- 用最直接的方式打开网卡抓包
- 通过 BPF 过滤器筛选流量
- 把常见协议字段打印出来，方便看包结构

如果你在学网络协议、抓包流程、或者想看 `libpcap` 最小可运行样例，这个项目就很合适。

## 版本说明

本项目包含三个版本的实现：

- **C版本**: 根目录下的原始代码（已优化到C99标准）
- **Go版本**: `go_version/` 目录，使用 `gopacket` 库
- **Rust版本**: `rust_version/` 目录，使用 `pcap` + `etherparse` 库

---

## C版本

### 依赖

需要系统安装：

- `gcc`
- `make`
- `libpcap`（开发头文件也要有）

在 Debian/Ubuntu 上可以先装：

`sudo apt-get install build-essential libpcap-dev`

### 编译

在项目目录执行：

`make`

成功后会生成可执行文件：`scoop`

### 运行

常见用法：

`./scoop [options] ["pcap filter"]`

示例：

- 自动选择网卡抓包：`sudo ./scoop`
- 指定网卡：`sudo ./scoop -i eth0`
- 指定抓包长度：`sudo ./scoop -s 256`
- 输出十六进制：`sudo ./scoop -x`
- 自定义过滤器：`sudo ./scoop "tcp and port 80"`

### 参数说明

- `-h`：显示帮助
- `-i device`：指定抓包网卡
- `-S`：流式打印抓到的原始字节（偏演示用途）
- `-s snaplen`：设置抓包截断长度
- `-x`：额外打印十六进制内容

默认过滤器是：

`arp or tcp or udp or icmp`

---

## Go版本

`go_version/` 目录下的Go语言实现。

### 依赖

- Go 1.21+
- `libpcap` 开发库

### 编译

```bash
cd go_version
go mod tidy
go build -o scoop .
```

### 运行

与C版本参数相同：

```bash
sudo ./scoop -h
sudo ./scoop -i eth0 -x "tcp and port 80"
```

---

## Rust版本

`rust_version/` 目录下的Rust语言实现。

### 依赖

- Rust 1.70+ (edition 2021)
- `libpcap` 开发库

### 编译

```bash
cd rust_version
cargo build --release
```

编译后的可执行文件在 `target/release/scoop`

### 运行

```bash
sudo ./target/release/scoop -h
sudo ./target/release/scoop -i eth0 -x "tcp and port 80"
```

### Cargo依赖

- `pcap` - libpcap的Rust绑定
- `etherparse` - 协议解析库（支持Ethernet, IPv4, TCP, UDP, ICMP）
- `clap` - 命令行参数解析（derive特性）
- `ctrlc` - Ctrl+C信号处理

---

## 注意事项

- 抓包通常需要 root 权限，所以运行时一般要加 `sudo`
- 当前代码只支持以太网链路层（Ethernet）
- 这是教学示例，不是生产级抓包分析器
