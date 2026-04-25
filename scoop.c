/*
 *  $Id: scoop.c,v 1.2 2002/03/11 07:28:45 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  scoop.c - Packet Sniffing Technique example code
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "./scoop.h"

volatile sig_atomic_t loop = 1;

int main(int argc, char **argv) {
    int c, snaplen;
    u_char flags;
    char *device = NULL;
    char *filter = NULL;
    struct scoop_pack *vp;
    char errbuf[PCAP_ERRBUF_SIZE];
 
    printf("Scoop 1.0 [IP packet sniffing tool]\n");

    flags = 0;
    snaplen = 0;
    while ((c = getopt(argc, argv, "hi:Ss:x")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            case 'i':
                device = optarg;
                break;
            case 'S':
                flags |= STREAMING_BITS;
                break;
            case 's':
                snaplen = atoi(optarg);
                if (snaplen < 14) {
                    fprintf(stderr, "warning, very small snaplen!\n");
                }
                break;
            case 'x':
                flags |= PRINT_HEX;
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (argc - optind > 1) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    } else if (argc - optind == 1) {
        /* 用户指定了 pcap 过滤器 */
        filter = argv[optind];
    }

    /*
     *  初始化 scoop。这里我们将启动 libpcap 并设置过滤器。
     */
    vp = scoop_init(device, flags, snaplen, filter, errbuf);
    if (vp == NULL) {
        fprintf(stderr, "scoop_init() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("<ctrl-c> to quit\n");
    scoop(vp);
    scoop_destroy(vp);

    return (EXIT_SUCCESS);
}


struct scoop_pack *scoop_init(char *device, u_char flags, int snaplen,
            char *filter, char *errbuf) {
    struct scoop_pack *vp;
    struct bpf_program filter_code;
    bpf_u_int32 local_net, netmask;

    /*
     *  我们需要捕获中断信号，以便在退出前告诉用户我们捕获了多少个数据包。
     */
    if (catch_sig(SIGINT, cleanup) == -1) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "can't catch SIGINT signal.\n");
        return (NULL);
    }

    vp = malloc(sizeof(struct scoop_pack));
    if (vp == NULL) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", strerror(errno));
        return (NULL);
    }
    memset(vp, 0, sizeof(struct scoop_pack));

    vp->flags = flags;

    /*
     *  如果 device 为 NULL，说明用户没有指定设备，将由 libpcap 自动查找。
     *  使用 pcap_findalldevs() 替代已弃用的 pcap_lookupdev()
     */
    if (device == NULL) {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            free(vp);
            return (NULL);
        }
        if (alldevs == NULL) {
            snprintf(errbuf, PCAP_ERRBUF_SIZE, "no devices found\n");
            free(vp);
            return (NULL);
        }
        /* 使用列表中的第一个设备 */
        device = alldevs->name;
    }
 
    if (snaplen == 0) {
        snaplen = SNAPLEN;
    }

    /*
     *  使用以下参数打开数据包捕获设备：
     *
     *  snaplen: 用户指定或默认 200 字节
     *  promisc: 开启混杂模式
     *  接口需要处于混杂模式才能捕获本地网络上的所有流量。
     *  timeout: 500ms
     *  500 毫秒的超时时间对于大多数网络来说可能是合适的。
     *  对于支持此功能的架构，您可能需要根据网络流量情况调整此值。
     */
    vp->p = pcap_open_live(device, snaplen, PROMISC, TIMEOUT, errbuf);
    if (vp->p == NULL) {
        free(vp);
        return (NULL);
    }
 
    /*
     *  设置 BPF 过滤器。
     */
    if (pcap_lookupnet(device, &local_net, &netmask, errbuf) == -1) {
        /* 如果查找网络失败，使用未知网络掩码 */
        netmask = PCAP_NETMASK_UNKNOWN;
    }
    if (filter == NULL) {
        /* 使用默认过滤器: "arp or icmp or udp or tcp" */
        filter = FILTER;
    }
    if (pcap_compile(vp->p, &filter_code, filter, 1, netmask) == -1) {
        /* pcap_compile 失败时不会填充错误码，需要使用 pcap_geterr */
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                "pcap_compile() failed: %s\n", pcap_geterr(vp->p));
        scoop_destroy(vp);
        return (NULL);
    }
    if (pcap_setfilter(vp->p, &filter_code) == -1) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                "pcap_setfilter() failed: %s\n", pcap_geterr(vp->p));
        pcap_freecode(&filter_code);
        scoop_destroy(vp);
        return (NULL);
    }
    pcap_freecode(&filter_code);

    /*
     *  我们需要确保这是以太网。DLT_EN10MB 指定标准的 10MB 及更高速率的以太网。
     */
    if (pcap_datalink(vp->p) != DLT_EN10MB) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "Scoop only works with ethernet.\n");
        scoop_destroy(vp);
        return (NULL);
    }
    return (vp);
}


void scoop_destroy(struct scoop_pack *vp) {
    if (vp) {
        if (vp->p) {
            pcap_close(vp->p);
        }
        free(vp);
    }
} 


int catch_sig(int signo, void (*handler)(int)) {
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(signo, &action, NULL) == -1) {
        return (-1);
    } else {
        return (1);
    }
}
 

void scoop(struct scoop_pack *vp) {
    struct pcap_stat ps;
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;

    /* 循环直到用户在命令行按下 ctrl-c */
    while (loop) {
        /*
         *  使用 pcap_next_ex() 替代 pcap_next()，这是更现代的 API。
         *  返回值: 1 成功, 0 超时, -1 错误, -2 离线文件结束
         */
        int ret = pcap_next_ex(vp->p, &pkt_header, &pkt_data);
        if (ret == 1) {
            /* 成功获取数据包 */
            vp->h = *pkt_header;
            vp->packet = (u_char *)pkt_data;
            /* 将数据包传递给解复用引擎 */
            demultiplex(vp);
        } else if (ret == 0) {
            /* 超时，继续循环 */
            continue;
        } else if (ret == -1) {
            /* 发生错误 */
            fprintf(stderr, "pcap_next_ex() error: %s\n", pcap_geterr(vp->p));
            break;
        }
    }

    /*
     *  如果执行到这里，说明用户按下了 ctrl-c，现在需要输出统计信息。
     */
    if (pcap_stats(vp->p, &ps) == -1) {
        fprintf(stderr, "pcap_stats() failed: %s\n", pcap_geterr(vp->p));
    } else {
        /*
         *  注意，ps 统计信息会根据底层架构略有不同。这里我们忽略这个差异。
         */
        printf("\nPackets received by libpcap:\t%6u\n"
                 "Packets dropped by libpcap:\t%6u\n", ps.ps_recv,
                 ps.ps_drop);
    }
}


void demultiplex(struct scoop_pack *vp) {
    if (vp->flags & STREAMING_BITS) {
        /*
         *  如果用户指定了 STREAMING_BITS，我们将直接以十六进制输出
         *  从网络上捕获的整个帧，然后返回。这会产生漂亮的数据流；
         *  可用于创建电影和电视中看到的"技术感"背景。
         */
        for (int n = 0; n < vp->h.caplen; n++) {
            fprintf(stderr, "%02x", vp->packet[n]);
        }
        return;
    }

    /* 开始正常处理帧 */

    /*
     *  确定帧属于哪一层协议，并调用相应的解码模块。
     *  以太网 II 头部的协议字段是第 13 和 14 字节。
     *  这是一种与字节序无关的从内存中提取大端序短整型的方法。
     *  我们提取第一个字节作为高字节，然后提取下一个字节作为低字节。
     */
    u_short eth_type = (vp->packet[12] << 8) | vp->packet[13];
    switch (eth_type) {
        case 0x0800:
            /* IPv4 */
            decode_ip(&vp->packet[14], vp->flags);
            break;
        case 0x0806:
            /* ARP */
            decode_arp(&vp->packet[14], vp->flags);
            break;
        default:
            /* 我们不处理 802.3 或其他任何协议 */
            decode_unknown(&vp->packet[14], vp->flags);
            break;
    }

    if (vp->flags & PRINT_HEX) {
        /* 以十六进制输出从 IP 头部到结束的数据包 */
        print_hex(&vp->packet[14], vp->h.caplen - 14);
    }
}


void decode_arp(const u_char *packet, u_char flags) {
    printf("ARP: ");

    u_short arp_op = (packet[6] << 8) | packet[7];
    switch (arp_op) {
        case 0x01:
            /* ARP 请求 */
            printf("y0 who's got %d.%d.%d.%d tell %d.%d.%d.%d\n", 
                                                (packet[24] & 0xff),
                                                (packet[25] & 0xff),
                                                (packet[26] & 0xff),
                                                (packet[27] & 0xff),
                                                (packet[14] & 0xff),
                                                (packet[15] & 0xff),
                                                (packet[16] & 0xff),
                                                (packet[17] & 0xff));
            break;
        case 0x02:
            /* ARP 应答 */
            printf("y0 %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                                                (packet[14] & 0xff),
                                                (packet[15] & 0xff),
                                                (packet[16] & 0xff),
                                                (packet[17] & 0xff),
                                                packet[8],
                                                packet[9],
                                                packet[10],
                                                packet[11],
                                                packet[12],
                                                packet[13]);
            break;
        default:
            /* 我们不关心其他 ARP 类型 */
            printf("-\n");
            break;
    }
}


void decode_ip(const u_char *packet, u_char flags) {
    u_char ip_hl;

    printf("IP: ");

    /*
     *  打印源和目的 IP 地址。
     *  源 IP 地址的第一个字节偏移量是 12 字节；目的地址紧跟其后。
     */
    printf("%d.%d.%d.%d -> %d.%d.%d.%d ", (packet[12] & 0xff),
                                          (packet[13] & 0xff),
                                          (packet[14] & 0xff),
                                          (packet[15] & 0xff),
                                          (packet[16] & 0xff),
                                          (packet[17] & 0xff),
                                          (packet[18] & 0xff),
                                          (packet[19] & 0xff));

    /* 打印数据包总长度和 IP id */
    printf("(%d) ", (packet[2] << 8) | packet[3]);
    printf("id: %d ", (packet[4] << 8) | packet[5]);

    /*
     *  从 IPv4 头部的第一个字节中提取头部长度。
     *  这将允许我们跳过 IP 头部和可能存在的任何选项（我们对它们不感兴趣）。
     *  由于我们知道数据包是大端序的，我们知道第一个字节的格式是：`vvvvllll`。
     *                 ^   ^
     *                 |   |- 4 位头部长度
     *                 |---- 4 位版本号
     */
    ip_hl = (packet[0] & 0x0f) << 2;

    /*
     *  确定数据包属于哪一层 3 协议，并调用相应的解码模块。
     *  IPv4 头部的协议字段是第 9 个字节；
     *  要到达那里，我们需要跳过以太网头部。
     */
    switch (packet[9]) {
        case IPPROTO_TCP:
            decode_tcp(&packet[ip_hl], flags);
            break;
        case IPPROTO_UDP:
            decode_udp(&packet[ip_hl], flags);
            break;
        case IPPROTO_ICMP:
            decode_icmp(&packet[ip_hl], flags);
            break;
        default:
            decode_unknown(&packet[ip_hl], flags);
            break;
    }
}


void decode_tcp(const u_char *packet, u_char flags) {
    printf("TCP: ");

    /* 打印源和目的端口 */
    printf("%d -> %d ", (packet[0] << 8) | packet[1],
                        (packet[2] << 8) | packet[3]);

    /* 打印控制标志位（TCP 头部的第 14 个字节）。 */
    /* 这段方便的代码片段基于 ngrep 的 jonk */
    printf("%s%s%s%s%s%s\n",
                        (packet[13] & 0x01) ? "F" : "", /* FIN 标志 */
                        (packet[13] & 0x02) ? "S" : "", /* SYN 标志 */
                        (packet[13] & 0x04) ? "R" : "", /* RST 标志 */
                        (packet[13] & 0x08) ? "P" : "", /* PSH 标志 */
                        (packet[13] & 0x10) ? "A" : "", /* ACK 标志 */
                        (packet[13] & 0x20) ? "U" : "");/* URG 标志 */
}


void decode_udp(const u_char *packet, u_char flags) {
    printf("UDP: ");

    /* 打印源和目的端口 */
    printf("%d -> %d\n", (packet[0] << 8) | packet[1],
                         (packet[2] << 8) | packet[3]);
}


void decode_icmp(const u_char *packet, u_char flags) {
    printf("ICMP: ");

    /* 打印 ICMP 类型 */
    int type = packet[0];
    if (type >= 0 && type < 19 && icmp_type[type] != NULL) {
        printf("%s ", icmp_type[type]);
    } else {
        printf("unknown type (%d) ", type);
    }

    /* 如果适用，打印 ICMP 代码 */
    switch (type) {
        case 3:
            if (packet[1] >= 0 && packet[1] < 16 && icmp_code_unreach[packet[1]] != NULL) {
                printf("%s\n", icmp_code_unreach[packet[1]]);
            } else {
                printf("code %d\n", packet[1]);
            }
            break;
        case 5:
            if (packet[1] >= 0 && packet[1] < 4 && icmp_code_redirect[packet[1]] != NULL) {
                printf("%s\n", icmp_code_redirect[packet[1]]);
            } else {
                printf("code %d\n", packet[1]);
            }
            break;
        case 11:
            if (packet[1] >= 0 && packet[1] < 2 && icmp_code_exceed[packet[1]] != NULL) {
                printf("%s\n", icmp_code_exceed[packet[1]]);
            } else {
                printf("code %d\n", packet[1]);
            }
            break;
        case 12:
            if (packet[1] >= 0 && packet[1] < 1 && icmp_code_parameter[packet[1]] != NULL) {
                printf("%s\n", icmp_code_parameter[packet[1]]);
            } else {
                printf("code %d\n", packet[1]);
            }
            break;
        default:
            printf("\n");
    }
}


void decode_unknown(const u_char *packet, u_char flags) {
    printf("unsupported protocol\n");
}


void print_hex(const u_char *packet, u_short len) {
    int i, s_cnt;
    const u_short *p;
            
    p = (const u_short *)packet;
    s_cnt = len / sizeof(u_short);

    for (i = 0; --s_cnt >= 0; i++) {
        if ((!(i % 8))) {
            if (i != 0) {
                printf("\n");
            }
            printf("%04x\t", (i * 2));
        }
        printf("%04x ", ntohs(*(p++)));
    }
    
    if (len & 1) {
        if ((!(i % 8))) {
            printf("\n%04x\t", (i * 2));
        }
        printf("%02x ", *(const u_char *)p);
    }
    printf("\n");
}


void cleanup(int signo) {
    loop = 0;
    printf("Interrupt signal caught...\n");
}


void usage(const char *name) {
    printf("usage: %s [options] [\"pcap filter\"]\n"
                    "-h\t\tthis blurb you see right here\n"
                    "-i device\tspecify a device\n"
                    "-S\t\tstreaming packet dump (useless)\n"
                    "-s snaplen\tset the snapshot length\n"
                    "-x\t\tprint payload data in hex\n", name);
}


/* EOF */
