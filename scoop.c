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

int loop = 1;

int
main(int argc, char **argv)
{
    int c, snaplen;
    u_char flags;
    char *device, *filter;
    struct scoop_pack *vp;
    char errbuf[PCAP_ERRBUF_SIZE];
 
    printf("Scoop 1.0 [IP packet sniffing tool]\n");

    flags = 0;
    snaplen = 0;
    device = NULL;
    filter = NULL;
    while ((c = getopt(argc, argv, "hi:Ss:x")) != EOF)
    {
        switch (c)
        {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'i':
                device = optarg;
                break;
            case 'S':
                flags |= STREAMING_BITS;
                break;
            case 's':
                snaplen = atoi(optarg);
                if (snaplen < 14)
                {
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
    if (argc - optind > 1)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    else
    {
        /* user specified a pcap filter */
        filter = argv[optind];
    }

    /*
     *  Initialize scoop.  Here we'll bring up libpcap and set the
     *  filter.
     */
    vp = scoop_init(device, flags, snaplen, filter, errbuf);
    if (vp == NULL)
    {
        fprintf(stderr, "scoop_init() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("<ctrl-c> to quit\n");
    scoop(vp);
    scoop_destroy(vp);

    return (EXIT_SUCCESS);
}


struct scoop_pack *
scoop_init(char *device, u_char flags, int snaplen, char *filter,
            char *errbuf)
{
    struct scoop_pack *vp;
    struct bpf_program filter_code;
    bpf_u_int32 local_net, netmask;

    /*
     *  We want to catch the interrupt signal so we can inform the user
     *  how many packets we captured before we exit.
     */
    if (catch_sig(SIGINT, cleanup) == -1)
    {
        sprintf(errbuf, "can't catch SIGINT signal.\n");
        return (NULL);
    }

    vp = malloc(sizeof (struct scoop_pack));
    if (vp == NULL)
    {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, strerror(errno));
        return (NULL);
    }

    vp->flags = flags;

    /*
     *  If device is NULL, that means the user did not specify one and is
     *  leaving it up libpcap to find one.
     */
    if (device == NULL)
    {
        device = pcap_lookupdev(errbuf);
        if (device == NULL)
        {
            return (NULL);
        }
    }
 
    if (snaplen == 0)
    {
        snaplen = SNAPLEN;
    }

    /*
     *  Open the packet capturing device with the following values:
     *
     *  SNAPLEN: User defined or 200 bytes
     *  PROMISC: on
     *  The interface needs to be in promiscuous mode to capture all
     *  network traffic on the localnet.
     *  TIMEOUT: 500ms
     *  A 500 ms timeout is probably fine for most networks.  For
     *  architectures that support it, you might want tune this value
     *  depending on how much traffic you're seeing on the network.
     */
    vp->p = pcap_open_live(device, snaplen, PROMISC, TIMEOUT, errbuf);
    if (vp->p == NULL)
    {
        return (NULL);
    }
 
    /*
     *  Set the BPF filter.
     */
    if (pcap_lookupnet(device, &local_net, &netmask, errbuf) == -1)
    {
        scoop_destroy(vp);
        return (NULL);
    }
    if (filter == NULL)
    {
        /* use default filter: "arp or icmp or udp or tcp" */
        filter = FILTER;
    }
    if (pcap_compile(vp->p, &filter_code, filter, 1, netmask) == -1)
    {
        /* pcap does not fill in the error code on pcap_compile */
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                "pcap_compile() failed: %s\n", pcap_geterr(vp->p));
        scoop_destroy(vp);
        return (NULL);
    }
    if (pcap_setfilter(vp->p, &filter_code) == -1)
    {
        /* pcap does not fill in the error code on pcap_compile */
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                "pcap_setfilter() failed: %s\n", pcap_geterr(vp->p));
        scoop_destroy(vp);
        return (NULL);
    }

    /*
     *  We need to make sure this is Ethernet.  The DLTEN10MB specifies
     *  standard 10MB and higher Ethernet.
     */
    if (pcap_datalink(vp->p) != DLT_EN10MB)
    {
        sprintf(errbuf, "Scoop only works with ethernet.\n");
        scoop_destroy(vp);
        return (NULL);
    }
    return (vp);
}


void
scoop_destroy(struct scoop_pack *vp)
{
    if (vp)
    {
        if (vp->p)
        {
            pcap_close(vp->p);
        }
    }
} 


int
catch_sig(int signo, void (*handler)())
{
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(signo, &action, NULL) == -1)
    {
        return (-1);
    }
    else
    {
        return (1);
    }
}
 

void
scoop(struct scoop_pack *vp)
{
    struct pcap_stat ps;

    /* loop until user hits ctrl-c at the command prompt */
    for (; loop; )
    {
        /*
         *  pcap_next() gives us the next packet from pcap's internal
         *  packet buffer.
         */
        vp->packet = (u_char *)pcap_next(vp->p, &vp->h);
        if (vp->packet == NULL)
        {
            /*
             *  We have to be careful here as pcap_next() can return NULL
             *  if the timer expires with no data in the packet buffer or
             *  under some special circumstances under linux.
             */
            continue;
        }
        else
        {
            /*
             *  Pass the packet to the demultiplexing engine.
             */
            demultiplex(vp);
        }
    }

    /*
     *  If we get here, the user hit ctrl-c at the command prompt and it's
     *  time to dump the statistics.
     */
    if (pcap_stats(vp->p, &ps) == -1)
    {
        fprintf(stderr, "pcap_stats() failed: %s\n", pcap_geterr(vp->p));
    }
    else
    {
        /*
         *  Remember that the ps statistics change slightly depending on
         *  the underlying architecture.  We gloss over that here.
         */
        printf("\nPackets received by libpcap:\t%6d\n"
                 "Packets dropped by libpcap:\t%6d\n", ps.ps_recv,
                 ps.ps_drop);
    }
}


void
demultiplex(struct scoop_pack *vp)
{
    int n;

    if (vp->flags & STREAMING_BITS)
    {
        /*
         *  If the user specifies STREAMING_BITS we'll just dump the
         *  entire frame captured from the wire in hex and return.  It
         *  makes a pretty stream of data; useful to create "techy" 
         *  looking backrounds you see in movies and T.V..
         */
        for (n = 0; n < vp->h.caplen; n++)
        {
            fprintf(stderr, "%x", vp->packet[n]);
        }
        return;
    }

    /* begin regular processing of the frame */

    /*
     *  Figure out which layer 2 protocol the frame belongs to and call
     *  the corresponding decoding module.  The protocol field of an 
     *  Ethernet II header is the 13th + 14th byte.  This is an endian
     *  independent way of extracting a big endian short from memory.  We
     *  extract the first byte and make it the big byte and then extract
     *  the next byte and make it the small byte.
     */
    /* switch(ntohs(*(u_short *)&vp->packet[12])) */
    switch (vp->packet[12] << 0x08 | vp->packet[13])
    {
        case 0x0800:
            /* IPv4 */
            decode_ip(&vp->packet[14], vp->flags);
            break;
        case 0x0806:
            /* ARP */
            decode_arp(&vp->packet[14], vp->flags);
            break;
        default:
            /* We're not bothering with 802.3 or anything else */
            decode_unknown(&vp->packet[14], vp->flags);
            break;
    }

    if (vp->flags & PRINT_HEX)
    {
        /* hexdump the packet from IP header -> end */
        print_hex(&vp->packet[14], vp->h.caplen - 14);
    }
}


void
decode_arp(u_char *packet, u_char flags)
{
    printf("ARP: ");

    switch ((packet[6] << 0x08) | packet[7])
    {
        case 0x01:
            /* ARP request */
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
            /* ARP reply */
            printf("y0 %d.%d.%d.%d is at %x:%x:%x:%x:%x:%x\n",
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
            /* we're not interested in other ARP types */
            printf("-\n");
            break;
    }
}


void
decode_ip(u_char *packet, u_char flags)
{
    u_char ip_hl;

    printf("IP: ");

    /*
     *  Print the source and destination IP addresses.  The offset to
     *  the first byte of the source IP address is 12 bytes in; the
     *  destination address immediately follows.
     */
    printf("%d.%d.%d.%d -> %d.%d.%d.%d ", (packet[12] & 0xff),
                                          (packet[13] & 0xff),
                                          (packet[14] & 0xff),
                                          (packet[15] & 0xff),
                                          (packet[16] & 0xff),
                                          (packet[17] & 0xff),
                                          (packet[18] & 0xff),
                                          (packet[19] & 0xff));

    /* print the total packet length and IP id */
    printf("(%d) ", (packet[2] << 0x08) | packet[3]);
    printf("id: %d ", (packet[4] << 0x08) | packet[5]);

    /*
     *  Pull out the header length from the first byte of the IPv4 header.
     *  This will allow us to step over the IP header and any possible
     *  options that might be there (we're not interested in them).
     *  Since we know the packet is big-endian, we know the first byte is 
     *  of the form: `vvvv1111`.
     *                 ^   ^
     *                 |   |- 4 bits header length
     *                 |---- 4 bits version
     */
    ip_hl = (packet[0] & 0x0f) << 0x02;

    /*
     *  Figure out which layer 3 protocol the packet is and call the
     *  corresponding decoding module.  The protocol field of an IPv4 
     *  header is the 9th byte in; to get there, we have to step over
     *  the Ethernet header.
     */
    switch (packet[9])
    {
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


void
decode_tcp(u_char *packet, u_char flags)
{
    printf("TCP: ");

    /* print the source and destination ports */
    printf("%d -> %d ", (packet[0] << 0x08) | packet[1],
                        (packet[2] << 0x08) | packet[3]);

    /* print the control flags (14th byte into the TCP header). */
    /* this handy code snippet based on ngrep jonk */
    printf("%s%s%s%s%s%s\n",
                        (packet[13] & 0x01) ? "F" : "", /* FIN flag */
                        (packet[13] & 0x02) ? "S" : "", /* SYN flag */
                        (packet[13] & 0x04) ? "R" : "", /* RST flag */
                        (packet[13] & 0x08) ? "P" : "", /* PSH flag */
                        (packet[13] & 0x10) ? "A" : "", /* ACK flag */
                        (packet[13] & 0x20) ? "U" : "");/* URG flag */
}


void
decode_udp(u_char *packet, u_char flags)
{
    printf("UDP: ");

    /* print the source and destination ports */
    printf("%d -> %d\n", (packet[0] << 0x08) | packet[1],
                         (packet[2] << 0x08) | packet[3]);
}


void
decode_icmp(u_char *packet, u_char flags)
{
    printf("ICMP: ");

    /* print the ICMP type */
    printf("%s ", icmp_type[packet[0]]);

    /* print the ICMP code, if applicable */
    switch (packet[0])
    {
        case 3:
            printf("%s\n", icmp_code_unreach[packet[1]]);
            break;
        case 11:
            printf("%s\n", icmp_code_redirect[packet[1]]);
            break;
        case 12:
            printf("%s\n", icmp_code_exceed[packet[1]]);
            break;
        case 13:
            printf("%s\n", icmp_code_parameter[packet[1]]);
            break;
        default:
            printf("\n");
    }
}


void
decode_unknown(u_char *packet, u_char flags)
{
    printf("unsupported protocol\n");
}


void
print_hex(u_char *packet, u_short len)
{
    int i, s_cnt;
    u_short *p;
            
    p     = (u_short *)packet;
    s_cnt = len / sizeof(u_short);

    for (i = 0; --s_cnt >= 0; i++)
    {
        if ((!(i % 8)))
        {
            if (i != 0)
            {
                printf("\n");
            }
            printf("%02x\t", (i * 2));
        }
        printf("%04x ", ntohs(*(p++)));
    }
    
    if (len & 1)
    {
        if ((!(i % 8)))
        {
            printf("\n%02x\t", (i * 2));
        }
        printf("%02x ", *(u_char *)p);
    }
    printf("\n");
}


void
cleanup(int signo)
{
    loop = 0;
    printf("Interrupt signal caught...\n");
}


void
usage(char *name)
{
    printf("usage %s [options] [\"pcap filter\"]\n"
                    "-h\t\tthis blurb you see right here\n"
                    "-i device\tspecify a device\n"
                    "-S\t\tstreaming packet dump (useless)\n"
                    "-s snaplen\tset the snapshot length\n"
                    "-x\t\tprint payload data in hex\n", name);
}


/* EOF */
