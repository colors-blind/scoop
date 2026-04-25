/*
 *  $Id: scoop.h,v 1.2 2002/03/11 07:28:46 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  scoop.h - Packet Sniffing Technique example code
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

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pcap.h>
#include <string.h>
#include <signal.h>
 
#define SNAPLEN         200
#define PROMISC         1
#define TIMEOUT         500
#define FILTER          "arp or tcp or udp or icmp"

struct scoop_pack
{
    pcap_t *p;                      /* pcap descriptor */
    struct pcap_pkthdr h;           /* pcap packet header */
    u_char flags;                   /* control flags */
#define PRINT_HEX       0x01        /* print packet data */
#define STREAMING_BITS  0x02        /* stream packets */
    u_char *packet;                 /* the packet! */
};

struct scoop_pack *scoop_init(char *, u_char, int, char *, char *);
void scoop_destroy(struct scoop_pack *);
void scoop(struct scoop_pack *);
void demultiplex(struct scoop_pack *);
void decode_arp(u_char *, u_char);
void decode_ip(u_char *, u_char);
void decode_tcp(u_char *, u_char);
void decode_udp(u_char *, u_char);
void decode_icmp(u_char *, u_char);
void decode_unknown(u_char *, u_char);
void print_hex(u_char *, u_short);
void cleanup(int);
int catch_sig(int, void(*)());
void usage(char *);

u_char *icmp_type[] =
{
    "echo reply",
    "unknown (1)",
    "unknown (2)",
    "unreachable",
    "source quench",
    "redirect",
    "unknown (6)",
    "unknown (7)",
    "echo",
    "router adv",
    "router solicit",
    "time exceed",
    "parameter prob",
    "timestamp",
    "timestamp req",
    "info request",
    "info reply",
    "mask request",
    "mask reply",
    0
};

u_char *icmp_code_unreach[] =
{
    "net",
    "host",
    "protocol",
    "port",
    "need frag",
    "src rte fail",
    "net unknown",
    "host unknown",
    "isolated",
    "net prohib",
    "host prohib",
    "TOS net",
    "TOS host",
    "filter prohib",
    "host prec",
    "prec cutoff",
    0
};

u_char *icmp_code_redirect[] =
{
    "net",
    "host",
    "TOS net",
    "TOS host",
    0
};

u_char *icmp_code_exceed[] =
{
    "in transit",
    "reassembly",
    0
};

u_char *icmp_code_parameter[] =
{
    "options absent",
    0
};

/* EOF */
