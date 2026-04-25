package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

const (
	defaultSnaplen = 200
	defaultFilter  = "arp or tcp or udp or icmp"
	promisc        = true
	timeout        = 500 * time.Millisecond
)

type config struct {
	device       string
	snaplen      int
	filter       string
	printHex     bool
	streamingHex bool
}

var (
	icmpType = []string{
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
	}

	icmpCodeUnreach = []string{
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
	}

	icmpCodeRedirect = []string{
		"net",
		"host",
		"TOS net",
		"TOS host",
	}

	icmpCodeExceed = []string{
		"in transit",
		"reassembly",
	}

	icmpCodeParameter = []string{
		"options absent",
	}
)

func main() {
	cfg := parseFlags()

	fmt.Println("Scoop 1.0 [IP packet sniffing tool]")

	handle, err := initPcap(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scoop_init() failed: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nInterrupt signal caught...")
		handle.Close()
	}()

	fmt.Println("<ctrl-c> to quit")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet, cfg)
	}

	stats, err := handle.Stats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcap_stats() failed: %v\n", err)
	} else {
		fmt.Printf("\nPackets received by libpcap:\t%6d\n"+
			"Packets dropped by libpcap:\t%6d\n", stats.PacketsReceived, stats.PacketsDropped)
	}
}

func parseFlags() *config {
	cfg := &config{}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] [\"pcap filter\"]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t-h\t\tthis blurb you see right here\n")
		fmt.Fprintf(os.Stderr, "\t-i device\tspecify a device\n")
		fmt.Fprintf(os.Stderr, "\t-S\t\tstreaming packet dump (useless)\n")
		fmt.Fprintf(os.Stderr, "\t-s snaplen\tset the snapshot length\n")
		fmt.Fprintf(os.Stderr, "\t-x\t\tprint payload data in hex\n")
		os.Exit(0)
	}

	flag.StringVar(&cfg.device, "i", "", "specify a device")
	flag.IntVar(&cfg.snaplen, "s", defaultSnaplen, "set the snapshot length")
	flag.BoolVar(&cfg.streamingHex, "S", false, "streaming packet dump")
	flag.BoolVar(&cfg.printHex, "x", false, "print payload data in hex")

	flag.Parse()

	if flag.NArg() > 0 {
		cfg.filter = flag.Arg(0)
	} else {
		cfg.filter = defaultFilter
	}

	if cfg.snaplen < 14 {
		fmt.Fprintln(os.Stderr, "warning, very small snaplen!")
	}

	return cfg
}

func initPcap(cfg *config) (*pcap.Handle, error) {
	device := cfg.device
	if device == "" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return nil, err
		}
		if len(devices) == 0 {
			return nil, fmt.Errorf("no devices found")
		}
		device = devices[0].Name
		fmt.Printf("Using device: %s\n", device)
	}

	handle, err := pcap.OpenLive(device, int32(cfg.snaplen), promisc, timeout)
	if err != nil {
		return nil, err
	}

	dlt := handle.LinkType()
	if dlt != layers.LinkTypeEthernet {
		handle.Close()
		return nil, fmt.Errorf("Scoop only works with ethernet")
	}

	if err := handle.SetBPFFilter(cfg.filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("pcap_setfilter() failed: %w", err)
	}

	return handle, nil
}

func processPacket(packet gopacket.Packet, cfg *config) {
	if cfg.streamingHex {
		printStreamingHex(packet.Data())
		return
	}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	switch eth.EthernetType {
	case layers.EthernetTypeIPv4:
		decodeIPv4(packet)
	case layers.EthernetTypeARP:
		decodeARP(packet)
	default:
		decodeUnknown(packet)
	}

	if cfg.printHex {
		printHexDump(packet.Data()[14:])
	}
}

func printStreamingHex(data []byte) {
	for _, b := range data {
		fmt.Fprintf(os.Stderr, "%02x", b)
	}
}

func decodeARP(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return
	}
	arp, _ := arpLayer.(*layers.ARP)

	fmt.Print("ARP: ")

	switch arp.Operation {
	case layers.ARPRequest:
		fmt.Printf("y0 who's got %d.%d.%d.%d tell %d.%d.%d.%d\n",
			arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3],
			arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])
	case layers.ARPReply:
		fmt.Printf("y0 %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n",
			arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3],
			arp.SourceHwAddress[0], arp.SourceHwAddress[1], arp.SourceHwAddress[2],
			arp.SourceHwAddress[3], arp.SourceHwAddress[4], arp.SourceHwAddress[5])
	default:
		fmt.Println("-")
	}
}

func decodeIPv4(packet gopacket.Packet) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return
	}
	ip4, _ := ip4Layer.(*layers.IPv4)

	fmt.Printf("IP: %s -> %s (%d) id: %d ",
		ip4.SrcIP, ip4.DstIP, ip4.Length, ip4.Id)

	switch ip4.Protocol {
	case layers.IPProtocolTCP:
		decodeTCP(packet)
	case layers.IPProtocolUDP:
		decodeUDP(packet)
	case layers.IPProtocolICMPv4:
		decodeICMP(packet)
	default:
		decodeUnknown(packet)
	}
}

func decodeTCP(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	fmt.Printf("TCP: %d -> %d ", tcp.SrcPort, tcp.DstPort)

	flags := ""
	if tcp.FIN {
		flags += "F"
	}
	if tcp.SYN {
		flags += "S"
	}
	if tcp.RST {
		flags += "R"
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.ACK {
		flags += "A"
	}
	if tcp.URG {
		flags += "U"
	}
	fmt.Println(flags)
}

func decodeUDP(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	fmt.Printf("UDP: %d -> %d\n", udp.SrcPort, udp.DstPort)
}

func decodeICMP(packet gopacket.Packet) {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return
	}
	icmp, _ := icmpLayer.(*layers.ICMPv4)

	fmt.Print("ICMP: ")

	icmpTypeVal := int(icmp.TypeCode >> 8)
	icmpCodeVal := int(icmp.TypeCode & 0x00FF)

	if icmpTypeVal >= 0 && icmpTypeVal < len(icmpType) {
		fmt.Printf("%s ", icmpType[icmpTypeVal])
	} else {
		fmt.Printf("unknown type (%d) ", icmpTypeVal)
	}

	switch icmpTypeVal {
	case 3:
		if icmpCodeVal >= 0 && icmpCodeVal < len(icmpCodeUnreach) {
			fmt.Println(icmpCodeUnreach[icmpCodeVal])
		} else {
			fmt.Printf("code %d\n", icmpCodeVal)
		}
	case 5:
		if icmpCodeVal >= 0 && icmpCodeVal < len(icmpCodeRedirect) {
			fmt.Println(icmpCodeRedirect[icmpCodeVal])
		} else {
			fmt.Printf("code %d\n", icmpCodeVal)
		}
	case 11:
		if icmpCodeVal >= 0 && icmpCodeVal < len(icmpCodeExceed) {
			fmt.Println(icmpCodeExceed[icmpCodeVal])
		} else {
			fmt.Printf("code %d\n", icmpCodeVal)
		}
	case 12:
		if icmpCodeVal >= 0 && icmpCodeVal < len(icmpCodeParameter) {
			fmt.Println(icmpCodeParameter[icmpCodeVal])
		} else {
			fmt.Printf("code %d\n", icmpCodeVal)
		}
	default:
		fmt.Println()
	}
}

func decodeUnknown(packet gopacket.Packet) {
	fmt.Println("unsupported protocol")
}

func printHexDump(data []byte) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}

		fmt.Fprintf(os.Stdout, "%04x\t", i)

		for j := i; j < end; j += 2 {
			if j+1 < end {
				fmt.Fprintf(os.Stdout, "%02x%02x ", data[j], data[j+1])
			} else {
				fmt.Fprintf(os.Stdout, "%02x ", data[j])
			}
		}
		fmt.Fprintln(os.Stdout)
	}
}

var _ io.Writer = (*dummyWriter)(nil)

type dummyWriter struct{}

func (d *dummyWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}
