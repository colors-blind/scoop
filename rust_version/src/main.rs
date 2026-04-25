use clap::Parser;
use etherparse::*;
use pcap::{Capture, Device, Error, Linktype, PacketCodec, PacketHeader, Stat};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_SNAPLEN: i32 = 200;
const DEFAULT_PROMISC: bool = true;
const DEFAULT_TIMEOUT: i32 = 500;
const DEFAULT_FILTER: &str = "arp or tcp or udp or icmp";

const ICMP_TYPE: &[&str] = &[
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
];

const ICMP_CODE_UNREACH: &[&str] = &[
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
];

const ICMP_CODE_REDIRECT: &[&str] = &["net", "host", "TOS net", "TOS host"];
const ICMP_CODE_EXCEED: &[&str] = &["in transit", "reassembly"];
const ICMP_CODE_PARAMETER: &[&str] = &["options absent"];

#[derive(Parser, Debug)]
#[command(name = "scoop")]
#[command(about = "A lightweight packet sniffing tool", long_about = None)]
struct Args {
    #[arg(short = 'i', long)]
    device: Option<String>,

    #[arg(short = 's', long, default_value_t = DEFAULT_SNAPLEN)]
    snaplen: i32,

    #[arg(short = 'S', long)]
    streaming_hex: bool,

    #[arg(short = 'x', long)]
    print_hex: bool,

    #[arg(trailing_var_arg = true)]
    filter: Vec<String>,
}

struct PacketProcessor {
    streaming_hex: bool,
    print_hex: bool,
    payload_offset: usize,
}

impl PacketCodec for PacketProcessor {
    type Item = ();

    fn decode(&mut self, packet: PacketHeader, data: &[u8]) -> Self::Item {
        if self.streaming_hex {
            print_streaming_hex(data);
            return;
        }

        match SlicedPacket::from_ethernet(data) {
            Ok(sliced) => {
                process_sliced_packet(&sliced, self.print_hex);
            }
            Err(_) => {
                println!("unsupported protocol");
            }
        }

        if self.print_hex && data.len() > 14 {
            print_hex_dump(&data[14..]);
        }
    }
}

fn main() {
    let args = Args::parse();

    println!("Scoop 1.0 [IP packet sniffing tool]");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("\nInterrupt signal caught...");
    })
    .expect("Error setting Ctrl-C handler");

    let device_name = match args.device {
        Some(d) => d,
        None => match find_default_device() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("scoop_init() failed: {}", e);
                std::process::exit(1);
            }
        },
    };

    let filter = if !args.filter.is_empty() {
        args.filter.join(" ")
    } else {
        DEFAULT_FILTER.to_string()
    };

    if args.snaplen < 14 {
        eprintln!("warning, very small snaplen!");
    }

    let mut cap = match init_capture(&device_name, args.snaplen, &filter) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("scoop_init() failed: {}", e);
            std::process::exit(1);
        }
    };

    if cap.get_datalink() != Linktype(1) {
        eprintln!("Scoop only works with ethernet");
        std::process::exit(1);
    }

    println!("<ctrl-c> to quit");

    let processor = PacketProcessor {
        streaming_hex: args.streaming_hex,
        print_hex: args.print_hex,
        payload_offset: 14,
    };

    let mut codec_iter = cap.iter(processor).expect("Failed to create packet iterator");

    while running.load(Ordering::SeqCst) {
        if let Some(_) = codec_iter.next() {
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    match cap.stats() {
        Ok(stats) => print_statistics(&stats),
        Err(e) => eprintln!("pcap_stats() failed: {}", e),
    }
}

fn find_default_device() -> Result<String, Error> {
    let devices = Device::list()?;
    if devices.is_empty() {
        return Err(Error::InvalidInput);
    }
    println!("Using device: {}", devices[0].name);
    Ok(devices[0].name.clone())
}

fn init_capture(device: &str, snaplen: i32, filter: &str) -> Result<Capture<pcap::Active>, Error> {
    let cap = Capture::from_device(device)?
        .snaplen(snaplen)
        .promisc(DEFAULT_PROMISC)
        .timeout(DEFAULT_TIMEOUT)
        .open()?;

    let mut cap = cap;
    cap.filter(filter, true)?;

    Ok(cap)
}

fn process_sliced_packet(sliced: &SlicedPacket, print_hex: bool) {
    let mut found = false;

    for slice in &sliced.slice {
        match slice {
            LinkSlice::Ethernet2(_) => {}
            LinkSlice::Arp(arp) => {
                decode_arp(arp);
                found = true;
                break;
            }
            NetSlice::Ipv4(ip) => {
                decode_ipv4(ip, sliced);
                found = true;
                break;
            }
            _ => {}
        }
    }

    if !found {
        println!("unsupported protocol");
    }
}

fn decode_arp(arp: &ArpSlice) {
    print!("ARP: ");

    match arp.operation {
        ArpOperation::Request => {
            let spa = arp.sender_protocol_addr;
            let tpa = arp.target_protocol_addr;
            println!(
                "y0 who's got {}.{}.{}.{} tell {}.{}.{}.{}",
                tpa[0], tpa[1], tpa[2], tpa[3], spa[0], spa[1], spa[2], spa[3]
            );
        }
        ArpOperation::Reply => {
            let spa = arp.sender_protocol_addr;
            let sha = arp.sender_hardware_addr;
            println!(
                "y0 {}.{}.{}.{} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                spa[0], spa[1], spa[2], spa[3], sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]
            );
        }
        _ => println!("-"),
    }
}

fn decode_ipv4(ip: &Ipv4Slice, sliced: &SlicedPacket) {
    let src = ip.source_addr();
    let dst = ip.destination_addr();

    print!(
        "IP: {}.{}.{}.{} -> {}.{}.{}.{} ({}), id: {} ",
        src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3],
        ip.payload_len() + 20, ip.identification
    );

    for slice in &sliced.slice {
        match slice {
            TransportSlice::Tcp(tcp) => {
                decode_tcp(tcp);
                return;
            }
            TransportSlice::Udp(udp) => {
                decode_udp(udp);
                return;
            }
            NetSlice::Icmpv4(icmp) => {
                decode_icmp(icmp);
                return;
            }
            _ => {}
        }
    }

    println!("unsupported protocol");
}

fn decode_tcp(tcp: &TcpSlice) {
    print!("TCP: {} -> {} ", tcp.source_port(), tcp.destination_port());

    let mut flags = String::new();
    if tcp.fin() {
        flags.push('F');
    }
    if tcp.syn() {
        flags.push('S');
    }
    if tcp.rst() {
        flags.push('R');
    }
    if tcp.psh() {
        flags.push('P');
    }
    if tcp.ack() {
        flags.push('A');
    }
    if tcp.urg() {
        flags.push('U');
    }
    println!("{}", flags);
}

fn decode_udp(udp: &UdpSlice) {
    println!("UDP: {} -> {}", udp.source_port(), udp.destination_port());
}

fn decode_icmp(icmp: &Icmpv4Slice) {
    print!("ICMP: ");

    let type_val = icmp.icmp_type().0;
    let code_val = icmp.code_u8();

    if (type_val as usize) < ICMP_TYPE.len() {
        print!("{} ", ICMP_TYPE[type_val as usize]);
    } else {
        print!("unknown type ({}) ", type_val);
    }

    match type_val {
        3 => {
            if (code_val as usize) < ICMP_CODE_UNREACH.len() {
                println!("{}", ICMP_CODE_UNREACH[code_val as usize]);
            } else {
                println!("code {}", code_val);
            }
        }
        5 => {
            if (code_val as usize) < ICMP_CODE_REDIRECT.len() {
                println!("{}", ICMP_CODE_REDIRECT[code_val as usize]);
            } else {
                println!("code {}", code_val);
            }
        }
        11 => {
            if (code_val as usize) < ICMP_CODE_EXCEED.len() {
                println!("{}", ICMP_CODE_EXCEED[code_val as usize]);
            } else {
                println!("code {}", code_val);
            }
        }
        12 => {
            if (code_val as usize) < ICMP_CODE_PARAMETER.len() {
                println!("{}", ICMP_CODE_PARAMETER[code_val as usize]);
            } else {
                println!("code {}", code_val);
            }
        }
        _ => println!(),
    }
}

fn print_streaming_hex(data: &[u8]) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    for b in data {
        write!(handle, "{:02x}", b).ok();
    }
    handle.flush().ok();
}

fn print_hex_dump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:04x}\t", i * 16);

        let words = chunk.len() / 2;
        let has_odd = chunk.len() % 2 == 1;

        for j in 0..words {
            let idx = j * 2;
            print!("{:02x}{:02x} ", chunk[idx], chunk[idx + 1]);
        }

        if has_odd {
            print!("{:02x} ", chunk[words * 2]);
        }

        println!();
    }
}

fn print_statistics(stats: &Stat) {
    println!(
        "\nPackets received by libpcap:\t{:6}\nPackets dropped by libpcap:\t{:6}",
        stats.received, stats.dropped
    );
}
