use clap::Parser;
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

const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_ARP: u16 = 0x0806;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ICMP: u8 = 1;

const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

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
}

impl PacketCodec for PacketProcessor {
    type Item = ();

    fn decode(&mut self, _packet: PacketHeader, data: &[u8]) -> Self::Item {
        if self.streaming_hex {
            print_streaming_hex(data);
            return;
        }

        process_packet(data);

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

fn process_packet(data: &[u8]) {
    if data.len() < 14 {
        println!("unsupported protocol");
        return;
    }

    let eth_type = u16::from_be_bytes([data[12], data[13]]);

    match eth_type {
        ETH_TYPE_IPV4 => decode_ipv4(data),
        ETH_TYPE_ARP => decode_arp(data),
        _ => {
            println!("unsupported protocol");
        }
    }
}

fn decode_arp(data: &[u8]) {
    if data.len() < 42 {
        println!("-");
        return;
    }

    print!("ARP: ");

    let arp_op = u16::from_be_bytes([data[20], data[21]]);

    match arp_op {
        ARP_OP_REQUEST => {
            println!(
                "y0 who's got {}.{}.{}.{} tell {}.{}.{}.{}",
                data[38], data[39], data[40], data[41],
                data[28], data[29], data[30], data[31]
            );
        }
        ARP_OP_REPLY => {
            println!(
                "y0 {}.{}.{}.{} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                data[28], data[29], data[30], data[31],
                data[22], data[23], data[24], data[25], data[26], data[27]
            );
        }
        _ => println!("-"),
    }
}

fn decode_ipv4(data: &[u8]) {
    if data.len() < 34 {
        println!("unsupported protocol");
        return;
    }

    let ip_start = 14;
    let ip_hl = (data[ip_start] & 0x0f) << 2;
    let ip_total_len = u16::from_be_bytes([data[ip_start + 2], data[ip_start + 3]]);
    let ip_id = u16::from_be_bytes([data[ip_start + 4], data[ip_start + 5]]);
    let ip_proto = data[ip_start + 9];

    print!(
        "IP: {}.{}.{}.{} -> {}.{}.{}.{} ({}), id: {} ",
        data[ip_start + 12], data[ip_start + 13], data[ip_start + 14], data[ip_start + 15],
        data[ip_start + 16], data[ip_start + 17], data[ip_start + 18], data[ip_start + 19],
        ip_total_len, ip_id
    );

    let trans_start = ip_start + ip_hl as usize;

    match ip_proto {
        IP_PROTO_TCP => decode_tcp(data, trans_start),
        IP_PROTO_UDP => decode_udp(data, trans_start),
        IP_PROTO_ICMP => decode_icmp(data, trans_start),
        _ => println!("unsupported protocol"),
    }
}

fn decode_tcp(data: &[u8], offset: usize) {
    if data.len() < offset + 14 {
        println!("");
        return;
    }

    let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

    print!("TCP: {} -> {} ", src_port, dst_port);

    let flags = data[offset + 13];
    let mut flags_str = String::new();

    if flags & 0x01 != 0 {
        flags_str.push('F');
    }
    if flags & 0x02 != 0 {
        flags_str.push('S');
    }
    if flags & 0x04 != 0 {
        flags_str.push('R');
    }
    if flags & 0x08 != 0 {
        flags_str.push('P');
    }
    if flags & 0x10 != 0 {
        flags_str.push('A');
    }
    if flags & 0x20 != 0 {
        flags_str.push('U');
    }

    println!("{}", flags_str);
}

fn decode_udp(data: &[u8], offset: usize) {
    if data.len() < offset + 4 {
        println!("");
        return;
    }

    let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

    println!("UDP: {} -> {}", src_port, dst_port);
}

fn decode_icmp(data: &[u8], offset: usize) {
    if data.len() < offset + 2 {
        println!("");
        return;
    }

    print!("ICMP: ");

    let type_val = data[offset] as usize;
    let code_val = data[offset + 1] as usize;

    if type_val < ICMP_TYPE.len() {
        print!("{} ", ICMP_TYPE[type_val]);
    } else {
        print!("unknown type ({}) ", type_val);
    }

    match type_val {
        3 => {
            if code_val < ICMP_CODE_UNREACH.len() {
                println!("{}", ICMP_CODE_UNREACH[code_val]);
            } else {
                println!("code {}", code_val);
            }
        }
        5 => {
            if code_val < ICMP_CODE_REDIRECT.len() {
                println!("{}", ICMP_CODE_REDIRECT[code_val]);
            } else {
                println!("code {}", code_val);
            }
        }
        11 => {
            if code_val < ICMP_CODE_EXCEED.len() {
                println!("{}", ICMP_CODE_EXCEED[code_val]);
            } else {
                println!("code {}", code_val);
            }
        }
        12 => {
            if code_val < ICMP_CODE_PARAMETER.len() {
                println!("{}", ICMP_CODE_PARAMETER[code_val]);
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
