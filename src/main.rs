use std::env;

use pcap::Capture;
use pnet::packet::Packet;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <name>", args[0]);
        std::process::exit(1);
    }
    let filepath = &args[1];
    let mut cap = Capture::from_file(filepath).unwrap();
    while let Ok(packet) = cap.next_packet() {
        if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(packet.data) {
            if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
                println!("Not an IPv4 packet");
                continue;
            }
            if let Some(ipv4) = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()) {
                println!("Source: {}", ipv4.get_source());
                println!("Destination: {}", ipv4.get_destination());
            } else {
                println!("Not an IPv4 packet");
            }
        } else {
            println!("Not an Ethernet packet");
        }
        println!("{:?}", packet);
    }
}
