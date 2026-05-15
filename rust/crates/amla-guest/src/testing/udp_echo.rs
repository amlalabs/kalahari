//! Minimal UDP echo server for port-forwarding tests.

use std::io::{self, Write};
use std::net::UdpSocket;

pub fn run(args: &[String]) -> i32 {
    let Some(port) = args.first().and_then(|s| s.parse::<u16>().ok()) else {
        eprintln!("usage: amla-guest udp-echo <port>");
        return 1;
    };
    let sock = match UdpSocket::bind(("0.0.0.0", port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return 1;
        }
    };
    println!("amla-guest udp-echo ready {port}");
    if let Err(e) = io::stdout().flush() {
        eprintln!("ready flush failed: {e}");
        return 1;
    }
    let mut buf = [0u8; 2048];
    let (n, addr) = match sock.recv_from(&mut buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("recv_from failed: {e}");
            return 1;
        }
    };
    if let Err(e) = sock.send_to(&buf[..n], addr) {
        eprintln!("send_to failed: {e}");
        return 1;
    }
    0
}
