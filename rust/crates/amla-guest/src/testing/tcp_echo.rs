//! Minimal TCP echo server for port-forwarding tests.

use std::io::{self, Read, Write};
use std::net::TcpListener;

pub fn run(args: &[String]) -> i32 {
    let Some(port) = args.first().and_then(|s| s.parse::<u16>().ok()) else {
        eprintln!("usage: amla-guest tcp-echo <port>");
        return 1;
    };
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return 1;
        }
    };
    println!("amla-guest tcp-echo ready {port}");
    if let Err(e) = io::stdout().flush() {
        eprintln!("ready flush failed: {e}");
        return 1;
    }
    let (mut stream, _addr) = match listener.accept() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("accept failed: {e}");
            return 1;
        }
    };
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if stream.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    0
}
