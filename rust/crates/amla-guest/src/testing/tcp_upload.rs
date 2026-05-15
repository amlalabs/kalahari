//! Minimal TCP upload client for park/resume networking tests.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub fn run(args: &[String]) -> i32 {
    let Some(host) = args.first() else {
        eprintln!("usage: amla-guest tcp-upload <host> <port> <bytes> [chunk] [delay-us]");
        return 1;
    };
    let Some(port) = args.get(1).and_then(|s| s.parse::<u16>().ok()) else {
        eprintln!("tcp-upload: invalid port");
        return 1;
    };
    let Some(total) = args.get(2).and_then(|s| s.parse::<usize>().ok()) else {
        eprintln!("tcp-upload: invalid byte count");
        return 1;
    };
    if total > MAX_TOTAL_BYTES {
        eprintln!("tcp-upload: byte count exceeds {MAX_TOTAL_BYTES}");
        return 1;
    }
    let chunk_size = args
        .get(3)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4096)
        .max(1);
    if chunk_size > MAX_CHUNK_BYTES {
        eprintln!("tcp-upload: chunk size exceeds {MAX_CHUNK_BYTES}");
        return 1;
    }
    let delay = args
        .get(4)
        .and_then(|s| s.parse::<u64>().ok())
        .map_or(Duration::ZERO, Duration::from_micros);

    let addr = format!("{host}:{port}");
    let mut stream = match TcpStream::connect(&addr) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("tcp-upload: connect {addr}: {error}");
            return 1;
        }
    };
    stream.set_read_timeout(Some(Duration::from_mins(1))).ok();
    stream.set_write_timeout(Some(Duration::from_mins(1))).ok();

    let mut sent = 0usize;
    let mut chunk = vec![0u8; chunk_size];
    while sent < total {
        let len = chunk_size.min(total - sent);
        fill_pattern(&mut chunk[..len], sent);
        if let Err(error) = stream.write_all(&chunk[..len]) {
            eprintln!("tcp-upload: write at {sent}/{total}: {error}");
            return 1;
        }
        sent += len;
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }

    if let Err(error) = stream.shutdown(Shutdown::Write) {
        eprintln!("tcp-upload: shutdown write: {error}");
        return 1;
    }

    let mut response = Vec::with_capacity(4096);
    if let Err(error) = std::io::Read::by_ref(&mut stream)
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut response)
    {
        eprintln!("tcp-upload: read response: {error}");
        return 1;
    }
    if response.len() > MAX_RESPONSE_BYTES {
        eprintln!("tcp-upload: response exceeds {MAX_RESPONSE_BYTES}");
        return 1;
    }
    if let Err(error) = std::io::stdout().write_all(&response) {
        eprintln!("tcp-upload: stdout write: {error}");
        return 1;
    }
    if let Err(error) = std::io::stdout().flush() {
        eprintln!("tcp-upload: stdout flush: {error}");
        return 1;
    }
    0
}

fn fill_pattern(buf: &mut [u8], base: usize) {
    for (i, byte) in buf.iter_mut().enumerate() {
        let Ok(value) = u8::try_from((base + i) % 251) else {
            unreachable!("modulo 251 always fits in u8");
        };
        *byte = value;
    }
}
