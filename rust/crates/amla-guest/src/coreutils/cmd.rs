//! Applet implementations for the multi-call coreutils binary.

use std::io::{self, Read, Write};

use lexopt::prelude::*;

/// Convert an `OsString` value to `String`, returning an error message on failure.
fn val_to_string(val: std::ffi::OsString, applet: &str) -> Result<String, i32> {
    val.into_string().map_err(|_| {
        eprintln!("{applet}: invalid UTF-8 argument");
        1
    })
}

// ─── echo ───────────────────────────────────────────────────────────────

/// Print arguments separated by spaces, followed by a newline.
pub fn echo(mut parser: lexopt::Parser) -> i32 {
    let mut parts = Vec::new();
    loop {
        match parser.next() {
            Ok(Some(Value(val))) => match val_to_string(val, "echo") {
                Ok(s) => parts.push(s),
                Err(code) => return code,
            },
            // echo treats everything as positional — pass flags through as text
            Ok(Some(Short(c))) => parts.push(format!("-{c}")),
            Ok(Some(Long(l))) => parts.push(format!("--{l}")),
            Ok(None) => break,
            Err(e) => {
                eprintln!("echo: {e}");
                return 1;
            }
        }
    }
    println!("{}", parts.join(" "));
    0
}

// ─── cat ────────────────────────────────────────────────────────────────

/// Concatenate files to stdout, or copy stdin to stdout if no args.
pub fn cat(mut parser: lexopt::Parser) -> i32 {
    let mut paths = Vec::new();
    loop {
        match parser.next() {
            Ok(Some(Value(val))) => match val_to_string(val, "cat") {
                Ok(s) => paths.push(s),
                Err(code) => return code,
            },
            Ok(Some(other)) => {
                eprintln!("cat: {}", other.unexpected());
                return 1;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("cat: {e}");
                return 1;
            }
        }
    }

    if paths.is_empty() {
        // Stream stdin → stdout in chunks (supports PTY/pipe use)
        let mut buf = [0u8; 4096];
        loop {
            match io::stdin().read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if io::stdout().write_all(&buf[..n]).is_err() {
                        return 1;
                    }
                    if let Err(e) = io::stdout().flush() {
                        eprintln!("cat: stdout flush: {e}");
                        return 1;
                    }
                }
            }
        }
        return 0;
    }
    for path in &paths {
        match std::fs::read(path) {
            Ok(data) => {
                if let Err(e) = io::stdout().write_all(&data) {
                    eprintln!("cat: stdout write {path}: {e}");
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("cat: {path}: {e}");
                return 1;
            }
        }
    }
    0
}

// ─── id ─────────────────────────────────────────────────────────────────

/// Print user ID. Supports `-u` flag (default behavior).
pub fn id(mut parser: lexopt::Parser) -> i32 {
    // Consume args but ignore them — always print uid.
    loop {
        match parser.next() {
            Ok(Some(_)) => {} // ignore all flags
            Ok(None) => break,
            Err(e) => {
                eprintln!("id: {e}");
                return 1;
            }
        }
    }
    // SAFETY: getuid is always safe
    let uid = unsafe { libc::getuid() };
    println!("{uid}");
    0
}

// ─── ls ─────────────────────────────────────────────────────────────────

/// List directory contents (one entry per line).
pub fn ls(mut parser: lexopt::Parser) -> i32 {
    let mut dir = String::from(".");
    loop {
        match parser.next() {
            Ok(Some(Value(val))) => match val_to_string(val, "ls") {
                Ok(s) => {
                    dir = s;
                    break;
                }
                Err(code) => return code,
            },
            Ok(Some(_)) => {} // ignore flags
            Ok(None) => break,
            Err(e) => {
                eprintln!("ls: {e}");
                return 1;
            }
        }
    }
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                println!("{}", entry.file_name().to_string_lossy());
            }
            0
        }
        Err(e) => {
            eprintln!("ls: {dir}: {e}");
            1
        }
    }
}

// ─── mkdir ──────────────────────────────────────────────────────────────

/// Create directories. Always behaves like `mkdir -p`.
pub fn mkdir(mut parser: lexopt::Parser) -> i32 {
    let mut paths = Vec::new();
    loop {
        match parser.next() {
            Ok(Some(Short('p'))) => {} // accepted, always -p anyway
            Ok(Some(Value(val))) => match val_to_string(val, "mkdir") {
                Ok(s) => paths.push(s),
                Err(code) => return code,
            },
            Ok(Some(other)) => {
                eprintln!("mkdir: {}", other.unexpected());
                return 1;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("mkdir: {e}");
                return 1;
            }
        }
    }
    for path in &paths {
        if let Err(e) = std::fs::create_dir_all(path) {
            eprintln!("mkdir: {path}: {e}");
            return 1;
        }
    }
    0
}

// ─── dirname ────────────────────────────────────────────────────────────

/// Print the directory component of a path.
pub fn dirname(mut parser: lexopt::Parser) -> i32 {
    let path = match parser.next() {
        Ok(Some(Value(val))) => match val_to_string(val, "dirname") {
            Ok(s) => s,
            Err(code) => return code,
        },
        Ok(_) => {
            eprintln!("dirname: missing operand");
            return 1;
        }
        Err(e) => {
            eprintln!("dirname: {e}");
            return 1;
        }
    };
    let parent = std::path::Path::new(&path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or(".");
    println!("{parent}");
    0
}

// ─── printenv ───────────────────────────────────────────────────────────

/// Print the value of an environment variable.
pub fn printenv(mut parser: lexopt::Parser) -> i32 {
    let name = match parser.next() {
        Ok(Some(Value(val))) => match val_to_string(val, "printenv") {
            Ok(s) => s,
            Err(code) => return code,
        },
        Ok(_) => {
            eprintln!("printenv: missing variable name");
            return 1;
        }
        Err(e) => {
            eprintln!("printenv: {e}");
            return 1;
        }
    };
    std::env::var(&name).map_or(1, |val| {
        println!("{val}");
        0
    })
}

// ─── exit-with ──────────────────────────────────────────────────────────

/// Exit with the given exit code.
pub fn exit_with(mut parser: lexopt::Parser) -> i32 {
    let code_str = match parser.next() {
        Ok(Some(Value(val))) => match val_to_string(val, "exit-with") {
            Ok(s) => s,
            Err(code) => return code,
        },
        Ok(_) => {
            eprintln!("exit-with: missing exit code");
            return 1;
        }
        Err(e) => {
            eprintln!("exit-with: {e}");
            return 1;
        }
    };
    code_str.parse::<i32>().unwrap_or(1)
}

// ─── sleep ──────────────────────────────────────────────────────────────

/// Sleep for the given number of seconds.
pub fn sleep_cmd(mut parser: lexopt::Parser) -> i32 {
    let secs_str = match parser.next() {
        Ok(Some(Value(val))) => match val_to_string(val, "sleep") {
            Ok(s) => s,
            Err(code) => return code,
        },
        Ok(_) => {
            eprintln!("sleep: missing operand");
            return 1;
        }
        Err(e) => {
            eprintln!("sleep: {e}");
            return 1;
        }
    };
    let Ok(secs) = secs_str.parse::<f64>() else {
        eprintln!("sleep: invalid number: {secs_str}");
        return 1;
    };
    std::thread::sleep(std::time::Duration::from_secs_f64(secs));
    0
}

// ─── grep ───────────────────────────────────────────────────────────────

/// Basic pattern matching: `^` (start), `$` (end), `[chars]` (char class), `.` (any char).
fn matches_pattern(line: &str, pattern: &str) -> bool {
    let anchored_start = pattern.starts_with('^');
    let anchored_end = pattern.ends_with('$');

    let inner = pattern
        .strip_prefix('^')
        .unwrap_or(pattern)
        .strip_suffix('$')
        .unwrap_or_else(|| pattern.strip_prefix('^').unwrap_or(pattern));

    // If no special regex chars, fast path
    if !inner.contains('[') && !inner.contains('.') {
        if anchored_start && anchored_end {
            return line == inner;
        } else if anchored_start {
            return line.starts_with(inner);
        } else if anchored_end {
            return line.ends_with(inner);
        }
        return line.contains(inner);
    }

    // Simple regex: expand pattern to check against each position
    if anchored_start {
        regex_match_at(line, inner, 0)
    } else {
        (0..=line.len()).any(|i| regex_match_at(line, inner, i))
    }
}

/// Match a simple regex pattern at a specific position in the line.
/// Supports `[chars]`, `[a-z]`, `.` (any char), and literal chars.
fn regex_match_at(line: &str, pattern: &str, start: usize) -> bool {
    let line_bytes = line.as_bytes();
    let pat_bytes = pattern.as_bytes();
    let mut li = start;
    let mut pi = 0;

    while pi < pat_bytes.len() {
        if pat_bytes[pi] == b'[' {
            // Character class
            pi += 1;
            if li >= line_bytes.len() {
                return false;
            }
            let ch = line_bytes[li];
            let mut matched = false;
            while pi < pat_bytes.len() && pat_bytes[pi] != b']' {
                if pi + 2 < pat_bytes.len() && pat_bytes[pi + 1] == b'-' {
                    // Range like a-z or 0-9
                    if ch >= pat_bytes[pi] && ch <= pat_bytes[pi + 2] {
                        matched = true;
                    }
                    pi += 3;
                } else {
                    if ch == pat_bytes[pi] {
                        matched = true;
                    }
                    pi += 1;
                }
            }
            if pi < pat_bytes.len() {
                pi += 1; // skip ']'
            }
            if !matched {
                return false;
            }
        } else if pat_bytes[pi] == b'.' {
            // Any character
            if li >= line_bytes.len() {
                return false;
            }
            pi += 1;
        } else {
            // Literal
            if li >= line_bytes.len() || line_bytes[li] != pat_bytes[pi] {
                return false;
            }
            pi += 1;
        }
        // Each branch consumed exactly one character of `line` on a successful
        // match; advance `li` here once instead of in three places (clippy::
        // branches_sharing_code).
        li += 1;
    }
    true
}

/// Basic grep: match lines containing a pattern. Supports `-c` (count).
pub fn grep(mut parser: lexopt::Parser) -> i32 {
    let mut count_only = false;
    let mut pattern = None;
    let mut files = Vec::new();

    loop {
        match parser.next() {
            Ok(Some(Short('c'))) => count_only = true,
            Ok(Some(Short('i' | 'n' | 'v' | 'l'))) => {
                // Accept common flags silently for compatibility
            }
            Ok(Some(Value(val))) => match val_to_string(val, "grep") {
                Ok(s) => {
                    if pattern.is_none() {
                        pattern = Some(s);
                    } else {
                        files.push(s);
                    }
                }
                Err(code) => return code,
            },
            Ok(Some(other)) => {
                eprintln!("grep: {}", other.unexpected());
                return 1;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("grep: {e}");
                return 1;
            }
        }
    }

    let Some(pattern) = pattern else {
        eprintln!("grep: missing pattern");
        return 2;
    };

    let sources: Vec<Box<dyn io::BufRead>> = if files.is_empty() {
        vec![Box::new(io::BufReader::new(io::stdin()))]
    } else {
        let mut v: Vec<Box<dyn io::BufRead>> = Vec::new();
        for path in &files {
            match std::fs::File::open(path) {
                Ok(f) => v.push(Box::new(io::BufReader::new(f))),
                Err(e) => {
                    eprintln!("grep: {path}: {e}");
                    return 2;
                }
            }
        }
        v
    };

    let mut match_count = 0u64;
    let mut found = false;
    for source in sources {
        for line in io::BufRead::lines(source) {
            let Ok(line) = line else { break };
            if matches_pattern(&line, &pattern) {
                found = true;
                match_count += 1;
                if !count_only {
                    println!("{line}");
                }
            }
        }
    }

    if count_only {
        println!("{match_count}");
    }

    i32::from(!found)
}

// ─── nproc ──────────────────────────────────────────────────────────────

/// Print the number of available processors.
pub fn nproc(mut parser: lexopt::Parser) -> i32 {
    // Consume and ignore args
    loop {
        match parser.next() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                eprintln!("nproc: {e}");
                return 1;
            }
        }
    }

    // Read from /sys/devices/system/cpu/online (format: "0-3" or "0-7")
    if let Ok(content) = std::fs::read_to_string("/sys/devices/system/cpu/online") {
        let content = content.trim();
        // Parse range like "0-3" → 4 CPUs, or "0" → 1 CPU
        let count = if let Some((_, end)) = content.split_once('-') {
            end.parse::<u32>().unwrap_or(0) + 1
        } else {
            #[allow(clippy::cast_possible_truncation)]
            {
                content.split(',').count() as u32
            }
        };
        println!("{count}");
    } else {
        // Fallback: try sysconf
        #[allow(clippy::cast_sign_loss)]
        // SAFETY: sysconf has no preconditions; name is a valid _SC_ constant.
        let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if n > 0 {
            println!("{n}");
        } else {
            println!("1");
        }
    }
    0
}

// ─── wget ───────────────────────────────────────────────────────────────

/// Minimal HTTP GET. Supports `wget -qO- <url>` and `wget -O - <url>`.
/// No TLS — HTTPS handled by `amla_https_get`.
pub fn wget(mut parser: lexopt::Parser) -> i32 {
    let mut url = None;
    loop {
        match parser.next() {
            Ok(Some(Short('q') | Long("no-check-certificate"))) => {} // ignored
            Ok(Some(Short('O'))) => {
                // Consume and discard the -O value (stdout target). A missing
                // value is a user error; report and continue since wget treats
                // -O as optional positionally.
                if let Err(e) = parser.value() {
                    eprintln!("wget: -O missing value: {e}");
                    return 1;
                }
            }
            Ok(Some(Value(val))) => match val_to_string(val, "wget") {
                Ok(s) => {
                    url = Some(s);
                    break;
                }
                Err(code) => return code,
            },
            Ok(Some(other)) => {
                eprintln!("wget: {}", other.unexpected());
                return 1;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("wget: {e}");
                return 1;
            }
        }
    }

    let Some(url) = url else {
        eprintln!("wget: missing URL");
        return 1;
    };

    let Some(without_scheme) = url.strip_prefix("http://") else {
        eprintln!("wget: only http:// URLs supported (use https_get for HTTPS)");
        return 1;
    };

    let (host_port, path) = without_scheme.find('/').map_or((without_scheme, "/"), |i| {
        (&without_scheme[..i], &without_scheme[i..])
    });

    let (host, port) = host_port.rfind(':').map_or((host_port, 80u16), |i| {
        (
            &host_port[..i],
            host_port[i + 1..].parse::<u16>().unwrap_or(80),
        )
    });

    let addr = format!("{host}:{port}");
    let stream = match std::net::TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wget: connect {addr}: {e}");
            return 1;
        }
    };
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let mut stream = io::BufWriter::new(stream);
    if stream.write_all(request.as_bytes()).is_err() || stream.flush().is_err() {
        eprintln!("wget: write failed");
        return 1;
    }
    let mut stream = match stream.into_inner() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wget: flush error: {e}");
            return 1;
        }
    };

    let mut response = Vec::new();
    if let Err(e) = stream.read_to_end(&mut response) {
        eprintln!("wget: read: {e}");
        if response.is_empty() {
            return 1;
        }
    }

    // Strip HTTP headers (find \r\n\r\n)
    let body_start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(0, |p| p + 4);
    if let Err(e) = io::stdout().write_all(&response[body_start..]) {
        eprintln!("wget: stdout write: {e}");
        return 1;
    }
    if let Err(e) = io::stdout().flush() {
        eprintln!("wget: stdout flush: {e}");
        return 1;
    }
    0
}

// ─── ping ───────────────────────────────────────────────────────────────

/// Minimal ping: send one ICMP echo request.
/// Falls back to TCP connect probe if raw sockets unavailable.
pub fn ping(mut parser: lexopt::Parser) -> i32 {
    let mut host = None;
    loop {
        match parser.next() {
            Ok(Some(Short('c' | 'W' | 'w' | 'i'))) => {
                // These flags take a value argument — consume it.
                if let Err(e) = parser.value() {
                    eprintln!("ping: flag missing value: {e}");
                    return 1;
                }
            }
            Ok(Some(Value(val))) => match val_to_string(val, "ping") {
                Ok(s) => {
                    host = Some(s);
                    break;
                }
                Err(code) => return code,
            },
            Ok(Some(_)) => {} // ignore other flags
            Ok(None) => break,
            Err(e) => {
                eprintln!("ping: {e}");
                return 1;
            }
        }
    }

    let Some(host) = host else {
        eprintln!("ping: missing host");
        return 1;
    };

    // Try ICMP first (requires root or CAP_NET_RAW)
    if icmp_ping(&host) {
        println!("PING {host}: 1 packets transmitted, 1 received");
        return 0;
    }

    // Fallback: TCP connect to port 80
    let addr = format!("{host}:80");
    match std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| {
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 80)
        }),
        std::time::Duration::from_secs(2),
    ) {
        Ok(_) => {
            println!("PING {host}: reachable (tcp)");
            0
        }
        Err(e) => {
            eprintln!("ping: {host}: {e}");
            1
        }
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::borrow_as_ptr,
    clippy::ptr_as_ptr,
    clippy::ref_as_ptr
)]
fn icmp_ping(host: &str) -> bool {
    let addr: std::net::Ipv4Addr = match host.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // SAFETY: creating a raw ICMP socket
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return false;
    }

    // Set receive timeout
    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: fd is valid, tv is valid
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
    }

    // ICMP echo request: type=8, code=0, checksum, id, seq, payload
    let mut pkt = [0u8; 16];
    pkt[0] = 8; // type: echo request
    // pkt[1] = 0; // code
    pkt[4] = 0x42; // id
    pkt[6] = 0x01; // seq
    // Checksum
    let cksum = icmp_checksum(&pkt);
    pkt[2..4].copy_from_slice(&cksum.to_be_bytes());

    // SAFETY: `sockaddr_in` is an all-zero-valid POD.
    let mut dest: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    dest.sin_family = libc::AF_INET as libc::sa_family_t;
    dest.sin_addr.s_addr = u32::from_ne_bytes(addr.octets());

    // SAFETY: fd is valid, pkt and dest are valid
    let sent = unsafe {
        libc::sendto(
            fd,
            pkt.as_ptr().cast(),
            pkt.len(),
            0,
            &dest as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if sent < 0 {
        // SAFETY: `fd` is a valid OS fd owned by this scope; close takes a valid fd.
        unsafe {
            libc::close(fd);
        }
        return false;
    }

    // Wait for reply
    let mut reply = [0u8; 128];
    // SAFETY: fd is valid, reply buffer is valid
    let n = unsafe { libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), 0) };
    // SAFETY: `fd` is a valid OS fd owned by this scope; close takes a valid fd.
    unsafe {
        libc::close(fd);
    }

    // IP header is 20 bytes, ICMP reply type=0
    n > 20 && reply[20] == 0
}

// ─── tee ───────────────────────────────────────────────────────────────

/// Copy stdin to stdout AND to each named file.
pub fn tee(mut parser: lexopt::Parser) -> i32 {
    let mut files = Vec::new();
    loop {
        match parser.next() {
            Ok(Some(Value(val))) => match val_to_string(val, "tee") {
                Ok(s) => files.push(s),
                Err(code) => return code,
            },
            Ok(Some(_)) => {} // ignore flags like -a
            Ok(None) => break,
            Err(e) => {
                eprintln!("tee: {e}");
                return 1;
            }
        }
    }

    let mut buf = Vec::new();
    if io::stdin().read_to_end(&mut buf).is_err() {
        eprintln!("tee: read stdin failed");
        return 1;
    }

    if let Err(e) = io::stdout().write_all(&buf) {
        eprintln!("tee: stdout write: {e}");
        return 1;
    }
    if let Err(e) = io::stdout().flush() {
        eprintln!("tee: stdout flush: {e}");
        return 1;
    }

    for path in &files {
        if let Err(e) = std::fs::write(path, &buf) {
            eprintln!("tee: {path}: {e}");
            return 1;
        }
    }
    0
}

// ─── eof-marker ───────────────────────────────────────────────────────

/// Read stdin until EOF, then write a marker file.
#[cfg(feature = "test-binaries")]
pub fn eof_marker(mut parser: lexopt::Parser) -> i32 {
    let mut marker_path = None;
    loop {
        match parser.next() {
            Ok(Some(Value(val))) => match val_to_string(val, "eof-marker") {
                Ok(path) => {
                    if marker_path.is_some() {
                        eprintln!("usage: eof-marker <marker-path>");
                        return 1;
                    }
                    marker_path = Some(path);
                }
                Err(code) => return code,
            },
            Ok(Some(other)) => {
                eprintln!("eof-marker: {}", other.unexpected());
                return 1;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("eof-marker: {e}");
                return 1;
            }
        }
    }

    let Some(marker_path) = marker_path else {
        eprintln!("usage: eof-marker <marker-path>");
        return 1;
    };

    let mut buf = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut buf) {
        eprintln!("eof-marker: stdin: {e}");
        return 1;
    }

    if let Err(e) = std::fs::write(&marker_path, b"eof-seen\n") {
        eprintln!("eof-marker: {marker_path}: {e}");
        return 1;
    }
    0
}

// ─── dd ────────────────────────────────────────────────────────────────

/// Minimal dd: supports `if=`, `of=`, `bs=`, `count=`.
///
/// Only supports `bs` with `M` suffix (e.g. `bs=1M`).
pub fn dd(mut parser: lexopt::Parser) -> i32 {
    let mut if_path = String::from("/dev/stdin");
    let mut of_path = String::from("/dev/stdout");
    let mut bs: usize = 512;
    let mut count: Option<usize> = None;

    loop {
        match parser.next() {
            Ok(Some(Value(val))) => match val_to_string(val, "dd") {
                Ok(s) => {
                    if let Some(v) = s.strip_prefix("if=") {
                        if_path = v.to_string();
                    } else if let Some(v) = s.strip_prefix("of=") {
                        of_path = v.to_string();
                    } else if let Some(v) = s.strip_prefix("bs=") {
                        bs = parse_size(v).unwrap_or(512);
                    } else if let Some(v) = s.strip_prefix("count=") {
                        count = v.parse().ok();
                    }
                }
                Err(code) => return code,
            },
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                eprintln!("dd: {e}");
                return 1;
            }
        }
    }

    let mut input: Box<dyn Read> = if if_path == "/dev/stdin" {
        Box::new(io::stdin())
    } else {
        match std::fs::File::open(&if_path) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("dd: {if_path}: {e}");
                return 1;
            }
        }
    };

    let mut output: Box<dyn Write> = if of_path == "/dev/stdout" {
        Box::new(io::stdout())
    } else {
        match std::fs::File::create(&of_path) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("dd: {of_path}: {e}");
                return 1;
            }
        }
    };

    let mut buf = vec![0u8; bs];
    let mut blocks = 0usize;
    let mut total_bytes = 0u64;
    loop {
        if count.is_some_and(|c| blocks >= c) {
            break;
        }
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("dd: read: {e}");
                return 1;
            }
        };
        if let Err(e) = output.write_all(&buf[..n]) {
            eprintln!("dd: write: {e}");
            return 1;
        }
        blocks += 1;
        total_bytes += n as u64;
    }

    eprintln!("{blocks}+0 records in");
    eprintln!("{blocks}+0 records out");
    eprintln!("{total_bytes} bytes copied");
    0
}

/// Parse a size string like "1M", "512", "4K".
fn parse_size(s: &str) -> Option<usize> {
    s.strip_suffix('M').map_or_else(
        || {
            s.strip_suffix('K').map_or_else(
                || s.parse().ok(),
                |n| n.parse::<usize>().ok().map(|v| v * 1024),
            )
        },
        |n| n.parse::<usize>().ok().map(|v| v * 1024 * 1024),
    )
}

// ─── mount ─────────────────────────────────────────────────────────────

/// Minimal mount: `mount -t <type> [-o <opts>] <source> <target>`.
///
/// Linux-only; returns 1 on other platforms.
#[cfg(not(target_os = "linux"))]
pub fn mount(_parser: lexopt::Parser) -> i32 {
    eprintln!("mount: not supported on this platform");
    1
}

/// Minimal mount: `mount -t <type> [-o <opts>] <source> <target>`.
pub fn mount(mut parser: lexopt::Parser) -> i32 {
    let mut fstype = None;
    let mut opts = None;
    let mut positionals = Vec::new();

    loop {
        match parser.next() {
            Ok(Some(Short('t'))) => match parser.value() {
                Ok(val) => match val_to_string(val, "mount") {
                    Ok(s) => fstype = Some(s),
                    Err(code) => return code,
                },
                Err(e) => {
                    eprintln!("mount: -t: {e}");
                    return 1;
                }
            },
            Ok(Some(Short('o'))) => match parser.value() {
                Ok(val) => match val_to_string(val, "mount") {
                    Ok(s) => opts = Some(s),
                    Err(code) => return code,
                },
                Err(e) => {
                    eprintln!("mount: -o: {e}");
                    return 1;
                }
            },
            Ok(Some(Value(val))) => match val_to_string(val, "mount") {
                Ok(s) => positionals.push(s),
                Err(code) => return code,
            },
            Ok(Some(other)) => {
                eprintln!("mount: {}", other.unexpected());
                return 1;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("mount: {e}");
                return 1;
            }
        }
    }

    if positionals.len() != 2 {
        eprintln!("mount: usage: mount -t <type> [-o <opts>] <source> <target>");
        return 1;
    }

    let Ok(source) = std::ffi::CString::new(positionals[0].as_str()) else {
        eprintln!("mount: invalid source path");
        return 1;
    };
    let Ok(target) = std::ffi::CString::new(positionals[1].as_str()) else {
        eprintln!("mount: invalid target path");
        return 1;
    };
    let fstype_c = match fstype.as_deref().map(std::ffi::CString::new) {
        Some(Ok(c)) => Some(c),
        Some(Err(_)) => {
            eprintln!("mount: invalid fstype");
            return 1;
        }
        None => None,
    };
    let opts_c = match opts.as_deref().map(std::ffi::CString::new) {
        Some(Ok(c)) => Some(c),
        Some(Err(_)) => {
            eprintln!("mount: invalid options");
            return 1;
        }
        None => None,
    };

    let fstype_ptr = fstype_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    let opts_ptr = opts_c
        .as_ref()
        .map_or(std::ptr::null(), |c| c.as_ptr().cast());

    // SAFETY: all pointers are valid C strings or null.
    let ret = unsafe { libc::mount(source.as_ptr(), target.as_ptr(), fstype_ptr, 0, opts_ptr) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        eprintln!("mount: {}: {err}", positionals[1]);
        return 1;
    }
    0
}

// ─── umount ────────────────────────────────────────────────────────────

/// Minimal umount: `umount <target>`.
///
/// Linux-only; returns 1 on other platforms.
#[cfg(not(target_os = "linux"))]
pub fn umount(_parser: lexopt::Parser) -> i32 {
    eprintln!("umount: not supported on this platform");
    1
}

/// Minimal umount: `umount <target>`.
pub fn umount(mut parser: lexopt::Parser) -> i32 {
    let target = match parser.next() {
        Ok(Some(Value(val))) => match val_to_string(val, "umount") {
            Ok(s) => s,
            Err(code) => return code,
        },
        Ok(_) => {
            eprintln!("umount: missing target");
            return 1;
        }
        Err(e) => {
            eprintln!("umount: {e}");
            return 1;
        }
    };

    let Ok(target_c) = std::ffi::CString::new(target.as_str()) else {
        eprintln!("umount: invalid target path");
        return 1;
    };
    // SAFETY: target_c is a valid C string.
    let ret = unsafe { libc::umount2(target_c.as_ptr(), 0) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        eprintln!("umount: {target}: {err}");
        return 1;
    }
    0
}

// ─── wc ───────────────────────────────────────────────────────────────

/// Count bytes (`-c`) or lines (`-l`) in files or stdin.
/// Default (no flags) prints lines, words, and bytes.
pub fn wc(mut parser: lexopt::Parser) -> i32 {
    let mut count_bytes = false;
    let mut count_lines = false;
    let mut files = Vec::new();

    loop {
        match parser.next() {
            Ok(Some(Short('c'))) => count_bytes = true,
            Ok(Some(Short('l'))) => count_lines = true,
            Ok(Some(Value(val))) => match val_to_string(val, "wc") {
                Ok(s) => files.push(s),
                Err(code) => return code,
            },
            Ok(Some(other)) => {
                eprintln!("wc: {}", other.unexpected());
                return 1;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("wc: {e}");
                return 1;
            }
        }
    }

    // If no flags, default to lines + bytes
    if !count_bytes && !count_lines {
        count_bytes = true;
        count_lines = true;
    }

    let sources: Vec<(String, Box<dyn io::Read>)> = if files.is_empty() {
        vec![("-".to_string(), Box::new(io::stdin()))]
    } else {
        let mut v: Vec<(String, Box<dyn io::Read>)> = Vec::new();
        for path in &files {
            match std::fs::File::open(path) {
                Ok(f) => v.push((path.clone(), Box::new(f))),
                Err(e) => {
                    eprintln!("wc: {path}: {e}");
                    return 1;
                }
            }
        }
        v
    };

    for (name, mut source) in sources {
        let mut data = Vec::new();
        if source.read_to_end(&mut data).is_err() {
            eprintln!("wc: {name}: read error");
            return 1;
        }

        let mut parts = Vec::new();
        if count_lines {
            #[allow(clippy::naive_bytecount)]
            let lines = data.iter().filter(|&&b| b == b'\n').count();
            parts.push(lines.to_string());
        }
        if count_bytes {
            parts.push(data.len().to_string());
        }

        if files.len() > 1 || !files.is_empty() {
            parts.push(name);
        }
        println!("{}", parts.join(" "));
    }
    0
}

// ─── date ──────────────────────────────────────────────────────────────

/// Minimal `date` — print or set system time.
///
/// Supports `-s "YYYY-MM-DD HH:MM:SS"` to set the clock via `clock_settime`.
/// Without `-s`, prints the current time in ISO 8601 format.
pub fn date(mut parser: lexopt::Parser) -> i32 {
    let mut set_time: Option<String> = None;

    loop {
        match parser.next() {
            Ok(Some(Short('s'))) => {
                let Ok(val) = parser.value() else {
                    eprintln!("date: -s requires an argument");
                    return 1;
                };
                let Ok(s) = val.into_string() else {
                    eprintln!("date: invalid UTF-8");
                    return 1;
                };
                set_time = Some(s);
            }
            Ok(Some(_)) => {
                eprintln!("usage: date [-s \"YYYY-MM-DD HH:MM:SS\"]");
                return 1;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("date: {e}");
                return 1;
            }
        }
    }

    if let Some(timestr) = set_time {
        // Parse "YYYY-MM-DD HH:MM:SS"
        let Some(secs) = parse_datetime(&timestr) else {
            eprintln!("date: invalid date format: {timestr}");
            eprintln!("date: expected YYYY-MM-DD HH:MM:SS");
            return 1;
        };
        let ts = libc::timespec {
            tv_sec: secs,
            tv_nsec: 0,
        };
        // SAFETY: clock_settime is safe with a valid timespec pointer.
        let ret = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, std::ptr::from_ref(&ts)) };
        if ret != 0 {
            eprintln!("date: clock_settime failed: {}", io::Error::last_os_error());
            return 1;
        }
    }

    // Print current time (read back after set, or just print).
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime is safe with a valid timespec pointer.
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, std::ptr::from_mut(&mut ts));
    }
    // Format as "YYYY-MM-DD HH:MM:SS" (UTC, manual calendar arithmetic).
    let (y, m, d, hh, mm, ss) = unix_to_datetime(ts.tv_sec);
    println!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}");
    0
}

/// Parse "YYYY-MM-DD HH:MM:SS" into Unix timestamp (UTC).
fn parse_datetime(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<u32> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_parts: Vec<u32> = parts[1].split(':').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }
    let y = i64::from(date_parts[0]);
    let m = date_parts[1] as usize;
    let d = i64::from(date_parts[2]);
    let (hh, mm, ss) = (
        i64::from(time_parts[0]),
        i64::from(time_parts[1]),
        i64::from(time_parts[2]),
    );

    // Days from year 1970 to start of year y.
    let mut days = 0i64;
    for yr in 1970..y {
        days += if is_leap(yr) { 366 } else { 365 };
    }
    let month_days: &[i64] = &[
        31,
        if is_leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    for &md in &month_days[..m.saturating_sub(1)] {
        days += md;
    }
    days += d - 1;

    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

const fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

/// Convert Unix timestamp to (year, month, day, hour, minute, second) UTC.
fn unix_to_datetime(ts: i64) -> (i64, i64, i64, i64, i64, i64) {
    let secs_in_day = 86400i64;
    let mut days = ts / secs_in_day;
    let daytime = ts % secs_in_day;
    let hh = daytime / 3600;
    let mm = (daytime % 3600) / 60;
    let ss = daytime % 60;

    let mut y = 1970i64;
    loop {
        let yd = if is_leap(y) { 366 } else { 365 };
        if days < yd {
            break;
        }
        days -= yd;
        y += 1;
    }
    let month_days = [
        31,
        if is_leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 1i64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        m += 1;
    }
    (y, m, days + 1, hh, mm, ss)
}

#[allow(clippy::cast_possible_truncation)]
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

// ─── stat ──────────────────────────────────────────────────────────────

/// Print file uid, gid, and mode: `<uid> <gid> <mode_octal> <path>`.
pub fn stat(mut parser: lexopt::Parser) -> i32 {
    use lexopt::prelude::*;
    use std::os::unix::fs::MetadataExt;

    let mut paths = Vec::new();
    loop {
        match parser.next() {
            Ok(Some(Value(val))) => match val_to_string(val, "stat") {
                Ok(s) => paths.push(s),
                Err(code) => return code,
            },
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                eprintln!("stat: {e}");
                return 1;
            }
        }
    }
    if paths.is_empty() {
        eprintln!("usage: stat <path>...");
        return 1;
    }

    let mut rc = 0;
    for path in &paths {
        match std::fs::metadata(path) {
            Ok(m) => {
                println!("{} {} {:o} {path}", m.uid(), m.gid(), m.mode() & 0o7777);
            }
            Err(e) => {
                eprintln!("stat: {path}: {e}");
                rc = 1;
            }
        }
    }
    rc
}
