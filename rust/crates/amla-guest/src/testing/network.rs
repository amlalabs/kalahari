//! Network test mode — eth0 setup, gateway reachability, URL fetch.

use super::{TestRunner, cmdline_param, kmsg, run_cmd, setup_network, sysfs_exists};

pub fn run() {
    let mut t = TestRunner::new("NETWORK TEST");

    // Test 1: Network interface exists
    if sysfs_exists("/sys/class/net/eth0") {
        kmsg("NETIF:PASS");
        t.pass("netif", "eth0");
    } else {
        kmsg("NETIF:FAIL (no eth0)");
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let ifaces: Vec<_> = entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            kmsg(&format!("NET_IFACES:{}", ifaces.join(",")));
        }
        t.fail("netif", "no eth0");
    }

    // Test 2: Static network config via netlink
    if setup_network() {
        t.pass("dhcp", "");
    } else {
        t.fail("dhcp", "");
    }

    // Test 3: Gateway reachability (TCP connect probe to port 80)
    let Ok(gateway_addr) = "10.0.2.2:80".parse::<std::net::SocketAddr>() else {
        kmsg("GATEWAY_PING:FAIL (bad addr)");
        t.fail("gateway_ping", "bad addr");
        t.finish();
    };
    let gateway_reachable =
        std::net::TcpStream::connect_timeout(&gateway_addr, std::time::Duration::from_secs(2))
            .is_ok();
    if gateway_reachable {
        kmsg("GATEWAY_PING:PASS");
        t.pass("gateway_ping", "");
    } else {
        let (ping_ok, _) = run_cmd(
            "/bin/amla-guest",
            &["ping", "-c", "1", "-W", "2", "10.0.2.2"],
        );
        if ping_ok {
            kmsg("GATEWAY_PING:PASS");
            t.pass("gateway_ping", "");
        } else {
            kmsg("GATEWAY_PING:FAIL");
            t.fail("gateway_ping", "");
        }
    }

    // Test 4: URL fetch (if provided)
    let net_test_url = cmdline_param("net_test_url").ok().flatten();
    let net_no_verify = cmdline_param("net_no_verify").ok().flatten().as_deref() == Some("1");

    if let Some(url) = &net_test_url {
        kmsg(&format!("TEST_URL:{url}"));

        if net_no_verify {
            kmsg("TLS_VERIFY:disabled");
        }

        let is_https = url.starts_with("https://");

        kmsg("FETCH_CLIENT:amla-guest");
        let (fetch_ok, response) = if is_https {
            run_cmd("/bin/amla-guest", &["https-get", url])
        } else {
            run_cmd("/bin/amla-guest", &["wget", "-qO-", url])
        };

        if fetch_ok {
            kmsg("FETCH:PASS");
            if response.contains("ECHO_RESPONSE:OK") {
                kmsg("ECHO_RESPONSE:OK");
            }
            t.pass("fetch", "");
        } else {
            kmsg("FETCH:FAIL");
            let truncated: String = response.chars().take(500).collect();
            kmsg(&format!("FETCH_OUTPUT:{truncated}"));
            t.fail("fetch", "");
        }
    } else {
        kmsg("TEST_URL:SKIP (no net_test_url specified)");
        t.skip("fetch", "no URL");
    }

    // Summary
    if t.has_failures() {
        kmsg("NETWORK_TEST:FAIL");
    } else {
        kmsg("NETWORK_TEST:PASS");
    }

    t.finish();
}
