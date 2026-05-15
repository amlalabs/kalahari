// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Park/resume network continuity tests.

#[path = "../../amla-vm-vmm/tests/common/mod.rs"]
mod common;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use amla_constants::net::{DEFAULT_GATEWAY, DEFAULT_GUEST_MAC};
use amla_core::backends::NetBackend;
use amla_usernet::interceptor::{
    BoxFuture, LocalServiceHandler, LocalSocket, TcpConnectionPolicy, TcpFlow, TcpOpenAction,
};
use amla_usernet::{UserNetBackend, UserNetConfig};
use amla_vm_scheduler::{
    CollectedOutput, CommandExecutionHandle, ConsoleStream, LiveShellLimit, MemHandle, NetConfig,
    NetworkSession, Parked, VirtualMachine, VmBackends, VmConfig, VmScheduler,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RESPONSE_BODY: &str = "PARK_RESUME_OK\n";
const LOCAL_SERVICE_BODY: &str = "LOCAL_SERVICE_PARK_RESUME_OK\n";
const EGRESS_RESPONSE: &str = "EGRESS_UPLOAD_OK\n";
const EGRESS_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const EGRESS_PARK_AFTER_BYTES: usize = 64 * 1024;
const EGRESS_CHUNK_BYTES: usize = 4096;
const EGRESS_CHUNK_DELAY_US: u64 = 1000;

struct ParkedResponseServer {
    handle: std::thread::JoinHandle<()>,
    host_ip: Ipv4Addr,
    port: u16,
    accepted: tokio::sync::oneshot::Receiver<()>,
    release_response: mpsc::Sender<()>,
    response_sent: tokio::sync::oneshot::Receiver<()>,
}

struct ParkedEgressServer {
    handle: std::thread::JoinHandle<()>,
    host_ip: Ipv4Addr,
    port: u16,
    first_bytes: tokio::sync::oneshot::Receiver<usize>,
    release_read: mpsc::Sender<()>,
    upload_done: tokio::sync::oneshot::Receiver<usize>,
}

fn start_parked_response_server() -> ParkedResponseServer {
    let host_ip = common::get_host_ip();
    let listener = TcpListener::bind((host_ip, 0u16)).expect("bind parked response HTTP server");
    let port = listener.local_addr().unwrap().port();
    let (accepted_tx, accepted) = tokio::sync::oneshot::channel();
    let (release_response, release_rx) = mpsc::channel();
    let (sent_tx, response_sent) = tokio::sync::oneshot::channel();

    let handle = std::thread::spawn(move || {
        let (mut stream, addr) = listener.accept().expect("accept guest HTTP connection");
        eprintln!("park server: accepted connection from {addr}");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("set read timeout");

        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = stream.read(&mut buf).expect("read guest HTTP request");
            assert_ne!(n, 0, "guest closed connection before sending request");
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            accepted_tx.send(()).is_ok(),
            "parked response test stopped before server accepted request"
        );

        release_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("test released parked response");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{RESPONSE_BODY}",
            RESPONSE_BODY.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write parked response");
        stream.flush().expect("flush parked response");
        assert!(
            sent_tx.send(()).is_ok(),
            "parked response test stopped before server sent response"
        );
    });

    ParkedResponseServer {
        handle,
        host_ip,
        port,
        accepted,
        release_response,
        response_sent,
    }
}

fn start_parked_egress_server(total_bytes: usize, park_after: usize) -> ParkedEgressServer {
    let host_ip = common::get_host_ip();
    let listener = TcpListener::bind((host_ip, 0u16)).expect("bind parked egress TCP server");
    let port = listener.local_addr().unwrap().port();
    let (first_tx, first_bytes) = tokio::sync::oneshot::channel();
    let (release_read, release_rx) = mpsc::channel();
    let (done_tx, upload_done) = tokio::sync::oneshot::channel();

    let handle = std::thread::spawn(move || {
        let (mut stream, addr) = listener.accept().expect("accept guest upload connection");
        eprintln!("egress server: accepted connection from {addr}");
        stream
            .set_read_timeout(Some(Duration::from_mins(1)))
            .expect("set egress read timeout");

        let mut total_read = 0usize;
        let mut first_tx = Some(first_tx);
        let mut buf = [0u8; 8192];
        while total_read < total_bytes {
            let n = stream.read(&mut buf).expect("read guest upload");
            assert_ne!(n, 0, "guest closed upload before sending all bytes");
            verify_upload_pattern(&buf[..n], total_read);
            total_read += n;

            if total_read >= park_after
                && let Some(first_tx) = first_tx.take()
            {
                assert!(
                    first_tx.send(total_read).is_ok(),
                    "egress test stopped before initial upload bytes arrived"
                );
                release_rx
                    .recv_timeout(Duration::from_secs(20))
                    .expect("test released parked upload reader");
            }
        }

        stream
            .write_all(EGRESS_RESPONSE.as_bytes())
            .expect("write egress response");
        stream.flush().expect("flush egress response");
        assert!(
            done_tx.send(total_read).is_ok(),
            "egress test stopped before upload completed"
        );
    });

    ParkedEgressServer {
        handle,
        host_ip,
        port,
        first_bytes,
        release_read,
        upload_done,
    }
}

fn verify_upload_pattern(bytes: &[u8], base: usize) {
    for (index, byte) in bytes.iter().copied().enumerate() {
        let Ok(expected) = u8::try_from((base + index) % 251) else {
            unreachable!("modulo 251 always fits in u8");
        };
        assert_eq!(byte, expected, "bad upload byte at offset {}", base + index);
    }
}

fn scheduler_with_limit(limit: usize) -> VmScheduler {
    VmScheduler::new(
        LiveShellLimit::try_from(limit).unwrap(),
        common::worker_config(),
    )
}

type ParkedNetworkVm<N> = VirtualMachine<Parked<amla_fuse::NullFsBackend, NetworkSession<N>>>;

fn network_vm_config(image: &MemHandle) -> VmConfig {
    common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(DEFAULT_GUEST_MAC))
}

async fn load_network_vm<N>(
    scheduler: &VmScheduler,
    network: N,
    image: MemHandle,
    label: &'static str,
) -> ParkedNetworkVm<N>
where
    N: NetBackend,
{
    let config = network_vm_config(&image);
    let vm = scheduler
        .create_vm(
            config,
            VmBackends::new(ConsoleStream::new())
                .with_pmem(vec![image])
                .with_net(network),
        )
        .await
        .expect("create VM");
    vm.load_kernel(common::kernel()).await.expect(label)
}

async fn resume_and_collect_network_command<N>(
    parked: ParkedNetworkVm<N>,
    cmd_handle: CommandExecutionHandle,
    timeout: Duration,
    label: &'static str,
) -> CollectedOutput
where
    N: NetBackend,
{
    let cmd_id = cmd_handle.id();
    let (_parked, output) = parked
        .run(async move |mut vm| {
            vm.attach(cmd_handle).unwrap();
            let mut vm = vm.start();
            let mut cmd = vm.take_attached(cmd_id).expect("reattached command");
            tokio::time::timeout(timeout, cmd.collect_output())
                .await
                .expect("reattached command timed out")
                .expect("collect reattached command")
        })
        .await
        .expect(label);
    output
}

struct LocalServiceControl {
    accepted: tokio::sync::oneshot::Receiver<()>,
    release_response: tokio::sync::oneshot::Sender<()>,
    response_sent: tokio::sync::oneshot::Receiver<()>,
}

struct DeferredLocalServicePolicy {
    service_addr: SocketAddr,
    accepted: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release_response: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    response_sent: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl DeferredLocalServicePolicy {
    fn new(service_addr: SocketAddr) -> (Arc<Self>, LocalServiceControl) {
        let (accepted_tx, accepted) = tokio::sync::oneshot::channel();
        let (release_response, release_rx) = tokio::sync::oneshot::channel();
        let (sent_tx, response_sent) = tokio::sync::oneshot::channel();

        (
            Arc::new(Self {
                service_addr,
                accepted: Mutex::new(Some(accepted_tx)),
                release_response: Mutex::new(Some(release_rx)),
                response_sent: Mutex::new(Some(sent_tx)),
            }),
            LocalServiceControl {
                accepted,
                release_response,
                response_sent,
            },
        )
    }
}

impl TcpConnectionPolicy for DeferredLocalServicePolicy {
    fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction {
        if flow.remote_addr != self.service_addr {
            return TcpOpenAction::NoOpinion;
        }

        let accepted = self
            .accepted
            .lock()
            .unwrap()
            .take()
            .expect("local service should be opened once");
        let release_response = self
            .release_response
            .lock()
            .unwrap()
            .take()
            .expect("local service release receiver should be opened once");
        let response_sent = self
            .response_sent
            .lock()
            .unwrap()
            .take()
            .expect("local service response sender should be opened once");

        TcpOpenAction::LocalService(Box::new(DeferredHttpService {
            accepted,
            release_response,
            response_sent,
        }))
    }
}

struct DeferredHttpService {
    accepted: tokio::sync::oneshot::Sender<()>,
    release_response: tokio::sync::oneshot::Receiver<()>,
    response_sent: tokio::sync::oneshot::Sender<()>,
}

impl LocalServiceHandler for DeferredHttpService {
    fn handle(self: Box<Self>, mut socket: LocalSocket) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = socket
                    .read(&mut buf)
                    .await
                    .expect("read guest local-service HTTP request");
                assert_ne!(
                    n, 0,
                    "guest closed local-service connection before sending request"
                );
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(
                self.accepted.send(()).is_ok(),
                "local-service test stopped before request was accepted"
            );
            self.release_response
                .await
                .expect("test released local-service response");

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{LOCAL_SERVICE_BODY}",
                LOCAL_SERVICE_BODY.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write local-service response");
            socket
                .shutdown()
                .await
                .expect("shutdown local-service response");
            assert!(
                self.response_sent.send(()).is_ok(),
                "local-service test stopped before response was sent"
            );
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn parked_vm_preserves_live_tcp_connection_and_wakes_scheduler_on_response() {
    drop(env_logger::builder().is_test(true).try_init());

    if common::skip() {
        return;
    }

    let server = start_parked_response_server();
    let url = format!("http://{}:{}/parked", server.host_ip, server.port);

    let scheduler = scheduler_with_limit(1);
    let image = common::rootfs_handle();
    let usernet = UserNetBackend::try_new(
        UserNetConfig::try_default()
            .unwrap()
            .with_unrestricted_egress(),
    )
    .unwrap();
    let ready = load_network_vm(&scheduler, usernet, image, "load network VM").await;

    let (ready, cmd_handle) = ready
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "wget", "-qO-", &url])
                .await
                .expect("start guest wget");
            tokio::time::timeout(Duration::from_secs(30), server.accepted)
                .await
                .expect("server did not see guest request")
                .expect("server accepted sender dropped");
            cmd.into_handle()
                .expect("in-flight wget should be reattachable before response")
        })
        .await
        .expect("run until guest request is in flight");

    let parked = ready;
    let network = parked.backends().net().expect("scheduler owns network");
    let _stale_rx_wake = network.take_rx_wake();

    server
        .release_response
        .send(())
        .expect("release parked response");
    tokio::time::timeout(Duration::from_secs(10), server.response_sent)
        .await
        .expect("server did not write response while VM was parked")
        .expect("response-sent sender dropped");
    tokio::time::timeout(Duration::from_secs(10), network.wait_for_rx())
        .await
        .expect("network session did not wake scheduler while VM was parked");

    let output = resume_and_collect_network_command(
        parked,
        cmd_handle,
        Duration::from_secs(30),
        "run resumed VM to wget completion",
    )
    .await;

    assert_eq!(output.exit_code, 0, "wget failed: {output:?}");
    assert!(
        output.stdout_str().contains(RESPONSE_BODY),
        "guest did not receive parked response: {output:?}"
    );

    server.handle.join().expect("server thread");
}

#[tokio::test(flavor = "multi_thread")]
async fn parked_vm_preserves_live_tcp_connection_while_guest_egress_is_incomplete() {
    drop(env_logger::builder().is_test(true).try_init());

    if common::skip() {
        return;
    }

    let mut server = start_parked_egress_server(EGRESS_TOTAL_BYTES, EGRESS_PARK_AFTER_BYTES);
    let host_arg = server.host_ip.to_string();
    let port_arg = server.port.to_string();
    let total_arg = EGRESS_TOTAL_BYTES.to_string();
    let chunk_arg = EGRESS_CHUNK_BYTES.to_string();
    let delay_arg = EGRESS_CHUNK_DELAY_US.to_string();

    let scheduler = scheduler_with_limit(1);
    let image = common::rootfs_handle();
    let usernet = UserNetBackend::try_new(
        UserNetConfig::try_default()
            .unwrap()
            .with_unrestricted_egress(),
    )
    .unwrap();
    let ready = load_network_vm(&scheduler, usernet, image, "load egress VM").await;

    let (ready, cmd_handle) = ready
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec([
                    "/bin/amla-guest",
                    "tcp-upload",
                    &host_arg,
                    &port_arg,
                    &total_arg,
                    &chunk_arg,
                    &delay_arg,
                ])
                .await
                .expect("start guest tcp-upload");
            let initial_bytes = tokio::time::timeout(Duration::from_secs(30), server.first_bytes)
                .await
                .expect("server did not see guest upload bytes")
                .expect("egress first-bytes sender dropped");
            assert!(
                (EGRESS_PARK_AFTER_BYTES..EGRESS_TOTAL_BYTES).contains(&initial_bytes),
                "expected partial upload before park, got {initial_bytes}/{EGRESS_TOTAL_BYTES}"
            );
            cmd.into_handle()
                .expect("in-flight tcp-upload should be reattachable before upload completes")
        })
        .await
        .expect("run until guest upload is in flight");

    let parked = ready;

    server.release_read.send(()).expect("release upload reader");
    let completed_while_parked =
        tokio::time::timeout(Duration::from_millis(150), &mut server.upload_done).await;
    assert!(
        completed_while_parked.is_err(),
        "upload completed while VM was parked; test did not catch mid-egress state"
    );

    let output = resume_and_collect_network_command(
        parked,
        cmd_handle,
        Duration::from_mins(1),
        "run resumed VM to upload completion",
    )
    .await;

    let total_read = tokio::time::timeout(Duration::from_secs(10), &mut server.upload_done)
        .await
        .expect("server did not finish upload after resume")
        .expect("egress upload-done sender dropped");
    assert_eq!(total_read, EGRESS_TOTAL_BYTES);
    assert_eq!(output.exit_code, 0, "tcp-upload failed: {output:?}");
    assert!(
        output.stdout_str().contains(EGRESS_RESPONSE),
        "guest did not receive upload response: {output:?}"
    );

    server.handle.join().expect("egress server thread");
}

#[tokio::test(flavor = "multi_thread")]
async fn parked_vm_preserves_local_service_connection_and_wakes_scheduler_on_response() {
    drop(env_logger::builder().is_test(true).try_init());

    if common::skip() {
        return;
    }

    let service_addr = SocketAddr::new(IpAddr::V4(DEFAULT_GATEWAY), 8080);
    let (policy, control) = DeferredLocalServicePolicy::new(service_addr);
    let url = format!("http://{DEFAULT_GATEWAY}:8080/local");

    let scheduler = scheduler_with_limit(1);
    let image = common::rootfs_handle();
    let usernet =
        UserNetBackend::try_new_with_tcp_policy(UserNetConfig::try_default().unwrap(), policy)
            .unwrap();
    let ready = load_network_vm(&scheduler, usernet, image, "load local-service VM").await;

    let (ready, cmd_handle) = ready
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "wget", "-qO-", &url])
                .await
                .expect("start local-service guest wget");
            tokio::time::timeout(Duration::from_secs(30), control.accepted)
                .await
                .expect("local service did not see guest request")
                .expect("local-service accepted sender dropped");
            cmd.into_handle()
                .expect("in-flight local-service wget should be reattachable before response")
        })
        .await
        .expect("run until local-service request is in flight");

    let parked = ready;
    let network = parked.backends().net().expect("scheduler owns network");
    let _stale_rx_wake = network.take_rx_wake();

    control
        .release_response
        .send(())
        .expect("release local-service response");
    tokio::time::timeout(Duration::from_secs(10), control.response_sent)
        .await
        .expect("local service did not write response while VM was parked")
        .expect("local-service response sender dropped");
    tokio::time::timeout(Duration::from_secs(10), network.wait_for_rx())
        .await
        .expect("local-service network session did not wake scheduler while VM was parked");

    let output = resume_and_collect_network_command(
        parked,
        cmd_handle,
        Duration::from_secs(30),
        "run resumed local-service VM to wget completion",
    )
    .await;

    assert_eq!(output.exit_code, 0, "local-service wget failed: {output:?}");
    assert!(
        output.stdout_str().contains(LOCAL_SERVICE_BODY),
        "guest did not receive parked local-service response: {output:?}"
    );
}
