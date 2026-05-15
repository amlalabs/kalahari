// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! TCP connection proxy for NAT.
//!
//! Guest-facing TCP is terminated by smoltcp sockets. This module only bridges
//! byte streams between those sockets and host/interceptor transports.

mod task;

pub use task::InboundStream;
pub use task::{
    GuestPacket, HostConnectAccess, InboundTarget, TcpConnectionHandle, TcpConnectionMode,
    TcpStackConfig, inbound_tcp_task, tcp_connection_task,
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum data to buffer from guest before applying backpressure
const MAX_GUEST_BUFFER: usize = 4 * 1024 * 1024; // 4MB

/// Maximum service/interceptor data to hold toward the guest.
const MAX_GUEST_BOUND_BUFFER: usize = 4 * 1024 * 1024; // 4MB

/// Fixed per-flow smoltcp send/receive buffers.
pub const TCP_SOCKET_BUFFER: usize = 256 * 1024;

/// Fixed smoltcp memory per TCP flow: one receive and one transmit buffer.
pub const TCP_FIXED_BUFFER_BYTES: usize = 2 * TCP_SOCKET_BUFFER;

/// Timeout for connection establishment
const CONNECT_TIMEOUT_SECS: u64 = 30;

/// Keep TIME-WAIT flows alive briefly so late duplicate FINs are `ACKed`.
const TIME_WAIT_CLEANUP_SECS: u64 = 2;

/// Bound FIN-WAIT-2 half-closed tasks if the guest never sends FIN.
const FIN_WAIT2_TIMEOUT_SECS: u64 = 60;
