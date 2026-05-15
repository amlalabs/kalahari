# Platform-Native IPC Transports

Future direction: replace the current fd-centric doorbell/aux model with
platform-native primitives that avoid forcing both OSes into the same
abstraction.

## Current state

Both Linux and macOS use an AF_UNIX STREAM socketpair as the doorbell and
a generic `DoorbellSend`/`DoorbellRecv` trait pair designed around async
executor integration (epoll/kqueue readiness → tokio `AsyncFd`).

Aux transport already diverges: Linux uses SEQPACKET + SCM_RIGHTS, macOS
uses Mach messages with port descriptors. But both are wired through the
same `Sender<D,A>`/`Receiver<D,A>` generic in `channel.rs`, which assumes
the hot path lives on a tokio executor.

Problems with current approach:

- Doorbell kick can WOULDBLOCK on the STREAM socket; we swallow it
  (fire-and-forget) which is correct but relies on a subtle invariant.
- macOS `wait_kick` needs a 1ms timeout hack to work around kqueue
  edge-triggered event loss.
- macOS `send_slots` (Mach msg) blocks the tokio executor because
  Mach ports can't be polled for write-readiness.
- Sequence numbers are written to the doorbell but never read.

## Target state

### Linux: eventfd doorbell

Replace the STREAM socketpair doorbell with a pair of eventfds (one per
direction). eventfd is purpose-built for counted notifications:

- `write()` adds to a 64-bit counter (only WOULDBLOCK at u64::MAX)
- `read()` returns and resets the counter
- Native epoll/`AsyncFd` integration — no hacks needed
- No sequence number accumulation in a socket buffer

Bootstrap still uses the STREAM socketpair (needed for SCM_RIGHTS to send
the memfd + SEQPACKET fd to the child). After bootstrap, the doorbell
switches to eventfd.

Create two eventfds before fork (clear CLOEXEC on the child's ends, or
pass them via SCM_RIGHTS in the bootstrap message). Each IPC direction
gets its own eventfd — fully unidirectional, no shared-buffer concerns.

Aux transport (SEQPACKET + SCM_RIGHTS) stays the same. It already works
well with async writable-await.

### macOS: os_eventlink + dispatch_source

Two independent changes:

#### Doorbell: os_eventlink (private libdispatch SPI)

`os_eventlink` is a paired, counted signaling primitive backed by a Mach
kernel eventlink object (`IKOT_EVENTLINK`). Key properties:

- `signal_and_wait()` is a single syscall that atomically signals the
  peer and blocks waiting for their response.
- The kernel performs **direct thread handoff** through the scheduler
  fast-path — no run queue, no kqueue wakeup latency.
- Cross-process: activate on parent, extract remote Mach port, send to
  child, child creates endpoint with `os_eventlink_create_with_port()`.
- Optional shared-memory fast path: map `os_eventlink_shared_data_s`
  (`{local_count, remote_count}`) in the existing shared memory region.
  When the peer isn't blocked, signaling is just an atomic increment —
  zero syscalls.

Since eventlink is not pollable (no `EVFILT_*`, no fd), the IPC hot path
moves off the tokio executor onto a **dedicated thread per channel**:

```
[IPC thread A]                                [IPC thread B]
write to ring
signal_and_wait(ev) ───direct handoff───>     wake, read ring
                                              process, write response
                    <───direct handoff───     signal_and_wait(ev)
wake, read response
```

Bridge to tokio via `tokio::sync::mpsc` for the outer VM/hypervisor layer
that issues IPC requests from async contexts.

API surface (all in `os/eventlink_private.h`):

- `os_eventlink_create(name)` / `os_eventlink_activate(ev)`
- `os_eventlink_extract_remote_port(ev, &port)`
- `os_eventlink_create_with_port(name, port)`
- `os_eventlink_associate(ev, options)` — bind current thread
- `os_eventlink_signal(ev)` / `os_eventlink_wait(ev, &count)`
- `os_eventlink_signal_and_wait(ev, &count)` — the hot-path operation
- `os_eventlink_set_shared_data(ev, data)` — optional zero-syscall mode

#### Aux transport: dispatch_source for Mach port recv

Replace blocking `mach_msg(MACH_RCV_MSG, TIMEOUT_NONE)` in `recv_slots`
with GCD-bridged async receive:

```
dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, recv_port, 0, queue)
  -> handler: tokio::sync::Notify::notify_one()

// tokio side
notify.notified().await;
mach_msg(MACH_RCV_MSG | MACH_RCV_TIMEOUT, timeout=0, ..);
```

For sends, use `mach_msg(MACH_SEND_MSG | MACH_SEND_TIMEOUT, timeout=0)`.
If queue-full (rare), fall back to `MACH_SEND_NOTIFY` with a notification
port monitored by another dispatch_source.

This is independent of the eventlink change and can be done first.

## Architecture impact

The `channel.rs` generic `Sender<D,A>`/`Receiver<D,A>` with async trait
bounds assumes the IPC loop runs on a tokio executor. The eventlink
architecture moves the macOS hot path to dedicated threads with
`signal_and_wait`, so the trait abstraction no longer fits both platforms.

Options:

1. **Platform-specific channel impls**: `channel.rs` becomes a thin
   dispatch layer. Linux keeps the current async `Sender`/`Receiver`.
   macOS gets a thread-based impl where `send()`/`recv()` post to the
   IPC thread via mpsc and await the response.
2. **Shared async interface, platform-specific internals**: Keep the
   async `send()`/`recv()` API but macOS internally spawns the IPC
   thread and bridges through it. The traits stay the same; only the
   platform module changes.

Option 2 is less invasive. The public API stays `sender.send(msg).await`
/ `receiver.recv().await` regardless of platform.

## Sequencing

1. Linux eventfd doorbell (low risk, drop-in replacement for socketpair)
2. macOS dispatch_source for aux recv (unblocks tokio executor)
3. macOS os_eventlink doorbell + dedicated thread (bigger refactor)
4. Remove socketpair doorbell code, clean up sequence number plumbing
