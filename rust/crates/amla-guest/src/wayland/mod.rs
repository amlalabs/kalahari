//! Minimal Wayland compositor for guest display.
//!
//! Serves Chrome as a single Wayland client. Extracts damage rects + pixels
//! from `wl_shm` buffers on commit, LZ4-compresses them. Input events from
//! the host are injected as Wayland pointer/keyboard events to Chrome via
//! the compositor (not via virtio-input/evdev).

#![allow(clippy::similar_names)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]

mod handlers;
pub mod wire;

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;

use wayland_server::backend::{ClientId, ObjectId};
use wayland_server::protocol::wl_buffer::WlBuffer;
use wayland_server::protocol::wl_callback::WlCallback;
use wayland_server::protocol::wl_keyboard::WlKeyboard;
use wayland_server::protocol::wl_output::WlOutput;
use wayland_server::protocol::wl_pointer::WlPointer;
use wayland_server::protocol::wl_surface::WlSurface;
use wayland_server::{Display, ListeningSocket, Resource};

use wire::Rect;

// ─── Public types ────────────────────────────────────────────────────────

/// Input event from the host, injected into the Wayland compositor.
#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    /// Pointer moved to (x, y) in surface coordinates.
    PointerMotion { x: f64, y: f64 },
    /// Pointer button pressed/released (Linux BTN_* code).
    PointerButton { button: u32, pressed: bool },
    /// Scroll axis event.
    PointerAxis { axis: u32, value: f64 },
    /// Key pressed/released (Linux keycode).
    Key { keycode: u32, pressed: bool },
}

// ─── Internal state ──────────────────────────────────────────────────────

pub struct ShmPool {
    pub fd: OwnedFd,
    pub size: usize,
    pub mmap: *mut u8,
    /// Number of live buffers referencing this pool.
    pub buffer_count: u32,
    /// Client sent `wl_shm_pool.destroy` — remove when `buffer_count` hits 0.
    pub destroyed: bool,
}

// SAFETY: ShmPool is only accessed from the single compositor thread/task.
unsafe impl Send for ShmPool {}
// SAFETY: see `Send` impl above — ShmPool is compositor-thread-local, so
// `&ShmPool` is never actually shared across threads.
unsafe impl Sync for ShmPool {}

/// mmap a shared fd as read-only. Returns the mapped pointer.
fn mmap_shared_ro(fd: &OwnedFd, size: usize) -> Result<*mut u8, &'static str> {
    // SAFETY: null addr lets the kernel choose; `fd` is borrowed valid OwnedFd;
    // `size` is the requested mapping length; flags are valid.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err("mmap failed");
    }
    Ok(ptr.cast())
}

impl ShmPool {
    pub fn new(fd: OwnedFd, size: usize) -> Result<Self, &'static str> {
        let mmap = mmap_shared_ro(&fd, size)?;
        Ok(Self {
            fd,
            size,
            mmap,
            buffer_count: 0,
            destroyed: false,
        })
    }

    /// Re-mmap after pool resize. Maps new region before unmapping old
    /// to avoid a dangling pointer if the new mmap fails.
    pub fn resize(&mut self, new_size: usize) -> Result<(), &'static str> {
        let new_mmap = mmap_shared_ro(&self.fd, new_size)?;
        // SAFETY: `self.mmap` was returned by the previous mmap_shared_ro with
        // `self.size`; we own this mapping and are replacing it.
        unsafe {
            libc::munmap(self.mmap.cast(), self.size);
        }
        self.mmap = new_mmap;
        self.size = new_size;
        Ok(())
    }
}

impl Drop for ShmPool {
    fn drop(&mut self) {
        // SAFETY: `self.mmap`/`self.size` are the mapping returned by
        // mmap_shared_ro; the ShmPool uniquely owns it until drop.
        unsafe {
            libc::munmap(self.mmap.cast(), self.size);
        }
    }
}

#[derive(Debug, Clone)]
pub struct BufferMeta {
    pub pool_id: ObjectId,
    pub offset: i32,
    pub width: i32,
    pub height: i32,
    pub stride: i32,
    /// `wl_shm` format: 0 = ARGB8888 (has alpha), 1 = XRGB8888 (no alpha).
    pub format: u32,
}

#[derive(Default)]
pub struct SurfaceState {
    /// `None` = no attach this commit. `Some(None)` = attach null (unmap).
    /// `Some(Some(buf))` = attach buffer.
    #[allow(clippy::option_option)] // Three-state: no-op / unmap / attach.
    pub pending_buffer: Option<Option<WlBuffer>>,
    pub pending_damage: Vec<Rect>,
    pub frame_callbacks: Vec<WlCallback>,
    pub committed_buffer: Option<WlBuffer>,
    pub xdg_surface: Option<wayland_protocols::xdg::shell::server::xdg_surface::XdgSurface>,
    pub xdg_toplevel: Option<wayland_protocols::xdg::shell::server::xdg_toplevel::XdgToplevel>,
    /// Position in the compositor's framebuffer (0,0 for toplevel).
    pub x: i32,
    pub y: i32,
    /// Parent surface (for subsurfaces — position is relative to parent).
    pub parent: Option<ObjectId>,
    /// Snapshot of committed pixels — safe to read after buffer release.
    /// Recompositing reads from this, not live SHM (which Chrome may reuse).
    pub pixel_snapshot: Vec<u8>,
    pub snap_width: i32,
    pub snap_height: i32,
    pub snap_stride: usize,
    /// True if ARGB8888 (has real alpha). False if XRGB8888 (alpha undefined).
    pub snap_has_alpha: bool,
}

/// Positioner data for popup placement.
#[derive(Default, Clone)]
pub struct PositionerData {
    pub width: i32,
    pub height: i32,
    pub anchor_x: i32,
    pub anchor_y: i32,
    pub anchor_w: i32,
    pub anchor_h: i32,
    /// XDG anchor edge (bitmask: 1=top, 2=bottom, 4=left, 8=right).
    pub anchor: u32,
    /// XDG gravity (bitmask: same as anchor).
    pub gravity: u32,
    pub offset_x: i32,
    pub offset_y: i32,
}

impl PositionerData {
    /// Compute popup position using the XDG positioner algorithm.
    pub const fn compute_position(&self) -> (i32, i32) {
        // Step 1: anchor point on the anchor rect.
        let ax = if self.anchor & 4 != 0 {
            self.anchor_x // left
        } else if self.anchor & 8 != 0 {
            self.anchor_x + self.anchor_w // right
        } else {
            self.anchor_x + self.anchor_w / 2 // center
        };
        let ay = if self.anchor & 1 != 0 {
            self.anchor_y // top
        } else if self.anchor & 2 != 0 {
            self.anchor_y + self.anchor_h // bottom
        } else {
            self.anchor_y + self.anchor_h / 2 // center
        };

        // Step 2: apply gravity (direction popup extends from anchor).
        let mut x = if self.gravity & 4 != 0 {
            ax - self.width // grows left
        } else if self.gravity & 8 != 0 {
            ax // grows right
        } else {
            ax - self.width / 2 // centered
        };
        let mut y = if self.gravity & 1 != 0 {
            ay - self.height // grows up
        } else if self.gravity & 2 != 0 {
            ay // grows down
        } else {
            ay - self.height / 2 // centered
        };

        // Step 3: apply offset.
        x += self.offset_x;
        y += self.offset_y;

        // No constraint step — position is parent-relative, and Chrome
        // handles its own popup repositioning. Constraining against output
        // dimensions would be wrong without the parent's absolute position.

        (x, y)
    }
}

// ─── State (separate from Compositor to avoid self-referential borrow) ───

/// The Wayland protocol state — passed to `Display::dispatch_clients()`.
/// Separated from `Compositor` because `Display<State>` is a field of
/// `Compositor` and `dispatch_clients` needs `&mut State`.
/// Per-client input state. Each Wayland client gets its own pointer/keyboard
/// objects — they must never be mixed across clients.
pub struct ClientInput {
    pub pointer: Option<WlPointer>,
    pub keyboard: Option<WlKeyboard>,
    pub pointer_entered: bool,
    /// The surface that currently has keyboard focus (kb.enter was sent for it).
    /// None = keyboard not entered on any surface.
    pub keyboard_focus: Option<ObjectId>,
}

pub struct State {
    /// Pending output frames (populated by `handle_commit`, drained by caller).
    pub pending_frames: Vec<Vec<u8>>,
    pub output_width: u32,
    pub output_height: u32,
    pub serial: u32,
    pub surfaces: HashMap<ObjectId, SurfaceState>,
    /// Input objects per client — prevents cross-client object panics.
    pub clients: HashMap<ClientId, ClientInput>,
    /// Keyboard focus — the surface receiving key events.
    pub focused_surface: Option<WlSurface>,
    /// Pointer focus — the surface currently under the pointer (for motion/button/axis).
    pub pointer_surface: Option<WlSurface>,
    /// Last known pointer position in global/output coordinates.
    pub pointer_x: f64,
    pub pointer_y: f64,
    pub outputs: Vec<WlOutput>,
    /// `xdg_surface` ID → `wl_surface` it wraps.
    pub xdg_surface_map: HashMap<ObjectId, WlSurface>,
    /// `wl_subsurface` ID → `wl_surface` it wraps.
    pub subsurface_map: HashMap<ObjectId, WlSurface>,
    /// `wl_surface` `ObjectId` → `WlSurface` protocol object (for reverse lookup from hit-test).
    pub wl_surface_map: HashMap<ObjectId, WlSurface>,
    /// Surfaces used as cursors — skip in `handle_commit`.
    pub cursor_surfaces: HashSet<ObjectId>,
    /// Positioner data for popup placement.
    pub positioners: HashMap<ObjectId, PositionerData>,
    pub shm_pools: HashMap<ObjectId, ShmPool>,
    pub buffers: HashMap<ObjectId, BufferMeta>,
    pub keyframe_requested: bool,
    /// The primary toplevel surface — its dimensions drive the framebuffer size.
    pub primary_toplevel: Option<ObjectId>,
    /// Surface z-order, back to front (toplevel first, popups on top).
    pub z_order: Vec<ObjectId>,
    /// Canonical framebuffer — composited output of all surfaces.
    pub framebuffer: Vec<u8>,
    /// Previous framebuffer state for delta comparison.
    pub prev_framebuffer: Vec<u8>,
    pub fb_width: u32,
    pub fb_height: u32,
    pub fb_stride: usize,
    pub fb_format: u8,
}

/// Blit a surface's pixel snapshot into a framebuffer, clipped to `clip`.
/// Free function to allow disjoint borrows (&mut framebuffer + &surface).
fn blit_to_framebuffer(
    framebuffer: &mut [u8],
    fb_stride: usize,
    surface: &SurfaceState,
    sx: i32,
    sy: i32,
    clip: &Rect,
) {
    let pixels = &surface.pixel_snapshot;
    if pixels.is_empty() {
        return;
    }
    let src_stride = surface.snap_stride;
    let surf_w = surface.snap_width;
    let surf_h = surface.snap_height;
    let has_alpha = surface.snap_has_alpha;

    let x0 = sx.max(clip.x);
    let y0 = sy.max(clip.y);
    let x1 = (sx + surf_w).min(clip.x + clip.w);
    let y1 = (sy + surf_h).min(clip.y + clip.h);
    if x0 >= x1 || y0 >= y1 {
        return;
    }

    let w = (x1 - x0) as usize;
    for row in y0..y1 {
        let src_off = ((row - sy) as usize) * src_stride + ((x0 - sx) as usize) * 4;
        let dst_off = (row as usize) * fb_stride + (x0 as usize) * 4;
        let len = w * 4;
        if src_off + len > pixels.len() || dst_off + len > framebuffer.len() {
            continue;
        }
        if has_alpha {
            // Premultiplied alpha: dst = src + dst * (255 - src_a) / 255
            for col in 0..w {
                let s = src_off + col * 4;
                let d = dst_off + col * 4;
                let a = u32::from(pixels[s + 3]);
                if a == 255 {
                    framebuffer[d..d + 4].copy_from_slice(&pixels[s..s + 4]);
                } else if a > 0 {
                    let inv = 255 - a;
                    for c in 0..3 {
                        let sc = u32::from(pixels[s + c]);
                        let dc = u32::from(framebuffer[d + c]);
                        framebuffer[d + c] = (sc + (dc * inv + 127) / 255).min(255) as u8;
                    }
                    framebuffer[d + 3] = 255;
                }
            }
        } else {
            framebuffer[dst_off..dst_off + len].copy_from_slice(&pixels[src_off..src_off + len]);
        }
    }
}

impl State {
    /// Hit-test: find the topmost surface at global coordinates (x, y).
    /// Walks z-order front-to-back (reverse) and returns the first surface
    /// whose bounds contain the point, along with surface-local coordinates.
    pub fn surface_at(&self, gx: f64, gy: f64) -> Option<(ObjectId, f64, f64)> {
        for sid in self.z_order.iter().rev() {
            if self.cursor_surfaces.contains(sid) {
                continue;
            }
            let Some(surface) = self.surfaces.get(sid) else {
                continue;
            };
            if surface.pixel_snapshot.is_empty() {
                continue;
            }
            let (sx, sy) = self.resolve_position(sid);
            let sw = f64::from(surface.snap_width);
            let sh = f64::from(surface.snap_height);
            let local_x = gx - f64::from(sx);
            let local_y = gy - f64::from(sy);
            if local_x >= 0.0 && local_x < sw && local_y >= 0.0 && local_y < sh {
                return Some((sid.clone(), local_x, local_y));
            }
        }
        None
    }

    /// Resolve a surface's absolute position by walking the parent chain.
    #[allow(clippy::assigning_clones)] // pid is moved by the while-let pattern
    fn resolve_position(&self, surface_id: &ObjectId) -> (i32, i32) {
        let Some(surface) = self.surfaces.get(surface_id) else {
            return (0, 0);
        };
        let (mut x, mut y) = (surface.x, surface.y);
        let mut pid = surface.parent.clone();
        while let Some(p) = pid {
            if let Some(parent) = self.surfaces.get(&p) {
                x += parent.x;
                y += parent.y;
                pid = parent.parent.clone();
            } else {
                break;
            }
        }
        (x, y)
    }

    /// Clear a framebuffer region and redraw ALL overlapping surfaces, back to front.
    fn recomposite_region(&mut self, clip: &Rect) {
        // Clamp clip to framebuffer bounds — resolve_position() can produce
        // negative coordinates for off-screen subsurfaces.
        let fb_w = self.fb_width as i32;
        let fb_h = self.fb_height as i32;
        let cx = clip.x.max(0);
        let cy = clip.y.max(0);
        let cw = clip.w.min(fb_w - cx);
        let ch = clip.h.min(fb_h - cy);
        if cw <= 0 || ch <= 0 {
            return;
        }
        let clip = &Rect {
            x: cx,
            y: cy,
            w: cw,
            h: ch,
        };

        let fb_stride = self.fb_stride;
        // Clear to black.
        let x0 = clip.x as usize;
        let y0 = clip.y as usize;
        let x1 = (clip.x + clip.w) as usize;
        let y1 = (clip.y + clip.h) as usize;
        for row in y0..y1 {
            let off = row * fb_stride + x0 * 4;
            let len = (x1 - x0) * 4;
            if off + len <= self.framebuffer.len() {
                self.framebuffer[off..off + len].fill(0);
            }
        }
        // Redraw all surfaces in z-order. Disjoint borrows:
        // &mut self.framebuffer + &self.surfaces (different fields).
        let z_order = self.z_order.clone();
        for sid in &z_order {
            if self.cursor_surfaces.contains(sid) {
                continue;
            }
            let (sx, sy) = self.resolve_position(sid);
            if let Some(surface) = self.surfaces.get(sid) {
                blit_to_framebuffer(&mut self.framebuffer, fb_stride, surface, sx, sy, clip);
            }
        }
    }

    /// Handle a surface commit: recomposite damaged regions, encode tiles.
    #[allow(clippy::too_many_lines)]
    pub fn handle_commit(&mut self, surface_id: &ObjectId) {
        if self.cursor_surfaces.contains(surface_id) {
            return;
        }

        // Phase 1: update surface buffer state + snapshot pixels.
        {
            let Some(surface) = self.surfaces.get_mut(surface_id) else {
                return;
            };
            let mut unmapped = false;
            if let Some(attach) = surface.pending_buffer.take() {
                if let Some(buf) = attach {
                    if let Some(old) = surface.committed_buffer.replace(buf) {
                        old.release();
                    }
                } else {
                    // Attach null = unmap.
                    if let Some(old) = surface.committed_buffer.take() {
                        old.release();
                    }
                    surface.pixel_snapshot.clear();
                    unmapped = true;
                }
            }
            if unmapped {
                self.handle_surface_unmapped(surface_id);
                return;
            }
            let buffer_id = match &surface.committed_buffer {
                Some(buf) => buf.id(),
                None => return,
            };
            // Snapshot pixels from SHM before releasing the buffer.
            if let Some(meta) = self.buffers.get(&buffer_id).cloned()
                && let Some(pool) = self.shm_pools.get(&meta.pool_id)
            {
                let data_len = (meta.stride * meta.height) as usize;
                if meta.offset >= 0 && (meta.offset as usize) + data_len <= pool.size {
                    // SAFETY: offset+data_len ≤ pool.size (checked above); `pool.mmap`
                    // is a live PROT_READ mapping of `pool.size` bytes so the slice
                    // range is valid for reads.
                    let src = unsafe {
                        std::slice::from_raw_parts(pool.mmap.add(meta.offset as usize), data_len)
                    };
                    surface.pixel_snapshot.clear();
                    surface.pixel_snapshot.extend_from_slice(src);
                    surface.snap_width = meta.width;
                    surface.snap_height = meta.height;
                    surface.snap_stride = meta.stride as usize;
                    surface.snap_has_alpha = meta.format == 0;
                }
            }
            // Note: buffer is released when replaced (line 388-389) or unmapped
            // (line 394-395). We don't take() here because damage-only commits
            // (no new attach) still need committed_buffer to be present.
        }

        // O(n) but n is Chrome's surface count (~5-30). Not worth a HashSet.
        if !self.z_order.contains(surface_id) {
            self.z_order.push(surface_id.clone());
        }

        // Phase 2: get surface metadata from snapshot.
        let (damage, pixel_format) = {
            let surface = &self.surfaces[surface_id];
            if surface.pixel_snapshot.is_empty() {
                return;
            }
            let pixel_format = wire::FORMAT_BGRA; // Wayland ARGB8888/XRGB8888
            let damage = if surface.pending_damage.is_empty() {
                vec![Rect {
                    x: 0,
                    y: 0,
                    w: surface.snap_width,
                    h: surface.snap_height,
                }]
            } else {
                surface.pending_damage.clone()
            };
            (damage, pixel_format)
        };

        if let Some(surface) = self.surfaces.get_mut(surface_id) {
            surface.pending_damage.clear();
        }

        // Phase 3: resize framebuffer for the primary toplevel.
        // The first toplevel becomes primary; its buffer size drives the FB.
        // Additional toplevels (DevTools, new windows) composite at (0,0)
        // clipped to the existing framebuffer bounds.
        {
            let surface = &self.surfaces[surface_id];
            let is_primary = self
                .primary_toplevel
                .as_ref()
                .is_some_and(|id| id == surface_id);
            if is_primary || (surface.xdg_toplevel.is_some() && self.primary_toplevel.is_none()) {
                if self.primary_toplevel.is_none() {
                    self.primary_toplevel = Some(surface_id.clone());
                }
                let tw = surface.snap_width as u32;
                let th = surface.snap_height as u32;
                if tw > 0
                    && th > 0
                    && (self.fb_width != tw || self.fb_height != th || self.framebuffer.is_empty())
                {
                    let fb_len = tw as usize * th as usize * 4;
                    self.framebuffer.resize(fb_len, 0);
                    self.prev_framebuffer.resize(fb_len, 0);
                    self.fb_width = tw;
                    self.fb_height = th;
                    self.fb_stride = tw as usize * 4;
                    self.fb_format = pixel_format;
                    self.keyframe_requested = true;
                }
            }
        }

        if self.framebuffer.is_empty() {
            return;
        }

        let fb_w = self.fb_width as i32;
        let fb_h = self.fb_height as i32;

        // Phase 4: convert surface-local damage to global coords,
        // recomposite each damaged region from scratch.
        let (surf_x, surf_y) = self.resolve_position(surface_id);
        let mut fb_damage = Vec::new();
        for rect in &damage {
            let gx = (surf_x + rect.x.max(0)).max(0);
            let gy = (surf_y + rect.y.max(0)).max(0);
            let gw = rect.w.min(fb_w - gx);
            let gh = rect.h.min(fb_h - gy);
            if gw <= 0 || gh <= 0 {
                continue;
            }
            let global_rect = Rect {
                x: gx,
                y: gy,
                w: gw,
                h: gh,
            };
            self.recomposite_region(&global_rect);
            fb_damage.push(global_rect);
        }

        if fb_damage.is_empty() {
            return;
        }

        // Phase 5: encode changed tiles (delta vs prev_framebuffer).
        // Keyframe: expand damage to full framebuffer so browser gets complete frame.
        let is_keyframe = if self.keyframe_requested {
            self.keyframe_requested = false;
            fb_damage.clear();
            fb_damage.push(Rect {
                x: 0,
                y: 0,
                w: fb_w,
                h: fb_h,
            });
            true
        } else {
            false
        };

        let fb_stride = self.fb_stride;
        let mut encoded_tiles = Vec::new();
        let prev = if is_keyframe {
            None
        } else {
            Some(self.prev_framebuffer.as_slice())
        };
        for rect in &fb_damage {
            encoded_tiles.extend(wire::encode_region_tiles(
                &self.framebuffer,
                prev,
                rect,
                fb_stride,
            ));
        }

        // Sync prev_framebuffer.
        for rect in &fb_damage {
            for row in 0..rect.h as usize {
                let off = (rect.y as usize + row) * fb_stride + rect.x as usize * 4;
                let len = rect.w as usize * 4;
                if off + len <= self.framebuffer.len() {
                    self.prev_framebuffer[off..off + len]
                        .copy_from_slice(&self.framebuffer[off..off + len]);
                }
            }
        }

        if encoded_tiles.is_empty() {
            return;
        }

        let flags = if is_keyframe { wire::FLAG_KEYFRAME } else { 0 };
        let mut buf = Vec::new();
        wire::write_header(
            &mut buf,
            flags,
            self.fb_width as u16,
            self.fb_height as u16,
            self.fb_format,
            encoded_tiles.len() as u16,
        );
        for tile in &encoded_tiles {
            wire::write_tile(&mut buf, tile);
        }

        let compressed = lz4_flex::compress_prepend_size(&buf);
        self.pending_frames.push(compressed);
    }

    /// A surface was unmapped (null buffer attached) — recomposite its region.
    fn handle_surface_unmapped(&mut self, surface_id: &ObjectId) {
        let bounds = self.surfaces.get(surface_id).and_then(|s| {
            if s.snap_width == 0 || s.snap_height == 0 {
                return None;
            }
            let (x, y) = self.resolve_position(surface_id);
            Some(Rect {
                x,
                y,
                w: s.snap_width,
                h: s.snap_height,
            })
        });

        self.z_order.retain(|id| id != surface_id);

        if let Some(rect) = bounds
            && !self.framebuffer.is_empty()
        {
            self.recomposite_region(&rect);
            self.send_damage(&rect);
        }
    }

    /// A surface was destroyed — recomposite the region it occupied.
    pub fn handle_surface_destroyed(&mut self, surface_id: &ObjectId) {
        // Get bounds from snapshot before removing.
        let bounds = self.surfaces.get(surface_id).and_then(|s| {
            if s.pixel_snapshot.is_empty() {
                return None;
            }
            let (x, y) = self.resolve_position(surface_id);
            Some(Rect {
                x,
                y,
                w: s.snap_width,
                h: s.snap_height,
            })
        });

        self.surfaces.remove(surface_id);
        self.z_order.retain(|id| id != surface_id);
        self.cursor_surfaces.remove(surface_id);
        if self.primary_toplevel.as_ref() == Some(surface_id) {
            self.primary_toplevel = None;
        }
        self.xdg_surface_map.retain(|_, v| v.id() != *surface_id);
        self.subsurface_map.retain(|_, v| v.id() != *surface_id);

        // Recomposite the region this surface occupied.
        if let Some(rect) = bounds
            && !self.framebuffer.is_empty()
        {
            self.recomposite_region(&rect);
            self.send_damage(&rect);
        }
    }

    /// Encode a damaged region and queue for output.
    fn send_damage(&mut self, rect: &Rect) {
        // Clamp rect to framebuffer bounds — damage can extend beyond the
        // surface (e.g. negative position from resolve_position).
        let fb_w = self.fb_width as i32;
        let fb_h = self.fb_height as i32;
        let x = rect.x.max(0);
        let y = rect.y.max(0);
        let w = rect.w.min(fb_w - x);
        let h = rect.h.min(fb_h - y);
        if w <= 0 || h <= 0 {
            return;
        }
        let rect = &Rect { x, y, w, h };

        let fb_stride = self.fb_stride;
        let encoded_tiles = wire::encode_region_tiles(&self.framebuffer, None, rect, fb_stride);

        // Sync prev.
        for row in 0..rect.h as usize {
            let off = (rect.y as usize + row) * fb_stride + rect.x as usize * 4;
            let len = rect.w as usize * 4;
            if off + len <= self.framebuffer.len() {
                self.prev_framebuffer[off..off + len]
                    .copy_from_slice(&self.framebuffer[off..off + len]);
            }
        }

        if encoded_tiles.is_empty() {
            return;
        }

        let mut buf = Vec::new();
        wire::write_header(
            &mut buf,
            0,
            self.fb_width as u16,
            self.fb_height as u16,
            self.fb_format,
            encoded_tiles.len() as u16,
        );
        for tile in &encoded_tiles {
            wire::write_tile(&mut buf, tile);
        }
        let compressed = lz4_flex::compress_prepend_size(&buf);
        self.pending_frames.push(compressed);
    }

    /// Send a keyframe from the internal framebuffer. No SHM lookup needed.
    /// If framebuffer is empty (no commits yet), defers to next commit.
    fn send_keyframe(&mut self) {
        if self.framebuffer.is_empty() {
            self.keyframe_requested = true;
            return;
        }

        // Sync prev so subsequent deltas work correctly.
        self.prev_framebuffer.resize(self.framebuffer.len(), 0);
        self.prev_framebuffer.copy_from_slice(&self.framebuffer);

        // Encode full surface as tiles (raw + solid fill detection).
        let full_rect = wire::Rect {
            x: 0,
            y: 0,
            w: self.fb_width as i32,
            h: self.fb_height as i32,
        };
        let encoded_tiles =
            wire::encode_region_tiles(&self.framebuffer, None, &full_rect, self.fb_stride);

        let mut buf = Vec::new();
        wire::write_header(
            &mut buf,
            wire::FLAG_KEYFRAME,
            self.fb_width as u16,
            self.fb_height as u16,
            self.fb_format,
            encoded_tiles.len() as u16,
        );
        for tile in &encoded_tiles {
            wire::write_tile(&mut buf, tile);
        }

        let compressed = lz4_flex::compress_prepend_size(&buf);
        self.pending_frames.push(compressed);
    }
}

// ─── Compositor ──────────────────────────────────────────────────────────

/// Minimal Wayland compositor.
///
/// Runs in amla-init's synchronous poll loop. Call [`Compositor::poll_fd`]
/// and [`Compositor::listen_fd`] to get fds for your `poll(2)` set.
pub struct Compositor {
    display: Display<State>,
    listening_socket: ListeningSocket,
    state: State,
}

impl Compositor {
    /// Create a new compositor, bind to socket, register Wayland globals.
    ///
    /// # Errors
    ///
    /// Returns an error if the Wayland display or socket cannot be created.
    pub fn new(socket_path: &str) -> Result<Self, &'static str> {
        let display: Display<State> =
            Display::new().map_err(|_| "failed to create wayland display")?;
        let dh = display.handle();

        dh.create_global::<State, wayland_server::protocol::wl_compositor::WlCompositor, _>(6, ());
        dh.create_global::<State, wayland_server::protocol::wl_shm::WlShm, _>(1, ());
        dh.create_global::<State, wayland_server::protocol::wl_output::WlOutput, _>(2, ());
        dh.create_global::<State, wayland_server::protocol::wl_seat::WlSeat, _>(5, ());
        dh.create_global::<State, wayland_server::protocol::wl_data_device_manager::WlDataDeviceManager, _>(3, ());
        dh.create_global::<State, wayland_protocols::xdg::shell::server::xdg_wm_base::XdgWmBase, _>(1, ());
        dh.create_global::<State, wayland_server::protocol::wl_subcompositor::WlSubcompositor, _>(
            1,
            (),
        );

        // Stale sockets from a prior compositor would block bind_absolute();
        // NotFound is the expected happy path on a fresh XDG runtime dir.
        if let Err(e) = std::fs::remove_file(socket_path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("compositor: remove stale {socket_path}: {e}");
        }
        let listening_socket = ListeningSocket::bind_absolute(socket_path.into())
            .map_err(|_| "failed to bind wayland socket")?;

        // Make socket world-accessible
        if let Err(e) =
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o777))
        {
            eprintln!("compositor: set_permissions {socket_path}: {e}");
        }

        eprintln!("compositor: listening on {socket_path}");

        Ok(Self {
            display,
            listening_socket,
            state: State {
                pending_frames: Vec::new(),
                output_width: 1280,
                output_height: 720,
                serial: 0,
                surfaces: HashMap::new(),
                clients: HashMap::new(),
                focused_surface: None,
                pointer_surface: None,
                pointer_x: 0.0,
                pointer_y: 0.0,
                outputs: Vec::new(),
                xdg_surface_map: HashMap::new(),
                subsurface_map: HashMap::new(),
                wl_surface_map: HashMap::new(),
                cursor_surfaces: HashSet::new(),
                positioners: HashMap::new(),
                shm_pools: HashMap::new(),
                buffers: HashMap::new(),
                keyframe_requested: false,
                primary_toplevel: None,
                z_order: Vec::new(),
                framebuffer: Vec::new(),
                prev_framebuffer: Vec::new(),
                fb_width: 0,
                fb_height: 0,
                fb_stride: 0,
                fb_format: 0,
            },
        })
    }

    /// File descriptor of the listening socket (for poll).
    pub fn listen_fd(&self) -> BorrowedFd<'_> {
        self.listening_socket.as_fd()
    }

    /// File descriptor of the display backend (for poll).
    pub fn poll_fd(&mut self) -> BorrowedFd<'_> {
        self.display.backend().poll_fd()
    }

    /// Accept a pending client connection.
    pub fn accept(&self) {
        match self.listening_socket.accept() {
            Ok(Some(stream)) => {
                if let Err(e) = self
                    .display
                    .handle()
                    .insert_client(stream, std::sync::Arc::new(()))
                {
                    eprintln!("failed to insert wayland client: {e}");
                } else {
                    eprintln!("wayland client connected");
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("wayland accept error: {e}"),
        }
    }

    /// Drain pending output frames (populated by `wl_surface.commit`).
    pub fn drain_frames(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.state.pending_frames)
    }

    /// Dispatch pending Wayland client messages.
    pub fn dispatch(&mut self) {
        self.display.dispatch_clients(&mut self.state).ok();
        self.display.flush_clients().ok();
    }

    /// Inject an input event from the host into the Wayland client.
    pub fn inject_input(&mut self, event: InputEvent) {
        let time = monotonic_ms();
        match event {
            InputEvent::PointerMotion { x, y } => {
                self.state.pointer_x = x;
                self.state.pointer_y = y;
                self.handle_pointer_motion(time, x, y);
            }
            InputEvent::PointerButton { button, pressed } => {
                self.handle_pointer_button(time, button, pressed);
            }
            InputEvent::PointerAxis { axis, value } => {
                self.handle_pointer_axis(time, axis, value);
            }
            InputEvent::Key { keycode, pressed } => {
                self.handle_key(time, keycode, pressed);
            }
        }
        self.display.flush_clients().ok();
    }

    /// Ensure keyboard focus is on the given surface. Sends leave/enter as needed.
    fn ensure_keyboard_focus(&mut self, target: &WlSurface) {
        let target_id = target.id();
        let Some(client) = target.client() else {
            return;
        };
        let Some(input) = self.state.clients.get_mut(&client.id()) else {
            return;
        };
        // Already focused on this surface — nothing to do.
        if input.keyboard_focus.as_ref() == Some(&target_id) {
            return;
        }
        let kb = match &input.keyboard {
            Some(kb) => kb.clone(),
            None => return,
        };
        // Leave the old surface (if any, and if it belongs to this client).
        if let Some(old_id) = input.keyboard_focus.take()
            && let Some(old_surf) = self.state.wl_surface_map.get(&old_id)
        {
            self.state.serial += 1;
            kb.leave(self.state.serial, old_surf);
        }
        // Enter the new surface.
        self.state.serial += 1;
        kb.enter(self.state.serial, target, vec![]);
        self.state.serial += 1;
        kb.modifiers(self.state.serial, 0, 0, 0, 0);
        input.keyboard_focus = Some(target_id);
    }

    /// Update pointer focus via hit-testing and send motion to the surface under the pointer.
    fn handle_pointer_motion(&mut self, time: u32, gx: f64, gy: f64) {
        let hit = self.state.surface_at(gx, gy);

        // Determine new pointer surface and surface-local coords.
        let (new_surface, local_x, local_y) = match &hit {
            Some((sid, lx, ly)) => {
                let wl = self.state.wl_surface_map.get(sid).cloned();
                (wl, *lx, *ly)
            }
            None => (None, 0.0, 0.0),
        };

        let old_id = self
            .state
            .pointer_surface
            .as_ref()
            .map(wayland_server::Resource::id);
        let new_id = new_surface.as_ref().map(wayland_server::Resource::id);

        if old_id != new_id {
            // Pointer left the old surface.
            if let Some(old_surface) = &self.state.pointer_surface
                && let Some(client) = old_surface.client()
                && let Some(input) = self.state.clients.get_mut(&client.id())
            {
                if let Some(ptr) = &input.pointer {
                    self.state.serial += 1;
                    ptr.leave(self.state.serial, old_surface);
                    ptr.frame();
                }
                input.pointer_entered = false;
            }

            // Pointer entered the new surface.
            if let Some(new_surf) = &new_surface
                && let Some(client) = new_surf.client()
                && let Some(input) = self.state.clients.get_mut(&client.id())
                && let Some(ptr) = &input.pointer
            {
                self.state.serial += 1;
                ptr.enter(self.state.serial, new_surf, local_x, local_y);
                input.pointer_entered = true;
                ptr.frame();
            }

            self.state.pointer_surface = new_surface;
        } else if let Some(surface) = &self.state.pointer_surface {
            // Same surface — just send motion with surface-local coords.
            if let Some(client) = surface.client()
                && let Some(input) = self.state.clients.get_mut(&client.id())
                && let Some(ptr) = &input.pointer
            {
                if !input.pointer_entered {
                    self.state.serial += 1;
                    ptr.enter(self.state.serial, surface, local_x, local_y);
                    input.pointer_entered = true;
                }
                ptr.motion(time, local_x, local_y);
                ptr.frame();
            }
        }

        // Ensure keyboard focus is on the focused_surface (lazy — first motion
        // after toplevel creation triggers the initial kb.enter).
        if let Some(focused) = &self.state.focused_surface.clone() {
            self.ensure_keyboard_focus(focused);
        }
    }

    /// Handle pointer button — route to pointer surface, update keyboard focus on press.
    fn handle_pointer_button(&mut self, time: u32, button: u32, pressed: bool) {
        // On press, update keyboard focus to the toplevel that owns the pointer surface.
        if pressed && let Some(ptr_surf) = &self.state.pointer_surface {
            let ptr_id = ptr_surf.id();
            // Find the toplevel surface for this pointer surface (could be the
            // surface itself if it's a toplevel, or walk parent chain for popups).
            let focus_target = self.find_toplevel_for(&ptr_id).unwrap_or(ptr_id);
            let new_focus = self
                .state
                .wl_surface_map
                .get(&focus_target)
                .cloned()
                .or_else(|| self.state.pointer_surface.clone());

            if let Some(new_surf) = &new_focus {
                self.state.focused_surface = Some(new_surf.clone());
                self.ensure_keyboard_focus(new_surf);
            }
        }

        // Send button event to the surface under the pointer.
        let surface = match &self.state.pointer_surface {
            Some(s) => s.clone(),
            None => return,
        };
        if let Some(client) = surface.client()
            && let Some(input) = self.state.clients.get_mut(&client.id())
            && let Some(ptr) = &input.pointer
        {
            self.state.serial += 1;
            let s = if pressed {
                wayland_server::protocol::wl_pointer::ButtonState::Pressed
            } else {
                wayland_server::protocol::wl_pointer::ButtonState::Released
            };
            ptr.button(self.state.serial, time, button, s);
            ptr.frame();
        }
    }

    /// Handle scroll axis — route to pointer surface.
    fn handle_pointer_axis(&mut self, time: u32, axis: u32, value: f64) {
        let surface = match &self.state.pointer_surface {
            Some(s) => s.clone(),
            None => return,
        };
        if let Some(client) = surface.client()
            && let Some(input) = self.state.clients.get_mut(&client.id())
            && let Some(ptr) = &input.pointer
        {
            let a = if axis == 0 {
                wayland_server::protocol::wl_pointer::Axis::VerticalScroll
            } else {
                wayland_server::protocol::wl_pointer::Axis::HorizontalScroll
            };
            ptr.axis(time, a, value);
            ptr.frame();
        }
    }

    /// Handle key events — route to keyboard-focused surface.
    fn handle_key(&mut self, time: u32, keycode: u32, pressed: bool) {
        let surface = match &self.state.focused_surface {
            Some(s) => s.clone(),
            None => return,
        };
        // Ensure keyboard is entered on the focused surface before sending keys.
        self.ensure_keyboard_focus(&surface);
        if let Some(client) = surface.client()
            && let Some(input) = self.state.clients.get_mut(&client.id())
            && let Some(kb) = &input.keyboard
        {
            self.state.serial += 1;
            let s = if pressed {
                wayland_server::protocol::wl_keyboard::KeyState::Pressed
            } else {
                wayland_server::protocol::wl_keyboard::KeyState::Released
            };
            kb.key(self.state.serial, time, keycode, s);
        }
    }

    /// Find the toplevel surface that owns the given surface (walking parent chain).
    fn find_toplevel_for(&self, surface_id: &ObjectId) -> Option<ObjectId> {
        let mut current = surface_id.clone();
        for _ in 0..16 {
            if let Some(surface) = self.state.surfaces.get(&current) {
                if surface.xdg_toplevel.is_some() {
                    return Some(current);
                }
                if let Some(parent) = &surface.parent {
                    current = parent.clone();
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
        None
    }

    /// Fire pending frame callbacks for all surfaces.
    /// Call this at ~60fps (every ~16ms) to throttle Chrome's render rate.
    pub fn fire_frame_callbacks(&mut self) {
        let now = monotonic_ms();
        let mut any = false;
        for surface in self.state.surfaces.values_mut() {
            if !surface.frame_callbacks.is_empty() {
                for cb in surface.frame_callbacks.drain(..) {
                    cb.done(now);
                }
                any = true;
            }
        }
        if any {
            self.display.flush_clients().ok();
        }
    }

    /// Request a keyframe (full surface with `FLAG_KEYFRAME`).
    /// Sends immediately if a buffer is committed, defers to next commit if not.
    pub fn request_keyframe(&mut self) {
        self.state.send_keyframe();
    }

    /// Update display size.
    pub fn set_size(&mut self, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        self.state.output_width = width;
        self.state.output_height = height;

        // Notify all bound outputs
        for output in &self.state.outputs {
            output.mode(
                wayland_server::protocol::wl_output::Mode::Current,
                width as i32,
                height as i32,
                60_000,
            );
            output.done();
        }

        // Configure toplevel surfaces only (not popups/subsurfaces).
        for surface in self.state.surfaces.values() {
            if let Some(toplevel) = &surface.xdg_toplevel {
                use wayland_protocols::xdg::shell::server::xdg_toplevel as xt;
                let activated = (xt::State::Activated as u32).to_ne_bytes();
                toplevel.configure(width as i32, height as i32, activated.to_vec());
                if let Some(xdg_surface) = &surface.xdg_surface {
                    self.state.serial += 1;
                    xdg_surface.configure(self.state.serial);
                }
            }
        }
        self.display.flush_clients().ok();
    }
}

#[allow(clippy::cast_possible_truncation)]
fn monotonic_ms() -> u32 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    start.elapsed().as_millis() as u32
}
