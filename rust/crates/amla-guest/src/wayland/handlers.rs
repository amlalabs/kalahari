//! Dispatch and `GlobalDispatch` implementations for all Wayland interfaces.

use std::os::fd::{AsFd, FromRawFd};

#[allow(clippy::wildcard_imports)]
use wayland_server::protocol::*;
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, Resource};

use wayland_protocols::xdg::shell::server::{
    xdg_popup, xdg_positioner, xdg_surface, xdg_toplevel, xdg_wm_base,
};

use super::wire::Rect;
use super::{BufferMeta, ShmPool, State, SurfaceState};

/// No-op `Dispatch` impl for interfaces where we ignore all requests.
macro_rules! noop_dispatch {
    ($($mod:ident :: $iface:ident),* $(,)?) => {
        $(
            impl Dispatch<$mod::$iface, ()> for State {
                fn request(
                    _state: &mut Self,
                    _client: &Client,
                    _resource: &$mod::$iface,
                    _request: $mod::Request,
                    _data: &(),
                    _dhandle: &DisplayHandle,
                    _data_init: &mut DataInit<'_, Self>,
                ) {}
            }
        )*
    };
}

/// `GlobalDispatch` impl that just initializes the resource with no side effects.
macro_rules! simple_global_dispatch {
    ($($mod:ident :: $iface:ident),* $(,)?) => {
        $(
            impl GlobalDispatch<$mod::$iface, ()> for State {
                fn bind(
                    _state: &mut Self,
                    _handle: &DisplayHandle,
                    _client: &Client,
                    resource: New<$mod::$iface>,
                    _global_data: &(),
                    data_init: &mut DataInit<'_, Self>,
                ) {
                    data_init.init(resource, ());
                }
            }
        )*
    };
}

// ─── Bulk no-op impls ────────────────────────────────────────────────────

noop_dispatch!(
    wl_region::WlRegion,
    wl_callback::WlCallback,
    wl_keyboard::WlKeyboard,
    wl_touch::WlTouch,
    wl_data_device::WlDataDevice,
    wl_data_source::WlDataSource,
    wl_data_offer::WlDataOffer,
    xdg_popup::XdgPopup,
);

simple_global_dispatch!(
    wl_compositor::WlCompositor,
    wl_data_device_manager::WlDataDeviceManager,
    wl_subcompositor::WlSubcompositor,
    xdg_wm_base::XdgWmBase,
);

// ─── wl_pointer ─────────────────────────────────────────────────────────

impl Dispatch<wl_pointer::WlPointer, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &wl_pointer::WlPointer,
        request: wl_pointer::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        if let wl_pointer::Request::SetCursor {
            surface: Some(s), ..
        } = request
        {
            state.cursor_surfaces.insert(s.id());
        }
    }
}

// ─── wl_compositor ───────────────────────────────────────────────────────

impl Dispatch<wl_compositor::WlCompositor, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &wl_compositor::WlCompositor,
        request: wl_compositor::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_compositor::Request::CreateSurface { id } => {
                let surface = data_init.init(id, ());
                let obj_id = surface.id();
                state.wl_surface_map.insert(obj_id.clone(), surface);
                state.surfaces.insert(obj_id, SurfaceState::default());
            }
            wl_compositor::Request::CreateRegion { id } => {
                data_init.init(id, ());
            }
            _ => {}
        }
    }
}

// ─── wl_surface ──────────────────────────────────────────────────────────

impl Dispatch<wl_surface::WlSurface, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &wl_surface::WlSurface,
        request: wl_surface::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        let surface_id = resource.id();
        match request {
            wl_surface::Request::Attach { buffer, x: _, y: _ } => {
                if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                    // Some(Some(buf)) = attach buffer, Some(None) = attach null (unmap).
                    surface.pending_buffer = Some(buffer);
                }
            }
            wl_surface::Request::Damage {
                x,
                y,
                width,
                height,
            }
            | wl_surface::Request::DamageBuffer {
                x,
                y,
                width,
                height,
            } => {
                if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                    surface.pending_damage.push(Rect {
                        x,
                        y,
                        w: width,
                        h: height,
                    });
                }
            }
            wl_surface::Request::Frame { callback } => {
                let cb = data_init.init(callback, ());
                if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                    surface.frame_callbacks.push(cb);
                }
            }
            wl_surface::Request::Commit => {
                state.handle_commit(&surface_id);
            }
            wl_surface::Request::SetBufferScale { .. }
            | wl_surface::Request::SetBufferTransform { .. }
            | wl_surface::Request::SetOpaqueRegion { .. }
            | wl_surface::Request::SetInputRegion { .. }
            | wl_surface::Request::Offset { .. } => {}
            wl_surface::Request::Destroy => {
                let was_focused = state
                    .focused_surface
                    .as_ref()
                    .is_some_and(|s| s.id() == surface_id);
                let was_pointer = state
                    .pointer_surface
                    .as_ref()
                    .is_some_and(|s| s.id() == surface_id);
                if was_focused || was_pointer {
                    if let Some(client_id) = resource.client().map(|c| c.id())
                        && let Some(input) = state.clients.get_mut(&client_id)
                    {
                        if was_pointer {
                            input.pointer_entered = false;
                        }
                        if was_focused {
                            input.keyboard_focus = None;
                        }
                    }
                    if was_focused {
                        state.focused_surface = None;
                    }
                    if was_pointer {
                        state.pointer_surface = None;
                    }
                }
                // Clean up wl_surface reverse lookup.
                state.wl_surface_map.remove(&surface_id);
                // Recomposite the region this surface occupied, then remove it.
                state.handle_surface_destroyed(&surface_id);
                // If focused surface was destroyed, focus the next toplevel.
                if was_focused {
                    for surf in state.surfaces.values() {
                        if surf.xdg_toplevel.is_some()
                            && let Some(xdg) = &surf.xdg_surface
                            && let Some(wl) = state.xdg_surface_map.get(&xdg.id())
                        {
                            state.focused_surface = Some(wl.clone());
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

// ─── wl_shm ──────────────────────────────────────────────────────────────

impl GlobalDispatch<wl_shm::WlShm, ()> for State {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<wl_shm::WlShm>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let shm = data_init.init(resource, ());
        shm.format(wl_shm::Format::Argb8888);
        shm.format(wl_shm::Format::Xrgb8888);
    }
}

impl Dispatch<wl_shm::WlShm, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &wl_shm::WlShm,
        request: wl_shm::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        if let wl_shm::Request::CreatePool { id, fd, size } = request {
            let pool_resource = data_init.init(id, ());
            let pool_id = pool_resource.id();
            let Ok(owned_fd) = fd.as_fd().try_clone_to_owned() else {
                eprintln!("shm pool: failed to clone fd");
                return;
            };
            #[allow(clippy::cast_sign_loss)]
            match ShmPool::new(owned_fd, size as usize) {
                Ok(pool) => {
                    state.shm_pools.insert(pool_id, pool);
                }
                Err(e) => {
                    eprintln!("shm pool creation failed: {e}");
                }
            }
        }
    }
}

// ─── wl_shm_pool ─────────────────────────────────────────────────────────

impl Dispatch<wl_shm_pool::WlShmPool, ()> for State {
    #[allow(clippy::cast_sign_loss)]
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &wl_shm_pool::WlShmPool,
        request: wl_shm_pool::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        let pool_id = resource.id();
        match request {
            wl_shm_pool::Request::CreateBuffer {
                id,
                offset,
                width,
                height,
                stride,
                format,
            } => {
                let buffer = data_init.init(id, ());
                state.buffers.insert(
                    buffer.id(),
                    BufferMeta {
                        pool_id: pool_id.clone(),
                        offset,
                        width,
                        height,
                        stride,
                        format: format.into(),
                    },
                );
                if let Some(pool) = state.shm_pools.get_mut(&pool_id) {
                    pool.buffer_count += 1;
                }
            }
            wl_shm_pool::Request::Resize { size } => {
                if let Some(pool) = state.shm_pools.get_mut(&pool_id)
                    && let Err(e) = pool.resize(size as usize)
                {
                    eprintln!("shm pool resize failed: {e}");
                }
            }
            wl_shm_pool::Request::Destroy => {
                let should_remove = if let Some(pool) = state.shm_pools.get_mut(&pool_id) {
                    pool.destroyed = true;
                    pool.buffer_count == 0
                } else {
                    false
                };
                if should_remove {
                    state.shm_pools.remove(&pool_id);
                }
            }
            _ => {}
        }
    }
}

// ─── wl_buffer ───────────────────────────────────────────────────────────

impl Dispatch<wl_buffer::WlBuffer, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &wl_buffer::WlBuffer,
        request: wl_buffer::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        if matches!(request, wl_buffer::Request::Destroy)
            && let Some(meta) = state.buffers.remove(&resource.id())
        {
            // Decrement pool ref count; remove pool if destroyed + no refs.
            if let Some(pool) = state.shm_pools.get_mut(&meta.pool_id) {
                pool.buffer_count = pool.buffer_count.saturating_sub(1);
                if pool.destroyed && pool.buffer_count == 0 {
                    state.shm_pools.remove(&meta.pool_id);
                }
            }
        }
    }
}

// ─── wl_output ───────────────────────────────────────────────────────────

impl GlobalDispatch<wl_output::WlOutput, ()> for State {
    fn bind(
        state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<wl_output::WlOutput>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let output = data_init.init(resource, ());
        output.geometry(
            0,
            0,
            0,
            0,
            wl_output::Subpixel::None,
            "amla".into(),
            "virtual".into(),
            wl_output::Transform::Normal,
        );
        output.mode(
            wl_output::Mode::Current | wl_output::Mode::Preferred,
            state.output_width as i32,
            state.output_height as i32,
            60_000,
        );
        output.scale(1);
        output.done();
        state.outputs.push(output);
    }
}

impl Dispatch<wl_output::WlOutput, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &wl_output::WlOutput,
        request: wl_output::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        if matches!(request, wl_output::Request::Release) {
            state.outputs.retain(|o| o.id() != resource.id());
        }
    }
}

// ─── wl_seat ─────────────────────────────────────────────────────────────

impl GlobalDispatch<wl_seat::WlSeat, ()> for State {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<wl_seat::WlSeat>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let seat = data_init.init(resource, ());
        seat.capabilities(wl_seat::Capability::Pointer | wl_seat::Capability::Keyboard);
        seat.name("default".into());
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for State {
    fn request(
        state: &mut Self,
        client: &Client,
        _resource: &wl_seat::WlSeat,
        request: wl_seat::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        let cid = client.id();
        let input = state.clients.entry(cid).or_insert(super::ClientInput {
            pointer: None,
            keyboard: None,
            pointer_entered: false,
            keyboard_focus: None,
        });
        match request {
            wl_seat::Request::GetPointer { id } => {
                input.pointer = Some(data_init.init(id, ()));
            }
            wl_seat::Request::GetKeyboard { id } => {
                let keyboard = data_init.init(id, ());
                send_keymap(&keyboard);
                keyboard.repeat_info(25, 600);
                input.keyboard = Some(keyboard);
            }
            wl_seat::Request::GetTouch { id } => {
                data_init.init(id, ());
            }
            _ => {}
        }
    }
}

/// Send a compiled US XKB keymap to the keyboard.
///
/// The keymap was compiled from `xkb_keymap_new_from_names(NULL, "us")`
/// via xkbcommon. Chrome reads it with `xkb_keymap_new_from_fd()` which
/// does NOT process `include` directives, so the keymap must be fully
/// self-contained (pre-compiled).
#[allow(clippy::cast_possible_truncation)]
fn send_keymap(keyboard: &wl_keyboard::WlKeyboard) {
    use std::io::{Seek, Write};

    // Compiled US keymap — generated from xkbcommon, ~64KB.
    static KEYMAP: &[u8] = include_bytes!("us-keymap.xkb");

    // SAFETY: `c"keymap"` is a NUL-terminated CStr; flags are valid memfd flags.
    let fd = unsafe {
        libc::memfd_create(
            c"keymap".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        eprintln!("memfd_create for keymap failed");
        return;
    }

    // SAFETY: fd is a valid file descriptor from memfd_create above.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let mut file = std::fs::File::from(owned);

    // Write keymap + null terminator, then seek to start.
    // Wayland protocol requires the size to include the null terminator.
    if file.write_all(KEYMAP).is_err() || file.write_all(&[0]).is_err() {
        eprintln!("keymap write failed");
        return;
    }
    if file.seek(std::io::SeekFrom::Start(0)).is_err() {
        eprintln!("keymap lseek failed");
        return;
    }

    let size = KEYMAP.len() as u32 + 1; // includes null terminator
    let owned = std::os::fd::OwnedFd::from(file);
    keyboard.keymap(wl_keyboard::KeymapFormat::XkbV1, owned.as_fd(), size);
}

// ─── wl_data_device_manager ──────────────────────────────────────────────

impl Dispatch<wl_data_device_manager::WlDataDeviceManager, ()> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &wl_data_device_manager::WlDataDeviceManager,
        request: wl_data_device_manager::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_data_device_manager::Request::CreateDataSource { id } => {
                data_init.init(id, ());
            }
            wl_data_device_manager::Request::GetDataDevice { id, .. } => {
                data_init.init(id, ());
            }
            _ => {}
        }
    }
}

// ─── wl_subcompositor ────────────────────────────────────────────────────

impl Dispatch<wl_subcompositor::WlSubcompositor, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &wl_subcompositor::WlSubcompositor,
        request: wl_subcompositor::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        if let wl_subcompositor::Request::GetSubsurface {
            id,
            surface,
            parent,
        } = request
        {
            let subsurface = data_init.init(id, ());
            state
                .subsurface_map
                .insert(subsurface.id(), surface.clone());
            // Track parent for absolute position computation.
            if let Some(surf) = state.surfaces.get_mut(&surface.id()) {
                surf.parent = Some(parent.id());
            }
        }
    }
}

impl Dispatch<wl_subsurface::WlSubsurface, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &wl_subsurface::WlSubsurface,
        request: wl_subsurface::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_subsurface::Request::SetPosition { x, y } => {
                if let Some(wl_surface) = state.subsurface_map.get(&resource.id())
                    && let Some(surface) = state.surfaces.get_mut(&wl_surface.id())
                {
                    surface.x = x;
                    surface.y = y;
                }
            }
            wl_subsurface::Request::Destroy => {
                if let Some(wl_surface) = state.subsurface_map.remove(&resource.id())
                    && let Some(surface) = state.surfaces.get_mut(&wl_surface.id())
                {
                    surface.parent = None;
                }
            }
            _ => {}
        }
    }
}

// ─── xdg_wm_base ────────────────────────────────────────────────────────

impl Dispatch<xdg_wm_base::XdgWmBase, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &xdg_wm_base::XdgWmBase,
        request: xdg_wm_base::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            xdg_wm_base::Request::GetXdgSurface { id, surface } => {
                let xdg = data_init.init(id, ());
                state.xdg_surface_map.insert(xdg.id(), surface);
            }
            xdg_wm_base::Request::CreatePositioner { id } => {
                data_init.init(id, ());
            }
            _ => {}
        }
    }
}

// ─── xdg_toplevel ────────────────────────────────────────────────────────

impl Dispatch<xdg_toplevel::XdgToplevel, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &xdg_toplevel::XdgToplevel,
        request: xdg_toplevel::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        // Chrome has no window manager — ignore minimize/maximize/fullscreen.
        // On minimize, re-send activated configure to un-minimize immediately.
        if matches!(request, xdg_toplevel::Request::SetMinimized) {
            let activated = (xdg_toplevel::State::Activated as u32).to_ne_bytes();
            resource.configure(
                state.output_width as i32,
                state.output_height as i32,
                activated.to_vec(),
            );
            // Find the xdg_surface for this toplevel and send configure.
            for surface in state.surfaces.values() {
                if surface
                    .xdg_toplevel
                    .as_ref()
                    .is_some_and(|t| t.id() == resource.id())
                {
                    if let Some(xdg_surface) = &surface.xdg_surface {
                        state.serial += 1;
                        xdg_surface.configure(state.serial);
                    }
                    break;
                }
            }
        }
    }
}

// ─── xdg_positioner ──────────────────────────────────────────────────────

impl Dispatch<xdg_positioner::XdgPositioner, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &xdg_positioner::XdgPositioner,
        request: xdg_positioner::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        let pos = state.positioners.entry(resource.id()).or_default();
        match request {
            xdg_positioner::Request::SetSize { width, height } => {
                pos.width = width;
                pos.height = height;
            }
            xdg_positioner::Request::SetAnchorRect {
                x,
                y,
                width,
                height,
            } => {
                pos.anchor_x = x;
                pos.anchor_y = y;
                pos.anchor_w = width;
                pos.anchor_h = height;
            }
            xdg_positioner::Request::SetAnchor { anchor } => {
                pos.anchor = anchor.into();
            }
            xdg_positioner::Request::SetGravity { gravity } => {
                pos.gravity = gravity.into();
            }
            xdg_positioner::Request::SetOffset { x, y } => {
                pos.offset_x = x;
                pos.offset_y = y;
            }
            xdg_positioner::Request::Destroy => {
                state.positioners.remove(&resource.id());
            }
            _ => {}
        }
    }
}

// ─── xdg_surface ─────────────────────────────────────────────────────────

impl Dispatch<xdg_surface::XdgSurface, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &xdg_surface::XdgSurface,
        request: xdg_surface::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            xdg_surface::Request::GetToplevel { id } => {
                let toplevel = data_init.init(id, ());

                let activated = (xdg_toplevel::State::Activated as u32).to_ne_bytes();
                toplevel.configure(
                    state.output_width as i32,
                    state.output_height as i32,
                    activated.to_vec(),
                );
                state.serial += 1;
                resource.configure(state.serial);

                // Look up which wl_surface this xdg_surface wraps.
                let xdg_id = resource.id();
                if let Some(wl_surface) = state.xdg_surface_map.get(&xdg_id) {
                    let surface_id = wl_surface.id();
                    if let Some(surface) = state.surfaces.get_mut(&surface_id) {
                        surface.xdg_surface = Some(resource.clone());
                        surface.xdg_toplevel = Some(toplevel);
                    }
                    // The toplevel surface is the one that should receive input.
                    state.focused_surface = Some(wl_surface.clone());
                }
            }
            xdg_surface::Request::Destroy => {
                state.xdg_surface_map.remove(&resource.id());
            }
            xdg_surface::Request::GetPopup {
                id,
                parent,
                positioner,
            } => {
                let popup = data_init.init(id, ());

                let pos = state
                    .positioners
                    .get(&positioner.id())
                    .cloned()
                    .unwrap_or_default();

                let w = pos.width.max(1);
                let h = pos.height.max(1);
                let (x, y) = pos.compute_position();

                popup.configure(x, y, w, h);
                state.serial += 1;
                resource.configure(state.serial);

                // Set popup position relative to parent. resolve_position
                // walks the parent chain to get absolute framebuffer coords.
                let xdg_id = resource.id();
                if let Some(wl_surface) = state.xdg_surface_map.get(&xdg_id)
                    && let Some(surface) = state.surfaces.get_mut(&wl_surface.id())
                {
                    surface.x = x;
                    surface.y = y;
                    surface.xdg_surface = Some(resource.clone());
                    // Set parent: look up parent xdg_surface → wl_surface.
                    if let Some(parent_xdg) = parent
                        && let Some(parent_wl) = state.xdg_surface_map.get(&parent_xdg.id())
                    {
                        surface.parent = Some(parent_wl.id());
                    }
                }
            }
            _ => {}
        }
    }
}
