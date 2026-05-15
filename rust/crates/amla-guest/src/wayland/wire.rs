//! Tile-based display frame wire format.
//!
//! One message (LZ4-compressed):
//! ```text
//! [u8 version=3]
//! [u8 flags]  (bit 0 = keyframe)
//! [u16 LE surface_width][u16 LE surface_height]
//! [u8 pixel_format (0=RGBA, 1=BGRA)]
//! [u16 LE tile_count]
//! For each tile:
//!   [u16 LE x][u16 LE y][u16 LE w][u16 LE h]
//!   [u8 encoding]
//!     0 = raw pixels (w * h * 4 bytes follow)
//!     1 = solid fill (4 bytes: single pixel value)
//!     2 = XOR delta  (w * h * 4 bytes, XOR against previous frame)
//! ```

/// Wire format version.
pub const VERSION: u8 = 3;

/// Pixel format: BGRA (Wayland `ARGB8888`/`XRGB8888` on little-endian).
pub const FORMAT_BGRA: u8 = 1;

/// Flags: this frame is a keyframe (full surface, sent on connect).
pub const FLAG_KEYFRAME: u8 = 1;

/// Tile encoding: raw pixels.
pub const ENC_RAW: u8 = 0;

/// Tile encoding: solid fill (4 bytes).
pub const ENC_SOLID: u8 = 1;

/// Tile encoding: XOR delta against previous frame.
pub const ENC_DELTA: u8 = 2;

/// A damage rectangle.
#[derive(Debug, Clone, Copy)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// Encoded tile with its encoding type and payload.
pub struct EncodedTile {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    pub encoding: u8,
    pub data: Vec<u8>,
}

/// Write frame header.
#[allow(clippy::cast_possible_truncation)]
pub fn write_header(
    out: &mut Vec<u8>,
    flags: u8,
    surf_w: u16,
    surf_h: u16,
    pixel_format: u8,
    tile_count: u16,
) {
    out.push(VERSION);
    out.push(flags);
    out.extend_from_slice(&surf_w.to_le_bytes());
    out.extend_from_slice(&surf_h.to_le_bytes());
    out.push(pixel_format);
    out.extend_from_slice(&tile_count.to_le_bytes());
}

/// Write a single encoded tile.
pub fn write_tile(out: &mut Vec<u8>, tile: &EncodedTile) {
    out.extend_from_slice(&tile.x.to_le_bytes());
    out.extend_from_slice(&tile.y.to_le_bytes());
    out.extend_from_slice(&tile.w.to_le_bytes());
    out.extend_from_slice(&tile.h.to_le_bytes());
    out.push(tile.encoding);
    out.extend_from_slice(&tile.data);
}

/// Extract tile pixels from a framebuffer, row by row.
///
/// Coordinates must be non-negative and within the framebuffer bounds.
/// Returns zero-filled output if any coordinate is out of range.
pub fn extract_tile(pixels: &[u8], x: i32, y: i32, w: i32, h: i32, stride: usize) -> Vec<u8> {
    // Guard against negative or zero dimensions.
    if x < 0 || y < 0 || w <= 0 || h <= 0 {
        return vec![0u8; w.unsigned_abs() as usize * h.unsigned_abs() as usize * 4];
    }
    let (x, y, w, h) = (x as usize, y as usize, w as usize, h as usize);
    let mut out = Vec::with_capacity(w * h * 4);
    for row in 0..h {
        let off = (y + row) * stride + x * 4;
        let len = w * 4;
        if off + len <= pixels.len() {
            out.extend_from_slice(&pixels[off..off + len]);
        } else {
            out.resize(out.len() + len, 0);
        }
    }
    out
}

/// Check if all pixels in a tile are the same color. Returns the color if so.
pub fn detect_solid(tile_pixels: &[u8]) -> Option<[u8; 4]> {
    if tile_pixels.len() < 4 {
        return None;
    }
    let color: [u8; 4] = [
        tile_pixels[0],
        tile_pixels[1],
        tile_pixels[2],
        tile_pixels[3],
    ];
    if tile_pixels.chunks_exact(4).all(|p| p == color) {
        Some(color)
    } else {
        None
    }
}

/// Tile size used by all encoding paths.
pub const TILE: i32 = 64;

/// Encode a rectangular region of a framebuffer into tiles.
///
/// If `prev` is `Some`, changed tiles use XOR delta encoding (`ENC_DELTA`).
/// If `prev` is `None`, non-solid tiles use raw encoding (`ENC_RAW`).
/// Unchanged tiles (identical to prev) are omitted entirely.
/// Solid-color tiles always use `ENC_SOLID` regardless of mode.
//
// The three-way encoder selection (prev/no-prev × solid/non-solid) is
// expressed naturally as nested `if let Some`. Rewriting to nested
// `Option::map_or` (as clippy::option_if_let_else suggests) inlines
// large struct literals into closures and reads strictly worse here.
#[allow(clippy::cast_possible_truncation, clippy::option_if_let_else)]
pub fn encode_region_tiles(
    framebuffer: &[u8],
    prev: Option<&[u8]>,
    rect: &Rect,
    fb_stride: usize,
) -> Vec<EncodedTile> {
    let mut tiles = Vec::new();
    let mut ty = rect.y;
    while ty < rect.y + rect.h {
        let th = TILE.min(rect.y + rect.h - ty);
        let mut tx = rect.x;
        while tx < rect.x + rect.w {
            let tw = TILE.min(rect.x + rect.w - tx);
            let current = extract_tile(framebuffer, tx, ty, tw, th, fb_stride);

            let tile = if let Some(prev_buf) = prev {
                let previous = extract_tile(prev_buf, tx, ty, tw, th, fb_stride);
                if let Some(delta) = compute_delta(&current, &previous) {
                    if let Some(c) = detect_solid(&current) {
                        Some(EncodedTile {
                            x: tx as u16,
                            y: ty as u16,
                            w: tw as u16,
                            h: th as u16,
                            encoding: ENC_SOLID,
                            data: c.to_vec(),
                        })
                    } else {
                        Some(EncodedTile {
                            x: tx as u16,
                            y: ty as u16,
                            w: tw as u16,
                            h: th as u16,
                            encoding: ENC_DELTA,
                            data: delta,
                        })
                    }
                } else {
                    None // unchanged
                }
            } else {
                // No prev — raw/solid only (keyframe or damage-only).
                Some(if let Some(c) = detect_solid(&current) {
                    EncodedTile {
                        x: tx as u16,
                        y: ty as u16,
                        w: tw as u16,
                        h: th as u16,
                        encoding: ENC_SOLID,
                        data: c.to_vec(),
                    }
                } else {
                    EncodedTile {
                        x: tx as u16,
                        y: ty as u16,
                        w: tw as u16,
                        h: th as u16,
                        encoding: ENC_RAW,
                        data: current,
                    }
                })
            };

            if let Some(t) = tile {
                tiles.push(t);
            }
            tx += TILE;
        }
        ty += TILE;
    }
    tiles
}

/// Compute XOR delta between current and previous tile pixels.
/// Returns None if tiles are identical (all zeros after XOR).
pub fn compute_delta(current: &[u8], previous: &[u8]) -> Option<Vec<u8>> {
    let delta: Vec<u8> = current
        .iter()
        .zip(previous.iter())
        .map(|(c, p)| c ^ p)
        .collect();
    if delta.iter().all(|&b| b == 0) {
        None // unchanged
    } else {
        Some(delta)
    }
}
