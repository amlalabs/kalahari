//! OCI runtime config parsing and container helpers.
//!
//! Parses the OCI runtime spec format (`/process/args`, `/process/user`, etc.).
//! The host converts Docker image configs to this format at import time
//! (see `amla_oci::runtime_config`).
//!
//! Used by both `init` (reads config from argv) and `exec` (reads from state dir).

use std::ffi::CString;

/// Parsed OCI runtime process configuration.
pub struct OciConfig {
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub uid: u32,
    pub gid: u32,
    /// Unresolved named user (e.g. `"nobody"`). Set when the OCI config
    /// has a `username` field that couldn't be resolved at import time.
    /// Call [`resolve_named_user`] after entering the container's mount
    /// namespace to resolve this via `/etc/passwd`.
    pub unresolved_user: Option<String>,
}

/// Parse an OCI runtime config JSON string.
///
/// If `process.user.username` is set (named user that couldn't be resolved
/// at import time), looks up `/etc/passwd` to resolve uid/gid. Call this
/// after `pivot_root` so the container's passwd file is available.
#[allow(clippy::cast_possible_truncation)]
pub fn parse_oci_config(json: &str) -> Result<OciConfig, String> {
    let spec: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("parse config json: {e}"))?;

    let process = spec.get("process");

    let args = process
        .and_then(|p| p.get("args"))
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let env = process
        .and_then(|p| p.get("env"))
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Treat missing *or* empty `cwd` as `/`. The host normalizes at import,
    // but defensively re-check here so pre-existing metadata.json files
    // (written before the host-side fix) still boot.
    let cwd = process
        .and_then(|p| p.get("cwd"))
        .and_then(|c| c.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string();

    let user = process.and_then(|p| p.get("user"));
    let uid = user
        .and_then(|u| u.get("uid"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as u32;
    let gid = user
        .and_then(|u| u.get("gid"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as u32;
    let unresolved_user = user
        .and_then(|u| u.get("username"))
        .and_then(|u| u.as_str())
        .map(String::from);

    Ok(OciConfig {
        args,
        env,
        cwd,
        uid,
        gid,
        unresolved_user,
    })
}

/// Resolve the `unresolved_user` field via `/etc/passwd` and `/etc/group`.
///
/// Call this after entering the container's mount namespace (e.g. after
/// `pivot_root` or `setns(CLONE_NEWNS)`).
pub fn resolve_named_user(config: &mut OciConfig) -> Result<(), String> {
    if let Some(username) = config.unresolved_user.take() {
        let (uid, gid) = resolve_username(&username)?;
        config.uid = uid;
        config.gid = gid;
    }
    Ok(())
}

/// Resolve a username string (e.g. `"nobody"` or `"nobody:nogroup"`)
/// via `/etc/passwd` and `/etc/group`.
///
/// Numeric parts (e.g. `"1000:nogroup"`) are used directly without lookup.
fn resolve_username(user: &str) -> Result<(u32, u32), String> {
    if let Some((user_part, group_part)) = user.split_once(':') {
        let uid = match user_part.parse::<u32>() {
            Ok(n) => n,
            Err(_) => lookup_passwd_uid(user_part)?,
        };
        let gid = match group_part.parse::<u32>() {
            Ok(n) => n,
            Err(_) => lookup_group_gid(group_part)?,
        };
        Ok((uid, gid))
    } else {
        lookup_passwd_user(user)
    }
}

/// Look up a username in `/etc/passwd`, returning (uid, gid).
fn lookup_passwd_user(username: &str) -> Result<(u32, u32), String> {
    let data = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| format!("failed to read /etc/passwd: {e}"))?;
    for line in data.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next() else {
            continue;
        };
        if name != username {
            continue;
        }
        let _password = fields.next();
        let uid_str = fields
            .next()
            .ok_or_else(|| format!("malformed /etc/passwd entry for {username:?}: missing uid"))?;
        let uid: u32 = uid_str.parse().map_err(|e| {
            format!("malformed uid {uid_str:?} for {username:?} in /etc/passwd: {e}")
        })?;
        let gid_str = fields
            .next()
            .ok_or_else(|| format!("malformed /etc/passwd entry for {username:?}: missing gid"))?;
        let gid: u32 = gid_str.parse().map_err(|e| {
            format!("malformed gid {gid_str:?} for {username:?} in /etc/passwd: {e}")
        })?;
        return Ok((uid, gid));
    }
    Err(format!("user {username:?} not found in /etc/passwd"))
}

/// Look up a username in `/etc/passwd`, returning just the uid.
fn lookup_passwd_uid(username: &str) -> Result<u32, String> {
    lookup_passwd_user(username).map(|(uid, _)| uid)
}

/// Look up the home directory for a uid in `/etc/passwd` (field 6).
pub fn lookup_home_dir(uid: u32) -> Result<String, String> {
    let data = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| format!("failed to read /etc/passwd: {e}"))?;
    for line in data.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        // passwd format: name:password:uid:gid:gecos:home:shell
        if fields.len() >= 6 && fields[2].parse::<u32>() == Ok(uid) {
            let home = fields[5];
            if home.is_empty() {
                return Err(format!("uid {uid} has empty home directory in /etc/passwd"));
            }
            return Ok(home.to_string());
        }
    }
    Err(format!("uid {uid} not found in /etc/passwd"))
}

/// Look up a group name in `/etc/group`, returning the gid.
fn lookup_group_gid(groupname: &str) -> Result<u32, String> {
    let data = std::fs::read_to_string("/etc/group")
        .map_err(|e| format!("failed to read /etc/group: {e}"))?;
    for line in data.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next() else {
            continue;
        };
        if name != groupname {
            continue;
        }
        let _password = fields.next();
        let gid_str = fields
            .next()
            .ok_or_else(|| format!("malformed /etc/group entry for {groupname:?}: missing gid"))?;
        let gid: u32 = gid_str.parse().map_err(|e| {
            format!("malformed gid {gid_str:?} for {groupname:?} in /etc/group: {e}")
        })?;
        return Ok(gid);
    }
    Err(format!("group {groupname:?} not found in /etc/group"))
}

/// Validate a container name (no path separators, not empty, not `.`/`..`).
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name == "."
        || name == ".."
    {
        return Err(format!("invalid container name: {name:?}"));
    }
    Ok(())
}

/// Convert a `&str` to `CString`, panicking on interior NUL.
#[allow(clippy::expect_used)]
pub fn cstr(s: &str) -> CString {
    CString::new(s).expect("CString from &str with no interior NUL")
}
