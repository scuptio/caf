//! Guest-side helpers for CAF WASM components.
//!
//! This crate is the guest half of `doc/spec/caf-abi.md`: it declares the
//! host ABI (`caf.*` imports), provides the `alloc`/`dealloc` memory bridge,
//! and packs results as `(ptr | len << 32)` values. Depend on it from a
//! `cdylib` component built for `wasm32-unknown-unknown`; on any other target
//! it compiles but the host imports are never linked.

// ---------------------------------------------------------------------------
// Host ABI: a minimal, read-only payload filesystem plus meta I/O. The host
// (native runtime or browser) implements these against the .caf file; the
// component never sees raw offsets or container details. The imports exist
// only on wasm32; host-target stubs fail closed so the crate compiles
// everywhere (they are never linked into a real host binary).
// ---------------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
mod ffi {
    #[link(wasm_import_module = "caf")]
    unsafe extern "C" {
        pub fn open(path_ptr: u32, path_len: u32) -> i32;
        pub fn read(fd: i32, buf_ptr: u32, buf_len: u32) -> i32;
        pub fn readdir(path_ptr: u32, path_len: u32, buf_ptr: u32, buf_len: u32) -> i32;
        pub fn stat(path_ptr: u32, path_len: u32) -> i64;
        pub fn seek(fd: i32, offset: i64) -> i32;
        pub fn close(fd: i32) -> i32;
        pub fn self_size() -> i64;
        pub fn emit(ptr: u32, len: u32) -> i32;
        pub fn log(ptr: u32, len: u32) -> i32;
        pub fn abort(code: i32);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_variables, unsafe_code)]
mod ffi {
    pub unsafe fn open(path_ptr: u32, path_len: u32) -> i32 {
        -1
    }
    pub unsafe fn read(fd: i32, buf_ptr: u32, buf_len: u32) -> i32 {
        -1
    }
    pub unsafe fn readdir(path_ptr: u32, path_len: u32, buf_ptr: u32, buf_len: u32) -> i32 {
        -1
    }
    pub unsafe fn stat(path_ptr: u32, path_len: u32) -> i64 {
        -1
    }
    pub unsafe fn seek(fd: i32, offset: i64) -> i32 {
        -1
    }
    pub unsafe fn close(fd: i32) -> i32 {
        -1
    }
    pub unsafe fn self_size() -> i64 {
        -1
    }
    pub unsafe fn emit(ptr: u32, len: u32) -> i32 {
        -1
    }
    pub unsafe fn log(ptr: u32, len: u32) -> i32 {
        -1
    }
    pub unsafe fn abort(code: i32) {}
}

use ffi::{abort, close, emit, log, open, read, readdir, seek, self_size, stat};

// ---------------------------------------------------------------------------
// Memory bridge: the host reads results out of component memory; the guest
// hands back a packed (ptr | len<<32) value and keeps the buffer alive until
// the host releases it with `dealloc`.
// ---------------------------------------------------------------------------

/// Allocate `len` bytes of component memory for the host to write into.
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: u32) -> u32 {
    if len == 0 {
        return 0;
    }
    let mut boxed: Box<[u8]> = vec![0u8; len as usize].into_boxed_slice();
    let ptr = boxed.as_mut_ptr() as u32;
    std::mem::forget(boxed);
    ptr
}

/// Release a buffer previously returned to the host (packed result) or
/// allocated via [`alloc`].
///
/// # Safety
/// `ptr`/`len` must designate a buffer produced by [`alloc`] or a packed
/// result that has not been freed yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(ptr: u32, len: u32) {
    if len == 0 || ptr == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, len as usize);
        let boxed: Box<[u8]> = Box::from_raw(slice as *mut [u8]);
        drop(boxed);
    }
}

/// Return `bytes` to the host as a packed `ptr | len << 32` result.
pub fn return_bytes(bytes: &[u8]) -> u64 {
    let boxed: Box<[u8]> = bytes.to_vec().into_boxed_slice();
    let ptr = boxed.as_ptr() as u32;
    let len = boxed.len() as u32;
    std::mem::forget(boxed);
    (ptr as u64) | ((len as u64) << 32)
}

/// Return a UTF-8 string as a packed result.
pub fn return_str(s: &str) -> u64 {
    return_bytes(s.as_bytes())
}

/// Return a serializable value as packed canonical JSON (the caller picks the
/// encoding; JSON keeps results human-inspectable with `caf-tool run`).
#[cfg(feature = "json")]
pub fn return_json<T: serde::Serialize>(value: &T) -> u64 {
    match serde_json::to_string(value) {
        Ok(s) => return_str(&s),
        Err(e) => return_str(&format!("{{\"error\":\"{e}\"}}")),
    }
}

// ---------------------------------------------------------------------------
// Convenience wrappers over the host ABI.
// ---------------------------------------------------------------------------

/// Read an entire payload file by `/`-prefixed path.
pub fn read_payload(path: &str) -> Result<Vec<u8>, String> {
    let fd = unsafe { open(path.as_ptr() as u32, path.len() as u32) };
    if fd < 0 {
        return Err(format!("open failed: {path}"));
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { read(fd, buf.as_mut_ptr() as u32, buf.len() as u32) };
        if n < 0 {
            unsafe { close(fd) };
            return Err(format!("read failed: {path}"));
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { close(fd) };
    Ok(out)
}

/// Read `[offset, offset+len)` of a payload file without loading the rest.
pub fn read_payload_range(path: &str, offset: u64, len: u32) -> Result<Vec<u8>, String> {
    let fd = unsafe { open(path.as_ptr() as u32, path.len() as u32) };
    if fd < 0 {
        return Err(format!("open failed: {path}"));
    }
    if unsafe { seek(fd, offset as i64) } < 0 {
        unsafe { close(fd) };
        return Err(format!("seek failed: {path}"));
    }
    let mut out = vec![0u8; len as usize];
    let mut filled = 0usize;
    while filled < out.len() {
        let n = unsafe {
            read(
                fd,
                out[filled..].as_mut_ptr() as u32,
                (out.len() - filled) as u32,
            )
        };
        if n < 0 {
            unsafe { close(fd) };
            return Err(format!("read failed: {path}"));
        }
        if n == 0 {
            break;
        }
        filled += n as usize;
    }
    unsafe { close(fd) };
    out.truncate(filled);
    Ok(out)
}

/// Payload file size; `None` if the path is a directory or does not exist.
pub fn payload_len(path: &str) -> Option<u64> {
    let n = unsafe { stat(path.as_ptr() as u32, path.len() as u32) };
    u64::try_from(n).ok()
}

/// List the entries of a payload directory (names only).
pub fn list_dir(path: &str) -> Result<Vec<String>, String> {
    let mut buf = vec![0u8; 8192];
    let n = unsafe {
        readdir(
            path.as_ptr() as u32,
            path.len() as u32,
            buf.as_mut_ptr() as u32,
            buf.len() as u32,
        )
    };
    if n < 0 {
        return Err(format!("readdir failed: {path}"));
    }
    let s = std::str::from_utf8(&buf[..n as usize]).map_err(|e| e.to_string())?;
    Ok(s.split('\n')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect())
}

/// Total byte length of the artifact this component runs inside.
pub fn artifact_size() -> u64 {
    unsafe { self_size() as u64 }
}

/// Emit structured output to the host (charged to the output budget).
pub fn emit_bytes(bytes: &[u8]) -> Result<(), String> {
    if unsafe { emit(bytes.as_ptr() as u32, bytes.len() as u32) } < 0 {
        return Err("emit failed".to_string());
    }
    Ok(())
}

/// Write a diagnostic line to the host's log.
pub fn log_line(msg: &str) {
    unsafe { log(msg.as_ptr() as u32, msg.len() as u32) };
}

/// Trap deterministically with `code`.
pub fn abort_with(code: i32) -> ! {
    unsafe { abort(code) };
    // The host traps on abort; if it ever returns, trap locally instead.
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();
    #[cfg(not(target_arch = "wasm32"))]
    unreachable!("host abort() returned");
}

// ---------------------------------------------------------------------------
// Host-side tests. The ABI is 32-bit-pointer based, so only the fail-closed
// wrapper paths and the pointer-free bridge entry points can run on a host
// target; the dereferencing paths execute on wasm32 (see examples/gis-demo).
// ---------------------------------------------------------------------------
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn alloc_reports_zero_length_without_allocating() {
        assert_eq!(alloc(0), 0);
        // A non-zero allocation returns a handle; the buffer stays leaked for
        // the host (dealloc with a truncated host pointer would be UB).
        assert_ne!(alloc(16), 0);
    }

    #[test]
    fn dealloc_rejects_zero_length_and_null() {
        unsafe {
            dealloc(0, 8);
            dealloc(1, 0);
            dealloc(0, 0);
        }
    }

    #[test]
    fn return_bytes_packs_len_into_the_high_word() {
        let packed = return_bytes(b"hello");
        assert_eq!(packed >> 32, 5);
        assert_ne!(packed & 0xffff_ffff, 0);
    }

    #[test]
    fn return_str_counts_utf8_bytes() {
        assert_eq!(return_str("héllo") >> 32, 6);
        assert_eq!(return_str("") >> 32, 0);
    }

    /// The host stubs fail closed, so every wrapper surfaces its error path.
    #[test]
    fn host_wrappers_fail_closed_off_wasm() {
        assert!(read_payload("/x").is_err());
        assert!(read_payload_range("/x", 0, 4).is_err());
        assert_eq!(payload_len("/x"), None);
        assert!(list_dir("/x").is_err());
        assert!(emit_bytes(b"x").is_err());
        log_line("diagnostic");
        assert_eq!(artifact_size(), u64::MAX); // stub self_size() == -1
    }

    #[test]
    #[should_panic]
    fn abort_with_traps_when_the_host_stub_returns() {
        abort_with(7);
    }
}
