//! Filesystem free-space introspection for preflight checks and reporting.

use std::{
    ffi::CString,
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use serde::Serialize;

/// Extra free space required beyond the expected write size, so a preflighted
/// operation cannot itself fill the filesystem to the brim.
pub const DISK_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct DiskStats {
    pub path: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

/// statvfs for the filesystem containing `path`. Walks up to the nearest
/// existing ancestor so preflights work before a target directory is created.
pub fn stats(path: &Path) -> io::Result<DiskStats> {
    let mut probe: PathBuf = path.to_path_buf();
    while !probe.exists() {
        if !probe.pop() {
            probe = PathBuf::from("/");
            break;
        }
    }
    let raw = CString::new(probe.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(raw.as_ptr(), &mut vfs) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let frsize = if vfs.f_frsize > 0 {
        vfs.f_frsize as u64
    } else {
        vfs.f_bsize as u64
    };
    Ok(DiskStats {
        path: probe.display().to_string(),
        total_bytes: (vfs.f_blocks as u64).saturating_mul(frsize),
        available_bytes: (vfs.f_bavail as u64).saturating_mul(frsize),
    })
}

/// Fail fast when the filesystem holding `path` cannot absorb an expected
/// write of `expected_bytes` plus headroom. A statvfs failure is reported as
/// an error only for the caller to log; it does not block the operation.
pub fn ensure_headroom(path: &Path, expected_bytes: u64, what: &str) -> Result<()> {
    let stats = match stats(path) {
        Ok(stats) => stats,
        Err(err) => {
            tracing::warn!(error = %err, path = %path.display(), "failed to stat filesystem; skipping disk preflight");
            return Ok(());
        }
    };
    let required = expected_bytes.saturating_add(DISK_HEADROOM_BYTES);
    if stats.available_bytes < required {
        bail!(
            "insufficient disk space for {what}: {} available on {}, {} required",
            format_bytes(stats.available_bytes),
            stats.path,
            format_bytes(required),
        );
    }
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_reports_nonzero_for_root() {
        let stats = stats(Path::new("/")).expect("statvfs /");
        assert!(stats.total_bytes > 0);
        assert!(stats.available_bytes <= stats.total_bytes);
    }

    #[test]
    fn stats_walks_up_to_existing_ancestor() {
        let stats = stats(Path::new("/definitely/not/a/real/path/cybex-forge-test"))
            .expect("statvfs fallback");
        assert!(stats.total_bytes > 0);
    }

    #[test]
    fn ensure_headroom_rejects_absurd_requirement() {
        let err = ensure_headroom(Path::new("/"), u64::MAX - DISK_HEADROOM_BYTES, "test write")
            .expect_err("must not have u64::MAX bytes free");
        assert!(err.to_string().contains("insufficient disk space"));
    }

    #[test]
    fn format_bytes_is_humane() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.0 GiB");
    }
}
