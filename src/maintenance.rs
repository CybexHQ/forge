#[cfg(unix)]
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt},
};
use std::{fs, io, path::Path};

use anyhow::{Context, Result, bail};

const APPLIANCE_UPDATE_LOCK: &str = "/var/lib/cybex-forge/state/appliance-update.lock";

/// Return whether appliance maintenance currently holds the shared mutation
/// lease. Netboot publication uses this as a promotion barrier while an
/// appliance update is changing the installed runtime.
pub fn lease_active() -> Result<bool> {
    let path = Path::new(APPLIANCE_UPDATE_LOCK);
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(true),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };

    #[cfg(unix)]
    {
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect {}", path.display()))?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || (metadata.uid() != unsafe { libc::geteuid() } && metadata.uid() != 0)
        {
            bail!("appliance maintenance lock must be a singly-linked trusted file");
        }
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(true);
            }
            return Err(error).with_context(|| format!("lock {}", path.display()));
        }
        let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }

    Ok(false)
}
