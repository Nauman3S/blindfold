use std::fs::{self, File, OpenOptions};
use std::path::Path;

use crate::{VaultError, VaultResult};

pub(crate) fn prepare_parent(path: &Path) -> VaultResult<()> {
    let parent = path.parent().ok_or(VaultError::InvalidInput)?;
    let create_private = match reject_symlink(parent)? {
        PathState::Missing => true,
        PathState::Present => false,
    };
    fs::create_dir_all(parent).map_err(|_| VaultError::StorageUnavailable)?;
    reject_symlink(parent)?;
    if create_private {
        restrict_dir(parent)?;
    }
    Ok(())
}

pub(crate) fn open_lock(path: &Path) -> VaultResult<File> {
    reject_symlink(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_file_mode(&mut options);
    let file = options
        .open(path)
        .map_err(|_| VaultError::StorageUnavailable)?;
    reject_symlink(path)?;
    restrict_file(path)?;
    file.lock().map_err(|_| VaultError::StorageUnavailable)?;
    Ok(file)
}

pub(crate) fn restrict_file(path: &Path) -> VaultResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if reject_symlink(path)? == PathState::Present {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|_| VaultError::StorageUnavailable)?;
        }
    }
    Ok(())
}

fn restrict_dir(path: &Path) -> VaultResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        reject_symlink(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| VaultError::StorageUnavailable)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PathState {
    Missing,
    Present,
}

pub(crate) fn reject_symlink(path: &Path) -> VaultResult<PathState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(VaultError::StorageUnavailable),
        Ok(_) => Ok(PathState::Present),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PathState::Missing),
        Err(_) => Err(VaultError::StorageUnavailable),
    }
}

pub(crate) fn set_file_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
}
