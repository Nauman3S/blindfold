use std::fs::{self, File, OpenOptions};
use std::path::Path;

use crate::{VaultError, VaultResult};

pub(crate) fn prepare_parent(path: &Path) -> VaultResult<()> {
    let parent = path.parent().ok_or(VaultError::InvalidInput)?;
    let create_private = !parent.exists();
    fs::create_dir_all(parent).map_err(|_| VaultError::StorageUnavailable)?;
    if create_private {
        restrict_dir(parent)?;
    }
    Ok(())
}

pub(crate) fn open_lock(path: &Path) -> VaultResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_file_mode(&mut options);
    let file = options
        .open(path)
        .map_err(|_| VaultError::StorageUnavailable)?;
    restrict_file(path)?;
    file.lock().map_err(|_| VaultError::StorageUnavailable)?;
    Ok(file)
}

pub(crate) fn restrict_file(path: &Path) -> VaultResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if path.exists() {
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

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| VaultError::StorageUnavailable)?;
    }
    Ok(())
}

pub(crate) fn set_file_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
}
