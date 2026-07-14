//! Host-only credential materialization for the locked gateway mount.

use std::{
    env, fmt, fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
static NEXT_CREDENTIAL: AtomicU64 = AtomicU64::new(0);

pub(crate) struct HostCredential {
    path: PathBuf,
    cleanup_directory: Option<PathBuf>,
}

impl HostCredential {
    pub(crate) fn from_file(path: &Path) -> Result<Self, HostCredentialError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| HostCredentialError::File)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(HostCredentialError::File);
        }
        let path = fs::canonicalize(path).map_err(|_| HostCredentialError::File)?;
        Ok(Self {
            path,
            cleanup_directory: None,
        })
    }

    pub(crate) fn from_environment(name: &str) -> Result<Self, HostCredentialError> {
        if !valid_environment_name(name) {
            return Err(HostCredentialError::EnvironmentName);
        }
        let value = env::var(name).map_err(|_| HostCredentialError::EnvironmentMissing)?;
        validate_value(&value)?;
        let sequence = NEXT_CREDENTIAL.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HostCredentialError::Create)?
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "blindfold-credential-{}-{timestamp:x}-{sequence:x}",
            std::process::id()
        ));
        create_private_directory(&directory)?;
        let path = directory.join("provider.key");
        let result = write_private_file(&path, value.as_bytes());
        if let Err(error) = result {
            let _ = fs::remove_dir(&directory);
            return Err(error);
        }
        let Ok(canonical_path) = fs::canonicalize(&path) else {
            let _ = fs::remove_file(&path);
            let _ = fs::remove_dir(&directory);
            return Err(HostCredentialError::Create);
        };
        Ok(Self {
            path: canonical_path,
            cleanup_directory: Some(directory),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HostCredential {
    fn drop(&mut self) {
        let Some(directory) = self.cleanup_directory.take() else {
            return;
        };
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(directory);
    }
}

#[derive(Debug)]
pub(crate) enum HostCredentialError {
    File,
    EnvironmentName,
    EnvironmentMissing,
    Value,
    Create,
}

impl fmt::Display for HostCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => formatter.write_str(
                "credential file must be a readable regular file and not a symbolic link",
            ),
            Self::EnvironmentName => formatter.write_str("credential environment name is invalid"),
            Self::EnvironmentMissing => {
                formatter.write_str("provider credential environment variable is not set")
            }
            Self::Value => formatter.write_str("provider credential value is invalid"),
            Self::Create => {
                formatter.write_str("could not create the temporary gateway credential")
            }
        }
    }
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_value(value: &str) -> Result<(), HostCredentialError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES || value.contains(['\r', '\n', '\0'])
    {
        Err(HostCredentialError::Value)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), HostCredentialError> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| HostCredentialError::Create)
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> Result<(), HostCredentialError> {
    Err(HostCredentialError::Create)
}

#[cfg(unix)]
fn write_private_file(path: &Path, value: &[u8]) -> Result<(), HostCredentialError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| HostCredentialError::Create)?;
    file.write_all(value)
        .and_then(|()| file.sync_all())
        .map_err(|_| HostCredentialError::Create)
}

#[cfg(not(unix))]
fn write_private_file(_path: &Path, _value: &[u8]) -> Result<(), HostCredentialError> {
    Err(HostCredentialError::Create)
}

#[cfg(test)]
mod tests {
    use super::{valid_environment_name, validate_value};

    #[test]
    fn accepts_only_simple_environment_names_and_single_line_values() {
        assert!(valid_environment_name("OPENAI_API_KEY"));
        assert!(!valid_environment_name("openai_api_key"));
        assert!(!valid_environment_name("9KEY"));
        assert!(validate_value("test-only-value").is_ok());
        assert!(validate_value("first\nsecond").is_err());
        assert!(validate_value("").is_err());
    }
}
