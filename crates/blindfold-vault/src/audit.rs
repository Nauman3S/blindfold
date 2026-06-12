use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use blindfold_core::SafeRef;
use serde::{Deserialize, Serialize};

use crate::fs::{
    PathState, open_lock, prepare_parent, reject_symlink, restrict_file, set_file_mode,
};
use crate::{VaultError, VaultResult};

/// Closed set of operations that may be recorded in the safe audit log.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditAction {
    /// A secret was stored.
    Store,
    /// A reference resolution was attempted.
    Resolve,
    /// Vault metadata was listed.
    List,
    /// A scope was cleared.
    Clear,
    /// Expired entries were purged.
    PurgeExpired,
}

/// Closed set of safe audit outcomes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditOutcome {
    /// The operation completed.
    Succeeded,
    /// The operation was denied or its reference rejected.
    Rejected,
    /// Protected storage was unavailable or unauthenticated.
    Failed,
}

/// A safe, structured audit event.
///
/// Events contain only a timestamp, closed action/outcome enums, and an optional
/// opaque [`SafeRef`]. There is intentionally no free-form message field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    timestamp: SystemTime,
    action: AuditAction,
    outcome: AuditOutcome,
    safe_ref: Option<SafeRef>,
}

impl AuditEvent {
    /// Creates an event timestamped with the current system time.
    #[must_use]
    pub fn now(action: AuditAction, outcome: AuditOutcome, safe_ref: Option<SafeRef>) -> Self {
        Self {
            timestamp: SystemTime::now(),
            action,
            outcome,
            safe_ref,
        }
    }

    /// Returns the event timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// Returns the recorded action.
    #[must_use]
    pub const fn action(&self) -> AuditAction {
        self.action
    }

    /// Returns the recorded outcome.
    #[must_use]
    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    /// Returns the optional opaque reference.
    #[must_use]
    pub const fn safe_ref(&self) -> Option<&SafeRef> {
        self.safe_ref.as_ref()
    }
}

/// Size-based audit rotation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationPolicy {
    max_bytes: u64,
    retained_files: usize,
}

impl RotationPolicy {
    /// Creates a policy with a non-zero active-file limit and archive count.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidInput`] when either value is zero.
    pub const fn new(max_bytes: u64, retained_files: usize) -> VaultResult<Self> {
        if max_bytes == 0 || retained_files == 0 {
            return Err(VaultError::InvalidInput);
        }
        Ok(Self {
            max_bytes,
            retained_files,
        })
    }

    /// Returns the target maximum active log size.
    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    /// Returns the number of rotated files retained.
    #[must_use]
    pub const fn retained_files(self) -> usize {
        self.retained_files
    }
}

/// Lock-coordinated append-only JSON-lines audit log with size rotation.
///
/// The active file is only appended to. Rotation renames complete files while
/// holding an adjacent exclusive lock. Audit logs are safe metadata and are not
/// encrypted by this type.
pub struct AuditLog {
    path: PathBuf,
    lock_path: PathBuf,
    rotation: RotationPolicy,
}

impl AuditLog {
    /// Opens an audit log at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory or lock file cannot be prepared.
    pub fn open(path: impl AsRef<Path>, rotation: RotationPolicy) -> VaultResult<Self> {
        let path = path.as_ref().to_path_buf();
        prepare_parent(&path)?;
        let lock_path = adjacent_path(&path, "lock")?;
        reject_symlink(&path)?;
        drop(open_lock(&lock_path)?);
        restrict_file(&path)?;
        Ok(Self {
            path,
            lock_path,
            rotation,
        })
    }

    /// Appends one complete event, rotating first when the configured size would
    /// be exceeded.
    ///
    /// # Errors
    ///
    /// Returns an error if the timestamp is invalid, serialization fails, or the
    /// append/rotation cannot be completed.
    pub fn append(&self, event: &AuditEvent) -> VaultResult<()> {
        let timestamp = event
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VaultError::InvalidInput)?
            .as_secs();
        let line = serde_json::to_vec(&DiskEvent {
            version: 1,
            timestamp,
            action: event.action,
            outcome: event.outcome,
            safe_ref: event.safe_ref.as_ref().map(SafeRef::as_str),
        })
        .map_err(|_| VaultError::StorageUnavailable)?;

        let _lock = open_lock(&self.lock_path)?;
        let current_len = match reject_symlink(&self.path)? {
            PathState::Missing => 0,
            PathState::Present => fs::metadata(&self.path)
                .map_err(|_| VaultError::StorageUnavailable)?
                .len(),
        };
        let line_len = u64::try_from(line.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or(VaultError::InvalidInput)?;
        if current_len != 0 && current_len.saturating_add(line_len) > self.rotation.max_bytes {
            self.rotate()?;
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        set_file_mode(&mut options);
        reject_symlink(&self.path)?;
        let mut file = options
            .open(&self.path)
            .map_err(|_| VaultError::StorageUnavailable)?;
        reject_symlink(&self.path)?;
        restrict_file(&self.path)?;
        file.write_all(&line)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_data())
            .map_err(|_| VaultError::StorageUnavailable)
    }

    /// Reads and validates the active audit log as canonical JSON lines.
    ///
    /// The active file is bounded by the configured rotation size. Every record
    /// must match the closed audit schema before any content is returned.
    ///
    /// # Errors
    ///
    /// Returns an error for symlinks, oversized or malformed files, unsupported
    /// record versions, or invalid references.
    pub fn read_lines(&self) -> VaultResult<Vec<String>> {
        let _lock = open_lock(&self.lock_path)?;
        if reject_symlink(&self.path)? == PathState::Missing {
            return Ok(Vec::new());
        }
        let metadata = fs::metadata(&self.path).map_err(|_| VaultError::StorageUnavailable)?;
        if metadata.len() > self.rotation.max_bytes {
            return Err(VaultError::StorageUnavailable);
        }

        let mut options = OpenOptions::new();
        options.read(true);
        let file = options
            .open(&self.path)
            .map_err(|_| VaultError::StorageUnavailable)?;
        reject_symlink(&self.path)?;
        let capacity =
            usize::try_from(metadata.len()).map_err(|_| VaultError::StorageUnavailable)?;
        let mut contents = Vec::with_capacity(capacity);
        file.take(self.rotation.max_bytes.saturating_add(1))
            .read_to_end(&mut contents)
            .map_err(|_| VaultError::StorageUnavailable)?;
        if u64::try_from(contents.len()).map_or(true, |length| length > self.rotation.max_bytes) {
            return Err(VaultError::StorageUnavailable);
        }

        contents
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let event: StoredEvent =
                    serde_json::from_slice(line).map_err(|_| VaultError::StorageUnavailable)?;
                if event.version != 1 {
                    return Err(VaultError::StorageUnavailable);
                }
                if let Some(reference) = event.safe_ref.as_deref() {
                    SafeRef::parse(reference).map_err(|_| VaultError::StorageUnavailable)?;
                }
                serde_json::to_string(&event).map_err(|_| VaultError::StorageUnavailable)
            })
            .collect()
    }

    fn rotate(&self) -> VaultResult<()> {
        let oldest = rotated_path(&self.path, self.rotation.retained_files)?;
        reject_symlink(&oldest)?;
        match fs::remove_file(&oldest) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(VaultError::StorageUnavailable),
        }
        for generation in (1..self.rotation.retained_files).rev() {
            let source = rotated_path(&self.path, generation)?;
            let destination = rotated_path(&self.path, generation + 1)?;
            reject_symlink(&source)?;
            reject_symlink(&destination)?;
            match fs::rename(&source, &destination) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(VaultError::StorageUnavailable),
            }
        }
        let destination = rotated_path(&self.path, 1)?;
        reject_symlink(&self.path)?;
        reject_symlink(&destination)?;
        fs::rename(&self.path, destination).map_err(|_| VaultError::StorageUnavailable)
    }
}

#[derive(Serialize)]
struct DiskEvent<'a> {
    version: u8,
    timestamp: u64,
    action: AuditAction,
    outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_ref: Option<&'a str>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEvent {
    version: u8,
    timestamp: u64,
    action: AuditAction,
    outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_ref: Option<String>,
}

fn adjacent_path(path: &Path, suffix: &str) -> VaultResult<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(VaultError::InvalidInput)?;
    Ok(path.with_file_name(format!("{name}.{suffix}")))
}

fn rotated_path(path: &Path, generation: usize) -> VaultResult<PathBuf> {
    adjacent_path(path, &generation.to_string())
}
