use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atomic_write_file::AtomicWriteFile;
use blindfold_core::{SafeRef, SafeRefKind, SecretValue};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::fs::{open_lock, prepare_parent, restrict_file};
use crate::{VaultError, VaultResult};

const MAGIC: &[u8; 8] = b"BFVAULT1";
const FORMAT_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + 1 + NONCE_LEN;
const MAX_SCOPE_COMPONENT_LEN: usize = 256;

/// A caller-supplied 256-bit vault master key.
///
/// This type redacts its formatting and clears its owned byte array on drop.
/// It is not serializable. The crate does not persist or retrieve this key from
/// an OS keychain.
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Takes ownership of exactly 32 bytes of key material.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey([REDACTED])")
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Project and session authorization scope for a vault record.
///
/// Scope identifiers are metadata, not secret storage. Callers must not put raw
/// secret values in them.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Scope {
    project: String,
    session: String,
}

impl Scope {
    /// Creates a scope from non-empty, bounded project and session identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidInput`] for empty identifiers, identifiers
    /// longer than 256 bytes, or identifiers containing control characters.
    pub fn new(project: impl Into<String>, session: impl Into<String>) -> VaultResult<Self> {
        let project = project.into();
        let session = session.into();
        validate_scope_component(&project)?;
        validate_scope_component(&session)?;
        Ok(Self { project, session })
    }

    /// Returns the project identifier.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Returns the session identifier.
    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }
}

/// Non-secret metadata describing a vault entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryMetadata {
    safe_ref: SafeRef,
    scope: Scope,
    created_at: SystemTime,
    expires_at: SystemTime,
}

impl EntryMetadata {
    /// Returns the opaque safe reference.
    #[must_use]
    pub const fn safe_ref(&self) -> &SafeRef {
        &self.safe_ref
    }

    /// Returns the project and session scope.
    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Returns when the entry was created.
    #[must_use]
    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Returns when the entry expires.
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

/// Authenticated encrypted file-backed vault.
///
/// Every operation coordinates through an adjacent lock file. Mutations decrypt
/// and authenticate the current state, update it in memory, and atomically
/// replace the encrypted file. The data format is portable; Unix permissions
/// are additionally restricted to the current user.
pub struct Vault {
    path: PathBuf,
    lock_path: PathBuf,
    key: MasterKey,
}

impl Vault {
    /// Opens a vault path with a caller-managed master key.
    ///
    /// Opening does not create the encrypted data file until the first mutation.
    /// An existing file is authenticated on every operation.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StorageUnavailable`] if the directory or lock file
    /// cannot be prepared.
    pub fn open(path: impl AsRef<Path>, key: MasterKey) -> VaultResult<Self> {
        let path = path.as_ref().to_path_buf();
        prepare_parent(&path)?;
        let lock_path = adjacent_path(&path, "lock")?;
        restrict_file(&path)?;
        let vault = Self {
            path,
            lock_path,
            key,
        };
        {
            let _lock = open_lock(&vault.lock_path)?;
            vault.read_state()?;
        }
        Ok(vault)
    }

    /// Stores a secret under a new random safe reference.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidInput`] for an empty value or zero TTL.
    /// Existing corrupt state or a wrong key fails closed.
    pub fn store(
        &self,
        kind: SafeRefKind,
        scope: &Scope,
        value: &SecretValue,
        ttl: Duration,
    ) -> VaultResult<SafeRef> {
        if value.is_empty() || ttl.is_zero() {
            return Err(VaultError::InvalidInput);
        }
        let now = unix_seconds(SystemTime::now())?;
        let expires_at = now
            .checked_add(ttl.as_secs())
            .ok_or(VaultError::InvalidInput)?;
        if expires_at == now {
            return Err(VaultError::InvalidInput);
        }

        let _lock = open_lock(&self.lock_path)?;
        let mut state = self.read_state()?;
        state.records.retain(|_, record| record.expires_at > now);

        let (id, safe_ref) = loop {
            let mut id_bytes = [0_u8; 16];
            getrandom::fill(&mut id_bytes).map_err(|_| VaultError::RandomnessUnavailable)?;
            let id = encode_hex(&id_bytes);
            if !state.records.contains_key(&id) {
                let safe_ref = SafeRef::from_id(kind, &id).map_err(|_| VaultError::InvalidInput)?;
                break (id, safe_ref);
            }
        };

        state.records.insert(
            id,
            DiskRecord {
                kind: kind_code(kind)?,
                project: scope.project.clone(),
                session: scope.session.clone(),
                created_at: now,
                expires_at,
                value: value.expose_secret().to_owned(),
            },
        );
        self.write_state(&state)?;
        Ok(safe_ref)
    }

    /// Resolves an unexpired reference only when its project and session match.
    ///
    /// This method performs vault authentication and scope/lifetime checks. A
    /// higher-level policy layer must still authorize the destination and
    /// operation before exposing the returned value.
    ///
    /// # Errors
    ///
    /// Missing, forged, expired, kind-mismatched, and cross-scope references all
    /// return [`VaultError::ReferenceRejected`].
    pub fn resolve(&self, safe_ref: &SafeRef, scope: &Scope) -> VaultResult<SecretValue> {
        let _lock = open_lock(&self.lock_path)?;
        let state = self.read_state()?;
        let id = reference_id(safe_ref)?;
        let record = state.records.get(id).ok_or(VaultError::ReferenceRejected)?;
        let now = unix_seconds(SystemTime::now())?;
        if record.expires_at <= now
            || record.project != scope.project
            || record.session != scope.session
            || record.kind != kind_code(safe_ref.kind())?
        {
            return Err(VaultError::ReferenceRejected);
        }
        Ok(SecretValue::new(record.value.clone()))
    }

    /// Lists non-secret metadata for unexpired records in one scope.
    ///
    /// Values are never returned or serialized through this API.
    ///
    /// # Errors
    ///
    /// Returns an error if storage cannot be read or authenticated.
    pub fn list(&self, scope: &Scope) -> VaultResult<Vec<EntryMetadata>> {
        let _lock = open_lock(&self.lock_path)?;
        let state = self.read_state()?;
        let now = unix_seconds(SystemTime::now())?;
        state
            .records
            .iter()
            .filter(|(_, record)| {
                record.expires_at > now
                    && record.project == scope.project
                    && record.session == scope.session
            })
            .map(|(id, record)| metadata(id, record))
            .collect()
    }

    /// Removes all records in one project and session scope.
    ///
    /// The returned count is metadata only. Atomic replacement cannot guarantee
    /// erasure from filesystem snapshots, backups, or storage media.
    ///
    /// # Errors
    ///
    /// Returns an error if storage cannot be authenticated or atomically updated.
    pub fn clear(&self, scope: &Scope) -> VaultResult<usize> {
        let _lock = open_lock(&self.lock_path)?;
        let mut state = self.read_state()?;
        let before = state.records.len();
        state
            .records
            .retain(|_, record| record.project != scope.project || record.session != scope.session);
        let removed = before - state.records.len();
        if removed != 0 {
            self.write_state(&state)?;
        }
        Ok(removed)
    }

    /// Removes every expired record and returns the number removed.
    ///
    /// # Errors
    ///
    /// Returns an error if storage cannot be authenticated or atomically updated.
    pub fn purge_expired(&self) -> VaultResult<usize> {
        let _lock = open_lock(&self.lock_path)?;
        let mut state = self.read_state()?;
        let now = unix_seconds(SystemTime::now())?;
        let before = state.records.len();
        state.records.retain(|_, record| record.expires_at > now);
        let removed = before - state.records.len();
        if removed != 0 {
            self.write_state(&state)?;
        }
        Ok(removed)
    }

    fn read_state(&self) -> VaultResult<DiskState> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DiskState::default());
            }
            Err(_) => return Err(VaultError::StorageUnavailable),
        };
        if bytes.len() < HEADER_LEN || &bytes[..MAGIC.len()] != MAGIC {
            return Err(VaultError::CorruptOrWrongKey);
        }
        if bytes[MAGIC.len()] != FORMAT_VERSION {
            return Err(VaultError::CorruptOrWrongKey);
        }
        let nonce_start = MAGIC.len() + 1;
        let nonce_end = nonce_start + NONCE_LEN;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key.0));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&bytes[nonce_start..nonce_end]),
                Payload {
                    msg: &bytes[nonce_end..],
                    aad: &bytes[..nonce_start],
                },
            )
            .map_err(|_| VaultError::CorruptOrWrongKey)?;
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::CorruptOrWrongKey)
    }

    fn write_state(&self, state: &DiskState) -> VaultResult<()> {
        let plaintext = serde_json::to_vec(state).map_err(|_| VaultError::CorruptOrWrongKey)?;
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::RandomnessUnavailable)?;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(FORMAT_VERSION);
        header.extend_from_slice(&nonce);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key.0));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &header[..=MAGIC.len()],
                },
            )
            .map_err(|_| VaultError::CorruptOrWrongKey)?;
        header.extend_from_slice(&ciphertext);

        let mut file =
            AtomicWriteFile::open(&self.path).map_err(|_| VaultError::StorageUnavailable)?;
        #[cfg(unix)]
        file.as_file()
            .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .map_err(|_| VaultError::StorageUnavailable)?;
        file.write_all(&header)
            .map_err(|_| VaultError::StorageUnavailable)?;
        file.commit().map_err(|_| VaultError::StorageUnavailable)?;
        restrict_file(&self.path)
    }
}

#[derive(Default, Deserialize, Serialize)]
struct DiskState {
    records: BTreeMap<String, DiskRecord>,
}

#[derive(Deserialize, Serialize)]
struct DiskRecord {
    kind: u8,
    project: String,
    session: String,
    created_at: u64,
    expires_at: u64,
    value: String,
}

fn validate_scope_component(value: &str) -> VaultResult<()> {
    if value.is_empty()
        || value.len() > MAX_SCOPE_COMPONENT_LEN
        || value.chars().any(char::is_control)
    {
        return Err(VaultError::InvalidInput);
    }
    Ok(())
}

fn unix_seconds(time: SystemTime) -> VaultResult<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| VaultError::InvalidInput)
}

fn metadata(id: &str, record: &DiskRecord) -> VaultResult<EntryMetadata> {
    let kind = decode_kind(record.kind)?;
    let safe_ref = SafeRef::from_id(kind, id).map_err(|_| VaultError::CorruptOrWrongKey)?;
    Ok(EntryMetadata {
        safe_ref,
        scope: Scope {
            project: record.project.clone(),
            session: record.session.clone(),
        },
        created_at: UNIX_EPOCH + Duration::from_secs(record.created_at),
        expires_at: UNIX_EPOCH + Duration::from_secs(record.expires_at),
    })
}

fn kind_code(kind: SafeRefKind) -> VaultResult<u8> {
    match kind {
        SafeRefKind::Secret => Ok(1),
        SafeRefKind::Environment => Ok(2),
        SafeRefKind::PersonallyIdentifiableInformation => Ok(3),
        SafeRefKind::PrivateKey => Ok(4),
        SafeRefKind::Certificate => Ok(5),
        _ => Err(VaultError::InvalidInput),
    }
}

fn decode_kind(code: u8) -> VaultResult<SafeRefKind> {
    match code {
        1 => Ok(SafeRefKind::Secret),
        2 => Ok(SafeRefKind::Environment),
        3 => Ok(SafeRefKind::PersonallyIdentifiableInformation),
        4 => Ok(SafeRefKind::PrivateKey),
        5 => Ok(SafeRefKind::Certificate),
        _ => Err(VaultError::CorruptOrWrongKey),
    }
}

fn reference_id(safe_ref: &SafeRef) -> VaultResult<&str> {
    safe_ref
        .as_str()
        .strip_suffix("}}")
        .and_then(|value| value.rsplit_once(':').map(|(_, id)| id))
        .ok_or(VaultError::ReferenceRejected)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn adjacent_path(path: &Path, suffix: &str) -> VaultResult<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(VaultError::InvalidInput)?;
    Ok(path.with_file_name(format!("{name}.{suffix}")))
}
