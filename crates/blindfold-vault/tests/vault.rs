//! Integration tests for encrypted storage and safe audit behavior.

#![allow(clippy::duration_suboptimal_units, clippy::expect_used, clippy::panic)]

use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use blindfold_core::{SafeRefKind, SecretValue};
use blindfold_vault::{
    AuditAction, AuditEvent, AuditLog, AuditOutcome, MasterKey, RotationPolicy, Scope, Vault,
    VaultError,
};
use tempfile::tempdir;

const KEY: [u8; 32] = [0x42; 32];

fn scope() -> Scope {
    Scope::new("project-a", "session-a").unwrap_or_else(|error| {
        unreachable!("test scope must be valid: {error}");
    })
}

#[test]
fn round_trip_scope_list_clear_and_no_plaintext_artifact() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let path = directory.path().join("vault.bin");
    let vault = Vault::open(&path, MasterKey::new(KEY))
        .unwrap_or_else(|error| panic!("open failed: {error}"));
    let raw = "fake-secret-never-on-disk";

    let safe_ref = vault
        .store(
            SafeRefKind::Secret,
            &scope(),
            &SecretValue::new(raw),
            Duration::from_secs(60),
        )
        .unwrap_or_else(|error| panic!("store failed: {error}"));
    let metadata = vault
        .list(&scope())
        .unwrap_or_else(|error| panic!("list failed: {error}"));
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].safe_ref(), &safe_ref);

    let restored = vault
        .resolve(&safe_ref, &scope())
        .unwrap_or_else(|error| panic!("resolve failed: {error}"));
    assert_eq!(restored.expose_secret(), raw);

    let other_scope = Scope::new("project-a", "session-b")
        .unwrap_or_else(|error| panic!("scope failed: {error}"));
    assert_eq!(
        vault.resolve(&safe_ref, &other_scope),
        Err(VaultError::ReferenceRejected)
    );
    assert_eq!(
        vault
            .clear(&scope())
            .unwrap_or_else(|error| panic!("clear failed: {error}")),
        1
    );
    assert_eq!(
        vault.resolve(&safe_ref, &scope()),
        Err(VaultError::ReferenceRejected)
    );

    for entry in
        fs::read_dir(directory.path()).unwrap_or_else(|error| panic!("read_dir failed: {error}"))
    {
        let entry = entry.unwrap_or_else(|error| panic!("dir entry failed: {error}"));
        if entry
            .file_type()
            .unwrap_or_else(|error| panic!("file_type failed: {error}"))
            .is_file()
        {
            let bytes =
                fs::read(entry.path()).unwrap_or_else(|error| panic!("read failed: {error}"));
            assert!(
                !bytes
                    .windows(raw.len())
                    .any(|window| window == raw.as_bytes())
            );
        }
    }
}

#[test]
fn wrong_key_and_corruption_fail_closed_without_secret_in_errors() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let path = directory.path().join("vault.bin");
    let raw = "fake-error-leak-secret";
    let vault = Vault::open(&path, MasterKey::new(KEY))
        .unwrap_or_else(|error| panic!("open failed: {error}"));
    vault
        .store(
            SafeRefKind::Secret,
            &scope(),
            &SecretValue::new(raw),
            Duration::from_secs(60),
        )
        .unwrap_or_else(|error| panic!("store failed: {error}"));

    let wrong_error = Vault::open(&path, MasterKey::new([0x24; 32]))
        .err()
        .unwrap_or_else(|| panic!("wrong key must fail authentication"));
    assert_eq!(wrong_error, VaultError::CorruptOrWrongKey);
    assert!(!format!("{wrong_error:?} {wrong_error}").contains(raw));

    let mut bytes = fs::read(&path).unwrap_or_else(|error| panic!("read failed: {error}"));
    let last = bytes
        .last_mut()
        .unwrap_or_else(|| panic!("encrypted vault must not be empty"));
    *last ^= 1;
    fs::write(&path, bytes).unwrap_or_else(|error| panic!("write failed: {error}"));
    assert_eq!(vault.list(&scope()), Err(VaultError::CorruptOrWrongKey));
}

#[test]
fn concurrent_writers_do_not_lose_records() {
    const WRITERS: usize = 12;

    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let vault = Arc::new(
        Vault::open(directory.path().join("vault.bin"), MasterKey::new(KEY))
            .unwrap_or_else(|error| panic!("open failed: {error}")),
    );
    let barrier = Arc::new(Barrier::new(WRITERS));
    let mut threads = Vec::new();

    for index in 0..WRITERS {
        let vault = Arc::clone(&vault);
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            barrier.wait();
            vault.store(
                SafeRefKind::Secret,
                &scope(),
                &SecretValue::new(format!("fake-concurrent-secret-{index}")),
                Duration::from_secs(60),
            )
        }));
    }
    for handle in threads {
        handle
            .join()
            .unwrap_or_else(|_| panic!("writer thread panicked"))
            .unwrap_or_else(|error| panic!("store failed: {error}"));
    }

    assert_eq!(
        vault
            .list(&scope())
            .unwrap_or_else(|error| panic!("list failed: {error}"))
            .len(),
        WRITERS
    );
}

#[test]
fn ttl_expires_and_is_purged() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let vault = Vault::open(directory.path().join("vault.bin"), MasterKey::new(KEY))
        .unwrap_or_else(|error| panic!("open failed: {error}"));
    let safe_ref = vault
        .store(
            SafeRefKind::Secret,
            &scope(),
            &SecretValue::new("fake-short-lived"),
            Duration::from_secs(1),
        )
        .unwrap_or_else(|error| panic!("store failed: {error}"));
    thread::sleep(Duration::from_millis(1_100));

    assert_eq!(
        vault.resolve(&safe_ref, &scope()),
        Err(VaultError::ReferenceRejected)
    );
    assert_eq!(
        vault
            .purge_expired()
            .unwrap_or_else(|error| panic!("purge failed: {error}")),
        1
    );
}

#[test]
fn audit_is_safe_append_only_and_rotates() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let path = directory.path().join("audit.jsonl");
    let policy = RotationPolicy::new(140, 2)
        .unwrap_or_else(|error| panic!("rotation policy failed: {error}"));
    let audit =
        AuditLog::open(&path, policy).unwrap_or_else(|error| panic!("open failed: {error}"));

    for _ in 0..6 {
        audit
            .append(&AuditEvent::now(
                AuditAction::Resolve,
                AuditOutcome::Rejected,
                None,
            ))
            .unwrap_or_else(|error| panic!("append failed: {error}"));
    }

    assert!(path.exists());
    assert!(directory.path().join("audit.jsonl.1").exists());
    let combined = fs::read_dir(directory.path())
        .unwrap_or_else(|error| panic!("read_dir failed: {error}"))
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read(entry.path()).ok())
        .flatten()
        .collect::<Vec<_>>();
    let text = String::from_utf8_lossy(&combined);
    assert!(text.contains("\"action\":\"resolve\""));
    assert!(!text.contains("fake-secret"));
}

#[cfg(unix)]
#[test]
fn unix_files_and_directory_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let directory = parent.path().join("private");
    let vault_path = directory.join("vault.bin");
    let audit_path = directory.join("audit.jsonl");
    let vault = Vault::open(&vault_path, MasterKey::new(KEY))
        .unwrap_or_else(|error| panic!("open failed: {error}"));
    vault
        .store(
            SafeRefKind::Secret,
            &scope(),
            &SecretValue::new("fake-permission-secret"),
            Duration::from_secs(60),
        )
        .unwrap_or_else(|error| panic!("store failed: {error}"));
    let audit = AuditLog::open(
        &audit_path,
        RotationPolicy::new(1024, 2)
            .unwrap_or_else(|error| panic!("rotation policy failed: {error}")),
    )
    .unwrap_or_else(|error| panic!("audit open failed: {error}"));
    audit
        .append(&AuditEvent::now(
            AuditAction::Store,
            AuditOutcome::Succeeded,
            None,
        ))
        .unwrap_or_else(|error| panic!("append failed: {error}"));

    assert_eq!(
        fs::metadata(&directory)
            .unwrap_or_else(|error| panic!("metadata failed: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for path in [
        &vault_path,
        &directory.join("vault.bin.lock"),
        &audit_path,
        &directory.join("audit.jsonl.lock"),
    ] {
        assert_eq!(
            fs::metadata(path)
                .unwrap_or_else(|error| panic!("metadata failed: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn existing_parent_permissions_are_not_changed() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|error| panic!("set_permissions failed: {error}"));
    Vault::open(parent.path().join("vault.bin"), MasterKey::new(KEY))
        .unwrap_or_else(|error| panic!("open failed: {error}"));

    assert_eq!(
        fs::metadata(parent.path())
            .unwrap_or_else(|error| panic!("metadata failed: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[cfg(unix)]
#[test]
fn symlinked_storage_directory_is_rejected_without_touching_target() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let external = tempdir().unwrap_or_else(|error| panic!("external tempdir failed: {error}"));
    fs::set_permissions(external.path(), fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|error| panic!("set_permissions failed: {error}"));
    let storage = directory.path().join("storage");
    symlink(external.path(), &storage)
        .unwrap_or_else(|error| panic!("directory symlink failed: {error}"));

    assert!(matches!(
        Vault::open(storage.join("vault.bin"), MasterKey::new(KEY)),
        Err(VaultError::StorageUnavailable)
    ));
    assert_eq!(
        fs::metadata(external.path())
            .unwrap_or_else(|error| panic!("metadata failed: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(
        fs::read_dir(external.path())
            .unwrap_or_else(|error| panic!("read_dir failed: {error}"))
            .next()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn symlinked_vault_and_lock_files_are_rejected_without_touching_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    for name in ["vault.bin", "vault.bin.lock"] {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let external = directory.path().join("external");
        fs::write(&external, b"vault sentinel")
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        fs::set_permissions(&external, fs::Permissions::from_mode(0o644))
            .unwrap_or_else(|error| panic!("set_permissions failed: {error}"));
        symlink(&external, directory.path().join(name))
            .unwrap_or_else(|error| panic!("file symlink failed: {error}"));

        assert!(matches!(
            Vault::open(directory.path().join("vault.bin"), MasterKey::new(KEY)),
            Err(VaultError::StorageUnavailable)
        ));
        assert_eq!(
            fs::read(&external).unwrap_or_else(|error| panic!("read failed: {error}")),
            b"vault sentinel"
        );
        assert_eq!(
            fs::metadata(&external)
                .unwrap_or_else(|error| panic!("metadata failed: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinked_audit_and_lock_files_are_rejected_without_touching_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    for name in ["audit.jsonl", "audit.jsonl.lock"] {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let external = directory.path().join("external");
        fs::write(&external, b"audit sentinel")
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        fs::set_permissions(&external, fs::Permissions::from_mode(0o644))
            .unwrap_or_else(|error| panic!("set_permissions failed: {error}"));
        symlink(&external, directory.path().join(name))
            .unwrap_or_else(|error| panic!("file symlink failed: {error}"));

        assert!(matches!(
            AuditLog::open(
                directory.path().join("audit.jsonl"),
                RotationPolicy::new(1, 2)
                    .unwrap_or_else(|error| panic!("rotation policy failed: {error}")),
            ),
            Err(VaultError::StorageUnavailable)
        ));
        assert_eq!(
            fs::read(&external).unwrap_or_else(|error| panic!("read failed: {error}")),
            b"audit sentinel"
        );
        assert_eq!(
            fs::metadata(&external)
                .unwrap_or_else(|error| panic!("metadata failed: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinked_audit_rotation_target_is_rejected_without_touching_target() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let path = directory.path().join("audit.jsonl");
    let external = directory.path().join("external");
    fs::write(&external, b"rotation sentinel")
        .unwrap_or_else(|error| panic!("write failed: {error}"));
    fs::write(&path, b"existing audit line\n")
        .unwrap_or_else(|error| panic!("write failed: {error}"));
    let rotation_target = directory.path().join("audit.jsonl.1");
    symlink(&external, &rotation_target)
        .unwrap_or_else(|error| panic!("rotation symlink failed: {error}"));
    let audit = AuditLog::open(
        &path,
        RotationPolicy::new(1, 2).unwrap_or_else(|error| panic!("rotation policy failed: {error}")),
    )
    .unwrap_or_else(|error| panic!("audit open failed: {error}"));

    assert_eq!(
        audit.append(&AuditEvent::now(
            AuditAction::Resolve,
            AuditOutcome::Rejected,
            None,
        )),
        Err(VaultError::StorageUnavailable)
    );
    assert_eq!(
        fs::read(&external).unwrap_or_else(|error| panic!("read failed: {error}")),
        b"rotation sentinel"
    );
    assert!(
        fs::symlink_metadata(&rotation_target)
            .unwrap_or_else(|error| panic!("symlink metadata failed: {error}"))
            .file_type()
            .is_symlink()
    );
}

#[test]
fn secret_types_and_errors_redact_formatting() {
    let raw = "fake-format-secret";
    let key = MasterKey::new(KEY);
    assert!(!format!("{key:?}").contains(raw));
    let value = SecretValue::new(raw);
    assert!(!format!("{value:?} {value}").contains(raw));
    for error in [
        VaultError::InvalidInput,
        VaultError::StorageUnavailable,
        VaultError::RandomnessUnavailable,
        VaultError::CorruptOrWrongKey,
        VaultError::ReferenceRejected,
    ] {
        assert!(!format!("{error:?} {error}").contains(raw));
    }
}
