//! Environment diagnostics for the CLI.

use std::{
    env, fs,
    net::{IpAddr, TcpListener},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::config::{self, CONFIG_FILE, Config, LOCAL_CONFIG_FILE};

pub(crate) struct DoctorReport {
    checks: Vec<Check>,
}

struct Check {
    label: &'static str,
    outcome: Outcome,
}

enum Outcome {
    Pass(&'static str),
    Info(&'static str),
    Fail(String),
}

impl DoctorReport {
    pub(crate) fn is_healthy(&self) -> bool {
        self.checks
            .iter()
            .all(|check| !matches!(check.outcome, Outcome::Fail(_)))
    }

    pub(crate) fn print(&self) {
        for check in &self.checks {
            match &check.outcome {
                Outcome::Pass(detail) => println!("[ok] {}: {detail}", check.label),
                Outcome::Info(detail) => println!("[info] {}: {detail}", check.label),
                Outcome::Fail(detail) => println!("[fail] {}: {detail}", check.label),
            }
        }
    }
}

pub(crate) fn run(root: &Path) -> DoctorReport {
    let config_path = root.join(CONFIG_FILE);
    let local_path = root.join(LOCAL_CONFIG_FILE);
    let presence = if config_path.is_file() {
        Outcome::Pass("present")
    } else {
        Outcome::Fail(format!("{CONFIG_FILE} is missing"))
    };
    let local_override = if local_path.is_file() {
        Outcome::Info("present and applied after the base configuration")
    } else {
        Outcome::Info("not present")
    };

    let (validity, config) = match config::load(root) {
        Ok(loaded) => {
            let override_detail = if loaded.local_override_present {
                "valid; local override applied"
            } else {
                "valid"
            };
            (Outcome::Pass(override_detail), loaded.config)
        }
        Err(error) => (Outcome::Fail(error.to_string()), Config::default()),
    };

    DoctorReport {
        checks: vec![
            Check {
                label: "config presence",
                outcome: presence,
            },
            Check {
                label: "local override",
                outcome: local_override,
            },
            Check {
                label: "config validity",
                outcome: validity,
            },
            Check {
                label: "storage directory",
                outcome: check_storage(root, &config),
            },
            Check {
                label: "loopback port",
                outcome: check_port(&config),
            },
            Check {
                label: "Claude command",
                outcome: check_command(&config.claude.command),
            },
            Check {
                label: "Codex command",
                outcome: check_optional_command("codex"),
            },
            Check {
                label: "OpenCode command",
                outcome: check_optional_command("opencode"),
            },
        ],
    }
}

fn check_storage(root: &Path, config: &Config) -> Outcome {
    let directory = if config.storage.directory.is_absolute() {
        config.storage.directory.clone()
    } else {
        root.join(&config.storage.directory)
    };

    if directory.exists() {
        if !directory.is_dir() {
            return Outcome::Fail("configured storage location is not a directory".to_owned());
        }
        return write_probe(&directory);
    }

    let Some(parent) = nearest_existing_ancestor(&directory) else {
        return Outcome::Fail("storage directory has no accessible parent".to_owned());
    };
    if !parent.is_dir() {
        return Outcome::Fail("storage directory has a non-directory parent".to_owned());
    }
    match write_probe(parent) {
        Outcome::Pass(_) => Outcome::Pass("can be created and written"),
        Outcome::Info(detail) => Outcome::Info(detail),
        Outcome::Fail(detail) => Outcome::Fail(detail),
    }
}

fn nearest_existing_ancestor(path: &Path) -> Option<&Path> {
    path.ancestors().find(|candidate| candidate.exists())
}

fn write_probe(directory: &Path) -> Outcome {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let probe = directory.join(format!(".blindfold-doctor-{}-{nonce}", std::process::id()));

    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(file) => {
            drop(file);
            match fs::remove_file(probe) {
                Ok(()) => Outcome::Pass("writable"),
                Err(_) => Outcome::Fail("write probe could not be cleaned up".to_owned()),
            }
        }
        Err(error) => Outcome::Fail(format!("not writable ({})", error.kind())),
    }
}

fn check_port(config: &Config) -> Outcome {
    let Ok(host) = config.proxy.host.parse::<IpAddr>() else {
        return Outcome::Fail("cannot check an invalid proxy host".to_owned());
    };
    match TcpListener::bind((host, config.proxy.port)) {
        Ok(listener) => {
            drop(listener);
            Outcome::Pass("available")
        }
        Err(error) => Outcome::Fail(format!("unavailable ({})", error.kind())),
    }
}

fn check_command(command: &str) -> Outcome {
    if command.contains(std::path::MAIN_SEPARATOR) {
        return if is_executable(Path::new(command)) {
            Outcome::Pass("available")
        } else {
            Outcome::Fail("not found or not executable".to_owned())
        };
    }

    let Some(path) = env::var_os("PATH") else {
        return Outcome::Fail("PATH is not set".to_owned());
    };
    if env::split_paths(&path).any(|directory| is_executable(&directory.join(command))) {
        Outcome::Pass("available")
    } else {
        Outcome::Fail("not found on PATH".to_owned())
    }
}

fn check_optional_command(command: &str) -> Outcome {
    match check_command(command) {
        Outcome::Fail(_) => Outcome::Info("not installed; this agent wrapper is unavailable"),
        outcome => outcome,
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs,
        net::{IpAddr, Ipv4Addr, TcpListener},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{Outcome, check_port, nearest_existing_ancestor};
    use crate::config::Config;

    #[test]
    fn finds_existing_parent_for_missing_storage() {
        let temp = std::env::temp_dir();
        let path = temp.join("blindfold-missing").join("nested");
        assert_eq!(nearest_existing_ancestor(&path), Some(temp.as_path()));
    }

    #[test]
    fn reports_occupied_port_without_exposing_address() -> Result<(), Box<dyn Error>> {
        let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let address = listener.local_addr()?;
        let mut config = Config::default();
        config.proxy.host = IpAddr::V4(Ipv4Addr::LOCALHOST).to_string();
        config.proxy.port = address.port();

        let Outcome::Fail(message) = check_port(&config) else {
            return Err("occupied port should fail".into());
        };
        assert!(!message.contains(&address.port().to_string()));
        drop(listener);
        Ok(())
    }

    #[test]
    fn write_probe_does_not_leave_a_file() -> Result<(), Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "blindfold-doctor-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory)?;
        let before = fs::read_dir(&directory)?.count();

        let outcome = super::write_probe(&directory);

        assert!(matches!(outcome, Outcome::Pass(_)));
        assert_eq!(fs::read_dir(&directory)?.count(), before);
        fs::remove_dir(directory)?;
        Ok(())
    }
}
