//! Configuration loading, defaults, and validation.

use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

pub(crate) const CONFIG_FILE: &str = ".blindfold.yaml";
pub(crate) const LOCAL_CONFIG_FILE: &str = ".blindfold.local.yaml";
const CURRENT_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const DEFAULT_CONFIG: &str = "\
version: 1
mode: balanced
storage:
  directory: .blindfold
proxy:
  host: 127.0.0.1
  port: 8765
claude:
  command: claude
";

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Config {
    #[serde(default = "missing_version")]
    pub(crate) version: u32,
    pub(crate) mode: Mode,
    pub(crate) storage: StorageConfig,
    pub(crate) proxy: ProxyConfig,
    pub(crate) claude: ClaudeConfig,
}

const fn missing_version() -> u32 {
    0
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            mode: Mode::Balanced,
            storage: StorageConfig::default(),
            proxy: ProxyConfig::default(),
            claude: ClaudeConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    Strict,
    #[default]
    Balanced,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct StorageConfig {
    pub(crate) directory: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from(".blindfold"),
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ProxyConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port: 8765,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ClaudeConfig {
    pub(crate) command: String,
}

impl Default for ClaudeConfig {
    fn default() -> Self {
        Self {
            command: "claude".to_owned(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigOverride {
    version: Option<u32>,
    mode: Option<Mode>,
    storage: Option<StorageOverride>,
    proxy: Option<ProxyOverride>,
    claude: Option<ClaudeOverride>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct StorageOverride {
    directory: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ProxyOverride {
    host: Option<String>,
    port: Option<u16>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClaudeOverride {
    command: Option<String>,
}

#[derive(Debug)]
pub(crate) enum ConfigError {
    Read {
        file: &'static str,
        source: io::Error,
    },
    Parse {
        file: &'static str,
    },
    TooLarge {
        file: &'static str,
    },
    InvalidEncoding {
        file: &'static str,
    },
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { file, source } => {
                write!(formatter, "could not read {file}: {}", source.kind())
            }
            Self::Parse { file } => write!(
                formatter,
                "{file} is not valid Blindfold YAML; check its syntax, fields, and value types"
            ),
            Self::TooLarge { file } => {
                write!(formatter, "{file} exceeds the maximum supported size")
            }
            Self::InvalidEncoding { file } => {
                write!(formatter, "{file} must contain valid UTF-8")
            }
            Self::Invalid { field, reason } => {
                write!(formatter, "invalid configuration field `{field}`: {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug)]
pub(crate) enum InitError {
    AlreadyExists,
    Write(io::Error),
}

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => write!(
                formatter,
                "{CONFIG_FILE} already exists; no changes were made"
            ),
            Self::Write(error) => write!(
                formatter,
                "could not create {CONFIG_FILE}: {}",
                error.kind()
            ),
        }
    }
}

pub(crate) struct LoadedConfig {
    pub(crate) config: Config,
    pub(crate) local_override_present: bool,
}

pub(crate) fn init(root: &Path) -> Result<(), InitError> {
    let path = root.join(CONFIG_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                InitError::AlreadyExists
            } else {
                InitError::Write(error)
            }
        })?;

    file.write_all(DEFAULT_CONFIG.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(InitError::Write)
}

pub(crate) fn load(root: &Path) -> Result<LoadedConfig, ConfigError> {
    let base = read::<Config>(&root.join(CONFIG_FILE), CONFIG_FILE)?;
    let local_path = root.join(LOCAL_CONFIG_FILE);
    let local_override_present = local_path.exists();
    let config = if local_override_present {
        let overrides = read::<ConfigOverride>(&local_path, LOCAL_CONFIG_FILE)?;
        merge(base, overrides)
    } else {
        base
    };

    validate(&config)?;
    Ok(LoadedConfig {
        config,
        local_override_present,
    })
}

fn read<T>(path: &Path, file: &'static str) -> Result<T, ConfigError>
where
    T: for<'de> Deserialize<'de>,
{
    let contents = fs::read(path).map_err(|source| ConfigError::Read { file, source })?;
    if contents.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge { file });
    }
    let contents =
        std::str::from_utf8(&contents).map_err(|_| ConfigError::InvalidEncoding { file })?;
    serde_saphyr::from_str(contents).map_err(|_| ConfigError::Parse { file })
}

fn merge(mut config: Config, overrides: ConfigOverride) -> Config {
    if let Some(version) = overrides.version {
        config.version = version;
    }
    if let Some(mode) = overrides.mode {
        config.mode = mode;
    }
    if let Some(storage) = overrides.storage
        && let Some(directory) = storage.directory
    {
        config.storage.directory = directory;
    }
    if let Some(proxy) = overrides.proxy {
        if let Some(host) = proxy.host {
            config.proxy.host = host;
        }
        if let Some(port) = proxy.port {
            config.proxy.port = port;
        }
    }
    if let Some(claude) = overrides.claude
        && let Some(command) = claude.command
    {
        config.claude.command = command;
    }
    config
}

fn validate(config: &Config) -> Result<(), ConfigError> {
    if config.version != CURRENT_VERSION {
        return Err(ConfigError::Invalid {
            field: "version",
            reason: "unsupported schema version",
        });
    }
    if config.storage.directory.as_os_str().is_empty() {
        return Err(ConfigError::Invalid {
            field: "storage.directory",
            reason: "must not be empty",
        });
    }
    let host = config
        .proxy
        .host
        .parse::<IpAddr>()
        .map_err(|_| ConfigError::Invalid {
            field: "proxy.host",
            reason: "must be a loopback IP address",
        })?;
    if !host.is_loopback() {
        return Err(ConfigError::Invalid {
            field: "proxy.host",
            reason: "must be a loopback IP address",
        });
    }
    if config.proxy.port == 0 {
        return Err(ConfigError::Invalid {
            field: "proxy.port",
            reason: "must be between 1 and 65535",
        });
    }
    if config.claude.command.trim().is_empty() {
        return Err(ConfigError::Invalid {
            field: "claude.command",
            reason: "must not be empty",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        CONFIG_FILE, Config, ConfigError, ConfigOverride, MAX_CONFIG_BYTES, merge, read, validate,
    };

    static NEXT_TEMP_PATH: AtomicU64 = AtomicU64::new(0);

    fn config_test_path() -> Result<PathBuf, std::time::SystemTimeError> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sequence = NEXT_TEMP_PATH.fetch_add(1, Ordering::Relaxed);
        Ok(std::env::temp_dir().join(format!(
            "blindfold-config-test-{}-{nonce}-{sequence}.yaml",
            std::process::id()
        )))
    }

    #[test]
    fn defaults_are_valid_and_loopback_only() {
        assert!(validate(&Config::default()).is_ok());
    }

    #[test]
    fn rejects_oversized_config_without_echoing_contents() -> Result<(), Box<dyn Error>> {
        let path = config_test_path()?;
        let sensitive_marker = "do-not-echo-this-marker";
        let mut contents = vec![b' '; MAX_CONFIG_BYTES + 1];
        contents[..sensitive_marker.len()].copy_from_slice(sensitive_marker.as_bytes());
        fs::write(&path, contents)?;

        let Err(error) = read::<Config>(&path, CONFIG_FILE) else {
            return Err("oversized configuration was accepted".into());
        };
        let diagnostic = error.to_string();

        assert!(matches!(error, ConfigError::TooLarge { .. }));
        assert!(!diagnostic.contains(sensitive_marker));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn rejects_invalid_utf8_without_echoing_bytes() -> Result<(), Box<dyn Error>> {
        let path = config_test_path()?;
        fs::write(&path, [0xff, 0xfe, 0xfd])?;

        let Err(error) = read::<Config>(&path, CONFIG_FILE) else {
            return Err("invalid UTF-8 configuration was accepted".into());
        };

        assert!(matches!(error, ConfigError::InvalidEncoding { .. }));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn rejects_duplicate_keys() {
        let result =
            serde_saphyr::from_str::<Config>("version: 1\nproxy:\n  port: 8765\n  port: 9000\n");

        assert!(result.is_err());
    }

    #[test]
    fn override_only_changes_present_fields() -> Result<(), serde_saphyr::Error> {
        let overrides: ConfigOverride = serde_saphyr::from_str("proxy:\n  port: 9000\n")?;
        let config = merge(Config::default(), overrides);

        assert_eq!(config.proxy.port, 9000);
        assert_eq!(config.proxy.host, "127.0.0.1");
        Ok(())
    }

    #[test]
    fn rejects_non_loopback_proxy_host_without_echoing_it() -> Result<(), &'static str> {
        let mut config = Config::default();
        let sensitive_value = "203.0.113.42";
        config.proxy.host = sensitive_value.to_owned();

        let Err(error) = validate(&config) else {
            return Err("non-loopback host was accepted");
        };
        let message = error.to_string();
        assert!(matches!(error, ConfigError::Invalid { .. }));
        assert!(!message.contains(sensitive_value));
        Ok(())
    }

    #[test]
    fn schema_version_is_required() -> Result<(), serde_saphyr::Error> {
        let config: Config = serde_saphyr::from_str("mode: balanced\n")?;
        let result = validate(&config);

        assert!(matches!(
            result,
            Err(ConfigError::Invalid {
                field: "version",
                ..
            })
        ));
        Ok(())
    }
}
