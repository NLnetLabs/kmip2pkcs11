use std::path::{Path, PathBuf};

use daemonbase::{
    config::ConfigPath,
    process::{GroupId, UserId},
};
use serde::{Deserialize, Serialize};
use tracing::level_filters::LevelFilter;

//-------- LogConfig ---------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub daemon: DaemonConfig,

    pub pkcs11: Pkcs11Config,

    pub server: ServerConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogConfig {
    #[serde(default)]
    pub log_level: LogLevel,

    #[serde(default)]
    pub log_target: LogTarget,
}

//-------- LogTarget ---------------------------------------------------------

/// A logging target.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogTarget {
    /// Append logs to a file.
    ///
    /// If the file is a terminal, ANSI color codes may be used.
    File(PathBuf),

    /// Write logs to the UNIX syslog.
    Syslog,

    // Not suppported as daemonbase logging doesn't support logging to stdout.
    // /// Write logs to stdout.
    // Stdout,
    /// Write logs to stderr.
    #[default]
    Stderr,
}

//-------- LogLevel ----------------------------------------------------------

/// A logging level.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogLevel {
    /// A function or variable was interacted with, for debugging.
    Trace,

    /// Something occurred that may be relevant to debugging.
    Debug,

    /// Things are proceeding as expected.
    Info,

    /// Something does not appear to be correct.
    #[default]
    Warning,

    /// Something is wrong (but Cascade can recover).
    Error,
    // Not suppported as daemonbase logging doesn't support the critical level.
    // /// Something is wrong and Cascade can't function at all.
    // Critical,
}

impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warning => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
            // LogLevel::Critical => LevelFilter::ERROR,
        }
    }
}

//-------- Pkcs11Config ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Pkcs11Config {
    /// Path to the PKCS#11 .so library file.
    pub lib_path: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DaemonConfig {
    /// The logging configuration.
    #[serde(flatten)]
    pub log: LogConfig,

    /// Whether kmip2pkcs11 should fork on startup.
    #[serde(default)]
    pub daemonize: bool,

    /// The path to a PID file to maintain.
    #[serde(default)]
    pub pid_file: Option<PathBuf>,

    /// The directory to chroot into after startup.
    #[serde(default)]
    pub chroot: Option<PathBuf>,

    /// The identity to assume after startup.
    #[serde(default)]
    pub identity: Option<(UserId, GroupId)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerConfig {
    pub listen_socket: ListenSocket,

    pub identity: ServerIdentity,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerIdentity {
    /// Path to the server certificate file in PEM format.
    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    /// Path to the server certificate key file in PEM format
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ListenSocket {
    /// IP address or hostname to listen on
    #[serde(default = "default_listen_addr")]
    pub addr: String,

    /// TCP port to listen on.
    #[serde(default = "default_listen_port")]
    pub port: u16,
}

impl Default for ListenSocket {
    fn default() -> Self {
        Self {
            addr: default_listen_addr(),
            port: default_listen_port(),
        }
    }
}

fn default_listen_addr() -> String {
    "localhost".to_string()
}

fn default_listen_port() -> u16 {
    5696
}

impl Config {
    /// Creates a configuration from a bytes slice with TOML data.
    pub fn from_toml(
        slice: &str,
        base_dir: Option<impl AsRef<Path>>,
    ) -> Result<Self, toml::de::Error> {
        if let Some(ref base_dir) = base_dir {
            ConfigPath::set_base_path(base_dir.as_ref().into())
        }
        let res = toml::de::from_str(slice);
        ConfigPath::clear_base_path();
        res
    }

    /// Creates a configuration from a configuration file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let toml_str = std::fs::read_to_string(path).unwrap();
        Self::from_toml(&toml_str, None::<PathBuf>).map_err(|err| err.to_string())
    }
}
