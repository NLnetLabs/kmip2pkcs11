//! Configuring kmip2pkcs11.
//!
//! This module defines configuration data types that match as closely as
//! possible the types and related TOML syntax used by Cascade, as kmip2pkcs11
//! is provided as a companion tool to Cascade and it is thus of benefit to
//! users of Cascade if the configuration interface offered by the two tools
//! is as similar as we can make it.
//!
//! Code re-use from Cascade is currently limited, instead types have been
//! reproduced in similar form here. Partly this difference is because the two
//! tools have distinct purposes, configuration needs and thus overlapping but
//! not identifical configuration settings. And partly it's because we build on
//! daemonbase while Cascade does not. It would be nice in future if we can
//! reduce these differences where applicable, but that would require making
//! daemonbase less proscriptive in how it is intended to be used so that it
//! can be fit into Cascade.
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use daemonbase::process::{GroupId, UserId};
use serde::{Deserialize, Serialize};
use tracing::level_filters::LevelFilter;

//-------- Config ------------------------------------------------------------

/// Configuration for kmip2pkcs11.
// Based on https://github.com/NLnetLabs/cascade/blob/v0.1.0-alpha5/src/config/mod.rs#L27
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Daemon-related configuration.
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// Settings required to load and use the customer provided PKCS#11 module.
    pub pkcs11: Pkcs11Config,

    /// The configuration of the KMIP TCP+TLS server.
    #[serde(default)]
    pub server: ServerConfig,
}

//-------- LoggingConfig -----------------------------------------------------

/// Logging configuration for kmip2pkcs11.
// Based on https://github.com/NLnetLabs/cascade/blob/v0.1.0-alpha5/src/config/mod.rs#L193
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LoggingConfig {
    /// The minimum severity of messages to log.
    #[serde(default, rename = "log-level")]
    pub level: LogLevel,

    /// Where to log messages to.
    #[serde(default, rename = "log-target")]
    pub target: LogTarget,
}

//-------- LogTarget ---------------------------------------------------------

/// A logging target.
// Based on https://github.com/NLnetLabs/cascade/blob/v0.1.0-alpha5/src/config/mod.rs#L397
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
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
// Based on https://github.com/NLnetLabs/cascade/blob/v0.1.0-alpha5/src/config/mod.rs#L353
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

/// Configuration settings required for kmip2pkcs11 to be able to load and use
/// a customer supplied PKCS#11 module.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Pkcs11Config {
    /// Path to the PKCS#11 .so library file.
    pub lib_path: PathBuf,
}

//-------- DaemonConfig ------------------------------------------------------

/// Daemon-related configuration for kmip2pkcs11.
// Based on https://github.com/NLnetLabs/cascade/blob/v0.1.0-alpha5/src/config/mod.rs#L152
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DaemonConfig {
    /// The logging configuration.
    #[serde(flatten)]
    pub log: LoggingConfig,

    /// Whether kmip2pkcs11 should fork on startup.
    #[serde(default)]
    pub daemonize: bool,

    /// The path to a PID file to maintain.
    #[serde(default)]
    pub pid_file: Option<PathBuf>,

    /// The identity to assume after startup.
    #[serde(default)]
    pub identity: Option<(UserId, GroupId)>,
}

//-------- ServerConfig ------------------------------------------------------

/// Configuration for the KMIP TCP+TLS server.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ServerConfig {
    /// The TCP socket address to listen on.
    #[serde(default = "default_server_addr")]
    pub addr: SocketAddr,

    /// The (optional) TLS certificate to use.
    ///
    /// If not specified a self-signed certificate will be generated.
    #[serde(default)]
    pub identity: Option<ServerIdentity>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addr: default_server_addr(),
            identity: None,
        }
    }
}

/// By default listen for incoming KMIP TCP connections on localhost port 5696
/// as defined by the KMIP specification and registered with IANA.
///
/// See:
///   - http://docs.oasis-open.org/kmip/profiles/v1.2/kmip-profiles-v1.2.html#_Toc409613170
///   - https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=kmip
fn default_server_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5696)
}

/// TLS certificate and corresponding private key for use with the KMIP
/// TCP+TLS server.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ServerIdentity {
    /// Path to the server certificate file in PEM format.
    pub cert_path: PathBuf,

    /// Path to the server certificate key file in PEM format
    pub key_path: PathBuf,
}
