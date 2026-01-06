use std::path::{Path, PathBuf};

use clap::{Args as _, FromArgMatches};
use daemonbase::config::ConfigPath;
use daemonbase::error::Failed;
use daemonbase::{logging, process};
use serde::Deserialize;

#[derive(clap::Parser)]
pub struct Args {
    /// The config file to use.
    #[arg(short, long)]
    pub config: ConfigPath,

    /// Detach from the terminal
    #[arg(short, long)]
    pub detach: bool,

    #[command(next_help_heading = "Logging options", flatten)]
    pub log: logging::Args,

    #[command(next_help_heading = "Process options", flatten)]
    pub process: process::Args,
}

/// A cryptographic token key lister
#[derive(Clone, Deserialize)]
pub struct Config {
    /// The logging configuration.
    #[serde(flatten)]
    pub log: logging::Config,

    /// Path to the PKCS#11 .so library file.
    pub lib_path: PathBuf,

    #[serde(flatten)]
    pub listen_socket: ListenSocket,

    #[serde(flatten)]
    pub server_identity: ServerIdentity,

    /// Default PKCS#11 slot label/id/index for clients that don't provide KMIP authentication.
    ///
    /// SECURITY NOTE: When set, any client that passes TLS authentication can access this slot
    /// without providing KMIP-level credentials. Only use in single-tenant deployments where
    /// TLS client certificate verification is sufficient for access control.
    ///
    /// Both default_slot and default_pin must be set for this feature to be active.
    #[serde(default)]
    pub default_slot: Option<String>,

    /// Default PKCS#11 PIN for clients that don't provide KMIP authentication.
    ///
    /// Both default_slot and default_pin must be set for this feature to be active.
    #[serde(default)]
    pub default_pin: Option<String>,

    /// Enable KMIP Encrypt operation.
    ///
    /// SECURITY NOTE: When enabled, clients can use keys to encrypt data.
    /// This is required for OpenBao KMIP seal functionality.
    /// Default: false (disabled for backwards compatibility)
    #[serde(default)]
    pub enable_encrypt: bool,

    /// Enable KMIP Decrypt operation.
    ///
    /// SECURITY NOTE: When enabled, clients can use keys to decrypt data.
    /// This is required for OpenBao KMIP seal functionality.
    /// Default: false (disabled for backwards compatibility)
    #[serde(default)]
    pub enable_decrypt: bool,
}

#[derive(Clone, Deserialize)]
pub struct ServerIdentity {
    /// Path to the server certificate file in PEM format.
    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    /// Path to the server certificate key file in PEM format
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

#[derive(Clone, Deserialize)]
pub struct ListenSocket {
    /// IP address or hostname to listen on
    #[serde(default = "default_listen_addr")]
    pub addr: String,

    /// TCP port to listen on.
    #[serde(default = "default_listen_port")]
    pub port: u16,
}

fn default_listen_addr() -> String {
    "localhost".to_string()
}

fn default_listen_port() -> u16 {
    5696
}

/// Environment variable name for default HSM PIN
pub const DEFAULT_HSM_PIN_ENV: &str = "DEFAULT_HSM_PIN";

impl Config {
    /// Get the effective default PIN, checking environment variable if config is empty.
    /// Environment variable DEFAULT_HSM_PIN takes precedence over config file.
    pub fn effective_default_pin(&self) -> Option<String> {
        std::env::var(DEFAULT_HSM_PIN_ENV).ok().or_else(|| self.default_pin.clone())
    }

    /// Adds the basic arguments to a Clap command.
    ///
    /// Returns the command with the arguments added.
    pub fn config_args(app: clap::Command) -> clap::Command {
        Args::augment_args(app)
    }

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

    /// Loads the configuration based on command line options provided.
    ///
    /// The `matches` must be the result of getting argument matches from a
    /// clap app previously configured with
    /// [`config_args`](Self::config_args). Otherwise, the function is likely
    /// to panic.
    ///
    /// TODO: The current path needs to be provided to be able to deal with relative
    /// paths.
    pub fn from_arg_matches(matches: &clap::ArgMatches) -> Result<(Self, Args), Failed> {
        let args = Args::from_arg_matches(matches).expect("bug in command line arguments parser");
        let toml_str = std::fs::read_to_string(&args.config).unwrap();
        let mut config = Self::from_toml(&toml_str, None::<PathBuf>).unwrap();
        config.log.apply_args(&args.log);
        Ok((config, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> Config {
        Config::from_toml(
            r#"
            lib_path = "/usr/lib/softhsm/libsofthsm2.so"
            "#,
            None::<PathBuf>,
        )
        .unwrap()
    }

    #[test]
    fn test_default_credentials_not_set_by_default() {
        let config = minimal_config();
        assert!(config.default_slot.is_none());
        assert!(config.default_pin.is_none());
    }

    #[test]
    fn test_default_credentials_from_config() {
        let config = Config::from_toml(
            r#"
            lib_path = "/usr/lib/softhsm/libsofthsm2.so"
            default_slot = "test-slot"
            default_pin = "1234"
            "#,
            None::<PathBuf>,
        )
        .unwrap();

        assert_eq!(config.default_slot, Some("test-slot".to_string()));
        assert_eq!(config.default_pin, Some("1234".to_string()));
    }

    // Note: Tests for env var override behavior (effective_default_pin with DEFAULT_HSM_PIN)
    // are omitted because they require single-threaded execution due to shared global state.
    // The env var logic is trivial (std::env::var check) and tested manually.
    // Run with `cargo test -- --test-threads=1` if env var tests are needed.

    #[test]
    fn test_encrypt_decrypt_disabled_by_default() {
        let config = minimal_config();
        assert!(!config.enable_encrypt);
        assert!(!config.enable_decrypt);
    }

    #[test]
    fn test_encrypt_decrypt_can_be_enabled() {
        let config = Config::from_toml(
            r#"
            lib_path = "/usr/lib/softhsm/libsofthsm2.so"
            enable_encrypt = true
            enable_decrypt = true
            "#,
            None::<PathBuf>,
        )
        .unwrap();

        assert!(config.enable_encrypt);
        assert!(config.enable_decrypt);
    }

    #[test]
    fn test_encrypt_only() {
        let config = Config::from_toml(
            r#"
            lib_path = "/usr/lib/softhsm/libsofthsm2.so"
            enable_encrypt = true
            "#,
            None::<PathBuf>,
        )
        .unwrap();

        assert!(config.enable_encrypt);
        assert!(!config.enable_decrypt);
    }
}
