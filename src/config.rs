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

impl Config {
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
