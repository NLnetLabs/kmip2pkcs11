use std::path::PathBuf;

use clap::Parser;
use cryptoki::types::AuthPin;
use daemonbase::{logging, process};

/// A cryptographic token key lister
#[derive(Parser)]
#[command(about)]
pub struct Cfg {
    #[command(flatten)]
    pub log: logging::Args,

    /// Detach from the terminal
    #[arg(short, long)]
    pub detach: bool,

    #[command(flatten)]
    pub process: process::Args,

    #[command(flatten)]
    pub server: ServerSettings,
}

#[derive(Clone, clap::Args)]
pub struct ServerSettings {
    /// Path to the server certificate file in PEM format
    #[arg(long = "server-cert")]
    pub cert_path: PathBuf,

    /// Path to the server certificate key file in PEM format
    #[arg(long = "server-key")]
    pub key_path: PathBuf,

    #[arg(long)]
    pub lib_path: PathBuf,

    #[arg(long)]
    pub slot_id: Option<u64>,

    #[arg(long)]
    pub slot_label: Option<String>,

    #[arg(long)]
    pub user_pin: Option<AuthPin>,
}
