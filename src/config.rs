use std::path::PathBuf;

use clap::Parser;
use cryptoki::types::AuthPin;

/// A cryptographic token key lister
#[derive(Clone, Parser)]
#[command(about)]
pub struct Cfg {
    /// Path to the server certificate file in PEM format
    #[arg(long = "server-cert")]
    pub server_cert_path: PathBuf,

    /// Path to the server certificate key file in PEM format
    #[arg(long = "server-key")]
    pub server_key_path: PathBuf,

    #[arg(long)]
    pub lib_path: PathBuf,

    #[arg(long)]
    pub slot_id: Option<u64>,

    #[arg(long)]
    pub slot_label: Option<String>,

    #[arg(long)]
    pub user_pin: Option<AuthPin>,
}
