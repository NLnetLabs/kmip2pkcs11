use std::path::PathBuf;

use clap::Parser;

/// A cryptographic token key lister
#[derive(Clone, Parser)]
#[command(about)]
pub struct Cfg {
    /// Path to the PKCS#11 .so library file.
    #[arg(long)]
    pub lib_path: PathBuf,

    #[command(flatten, next_help_heading = "Listen Socket (optional)")]
    pub listen_socket: ListenSocket,

    #[command(flatten, next_help_heading = "Server Identity (optional, default: self-signed)")]
    pub server_identity: ServerIdentity,
}

#[derive(Clone, Parser)]
pub struct ServerIdentity {
    /// Path to the server certificate file in PEM format.
    #[arg(long = "server-cert", requires = "key_path")]
    pub cert_path: Option<PathBuf>,

    /// Path to the server certificate key file in PEM format
    #[arg(long = "server-key", requires = "cert_path")]
    pub key_path: Option<PathBuf>,
}

#[derive(Clone, Parser)]
pub struct ListenSocket {
    /// IP address or hostname to listen on
    #[arg(long = "server-addr", default_value = "localhost")]
    pub addr: String,

    /// TCP port to listen on.
    #[arg(long = "server-port", default_value_t = 5696)]
    pub port: u16,
}
