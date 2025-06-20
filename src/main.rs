// TODO: Ensure clients can distinguish a problem with the relay vs a problem
// with the underlying PKCS#11 token.
mod client_request_handler;
mod config;
mod kmip;
mod pkcs11client;

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use config::Cfg;
use log::{error, info};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;

use crate::client_request_handler::handle_client_requests;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .with_span_events(FmtSpan::ENTER)
        .try_init()
        .ok();

    let cfg = Cfg::parse();

    let certs =
        CertificateDer::pem_file_iter(&cfg.server_cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&cfg.server_key_path)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:1818").await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let cfg = cfg.clone();

        info!("Waiting for connections...");
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    info!("Accepting connection from {peer_addr}");
                    if let Err(err) = handle_client_requests(stream, peer_addr, cfg).await {
                        error!("Connection with {peer_addr} terminated abnormally: {err}");
                    } else {
                        info!("Connection with {peer_addr} terminated");
                    }
                }
                Err(err) => {
                    error!("Error accepting connection: {err}");
                }
            }
        });
    }
}
