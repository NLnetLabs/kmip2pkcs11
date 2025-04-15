mod config;
mod key;
mod pkcs11client;

use core::net::SocketAddr;

use std::io::ErrorKind;
use std::sync::Arc;

use clap::Parser;
use config::{Cfg, ServerSettings};
use daemonbase::error::{ExitError, Failed};
use daemonbase::logging::Logger;
use daemonbase::process::Process;
use kmip::Config;
use kmip::types::common::{Operation, UniqueIdentifier};
use kmip::types::request::RequestMessage;
use kmip::types::response::ResultStatus;
use kmip::types::response::{
    BatchItem, LocateResponsePayload, ProtocolVersion, ResponseHeader, ResponseMessage,
    ResponsePayload,
};
use kmip_ttlv::PrettyPrinter;
use log::{debug, error, info, trace, warn};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

#[tokio::main]
async fn main() -> Result<(), ExitError> {
    Logger::init_logging()?;

    let cfg = Cfg::parse();
    let log = Logger::from_config(&cfg.log.to_config())?;
    let mut process = Process::from_config(cfg.process.into_config());

    log.switch_logging(cfg.detach)?;
    process.setup_daemon(cfg.detach)?;

    let certs = CertificateDer::pem_file_iter(&cfg.server.cert_path)
        .map_err(|_| Failed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Failed)?;
    let key = PrivateKeyDer::from_pem_file(&cfg.server.key_path).map_err(|_| Failed)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:1818")
        .await
        .map_err(|_| Failed)?;

    process.drop_privileges()?;

    loop {
        let (stream, peer_addr) = listener.accept().await.map_err(|_| Failed)?;
        let acceptor = acceptor.clone();
        let cfg = cfg.server.clone();

        eprintln!("Accepting");
        tokio::spawn(async move {
            let stream = acceptor.accept(stream).await.unwrap();
            eprintln!("Processing");
            process_stream(stream, peer_addr, cfg).await.unwrap();
        });
    }
}

async fn process_stream(
    mut stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    cfg: ServerSettings,
) -> Result<(), ExitError> {
    let reader_config = Config::new();
    let pp = PrettyPrinter::new().with_tag_prefix("4200".into());

    loop {
        if let Err(err) = stream.get_ref().0.readable().await {
            // Don't warn about client disconnection.
            // TODO: Categorize the various std::io::ErrorKinds into fatal and
            // non-fatal variants and only abort on fatal errors.
            if err.kind() != ErrorKind::UnexpectedEof {
                warn!("Closing connection with client {peer_addr} due to error: {err}");
                return Ok(());
            }
        }

        let (req, _cap): (RequestMessage, Vec<u8>) =
            match kmip_ttlv::from_reader(&mut stream, &reader_config).await {
                Ok((res, cap)) => (res, cap),
                Err((err, cap)) => {
                    error!("Error while parsing KMIP request: {err}");
                    debug!("KMIP TTLV: {}", pp.to_diag_string(&cap));
                    continue;
                    // TODO: Return a KMIP error to the client.
                }
            };

        for batch_item in req.batch_items() {
            info!(
                "Processing batch item operation {} from client {peer_addr}",
                batch_item.operation()
            );
            match batch_item.operation() {
                Operation::Locate => {
                    // TODO: Factor code out into helper function(s).
                    let keys = pkcs11client::get_keys(&cfg).unwrap();

                    let payload = ResponsePayload::Locate(LocateResponsePayload {
                        located_items: Some(keys.len() as i32),
                        unique_identifiers: if keys.is_empty() {
                            None
                        } else {
                            Some(
                                keys.iter()
                                    .map(|k| UniqueIdentifier(k.id.clone()))
                                    .collect(),
                            )
                        },
                    });

                    let resp = ResponseMessage {
                        header: ResponseHeader {
                            protocol_version: ProtocolVersion {
                                major: req.0.0.0.0,
                                minor: req.0.0.1.0,
                            },
                            timestamp: 0,
                            batch_count: 1,
                        },
                        batch_items: vec![BatchItem {
                            operation: Some(batch_item.operation()).copied(),
                            unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
                            result_status: ResultStatus::Success,
                            result_reason: None,
                            result_message: None,
                            payload: Some(payload),
                            message_extension: None,
                        }],
                    };

                    let ttlv = kmip_ttlv::ser::to_vec(&resp).unwrap();
                    trace!("DIAG: {}", pp.to_diag_string(&ttlv));
                    stream.write_all(&ttlv).await.unwrap();
                }
                _ => {
                    // TODO: Support more operations.
                    // TODO: Respond with unsupported error to the client.
                }
            }
        }
    }
}
