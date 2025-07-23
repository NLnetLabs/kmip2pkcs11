mod client_request_handler;
mod config;
mod kmip;
mod pkcs11;

use std::sync::Arc;

use clap::{Command, crate_authors, crate_version};
use config::Config;
use cryptoki::context::{Function, Pkcs11};
use cryptoki::error::Error as CryptokiError;
use cryptoki::error::RvError;
use daemonbase::error::ExitError;
use daemonbase::logging::Logger;
use daemonbase::process::Process;
use log::{error, info, warn};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::client_request_handler::handle_client_requests;
use crate::config::ServerIdentity;
use crate::pkcs11::error::Error;
use crate::pkcs11::util::{Pkcs11Pools, init_pkcs11};

impl From<pkcs11::error::Error> for ExitError {
    fn from(err: pkcs11::error::Error) -> Self {
        error!("PKCS#11 related fatal error: {err}");
        ExitError::default()
    }
}

fn main() -> Result<(), ExitError> {
    Logger::init_logging()?;

    let matches = Config::config_args(
        Command::new("nameshed-hsm-relay")
            .version(crate_version!())
            .author(crate_authors!())
            .about("Nameshed HSM Relay"),
    )
    .get_matches();
    let (mut config, args) = Config::from_arg_matches(&matches)?;
    Logger::from_config(&config.log)?.switch_logging(args.detach)?;
    let mut process = Process::from_config(args.process.into_config());

    // Note: This may fork. Don't create the Tokio runtime before calling this.
    // See: https://github.com/tokio-rs/tokio/issues/4301
    process.setup_daemon(args.detach)?;

    // TODO: Drop privileges before or after initializing the PKCS#11 library?
    info!(
        "Loading and initializing PKCS#11 library {}",
        config.lib_path.display()
    );
    let pkcs11 =
        init_pkcs11(&mut config).map_err(|err| improve_pkcs11_finalize_err(&config, err))?;
    announce_pkcs11_info(&pkcs11)?;
    let pkcs11_pools = Pkcs11Pools::new(pkcs11);

    let (certs, key) = load_or_generate_server_identity_cert(config.server_identity.clone())?;

    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .inspect_err(|err| error!("TLS fatal error: {err}"))
        .map_err(|_| ExitError::default())?;
    let acceptor = TlsAcceptor::from(Arc::new(rustls_config));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("nameshed-worker")
        .build()
        .unwrap();

    runtime.block_on(async move {
        info!(
            "Listening on {}:{}",
            config.listen_socket.addr, config.listen_socket.port
        );
        let listener = TcpListener::bind(format!(
            "{}:{}",
            config.listen_socket.addr, config.listen_socket.port
        ))
        .await
        .inspect_err(|err| {
            error!(
                "TCP fatal error while attempting to bind to {}:{}: {err}",
                config.listen_socket.addr, config.listen_socket.port
            )
        })
        .map_err(|_| ExitError::default())?;

        // TODO: This doesn't log at info/debug/trace level what it is doing
        // unless it fails. We also can't log ourselves if we think privileges
        // will be dropped because the args.process member fields are not visible
        // to us.
        process.drop_privileges()?;

        loop {
            let Ok((stream, peer_addr)) = listener
                .accept()
                .await
                .inspect_err(|err| error!("Error while accepting TCP connection: {err}"))
            else {
                continue;
            };
            let acceptor = acceptor.clone();
            let config = config.clone();
            let pkcs11_pools = pkcs11_pools.clone();

            info!("Waiting for connections...");
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    info!("Accepting connection from {peer_addr}");
                    let config = config.clone();
                    let pkcs11_pools = pkcs11_pools.clone();

                    tokio::spawn(async move {
                        if let Err(_err) =
                            handle_client_requests(stream, peer_addr, config, pkcs11_pools).await
                        {
                            error!("Connection with {peer_addr} terminated abnormally"); //: {err}");
                        } else {
                            info!("Connection with {peer_addr} terminated");
                        }
                    });
                }
                Err(err) => {
                    error!("Error accepting connection: {err}");
                }
            }
        }
    })
}

fn improve_pkcs11_finalize_err(config: &Config, err: pkcs11::error::Error) -> pkcs11::error::Error {
    {
        if matches!(
            err,
            Error::HsmFailure(CryptokiError::Pkcs11(
                RvError::ArgumentsBad,
                Function::Initialize
            ))
        ) {
            Error::UnusableConfig(format!(
                "PKCS#11 function C_Initialize() failed. Please consult the documentation for the PKCS#11 library at '{}'. Possible causes include insufficient access rights (e.g. to read a PKCS#11 vendor specific configuration file) or missing PKCS#11 vendor specific environment variables.",
                config.lib_path.display()
            ))
        } else {
            err
        }
    }
}

fn load_or_generate_server_identity_cert(
    server_identity: ServerIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ExitError> {
    match server_identity {
        ServerIdentity {
            cert_path: Some(cert_path),
            key_path: Some(key_path),
        } => {
            info!(
                "Loading server identity certificate '{}' and key '{}'",
                cert_path.display(),
                key_path.display()
            );
            let certs = CertificateDer::pem_file_iter(cert_path)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let key = PrivateKeyDer::from_pem_file(key_path).unwrap();
            Ok((certs, key))
        }

        _ => {
            warn!("Generating self-signed server identity certificate");
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let cert = cert.der().clone();
            let certs = vec![cert];
            let key = PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();
            Ok((certs, key))
        }
    }
}

fn announce_pkcs11_info(pkcs11: &Pkcs11) -> Result<(), Error> {
    let lib_info = pkcs11.get_library_info()?;
    info!(
        "Loaded {} PKCS#11 library v{} supporting Cryptoki v{}: {}",
        lib_info.manufacturer_id(),
        lib_info.library_version(),
        lib_info.cryptoki_version(),
        lib_info.library_description(),
    );
    Ok(())
}
