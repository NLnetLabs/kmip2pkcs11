mod client_request_handler;
mod kmip;
mod pkcs11;

use std::sync::Arc;

use clap::{Command, crate_authors, crate_description, crate_version};
use cryptoki::context::{Function, Pkcs11};
use cryptoki::error::Error as CryptokiError;
use cryptoki::error::RvError;
use daemonbase::error::{ExitError, Failed};
use daemonbase::logging::{Facility, Logger, Target};
use daemonbase::process::Process;
use kmip2pkcs11_cfg::args::Args;
use kmip2pkcs11_cfg::v1::{Config, LogLevel, LogTarget, ServerIdentity};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::client_request_handler::handle_client_requests;
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

    // Parse command-line arguments.
    let app = Command::new("kmip2pkcs11")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .next_line_help(true)
        .arg(
            clap::Arg::new("check_config")
                .long("check-config")
                .action(clap::ArgAction::SetTrue)
                .help("Check the configuration and exit"),
        );
    let cmd = Args::setup(app);
    let matches = cmd.get_matches();

    // Process parsed command-line arguments.
    let args = Args::process(&matches);

    // Load the config file.
    let mut config = Config::from_file(&args.config)
        .inspect_err(|err| error!("Invalid configuration file: {err}"))
        .map_err(|_| Failed)?;

    // Merge the command-line arguments into the config file.
    args.merge(&mut config);

    let level_filter = match config.daemon.log.log_level {
        LogLevel::Trace => daemonbase::logging::LevelFilter::Trace,
        LogLevel::Debug => daemonbase::logging::LevelFilter::Debug,
        LogLevel::Info => daemonbase::logging::LevelFilter::Info,
        LogLevel::Warning => daemonbase::logging::LevelFilter::Warn,
        LogLevel::Error => daemonbase::logging::LevelFilter::Error,
    };
    let log_target = match &config.daemon.log.log_target {
        LogTarget::File(path) => Target::File(path.to_path_buf()),
        LogTarget::Syslog => Target::Syslog(Facility::LOG_DAEMON),
        LogTarget::Stderr => Target::Stderr,
    };
    Logger::new(level_filter, log_target).switch_logging(config.daemon.daemonize)?;
    let mut process_config = daemonbase::process::Config::default();
    if let Some(file) = &config.daemon.pid_file {
        process_config = process_config.with_pid_file(file.clone().into());
    }
    if let Some(path) = &config.daemon.chroot {
        process_config = process_config.with_chroot(path.clone().into());
    }
    if let Some((user, group)) = &config.daemon.identity {
        process_config = process_config
            .with_user_id(user.clone())
            .with_group_id(group.clone());
    }
    let mut process = Process::from_config(process_config);

    // Note: This may fork. Don't create the Tokio runtime before calling this.
    // See: https://github.com/tokio-rs/tokio/issues/4301
    process.setup_daemon(config.daemon.daemonize)?;

    // Drop privileges before or after initializing the PKCS#11 library as it
    // may spawn threads which should not be done prior to forking.
    info!(
        "Loading and initializing PKCS#11 library {}",
        config.pkcs11.lib_path.display()
    );
    let pkcs11 =
        init_pkcs11(&mut config).map_err(|err| improve_pkcs11_finalize_err(&config, err))?;
    announce_pkcs11_info(&pkcs11)?;
    let pkcs11_pools = Pkcs11Pools::new(pkcs11);

    let (certs, key) = load_or_generate_server_identity_cert(config.server.identity.clone())?;

    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .inspect_err(|err| error!("TLS fatal error: {err}"))
        .map_err(|_| ExitError::default())?;
    let acceptor = TlsAcceptor::from(Arc::new(rustls_config));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kmip2pkcs11-worker")
        .build()
        .unwrap();

    runtime.block_on(async move {
        // Use the socket supplied by SystemD in preference to the config file
        // defined address and port.
        let listener =
            if let Ok(Some(std_listener)) = listenfd::ListenFd::from_env().take_tcp_listener(0) {
                info!(
                    "Listening on SystemD supplied socket at {}",
                    std_listener
                        .local_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or("unknown".into())
                );
                // As required by Tokio set the listener into non-blocking mode.
                // See: https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html#notes
                std_listener.set_nonblocking(true)
                    .inspect_err(|err| {
                        error!("Unable to set listener received from SystemD into non-blocking mode: {err}")
                    })
                    .map_err(|_| ExitError::default())?;
                let tokio_listener = TcpListener::from_std(std_listener)
                    .inspect_err(|err| {
                        error!("Unable to convert listener received from SystemD into a Tokio TcpListener: {err}")
                    })
                    .map_err(|_| ExitError::default())?;
                tokio_listener
            } else {
                info!(
                    "Listening on {}:{}",
                    config.server.listen_socket.addr, config.server.listen_socket.port
                );
                let listener = TcpListener::bind(format!(
                    "{}:{}",
                    config.server.listen_socket.addr, config.server.listen_socket.port
                ))
                .await
                .inspect_err(|err| {
                    error!(
                        "TCP fatal error while attempting to bind to {}:{}: {err}",
                        config.server.listen_socket.addr, config.server.listen_socket.port
                    )
                })
                .map_err(|_| ExitError::default())?;
                listener
            };

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
                config.pkcs11.lib_path.display()
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
