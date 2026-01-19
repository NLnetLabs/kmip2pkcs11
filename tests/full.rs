//! Test the full path between KMIP clients and PKCS#11 HSM.
//!
//! This is a full-system test: it initializes `kmip2pkcs11` with [SoftHSMv2]
//! and queries it from a KMIP client. The full breadth of supported KMIP
//! operations is tested.
//!
//! [SoftHSMv2]: https://github.com/softhsm/SoftHSMv2
//!
//! # Process
//!
//! A single `kmip2pkcs11` server is initialized using [SoftHSMv2]. It is
//! configured to store all filesystem state in a temporary directory, so that
//! distinct invocations do not affect each other. Multiple tests are executed
//! against that server. If any of them fail, they can be run in isolation.

// Only available on Unix machines.
#![cfg(unix)]

use std::{
    io,
    net::{Ipv6Addr, SocketAddr, TcpListener},
    process::Command,
    sync::Arc,
    time::Duration,
};

use domain::crypto::{
    ring,
    sign::{GenerateParams, SignRaw},
};
use kmip::client::pool::SyncConnPool;

use command_fds::{CommandFdExt, FdMapping};

/// A running `kmip2pkcs11` daemon.
pub struct Daemon {
    /// The address of the KMIP server.
    address: SocketAddr,

    /// The daemon process.
    process: std::process::Child,

    /// A pre-built slot (label, PIN, and SO PIN).
    slot: (String, String, String),

    /// The temporary directory holding the daemon's state.
    tempdir: tempfile::TempDir,
}

impl Daemon {
    /// Launch a new [`Daemon`].
    pub fn launch() -> io::Result<Self> {
        // Bind a TCP socket for the KMIP server.
        let sock = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))?;
        let addr = sock.local_addr()?;

        // Allocate a temporary directory for the daemon.
        let tempdir = tempfile::tempdir()?;

        // Determine the location of the SoftHSMv2 library.
        // TODO: Allow overriding with env var / CLI.
        let lib_path = "/usr/lib64/softhsm/libsofthsm2.so";

        // Configure the daemon.
        let config_path = tempdir.path().join("config.toml");
        let log_path = tempdir.path().join("log");
        // TODO: Use <https://crates.io/crates/indoc>?
        std::fs::write(
            &config_path,
            format!(
                r#"
version = "v1"
pkcs11.lib-path = {lib_path:?}
daemon.log-level = "debug"
daemon.log-target = {{ type = "file", path = {log_path:?} }}
"#
            ),
        )?;

        // Configure SoftHSMv2.
        let tokens_path = tempdir.path().join("tokens").display().to_string();
        let hsm_config_path = tempdir.path().join("softhsm2.conf");
        std::fs::write(
            &hsm_config_path,
            format!(
                r#"
directories.tokendir = {tokens_path}
objectstore.backend = file
log.level = DEBUG
"#
            ),
        )?;

        // Create the tokens directory.
        std::fs::create_dir_all(&tokens_path)?;

        // Initialize the HSM slot/token.
        let label = String::from("kmip2pkcs11-test");
        let so_pin = String::from("123456");
        let pin = String::from("abcdef");
        if !Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                &label,
                "--so-pin",
                &so_pin,
                "--pin",
                &pin,
            ])
            .env("SOFTHSM2_CONF", &hsm_config_path)
            .spawn()?
            .wait()?
            .success()
        {
            return Err(io::Error::other("could not initialize SoftHSMv2"));
        }

        // Make sure the daemon binary is ready.
        let project_dir = std::env::current_dir()?;
        if !Command::new("cargo")
            .args(["build", "--bin", "kmip2pkcs11"])
            .spawn()?
            .wait()?
            .success()
        {
            return Err(io::Error::other("could not build 'kmip2pkcs11'"));
        }

        // Launch the daemon.
        let daemon_path = project_dir.join("target/debug/kmip2pkcs11");
        let proc = Command::new(&daemon_path)
            .arg("--config")
            .arg(&config_path)
            .fd_mappings(vec![FdMapping {
                parent_fd: sock.into(),
                child_fd: 3,
            }])
            .unwrap()
            .env("SOFTHSM2_CONF", &hsm_config_path)
            .env("LISTEN_FDS", "1")
            .current_dir(tempdir.path())
            .spawn()?;

        Ok(Self {
            address: addr,
            process: proc,
            slot: (label, pin, so_pin),
            tempdir,
        })
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Stop the daemon.
        // TODO: Use SIGTERM?
        let _ = self.process.kill();

        if std::thread::panicking() {
            // Try to provide the daemon log file.
            if let Ok(log) = std::fs::read_to_string(self.tempdir.path().join("log")) {
                eprintln!("kmip2pkcs11 log:\n{log}");
            }
        }
    }
}

fn main() {
    // Launch the daemon.
    let daemon = Daemon::launch().unwrap_or_else(|err| {
        eprintln!("Could not launch the daemon: {err}");
        std::process::exit(1)
    });

    // Establish a connection pool for talking to the daemon.
    let conn_settings = Arc::new(domain_kmip::ConnectionSettings {
        host: daemon.address.ip().to_string(),
        port: daemon.address.port(),
        username: Some(daemon.slot.0.clone()),
        password: Some(daemon.slot.1.clone()),
        insecure: true,
        client_cert: None,
        server_cert: None,
        ca_cert: None,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        write_timeout: Some(Duration::from_secs(5)),
        max_response_bytes: Some(4096),
    });
    let conn_pool = SyncConnPool::new(
        daemon.address.to_string(),
        conn_settings,
        32,
        Some(Duration::from_secs(5)),
        Some(Duration::from_secs(5)),
    )
    .unwrap();

    print!("test_keygen_signing(RsaSha256 {{ bits: 1024 }})...");
    test_keygen_signing(&conn_pool, GenerateParams::RsaSha256 { bits: 1024 });
    println!("ok");

    print!("test_keygen_signing(EcdsaP256Sha256)...");
    test_keygen_signing(&conn_pool, GenerateParams::EcdsaP256Sha256);
    println!("ok");
}

/// Test that key generation and signing works.
///
/// A new key will be generated (using the given parameters) and used for
/// signing. The public key will be retrieved and used to locally verify the
/// signature.
fn test_keygen_signing(pool: &SyncConnPool, key_params: GenerateParams) {
    let algorithm = key_params.algorithm();

    // Generate a new key.
    let key =
        domain_kmip::sign::generate("A-pub".into(), "A-priv".into(), key_params, 0, pool.clone())
            .unwrap();

    // Retrive the public key, for local use.
    let dnskey = key.dnskey();
    let pubkey = ring::PublicKey::from_dnskey(&dnskey).unwrap();

    // Sign data with this key.
    let data = b"Hello World!";
    let sig = key.sign_raw(data).unwrap();

    // Verify the signature.
    assert_eq!(algorithm, sig.algorithm());
    pubkey.verify(data, sig.as_ref()).unwrap();
}
