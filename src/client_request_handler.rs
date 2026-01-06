use core::net::SocketAddr;

use std::io::ErrorKind;

use cryptoki::object::ObjectHandle;
use cryptoki::types::AuthPin;
use daemonbase::error::{ExitError, Failed};
use kmip::ttlv::FastScanner;
use kmip::types::common::Operation;
use kmip::types::request::RequestMessage;
use kmip::types::response::{BatchItem, ResultReason};
use kmip_ttlv::PrettyPrinter;
use log::{debug, error, info, log_enabled, warn};
use moka::sync::Cache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::config::Config;
use crate::kmip::operations::{
    activate, create_key_pair, decrypt, discover_versions, encrypt, get, get_attributes,
    modify_attribute, query, sign, unknown,
};
use crate::kmip::util::{mk_err_batch_item, mk_kmip_hex_dump, mk_response};
use crate::pkcs11::util::Pkcs11Pools;

pub type HandleCache = Cache<String, ObjectHandle>;

/// Read a complete TTLV message from the stream.
/// Returns the raw bytes of the message.
async fn read_ttlv_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    // TTLV header: 3 bytes tag + 1 byte type + 4 bytes length = 8 bytes
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).await?;

    // Extract length from bytes 4-7 (big endian)
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

    // Read the value bytes (padded to 8-byte boundary)
    let padded_length = (length + 7) & !7;
    let mut value = vec![0u8; padded_length];
    reader.read_exact(&mut value).await?;

    // Combine header and value into complete message
    let mut message = Vec::with_capacity(8 + padded_length);
    message.extend_from_slice(&header);
    message.extend_from_slice(&value);

    Ok(message)
}

/// Parse a RequestMessage from raw TTLV bytes using fast_scan.
fn parse_request_fast(bytes: &[u8]) -> Result<RequestMessage, String> {
    let mut scanner = FastScanner::new(bytes)
        .map_err(|e| format!("FastScanner init error: {:?}", e))?;
    RequestMessage::fast_scan(&mut scanner)
        .map_err(|e| format!("FastScan error: {:?}", e))
}

pub async fn handle_client_requests(
    mut stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    mut config: Config,
    mut pkcs11_pools: Pkcs11Pools,
) -> Result<(), ExitError> {
    let _reader_config = kmip::Config::new();
    let tag_map = kmip::tag_map::make_kmip_tag_map();
    let enum_map = kmip::tag_map::make_kmip_enum_map();
    let pp = PrettyPrinter::new()
        .with_tag_prefix("4200".into())
        .with_tag_map(tag_map)
        .with_enum_map(enum_map);

    loop {
        if let Err(err) = stream.get_ref().0.readable().await {
            // Don't warn about client disconnection.
            // TODO: Categorize the various std::io::ErrorKinds into fatal and
            // non-fatal variants and only abort on fatal errors.
            if err.kind() != ErrorKind::UnexpectedEof {
                warn!("Closing connection with client {peer_addr} due to error: {err}");
            }
            return Ok(());
        }

        let mut res_batch_items = vec![];

        // Read raw TTLV bytes from stream
        let req_bytes = match read_ttlv_message(&mut stream).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::UnexpectedEof || err.kind() == ErrorKind::ConnectionReset => {
                // Client disconnected
                break Ok(());
            }
            Err(err) => {
                error!("Error reading KMIP request from client {peer_addr}: {err}");
                res_batch_items.push(mk_err_batch_item(
                    ResultReason::GeneralFailure,
                    format!("Unable to read KMIP request: {err}"),
                ));
                // Send error response and continue
                let res_bytes = mk_response(res_batch_items);
                if let Err(e) = stream.write_all(&res_bytes).await {
                    warn!("Error sending response to {peer_addr}: {e}");
                }
                continue;
            }
        };

        if log_enabled!(log::Level::Debug) {
            let req_hex = mk_kmip_hex_dump(&req_bytes);
            let req_human = pp.to_string(&req_bytes);
            debug!("Request hex:\n{req_hex}\nRequest dump:\n{req_human}\n");
        }

        // Parse using fast_scan (handles operation-dependent payloads correctly)
        let req = match parse_request_fast(&req_bytes) {
            Ok(req) => req,
            Err(err) => {
                let req_hex = mk_kmip_hex_dump(&req_bytes);
                let req_human = pp.to_string(&req_bytes);
                error!(
                    "Error while parsing KMIP request from client {peer_addr}: {err}.\nRequest hex:\n{req_hex}\nRequest dump:\n{req_human}\n",
                );
                res_batch_items.push(mk_err_batch_item(
                    ResultReason::GeneralFailure,
                    format!("Unable to parse KMIP TTLV request: {err}"),
                ));
                // Send error response and continue
                let res_bytes = mk_response(res_batch_items);
                if let Err(e) = stream.write_all(&res_bytes).await {
                    warn!("Error sending response to {peer_addr}: {e}");
                }
                continue;
            }
        };

        if !is_supported_protocol_version(&req) {
            // https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613599
            // 11 Error Handling
            // 11.1 General
            //   Error Definition:
            //     "Protocol major version mismatch"
            //   Action:
            //     "Response message containing a header and a Batch Item
            //      without Operation, but with the Result Status field set to
            //      Operation Failed"
            res_batch_items.push(mk_err_batch_item(
                ResultReason::GeneralFailure,
                "Only KMIP protocol version <= 1.2 are supported".to_string(),
            ));
        } else {
            let (res, c, p) = tokio::task::spawn_blocking(move || {
                let r = process_request(&config, &pkcs11_pools, peer_addr, req);
                (r, config, pkcs11_pools)
            })
            .await
            .map_err(|_| ExitError::from(Failed))?;

            config = c;
            pkcs11_pools = p;

            res_batch_items.append(&mut res?);
        }

        let res_bytes = mk_response(res_batch_items);

        if log_enabled!(log::Level::Debug) {
            let res_hex = mk_kmip_hex_dump(&res_bytes);
            let res_human = pp.to_string(&res_bytes);
            debug!("Response hex:\n{res_hex}\nResponse dump:\n{res_human}\n");
        }

        stream.write_all(&res_bytes).await.unwrap();
    }
}

fn process_request(
    config: &Config,
    pkcs11_pools: &Pkcs11Pools,
    peer_addr: SocketAddr,
    req: RequestMessage,
) -> Result<Vec<BatchItem>, ExitError> {
    let authentication = req.header().authentication();

    // Get credentials from KMIP request or fall back to configured defaults
    let (slot_label_id_or_index, pin): (String, String) =
        match authentication.and_then(|auth| auth.username()) {
            Some(slot) => {
                // Username provided - password must also be provided (no mixing with defaults)
                let Some(pin) = authentication.and_then(|auth| auth.password()) else {
                    return Ok(vec![mk_err_batch_item(
                        ResultReason::GeneralFailure,
                        "Requests must be authenticated with a password (PKCS#11 pin)".to_string(),
                    )]);
                };
                (slot.to_string(), pin.to_string())
            }
            None => {
                // No username - check for configured defaults (both must be set)
                // PIN can come from config file or DEFAULT_HSM_PIN env var
                match (&config.default_slot, config.effective_default_pin()) {
                    (Some(slot), Some(ref pin)) => {
                        debug!(
                            "Using configured default credentials for client {peer_addr} (slot: {slot})"
                        );
                        (slot.clone(), pin.clone())
                    }
                    _ => {
                        return Ok(vec![mk_err_batch_item(
                            ResultReason::GeneralFailure,
                            "Requests must be authenticated with a username (PKCS#11 slot label/id/index)"
                                .to_string(),
                        )]);
                    }
                }
            }
        };

    let pool = match pkcs11_pools.get(&slot_label_id_or_index) {
        Ok(pool) => pool,
        Err(err) => {
            return Ok(vec![mk_err_batch_item(
                ResultReason::AuthenticationNotSuccessful,
                format!("No PKCS#11 slot found: {err}",),
            )]);
        }
    };

    let mut res_batch_items = vec![];

    let tid = std::thread::current();
    info!(
        "Processing batch of {} items from peer {peer_addr} on thread {tid:?}",
        req.batch_items().len()
    );

    for batch_item in req.batch_items() {
        debug!(
            "Processing batch item operation {} from client {peer_addr}",
            batch_item.operation()
        );

        let start = std::time::Instant::now();

        // Note: we are NOT compliant with the KMIP 1.2 Baseline
        // Server profile [1] because we lack support for the
        // following KMIP operations:
        //   - Locate
        //   - Check
        //   - Get Attributes
        //   - Add Attribute
        //   - Modify Attribute
        //   - Delete Attribute
        //   - Revoke
        //   - Destroy (TODO: We will need to support this)
        // [1]: https://docs.oasis-open.org/kmip/profiles/v1.2/os/kmip-profiles-v1.2-os.html#_Toc409613184
        let res = match batch_item.operation() {
            Operation::Query => query::op(&pool, config, batch_item),
            _ => {
                let pkcs11conn = pool.get().unwrap();
                if let Err(err) = pkcs11conn.ensure_logged_in(AuthPin::new(pin.to_string())) {
                    Err((ResultReason::AuthenticationNotSuccessful, err.to_string()))
                } else {
                    match batch_item.operation() {
                        Operation::Activate => activate::op(pkcs11conn, batch_item),
                        Operation::CreateKeyPair => create_key_pair::op(pkcs11conn, batch_item),
                        Operation::DiscoverVersions => discover_versions::op(batch_item),
                        Operation::Get => get::op(pkcs11conn, batch_item),
                        Operation::GetAttributes => get_attributes::op(pkcs11conn, batch_item),
                        Operation::ModifyAttribute => modify_attribute::op(pkcs11conn, batch_item),
                        Operation::Encrypt => {
                            if config.enable_encrypt {
                                encrypt::op(pkcs11conn, batch_item)
                            } else {
                                Err((
                                    ResultReason::OperationNotSupported,
                                    "Encrypt operation is disabled. Set enable_encrypt = true in config.".to_string(),
                                ))
                            }
                        }
                        Operation::Decrypt => {
                            if config.enable_decrypt {
                                decrypt::op(pkcs11conn, batch_item)
                            } else {
                                Err((
                                    ResultReason::OperationNotSupported,
                                    "Decrypt operation is disabled. Set enable_decrypt = true in config.".to_string(),
                                ))
                            }
                        }
                        Operation::Sign => sign::op(pkcs11conn, batch_item),
                        _ => unknown::op(batch_item),
                    }
                }
            }
        };

        debug!(
            "Processed batch item operation {} from client {peer_addr} in {}us: {}",
            batch_item.operation(),
            start.elapsed().as_micros(),
            if res.is_ok() { "Succeeded" } else { "Failed" },
        );

        let res_batch_item = match res {
            Ok(res_batch_item) => res_batch_item,
            Err((reason, message)) => mk_err_batch_item(reason, message),
        };

        res_batch_items.push(res_batch_item);
    }

    Ok(res_batch_items)
}

fn is_supported_protocol_version(req: &RequestMessage) -> bool {
    let ver = req.header().protocol_version();
    let major_ver = ver.0.0;
    let minor_ver = ver.1.0;
    major_ver == 1 && minor_ver <= 2
}

pub fn is_disconnection_err(err: &kmip_ttlv::error::Error) -> bool {
    if let kmip_ttlv::error::ErrorKind::IoError(err) = err.kind() {
        matches!(
            err.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
        )
    } else {
        false
    }
}
