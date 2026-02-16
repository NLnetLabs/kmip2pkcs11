use core::net::SocketAddr;

use cryptoki::object::ObjectHandle;
use cryptoki::types::AuthPin;
use daemonbase::error::{ExitError, Failed};
use kmip::ttlv::FastScanner;
use kmip::types::common::Operation;
use kmip::types::request::RequestMessage;
use kmip::types::response::{BatchItem, ResultReason};
use kmip_ttlv::PrettyPrinter;
use kmip2pkcs11_cfg::v1::Config;
use moka::sync::Cache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{Level, debug, enabled, error, info, warn};

use crate::kmip::operations::{
    activate, create_key_pair, discover_versions, get, modify_attribute, query, sign, unknown,
};
use crate::kmip::util::{mk_err_batch_item, mk_kmip_hex_dump, mk_response};
use crate::pkcs11::util::Pkcs11Pools;

pub type HandleCache = Cache<String, ObjectHandle>;

pub async fn handle_client_requests(
    mut stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    mut config: Config,
    mut pkcs11_pools: Pkcs11Pools,
) -> Result<(), ExitError> {
    let tag_map = kmip::tag_map::make_kmip_tag_map();
    let enum_map = kmip::tag_map::make_kmip_enum_map();
    let pp = PrettyPrinter::new()
        .with_tag_prefix("4200".into())
        .with_tag_map(tag_map)
        .with_enum_map(enum_map);

    // A buffer accumulating data read thus far.
    //
    // TODO: Use a more efficient buffer type, that can avoid shifting the data
    // every time a request message is consumed.
    let mut buffer = Vec::with_capacity(8192);

    loop {
        // Try parsing a request message from buffered data.
        let (request, request_bytes) = loop {
            // Try reading from the buffer.
            let available = buffer.len() - buffer.len() % 8;
            let mut scanner = FastScanner::new(&buffer[..available])
                .expect("the provided buffer has a multiple of 8 bytes");
            if scanner.have_next() {
                // A complete TTLV element is available. Try to parse it.
                let request = RequestMessage::fast_scan(&mut scanner);
                let consumed = available - scanner.remaining().as_flattened().len();
                break (request, &buffer[..consumed]);
            }

            // 'buffer' did not contain enough data. Try to add to it.
            if buffer.len() >= 8192 {
                // The message being received is concerningly large.
                warn!("Client {peer_addr} tried sending a >8KiB message");
                return Ok(());
            }
            let start = buffer.len();
            buffer.resize(8192, 0u8);

            match stream.read(&mut buffer[start..8192]).await {
                // The client has closed the connection.
                Ok(0) => {
                    if !buffer.is_empty() {
                        warn!(
                            "Client {peer_addr} closed connection with a partial request received"
                        );
                    }
                    return Ok(());
                }

                // Some data was received successfully.
                Ok(amt) => buffer.truncate(start + amt),

                // An unexpected error has occurred.
                Err(err) => {
                    // TODO: Categorize the various std::io::ErrorKinds into
                    // fatal and non-fatal variants and only abort on fatal
                    // errors.
                    warn!("Closing connection with client {peer_addr} due to error: {err}");
                    return Ok(());
                }
            };
        };

        let mut res_batch_items = vec![];

        match request {
            Ok(request) if !is_supported_protocol_version(&request) => {
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
            }

            Ok(request) => {
                if enabled!(Level::DEBUG) {
                    let req_hex = mk_kmip_hex_dump(request_bytes);
                    let req_human = pp.to_string(request_bytes);
                    debug!("Request hex:\n{req_hex}\nRequest dump:\n{req_human}\n");
                }

                let (res, c, p) = tokio::task::spawn_blocking(move || {
                    let r = process_request(&config, &pkcs11_pools, peer_addr, request);
                    (r, config, pkcs11_pools)
                })
                .await
                .map_err(|_| ExitError::from(Failed))?;

                config = c;
                pkcs11_pools = p;

                res_batch_items.append(&mut res?);
            }

            Err(error) => {
                let req_hex = mk_kmip_hex_dump(request_bytes);
                let req_human = pp.to_string(request_bytes);

                error!(
                    "Error while parsing KMIP request from client {peer_addr}: {error}.\nRequest hex:\n{req_hex}\nRequest dump:\n{req_human}\n",
                );

                // https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613599
                // 11 Error Handling
                // 11.1 General
                //   Error Definition:
                //     "Message cannot be parsed"
                //   Action:
                //     "Response message containing a header and a Batch Item
                //      without Operation, but with the Result Status field set to
                //      Operation Failed"
                res_batch_items.push(mk_err_batch_item(
                    ResultReason::GeneralFailure,
                    format!("Unable to parse KMIP TTLV request: {error}"),
                ));
            }
        };

        buffer.drain(..request_bytes.len());
        let res_bytes = mk_response(res_batch_items);

        if enabled!(Level::DEBUG) {
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

    let Some(slot_label_id_or_index) = authentication.and_then(|auth| auth.username()) else {
        return Ok(vec![mk_err_batch_item(
            ResultReason::GeneralFailure,
            "Requests must be authenticated with a username (PKCS#11 slot label/id/index)"
                .to_string(),
        )]);
    };

    let Some(pin) = authentication.and_then(|auth| auth.password()) else {
        return Ok(vec![mk_err_batch_item(
            ResultReason::GeneralFailure,
            "Requests must be authenticated with a password (PKCS#11 pin)".to_string(),
        )]);
    };

    let pool = match pkcs11_pools.get(slot_label_id_or_index) {
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
                if let Err(err) =
                    pkcs11conn.ensure_logged_in(AuthPin::new(pin.to_string().into_boxed_str()))
                {
                    Err((ResultReason::AuthenticationNotSuccessful, err.to_string()))
                } else {
                    match batch_item.operation() {
                        Operation::Activate => activate::op(pkcs11conn, batch_item),
                        Operation::CreateKeyPair => create_key_pair::op(pkcs11conn, batch_item),
                        Operation::DiscoverVersions => discover_versions::op(batch_item),
                        Operation::Get => get::op(pkcs11conn, batch_item),
                        Operation::ModifyAttribute => modify_attribute::op(pkcs11conn, batch_item),
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
