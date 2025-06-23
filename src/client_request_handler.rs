use core::net::SocketAddr;

use std::io::ErrorKind;

use kmip::Config;
use kmip::types::common::Operation;
use kmip::types::request::RequestMessage;
use kmip::types::response::ResultReason;
use kmip_ttlv::PrettyPrinter;
use log::{debug, error, info, log_enabled, warn};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::config::Cfg;
use crate::kmip::operations::{activate, create_key_pair, get, sign, unknown};
use crate::kmip::util::{mk_err_batch_item, mk_kmip_hex_dump, mk_response};

pub async fn handle_client_requests(
    mut stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    cfg: Cfg,
) -> anyhow::Result<()> {
    let reader_config = Config::new();
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

        match kmip_ttlv::from_reader::<RequestMessage, _>(&mut stream, &reader_config).await {
            Ok((req, _cap)) if !is_supported_protocol_version(&req) => {
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

            Ok((req, req_bytes)) => {
                if log_enabled!(log::Level::Debug) {
                    let req_hex = mk_kmip_hex_dump(&req_bytes);
                    let req_human = pp.to_string(&req_bytes);
                    debug!("Request hex:\n{req_hex}\nRequest dump:\n{req_human}\n");
                }

                for batch_item in req.batch_items() {
                    info!(
                        "Processing batch item operation {} from client {peer_addr}",
                        batch_item.operation()
                    );

                    let res = match batch_item.operation() {
                        Operation::Activate => activate::op(&cfg, batch_item),
                        Operation::CreateKeyPair => create_key_pair::op(&cfg, batch_item),
                        Operation::Get => get::op(&cfg, batch_item),
                        // Operation::Locate => locate::op(&cfg, batch_item),
                        Operation::Sign => sign::op(&cfg, batch_item),
                        _ => unknown::op(&cfg, batch_item),
                    };

                    let res_batch_item = match res {
                        Ok(res_batch_item) => res_batch_item,
                        Err((reason, message)) => mk_err_batch_item(reason, message),
                    };

                    res_batch_items.push(res_batch_item);
                }
            }

            Err((err, _cap)) if is_disconnection_err(&err) => {
                // The client has gone, terminate this response stream processor.
                break Ok(());
            }

            Err((err, res_bytes)) => {
                let req_hex = mk_kmip_hex_dump(&res_bytes);
                let req_human = pp.to_string(&res_bytes);

                error!(
                    "Error while parsing KMIP request from client {peer_addr}: {err}.\nRequest hex:\n{req_hex}\nRequest dump:\n{req_human}\n",
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
                    format!("Unable to parse KMIP TTLV request: {err}"),
                ));
            }
        };

        let res_bytes = mk_response(res_batch_items);

        if log_enabled!(log::Level::Debug) {
            let res_hex = mk_kmip_hex_dump(&res_bytes);
            let res_human = pp.to_string(&res_bytes);
            debug!("Response hex:\n{res_hex}\nResponse dump:\n{res_human}\n");
        }

        stream.write_all(&res_bytes).await?;
    }
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
