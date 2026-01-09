use std::time::SystemTime;

use hex::ToHex;
use kmip::types::{
    response::ProtocolVersion,
    response::{
        BatchItem as ResBatchItem, ResponseHeader, ResponseMessage, ResultReason, ResultStatus,
    },
};
use tracing::error;

pub fn mk_err_batch_item(reason: ResultReason, message: String) -> ResBatchItem {
    ResBatchItem {
        operation: None,
        unique_batch_item_id: None,
        result_status: ResultStatus::OperationFailed,
        result_reason: Some(reason),
        result_message: Some(message),
        payload: None,
        message_extension: None,
    }
}

pub fn mk_response(batch_items: Vec<ResBatchItem>) -> Vec<u8> {
    let epoch_time_now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();

    let mut res = ResponseMessage {
        header: ResponseHeader {
            protocol_version: ProtocolVersion { major: 1, minor: 2 },
            timestamp: epoch_time_now,
            batch_count: batch_items.len().try_into().unwrap(),
        },
        batch_items,
    };

    match kmip_ttlv::ser::to_vec(&res) {
        Ok(res_bytes) => res_bytes,
        Err(err) => {
            let msg = format!("Error while serializing KMIP response: {err}");
            error!("{msg}");
            dbg!(&res);
            res.batch_items = vec![mk_err_batch_item(ResultReason::GeneralFailure, msg)];
            kmip_ttlv::ser::to_vec(&res).unwrap()
        }
    }
}

pub fn mk_kmip_hex_dump(cap: &[u8]) -> String {
    cap.encode_hex_upper::<String>()
        .as_bytes()
        // Display 32 hex characters per line.
        .chunks(32)
        // Split the hex characters into 4 space separated groups
        // of 8 characters.
        .map(|buf| {
            buf.chunks(8)
                .map(|buf| unsafe { str::from_utf8_unchecked(buf) })
                .collect::<Vec<&str>>()
                .join(" ")
        })
        .enumerate()
        // Display byte offsets per line, with 32 hex characters
        // being 16 bytes per line.
        .map(|(line_num, line)| format!("{:05}  {line}", line_num * 16))
        .collect::<Vec<String>>()
        .join("\n")
}
