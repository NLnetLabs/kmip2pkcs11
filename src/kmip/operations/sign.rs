use kmip::types::{
    request::{BatchItem, RequestPayload},
    response::{BatchItem as ResBatchItem, ResponsePayload, ResultReason, ResultStatus},
};

use crate::{config::Cfg, pkcs11client};
use kmip::types::response::SignResponsePayload;

pub fn op(
    cfg: &Cfg,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, std::string::String)> {
    let RequestPayload::Sign(Some(id), cryptographic_parameters, data) =
        batch_item.request_payload()
    else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Sign payload".to_string(),
        ));
    };

    match pkcs11client::sign(cfg, id, cryptographic_parameters, data) {
        Ok(signature_data) => {
            // Nothing more to do as PKCS#11 doesn't support activation.
            Ok(ResBatchItem {
                operation: Some(*batch_item.operation()),
                unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
                result_status: ResultStatus::Success,
                result_reason: None,
                result_message: None,
                payload: Some(ResponsePayload::Sign(SignResponsePayload {
                    unique_identifier: id.clone(),
                    signature_data,
                })),
                message_extension: None,
            })
        }

        Err(err) => Err((ResultReason::GeneralFailure, err.to_string())),
    }
}
