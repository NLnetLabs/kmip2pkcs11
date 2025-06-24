use kmip::types::{
    request::{BatchItem, RequestPayload},
    response::{
        ActivateResponsePayload, BatchItem as ResBatchItem, ResponsePayload, ResultReason,
        ResultStatus,
    },
};

use crate::config::Cfg;
use crate::pkcs11::operations::get::get_public_key;

pub fn op(
    cfg: &Cfg,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, std::string::String)> {
    let RequestPayload::Activate(Some(id)) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not an Activate payload".to_string(),
        ));
    };

    // Make sure the key exists
    match get_public_key(cfg, id) {
        Ok(Some(_)) => {
            // Nothing more to do as PKCS#11 doesn't support activation.
            Ok(ResBatchItem {
                operation: Some(*batch_item.operation()),
                unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
                result_status: ResultStatus::Success,
                result_reason: None,
                result_message: None,
                payload: Some(ResponsePayload::Activate(ActivateResponsePayload {
                    unique_identifier: id.clone(),
                })),
                message_extension: None,
            })
        }

        Ok(None) => Ok(ResBatchItem {
            operation: Some(*batch_item.operation()),
            unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(ResultReason::ItemNotFound),
            result_message: None,
            payload: None,
            message_extension: None,
        }),

        Err(err) => Err((ResultReason::GeneralFailure, err.to_string())),
    }
}
