use kmip::types::{
    request::{BatchItem, RequestPayload},
    response::{
        BatchItem as ResBatchItem, ResponsePayload, ResultReason, ResultStatus, SignResponsePayload,
    },
};

use crate::pkcs11::operations::sign::sign;
use crate::pkcs11::pool::Pkcs11Connection;

pub fn op(
    pkcs11conn: Pkcs11Connection,
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

    match sign(pkcs11conn, id, cryptographic_parameters, data) {
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

        Err(err) if matches!(err, crate::pkcs11::error::Error::DataNotFound { .. }) => {
            Err((ResultReason::ItemNotFound, err.to_string()))
        }

        Err(err) => Err((ResultReason::GeneralFailure, err.to_string())),
    }
}
