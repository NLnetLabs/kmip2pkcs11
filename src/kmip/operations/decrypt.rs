use kmip::types::{
    common::Operation,
    request::{BatchItem, RequestPayload},
    response::{
        BatchItem as ResBatchItem, DecryptResponsePayload, ResponsePayload,
        ResultReason, ResultStatus,
    },
};

use crate::pkcs11::operations::decrypt::decrypt_data;
use crate::pkcs11::pool::Pkcs11Connection;

pub fn op(
    pkcs11conn: Pkcs11Connection,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, String)> {
    let RequestPayload::Decrypt(unique_identifier, cryptographic_parameters, data, iv_counter_nonce) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Decrypt payload".to_string(),
        ));
    };

    // UniqueIdentifier is required for this operation
    let Some(id) = unique_identifier else {
        return Err((
            ResultReason::InvalidMessage,
            "Decrypt requires a UniqueIdentifier".to_string(),
        ));
    };

    // Convert IV from request if provided
    let iv = iv_counter_nonce.as_ref().map(|v| v.as_bytes());

    match decrypt_data(
        pkcs11conn,
        id,
        cryptographic_parameters.as_ref(),
        &data.0,
        iv,
    ) {
        Ok(plaintext) => Ok(ResBatchItem {
            operation: Some(Operation::Decrypt),
            unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
            result_status: ResultStatus::Success,
            result_reason: None,
            result_message: None,
            payload: Some(ResponsePayload::Decrypt(DecryptResponsePayload {
                unique_identifier: id.clone(),
                data: plaintext,
            })),
            message_extension: None,
        }),
        Err(err) => Err((ResultReason::CryptographicFailure, err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    // Integration tests would require a real PKCS#11 token
}
