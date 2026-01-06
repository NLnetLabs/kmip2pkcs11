use kmip::types::{
    common::Operation,
    request::{BatchItem, IVOrCounterOrNonce, RequestPayload},
    response::{
        BatchItem as ResBatchItem, EncryptResponsePayload, ResponsePayload,
        ResultReason, ResultStatus,
    },
};

use crate::pkcs11::operations::encrypt::encrypt_data;
use crate::pkcs11::pool::Pkcs11Connection;

pub fn op(
    pkcs11conn: Pkcs11Connection,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, String)> {
    let RequestPayload::Encrypt(unique_identifier, cryptographic_parameters, data, iv_counter_nonce) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not an Encrypt payload".to_string(),
        ));
    };

    // UniqueIdentifier is required for this operation
    let Some(id) = unique_identifier else {
        return Err((
            ResultReason::InvalidMessage,
            "Encrypt requires a UniqueIdentifier".to_string(),
        ));
    };

    // Convert IV from request if provided
    let iv = iv_counter_nonce.as_ref().map(|v| v.as_bytes());

    match encrypt_data(
        pkcs11conn,
        id,
        cryptographic_parameters.as_ref(),
        &data.0,
        iv,
    ) {
        Ok(result) => Ok(ResBatchItem {
            operation: Some(Operation::Encrypt),
            unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
            result_status: ResultStatus::Success,
            result_reason: None,
            result_message: None,
            payload: Some(ResponsePayload::Encrypt(EncryptResponsePayload {
                unique_identifier: id.clone(),
                data: result.ciphertext,
                iv_counter_nonce: result.iv.map(IVOrCounterOrNonce::new),
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
