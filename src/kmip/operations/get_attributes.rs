use kmip::types::{
    common::Operation,
    request::{BatchItem, RequestPayload},
    response::{
        BatchItem as ResBatchItem, GetAttributesResponsePayload, ResponsePayload,
        ResultReason, ResultStatus,
    },
};

use crate::pkcs11::operations::get_attributes::get_key_attributes;
use crate::pkcs11::pool::Pkcs11Connection;

pub fn op(
    pkcs11conn: Pkcs11Connection,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, String)> {
    let RequestPayload::GetAttributes(unique_identifier, attribute_names) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a GetAttributes payload".to_string(),
        ));
    };

    // UniqueIdentifier is required for this operation
    let Some(id) = unique_identifier else {
        return Err((
            ResultReason::InvalidMessage,
            "GetAttributes requires a UniqueIdentifier".to_string(),
        ));
    };

    match get_key_attributes(pkcs11conn, id, attribute_names.as_ref()) {
        Ok(attributes) => Ok(ResBatchItem {
            operation: Some(Operation::GetAttributes),
            unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
            result_status: ResultStatus::Success,
            result_reason: None,
            result_message: None,
            payload: Some(ResponsePayload::GetAttributes(GetAttributesResponsePayload {
                unique_identifier: id.clone(),
                attributes: if attributes.is_empty() {
                    None
                } else {
                    Some(attributes)
                },
            })),
            message_extension: None,
        }),
        Err(err) => Err((ResultReason::ItemNotFound, err.to_string())),
    }
}
