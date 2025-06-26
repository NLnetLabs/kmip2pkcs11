use kmip::types::{
    common::ObjectType,
    request::{BatchItem, RequestPayload},
    response::{
        BatchItem as ResBatchItem, GetResponsePayload, ManagedObject, PublicKey, ResponsePayload,
        ResultReason, ResultStatus,
    },
};

use crate::pkcs11::operations::get::get_public_key;
use crate::pkcs11::pool::Pkcs11Connection;

pub fn op(
    pkcs11conn: Pkcs11Connection,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, std::string::String)> {
    let RequestPayload::Get(Some(id), _, _, _) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Create Key Pair payload".to_string(),
        ));
    };

    match get_public_key(pkcs11conn, id) {
        Ok(Some(key_block)) => {
            let cryptographic_object = ManagedObject::PublicKey(PublicKey { key_block });

            Ok(ResBatchItem {
                operation: Some(*batch_item.operation()),
                unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
                result_status: ResultStatus::Success,
                result_reason: None,
                result_message: None,
                payload: Some(ResponsePayload::Get(GetResponsePayload {
                    object_type: ObjectType::PublicKey,
                    unique_identifier: id.clone(),
                    cryptographic_object,
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
