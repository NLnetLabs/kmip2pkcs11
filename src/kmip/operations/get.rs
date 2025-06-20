use kmip::types::{
    request::{BatchItem, RequestPayload},
    response::{
        BatchItem as ResBatchItem, GetResponsePayload, ManagedObject, PublicKey, ResponsePayload,
        ResultReason, ResultStatus,
    },
};

use crate::{config::Cfg, pkcs11client};
use kmip::types::common::ObjectType;

pub fn op(
    cfg: &Cfg,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, std::string::String)> {
    let RequestPayload::Get(Some(id), _, _, _) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Create Key Pair payload".to_string(),
        ));
    };

    match pkcs11client::get_public_key(cfg, id) {
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
