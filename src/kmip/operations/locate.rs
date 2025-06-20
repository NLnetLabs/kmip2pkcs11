// use kmip::types::{
//     common::UniqueIdentifier,
//     request::BatchItem,
//     response::{
//         BatchItem as ResBatchItem, LocateResponsePayload, ResponsePayload, ResultReason,
//         ResultStatus,
//     },
// };

// use crate::{config::Cfg, pkcs11client};

// pub fn op(
//     cfg: &Cfg,
//     batch_item: &BatchItem,
// ) -> Result<ResBatchItem, (ResultReason, std::string::String)> {
//     let keys = pkcs11client::get_keys(cfg)
//         .map_err(|err| (ResultReason::CryptographicFailure, err.to_string()))?;

//     let payload = ResponsePayload::Locate(LocateResponsePayload {
//         located_items: Some(keys.len() as i32),
//         unique_identifiers: if keys.is_empty() {
//             None
//         } else {
//             Some(
//                 keys.iter()
//                     .map(|k| UniqueIdentifier(k.id.clone()))
//                     .collect(),
//             )
//         },
//     });

//     Ok(ResBatchItem {
//         operation: Some(batch_item.operation()).copied(),
//         unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
//         result_status: ResultStatus::Success,
//         result_reason: None,
//         result_message: None,
//         payload: Some(payload),
//         message_extension: None,
//     })
// }
