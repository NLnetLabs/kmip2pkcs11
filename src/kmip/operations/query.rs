use kmip::types::{
    common::{ObjectType, Operation},
    request::{BatchItem, QueryFunction, RequestPayload},
    response::{
        BatchItem as ResBatchItem, QueryResponsePayload, ResponsePayload, ResultReason,
        ResultStatus, ServerInformation,
    },
};

use crate::{
    config::Config,
    pkcs11::{pool::Pkcs11Pool, util::get_pkcs11_info},
};

pub fn op(
    pkcs11pool: &Pkcs11Pool,
    cfg: &Config,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, std::string::String)> {
    let RequestPayload::Query(query_functions) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Query payload".to_string(),
        ));
    };

    let mut operations = None;
    let mut object_types = None;
    let mut vendor_identification = None;
    let mut server_information = None;

    for query_function in query_functions {
        match query_function {
            QueryFunction::QueryOperations => {
                // TODO: Derive this from the operations we actually support.
                operations = Some(vec![
                    Operation::Activate,
                    Operation::CreateKeyPair,
                    Operation::DiscoverVersions,
                    Operation::Get,
                    Operation::Query,
                    Operation::Sign,
                ])
            }
            QueryFunction::QueryObjects => {
                object_types = Some(vec![ObjectType::PublicKey, ObjectType::PrivateKey])
            }
            QueryFunction::QueryServerInformation => {
                let self_ver = clap::crate_version!();
                let Ok(pkcs11_info) = get_pkcs11_info(pkcs11pool, cfg) else {
                    return Err((
                        ResultReason::GeneralFailure,
                        "Internal error: PKCS#11 info not available".to_string(),
                    ));
                };
                vendor_identification =
                    Some(format!("Nameshed-HSM-Relay {self_ver} using {pkcs11_info}"));
                server_information = Some(ServerInformation);
            }
            _ => { /* Ignore */ }
        }
    }

    Ok(ResBatchItem {
        operation: Some(*batch_item.operation()),
        unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
        result_status: ResultStatus::Success,
        result_reason: None,
        result_message: None,
        payload: Some(ResponsePayload::Query(QueryResponsePayload {
            operations,
            object_types,
            vendor_identification,
            server_information,
        })),
        message_extension: None,
    })
}
