use kmip::types::{
    request::{BatchItem, RequestPayload},
    response::{
        BatchItem as ResBatchItem, DiscoverVersionsResponsePayload, ResponsePayload, ResultReason,
        ResultStatus,
    },
};

pub fn op(batch_item: &BatchItem) -> Result<ResBatchItem, (ResultReason, std::string::String)> {
    let RequestPayload::DiscoverVersions(client_versions) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a DiscoverVersions payload".to_string(),
        ));
    };

    let supported_versions = vec![(1, 2), (1, 1), (1, 0)];
    let common_versions = if client_versions.is_empty() {
        supported_versions
    } else {
        supported_versions
            .iter()
            .filter_map(|&(major, minor)| {
                if client_versions.contains(&kmip::types::request::ProtocolVersion(
                    kmip::types::request::ProtocolVersionMajor(major),
                    kmip::types::request::ProtocolVersionMinor(minor),
                )) {
                    Some((major, minor))
                } else {
                    None
                }
            })
            .collect()
    };

    let response_versions = common_versions
        .iter()
        .map(|&(major, minor)| kmip::types::response::ProtocolVersion { major, minor })
        .collect();

    Ok(ResBatchItem {
        operation: Some(*batch_item.operation()),
        unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
        result_status: ResultStatus::Success,
        result_reason: None,
        result_message: None,
        payload: Some(ResponsePayload::DiscoverVersions(
            DiscoverVersionsResponsePayload {
                supported_versions: Some(response_versions),
            },
        )),
        message_extension: None,
    })
}
