use kmip::types::{
    common::{AttributeName, AttributeValue, LinkType, LinkedObjectIdentifier},
    request::{BatchItem, RequestPayload},
    response::{
        Attribute, BatchItem as ResBatchItem, GetAttributesResponsePayload, ResponsePayload,
        ResultReason, ResultStatus,
    },
};

pub fn op(batch_item: &BatchItem) -> Result<ResBatchItem, (ResultReason, std::string::String)> {
    let RequestPayload::GetAttributes(Some(id), Some(attributes)) = batch_item.request_payload()
    else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Get Attributes payload".to_string(),
        ));
    };

    // We only support the Link attribute at present. PKCS#11 doesn't have an
    // equivalent of Link so this is implemented here, no need to call PKCS#11
    // code.
    let link_info = if attributes.contains(&AttributeName("Link".into())) {
        match id {
            _ if id.ends_with("_pub") => {
                // Assume that we created the key and the linked key is the
                // corresponding private key, which has the same CKA_ID as the
                // public key so we just have to replace _pub with _priv.
                let link = id.replace("_pub", "_priv");
                Some((link, LinkType::PrivateKeyLink))
            }
            _ if id.ends_with("_priv") => {
                // Assume that we created the key and the linked key is the
                // corresponding private key, which has the same CKA_ID as the
                // public key so we just have to replace _pub with _priv.
                let link = id.replace("_priv", "_pub");
                Some((link, LinkType::PublicKeyLink))
            }
            _ => {
                // Assume that the given ID is a raw CKA_ID that refers to a key
                // that was not created by us, but was created by some other
                // DNS signer and that the most likely scenarios is that, as suggested
                // by the PKCS#11 v2.40 specification, and as done by OpenDNSSEC, that
                // the corresponding other half of this key has the same CKA_ID as the
                // given ID, i.e. the same ID. We have no way of knowing if the caller
                // passed us a public key ID or a private key ID as they have the same
                // value, so we assume they passed us a public key ID, and give back
                // an ID that is KMIP unique, i.e. has the _priv suffix..
                Some((format!("{}_priv", id.0), LinkType::PrivateKeyLink))
            }
        }
    } else {
        None
    };

    // KMIP 1.2 4.12 Get Attributes:
    //   "If no requested attributes exist, then the response SHALL consist
    //    only of the Unique Identifier"
    let attributes = link_info.map(|(link, link_type)| {
        vec![Attribute {
            name: AttributeName("Link".into()),
            index: None,
            value: AttributeValue::Link(link_type, LinkedObjectIdentifier(link)),
        }]
    });

    Ok(ResBatchItem {
        operation: Some(*batch_item.operation()),
        unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
        result_status: ResultStatus::Success,
        result_reason: None,
        result_message: None,
        payload: Some(ResponsePayload::GetAttributes(
            GetAttributesResponsePayload {
                unique_identifier: id.clone(),
                attributes,
            },
        )),
        message_extension: None,
    })
}
