use kmip::types::{
    common::{AttributeValue, NameType},
    request::{BatchItem, RequestPayload},
    response::{BatchItem as ResBatchItem, ResponsePayload, ResultReason, ResultStatus},
};

use cryptoki::object::Attribute;

use crate::pkcs11::pool::Pkcs11Connection;
use crate::pkcs11::util::get_cached_handle_for_key;

pub fn op(
    pkcs11conn: Pkcs11Connection,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, String)> {
    let RequestPayload::ModifyAttribute(id, attr) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Modify Attribute payload".to_string(),
        ));
    };

    if id.is_none() {
        return Err((
            ResultReason::InvalidField,
            format!("UniqueIdentifier must be provided"),
        ));
    }

    if attr.0.0 != "Name" {
        return Err((
            ResultReason::PermissionDenied,
            format!("Modification of attribute '{}' is not supported", attr.0.0),
        ));
    }

    let id = id.as_ref().unwrap();

    let AttributeValue::Name(val, typ) = &attr.2 else {
        return Err((
            ResultReason::InvalidMessage,
            "Attribute Value payload is not a Name".to_string(),
        ));
    };

    let NameType::UninterpretedTextString = typ else {
        return Err((
            ResultReason::InvalidField,
            format!(
                "Modification of attribute '{}' is only supported as the KMIP NameType UninterpretedTextString",
                attr.0.0
            ),
        ));
    };

    let Some(key_handle) = get_cached_handle_for_key(&pkcs11conn, &id, None) else {
        return Err((
            ResultReason::ItemNotFound,
            format!("Key with id {} not found", id.0),
        ));
    };

    // TODO: Verify that no other key already has this name. Return Illegal
    // Operation error if so, per https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613614

    let pkcs11_attr = Attribute::Label(val.0.as_bytes().to_vec());
    pkcs11conn
        .session()
        .update_attributes(key_handle, &[pkcs11_attr])
        .map_err(|err| {
            (
                ResultReason::GeneralFailure,
                format!("PKCS#11 C_SetAttributeValue() failed with error: {err}"),
            )
        })?;

    Ok(ResBatchItem {
        operation: Some(*batch_item.operation()),
        unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
        result_status: ResultStatus::Success,
        result_reason: None,
        result_message: None,
        payload: Some(ResponsePayload::ModifyAttribute(
            kmip::types::response::AttributeEditResponsePayload {
                unique_identifier: id.clone(),
                attribute: kmip::types::response::Attribute {
                    name: attr.0.clone(),
                    index: attr.1.clone(),
                    value: attr.2.clone(),
                },
            },
        )),
        message_extension: None,
    })
}
