use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
#[allow(unused_imports)]
use kmip::types::common::{
    AttributeName, AttributeValue, CryptographicAlgorithm, ObjectType, State, UniqueIdentifier,
};
use kmip::types::response::Attribute as KmipAttribute;
use log::{debug, info};

use crate::pkcs11::error::Error;
use crate::pkcs11::pool::Pkcs11Connection;

/// Get attributes for a key identified by its label (UniqueIdentifier).
///
/// This is used by OpenBao's KMIP seal to verify the key exists and is usable.
/// OpenBao sends the key label as the UniqueIdentifier (e.g., "openbao-seal-key").
pub fn get_key_attributes(
    pkcs11conn: Pkcs11Connection,
    id: &UniqueIdentifier,
    requested_attributes: Option<&Vec<AttributeName>>,
) -> Result<Vec<KmipAttribute>, Error> {
    // Find key by label (CKA_LABEL)
    let label = id.0.as_str();
    info!("Looking up key by label: {}", label);

    // Search for the key by label
    let handles = pkcs11conn
        .session()
        .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])?;

    if handles.is_empty() {
        return Err(Error::not_found("Key", "label", label));
    }

    let key_handle = handles[0];
    debug!("Found key handle: {:?}", key_handle);

    // Get key attributes from PKCS#11
    let attrs = pkcs11conn.session().get_attributes(
        key_handle,
        &[
            AttributeType::Class,
            AttributeType::KeyType,
            AttributeType::ValueLen,
            AttributeType::Label,
        ],
    )?;

    let mut object_type = None;
    let mut crypto_algorithm = None;
    let mut crypto_length: Option<i32> = None;

    for attr in attrs {
        match attr {
            Attribute::Class(class) => {
                object_type = match class {
                    ObjectClass::SECRET_KEY => Some(ObjectType::SymmetricKey),
                    ObjectClass::PUBLIC_KEY => Some(ObjectType::PublicKey),
                    ObjectClass::PRIVATE_KEY => Some(ObjectType::PrivateKey),
                    _ => None,
                };
            }
            Attribute::KeyType(kt) => {
                crypto_algorithm = match kt {
                    KeyType::AES => Some(CryptographicAlgorithm::AES),
                    KeyType::RSA => Some(CryptographicAlgorithm::RSA),
                    KeyType::EC => Some(CryptographicAlgorithm::ECDSA),
                    KeyType::DES3 => Some(CryptographicAlgorithm::TRIPLE_DES),
                    _ => None,
                };
            }
            Attribute::ValueLen(len) => {
                // PKCS#11 reports key length in bytes, KMIP uses bits
                // Ulong needs to be converted via into()
                let len_usize: usize = len.into();
                crypto_length = Some((len_usize * 8) as i32);
            }
            _ => {}
        }
    }

    // Build response attributes
    let mut result = Vec::new();

    // Helper to check if attribute is requested (or all if none specified)
    let should_include = |name: &str| -> bool {
        match requested_attributes {
            None => true, // Return all if none specified
            Some(names) if names.is_empty() => true,
            Some(names) => names.iter().any(|n| n.0 == name),
        }
    };

    // Note: ObjectType and CryptographicAlgorithm are commented out due to
    // serialization issues with the "Transparent" serde annotation that
    // produces TTLV that confuses some KMIP clients.
    // TODO: Fix kmip-protocol's serde serialization for these variants.

    // if should_include("Object Type") {
    //     if let Some(ot) = object_type {
    //         result.push(KmipAttribute {
    //             name: AttributeName("Object Type".to_string()),
    //             index: None,
    //             value: AttributeValue::ObjectType(ot),
    //         });
    //     }
    // }

    // if should_include("Cryptographic Algorithm") {
    //     if let Some(ca) = crypto_algorithm {
    //         result.push(KmipAttribute {
    //             name: AttributeName("Cryptographic Algorithm".to_string()),
    //             index: None,
    //             value: AttributeValue::CryptographicAlgorithm(ca),
    //         });
    //     }
    // }

    if should_include("Cryptographic Length") {
        if let Some(cl) = crypto_length {
            result.push(KmipAttribute {
                name: AttributeName("Cryptographic Length".to_string()),
                index: None,
                value: AttributeValue::Integer(cl),
            });
        }
    }

    if should_include("State") {
        // Keys in SoftHSM are always active once created
        result.push(KmipAttribute {
            name: AttributeName("State".to_string()),
            index: None,
            value: AttributeValue::State(State::Active),
        });
    }

    // Log what we found for debugging
    debug!(
        "Key {} found: object_type={:?}, algorithm={:?}, length_bits={:?}",
        label, object_type, crypto_algorithm, crypto_length
    );
    debug!("Returning {} attributes for key {}", result.len(), label);
    Ok(result)
}
