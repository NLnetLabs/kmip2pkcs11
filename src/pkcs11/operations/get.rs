use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use kmip::types::common::{
    CryptographicAlgorithm, KeyFormatType, KeyMaterial, TransparentRSAPublicKey, UniqueIdentifier,
};
use kmip::types::response::{KeyBlock, KeyValue};
use log::info;

use crate::pkcs11::error::Error;
use crate::pkcs11::pool::Pkcs11Connection;
use crate::pkcs11::util::get_cached_handle_for_key;

pub fn get_public_key(
    pkcs11conn: Pkcs11Connection,
    id: &UniqueIdentifier,
) -> Result<Option<KeyBlock>, Error> {
    let key_handle = get_cached_handle_for_key(&pkcs11conn, id, false);

    if let Some(key_handle) = key_handle {
        info!(
            "Getting attributes for public key handle {key_handle} (KMIP id {})...",
            id.0
        );
        Ok(Some(get_key_details(&pkcs11conn, key_handle)?))
    } else {
        Ok(None)
    }
}

pub fn get_private_key(
    pkcs11conn: Pkcs11Connection,
    id: &UniqueIdentifier,
) -> Result<Option<KeyBlock>, Error> {
    let key_handle = get_cached_handle_for_key(&pkcs11conn, id, true);

    if let Some(key_handle) = key_handle {
        info!(
            "Getting attributes for private key handle {key_handle} (KMIP id {})...",
            id.0
        );
        Ok(Some(get_key_details(&pkcs11conn, key_handle)?))
    } else {
        Ok(None)
    }
}

fn get_key_details(
    pkcs11conn: &Pkcs11Connection,
    key_handle: ObjectHandle,
) -> Result<KeyBlock, Error> {
    let mut cryptographic_algorithm: Option<CryptographicAlgorithm> = None;
    let mut cryptographic_length: Option<i32> = None;
    let mut modulus: Option<Vec<u8>> = None;
    let mut modulus_bits: Option<usize> = None;
    let mut public_exponent: Option<Vec<u8>> = None;
    let mut ec_point: Option<Vec<u8>> = None;

    let request_attrs = vec![
        AttributeType::Class,
        AttributeType::Modulus,
        AttributeType::ModulusBits,    // For RSA keys
        AttributeType::PublicExponent, // For RSA keys
        AttributeType::KeyType,
        AttributeType::EcPoint, // For ECDSA keys, DER encoded
        AttributeType::KeyGenMechanism,
    ];

    let attrs = pkcs11conn
        .session()
        .get_attributes(key_handle, &request_attrs)?;

    if attrs.is_empty() {
        return Err(Error::not_found("Key", "ObjectHandle", key_handle));
    }

    // https://docs.oasis-open.org/kmip/ug/v1.2/cn01/kmip-ug-v1.2-cn01.html#_Toc407027125
    //   "“Raw” key format is intended to be applied to symmetric keys and not
    //    asymmetric keys"
    //
    // As we deal in assymetric keys (RSA, ECDSA), not symmetric keys, we
    // should not use KeyFormatType::Raw. However, Fortanix DSM returns
    // KeyFormatType::Raw when fetching key data for an ECDSA public key.

    // NOTE: When generating DNSKEY RDATA OpenDNSSEC queries the modulus and
    // public exponent and trims leading zeros from their bytes by shifting
    // the bytes left and truncating the length. It does this to conform to
    // https://datatracker.ietf.org/doc/html/rfc3110#section-2. The
    // application implementing RFC 3110, i.e. Nameshed, should do that, not
    // us.

    for attr in attrs {
        match attr {
            Attribute::Class(class) => {
                if class != ObjectClass::PUBLIC_KEY {
                    return Err(Error::unsupported_object_class(class));
                }
            }

            Attribute::KeyType(key_type) => {
                if !matches!(key_type, KeyType::RSA | KeyType::EC) {
                    return Err(Error::unsupported_key_type(key_type));
                }
            }

            Attribute::KeyGenMechanism(mechanism_type) => {
                if mechanism_type == MechanismType::RSA_PKCS_KEY_PAIR_GEN {
                    cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
                } else if matches!(
                    mechanism_type,
                    MechanismType::ECDSA | MechanismType::ECC_KEY_PAIR_GEN
                ) {
                    // YubiHSM returns ECDSA.
                    // SoftHSMv2 returns CKM_EC_KEY_PAIR_GEN.
                    cryptographic_algorithm = Some(CryptographicAlgorithm::ECDSA);
                } else {
                    return Err(Error::unsupported_mechanism_type(mechanism_type));
                }
            }

            Attribute::Modulus(bytes) => {
                modulus = Some(bytes);
            }

            Attribute::ModulusBits(bits) => {
                modulus_bits = Some(bits.into());
            }

            Attribute::PublicExponent(bytes) => {
                public_exponent = Some(bytes);
            }

            Attribute::EcPoint(bytes) => {
                // Convert to DER encoding in the following form:
                // SubjectPublicKeyInfo SEQUENCE @0+89 (constructed): (2 elem)
                //  algorithm AlgorithmIdentifier SEQUENCE @2+19 (constructed): (2 elem)
                //    algorithm OBJECT_IDENTIFIER @4+7: 1.2.840.10045.2.1|ecPublicKey|ANSI X9.62 public key type
                //    parameters ANY OBJECT_IDENTIFIER @13+8: 1.2.840.10045.3.1.7|prime256v1|ANSI X9.62 named elliptic curve
                //  subjectPublicKey BIT_STRING @23+66: (520 bit)
                ec_point = Some(bytes);
            }

            _ => {
                // ignore unexpected attributes
            }
        }
    }

    let (key_format_type, key_material) = match cryptographic_algorithm {
        Some(CryptographicAlgorithm::RSA) => {
            let Some(modulus_bits) = modulus_bits else {
                return Err(Error::not_found(
                    "Attribute::ModulusBits",
                    "ObjectHandle",
                    key_handle,
                ));
            };
            let Some(modulus) = modulus else {
                return Err(Error::not_found(
                    "Attribute::Modulus",
                    "ObjectHandle",
                    key_handle,
                ));
            };
            let Some(public_exponent) = public_exponent else {
                return Err(Error::not_found(
                    "Attribute::PublicExponent",
                    "ObjectHandle",
                    key_handle,
                ));
            };
            let key = TransparentRSAPublicKey {
                modulus,
                public_exponent,
            };
            // TODO: SAFETY!
            cryptographic_length = Some(modulus_bits.try_into().unwrap());

            (
                KeyFormatType::TransparentRSAPublicKey,
                KeyMaterial::TransparentRSAPublicKey(key),
            )
        }
        Some(CryptographicAlgorithm::ECDSA) => {
            let Some(ec_point) = ec_point else {
                return Err(Error::not_found(
                    "Attribute::EcPoint",
                    "ObjectHandle",
                    key_handle,
                ));
            };

            // BitString::new(
            //     0,
            //     pub_key_sequence.to_captured(Mode::Der).into_bytes()
            // ),

            (KeyFormatType::Raw, KeyMaterial::Bytes(ec_point))
        }
        _ => {
            return Err(Error::not_found(
                "Attribute::CryptographicAlgorithm",
                "ObjectHandle",
                key_handle,
            ));
        }
    };

    Ok(KeyBlock {
        key_format_type,
        key_compression_type: None,
        key_value: KeyValue {
            key_material,
            attributes: None,
        },
        cryptographic_algorithm,
        cryptographic_length,
        key_wrapping_data: None,
    })
}
