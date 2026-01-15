use bcder::decode::IntoSource;
use bcder::encode::{Nothing, PrimitiveContent, Values};
use bcder::{BitString, ConstOid, Mode, OctetString, Oid};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use domain::utils::base16;
use kmip::types::common::{
    CryptographicAlgorithm, KeyFormatType, KeyMaterial, TransparentRSAPublicKey, UniqueIdentifier,
};
use kmip::types::response::{KeyBlock, KeyValue};
use tracing::{debug, info, trace};

use crate::pkcs11::error::Error;
use crate::pkcs11::pool::Pkcs11Connection;
use crate::pkcs11::util::get_cached_handle_for_key;

/// [RFC 5480](https://tools.ietf.org/html/rfc5480) `ecPublicKey`.
///
/// Identifies public keys for elliptic curve cryptography.
const EC_PUBLIC_KEY_OID: ConstOid = Oid(&[42, 134, 72, 206, 61, 2, 1]);

/// [RFC 5480](https://tools.ietf.org/html/rfc5480) `secp256r1`.
///
/// Identifies the P-256 curve for elliptic curve cryptography.
pub const SECP256R1_OID: ConstOid = Oid(&[42, 134, 72, 206, 61, 3, 1, 7]);

pub fn get_public_key(
    pkcs11conn: Pkcs11Connection,
    id: &UniqueIdentifier,
) -> Result<Option<KeyBlock>, Error> {
    let key_handle = get_cached_handle_for_key(&pkcs11conn, id);

    if let Some(key_handle) = key_handle {
        info!(
            "Getting attributes for public key handle {key_handle} (KMIP id {})...",
            id.0
        );
        Ok(Some(get_public_key_details(&pkcs11conn, key_handle)?))
    } else {
        Ok(None)
    }
}

fn get_public_key_details(
    pkcs11conn: &Pkcs11Connection,
    key_handle: ObjectHandle,
) -> Result<KeyBlock, Error> {
    let mut cryptographic_algorithm: Option<CryptographicAlgorithm> = None;
    let mut cryptographic_length: Option<i32> = None;
    let mut modulus: Option<Vec<u8>> = None;
    let mut modulus_bits: Option<usize> = None;
    let mut public_exponent: Option<Vec<u8>> = None;
    let mut ec_point: Option<Vec<u8>> = None;

    let mut request_attrs = vec![
        AttributeType::Class,
        AttributeType::Modulus,
        AttributeType::ModulusBits,    // For RSA keys
        AttributeType::PublicExponent, // For RSA keys
        AttributeType::KeyType,
        AttributeType::EcPoint, // For ECDSA keys, DER encoded
        AttributeType::KeyGenMechanism,
    ];

    let attrs = loop {
        let res = pkcs11conn
            .session()
            .get_attributes(key_handle, &request_attrs);

        if matches!(res, Err(cryptoki::error::Error::NotSupported)) {
            // Retry without KeyGenMechanism attribute, as at least the
            // Nitrokey NetHSM doesn't support it and we can also get the
            // information we need from the KeyType attribute.
            debug!("C_GetAttributeValue failed, re-trying without CKA_KEY_GEN_MECHANISM");
            let _ = request_attrs.pop();
            continue;
        }

        let attrs = res?;

        if attrs.is_empty() {
            return Err(Error::not_found("Key", "ObjectHandle", key_handle));
        } else {
            break attrs;
        }
    };

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
    // application implementing RFC 3110, i.e. Cascade, should do that, not
    // us.
    trace!("Returned PKCS#11 attributes: {attrs:?}");

    for attr in attrs {
        match attr {
            Attribute::Class(class) => {
                if class != ObjectClass::PUBLIC_KEY {
                    return Err(Error::unsupported_object_class(class));
                }
            }

            Attribute::KeyType(key_type) => match key_type {
                KeyType::RSA => cryptographic_algorithm = Some(CryptographicAlgorithm::RSA),
                KeyType::EC => cryptographic_algorithm = Some(CryptographicAlgorithm::ECDSA),
                _ => {
                    return Err(Error::unsupported_key_type(key_type));
                }
            },

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

            Attribute::EcPoint(der_octet_string) => {
                // The KMIP client expects to receive an ASN.1 DER encoded
                // SubjectPublicKeyInfo response like so, but we receive an
                // ASN.1 DER OCTET STRING.
                //
                //   SubjectPublicKeyInfo SEQUENCE @0+89 (constructed): (2 elem)
                //     algorithm AlgorithmIdentifier SEQUENCE @2+19 (constructed): (2 elem)
                //       algorithm OBJECT_IDENTIFIER @4+7: 1.2.840.10045.2.1|ecPublicKey|ANSI X9.62 public key type
                //       parameters ANY OBJECT_IDENTIFIER @13+8: 1.2.840.10045.3.1.7|prime256v1|ANSI X9.62 named elliptic curve
                //     subjectPublicKey BIT_STRING @23+66: (520 bit)
                //
                // From: https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1
                //   The parameter for id-ecPublicKey is as follows and MUST always be
                //   present:
                //
                //     ECParameters ::= CHOICE {
                //       namedCurve         OBJECT IDENTIFIER
                //       -- implicitCurve   NULL
                //       -- specifiedCurve  SpecifiedECDomain
                //     }
                //       -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.
                //       -- Details for SpecifiedECDomain can be found in [X9.62].
                //       -- Any future additions to this CHOICE should be coordinated
                //       -- with ANSI X9.
                trace!(
                    "Received {} bytes of EcPoint: {}",
                    der_octet_string.len(),
                    base16::encode_display(&der_octet_string)
                );

                let algorithm = bcder::encode::Choice2::<Nothing, _>::Two(bcder::encode::sequence(
                    (EC_PUBLIC_KEY_OID.encode(), SECP256R1_OID.encode()),
                ));

                let inner_bytes = bcder::Mode::Der
                    .decode(der_octet_string.into_source(), |cons| {
                        OctetString::take_from(cons)
                    })
                    .map_err(|err| {
                        Error::MalformedDataReceived(format!(
                            "Failed to parse CKA_EC_POINT value as a DER OCTET STRING: {err}"
                        ))
                    })?
                    .into_bytes();

                trace!(
                    "Converted EcPoint to {} bytes: {}",
                    inner_bytes.len(),
                    base16::encode_display(&inner_bytes)
                );
                let subject_public_key = BitString::new(0, inner_bytes);

                let bytes = bcder::encode::sequence((algorithm, subject_public_key.encode()))
                    .to_captured(Mode::Der)
                    .to_vec();

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
