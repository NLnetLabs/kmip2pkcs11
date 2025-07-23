use kmip::types::{
    common::{AttributeValue, NameType},
    request::{BatchItem, RequestPayload},
    response::{
        BatchItem as ResBatchItem, CreateKeyPairResponsePayload, ResponsePayload, ResultReason,
        ResultStatus,
    },
};

use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType};

use crate::pkcs11::operations::create_key_pair::{CreatedKeyPair, create_key_pair};
use crate::pkcs11::pool::Pkcs11Connection;

pub fn op(
    pkcs11conn: Pkcs11Connection,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, String)> {
    let RequestPayload::CreateKeyPair(common_attrs, priv_key_attrs, pub_key_attrs) =
        batch_item.request_payload()
    else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Create Key Pair payload".to_string(),
        ));
    };

    let mut pub_attrs = vec![];
    let mut priv_attrs = vec![]; // TODO: Optionally include Attribute::Extractable(true)?
    let mut mechanism: Option<Mechanism> = None;
    let mut modulus = None;

    if let Some(common_attrs) = common_attrs {
        for attr in common_attrs.attributes() {
            if attr.name() == "Cryptographic Algorithm" {
                if let AttributeValue::CryptographicAlgorithm(alg) = attr.value() {
                    match alg {
                        kmip::types::common::CryptographicAlgorithm::ECDSA => {
                            // Defined at
                            // https://docs.oasis-open.org/kmip/ug/v1.2/cn01/kmip-ug-v1.2-cn01.html#_Toc407027131.
                            // Also matches the OID value used by OpenDNSSEC
                            // 2.1.14.
                            // The OID is X.690 DER encoded.
                            //   0x06 - identifier octet:
                            //            00000110
                            //            ^^ Class
                            //              ^ P/C: 0 = Primitive, 1 = Constructed
                            //               ^^^^^ ASN.1 tag number
                            //          where ASN.1 tag number 0x06 denotes an
                            //          Object Identifier (aka OID) as defined
                            //          by X.690 section 8.19 "Encoding of an
                            //          object identifier value".
                            //  0x08 - the number of bytes that follow, 8 in this case.
                            //  0x2A.. DER (Distinguished Encoding Rules)
                            //         encoded value equivalent to
                            //         1.2.840.10045.3.1.7 (see
                            //         https://lapo.it/asn1js/#BggqhkjOPQMBBw)
                            //         which
                            //         https://docs.oasis-open.org/kmip/ug/v1.2/cn01/kmip-ug-v1.2-cn01.html#_Toc407027131
                            //         defines as algorithm P-256 aka
                            //         SECP256R1.
                            let oid_p256: Vec<u8> =
                                vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
                            pub_attrs.push(Attribute::EcParams(oid_p256));
                            pub_attrs.push(Attribute::KeyType(KeyType::EC));
                            priv_attrs.push(Attribute::KeyType(KeyType::EC));
                            mechanism = Some(Mechanism::EccKeyPairGen);
                        }

                        kmip::types::common::CryptographicAlgorithm::RSA => {
                            // TODO: Document where [1, 0, 1] comes from.
                            pub_attrs.push(Attribute::PublicExponent(vec![1, 0, 1]));
                            pub_attrs.push(Attribute::KeyType(KeyType::RSA));
                            priv_attrs.push(Attribute::KeyType(KeyType::RSA));
                            mechanism = Some(Mechanism::RsaPkcsKeyPairGen);
                        }

                        _ => {
                            return Err((
                                ResultReason::InvalidField,
                                format!("Cryptographic algorithm '{alg}' is not supported"),
                            ));
                        }
                    }
                }
            } else if attr.name() == "Cryptographic Length" {
                if let AttributeValue::Integer(key_size) = attr.value() {
                    // TODO: SAFETY!
                    modulus = Some(*key_size);
                }
            }
        }

        if let Some(attrs) = pub_key_attrs {
            for attr in attrs.attributes() {
                if attr.name() == "Name" {
                    if let AttributeValue::Name(name, name_type) = attr.value() {
                        match name_type {
                            NameType::UninterpretedTextString => {
                                pub_attrs.push(Attribute::Label(name.0.as_bytes().to_vec()));
                            }
                            _ => {
                                return Err((
                                    ResultReason::InvalidField,
                                    "Key name attributes must be uninterpreted text strings"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        if let Some(attrs) = priv_key_attrs {
            for attr in attrs.attributes() {
                if attr.name() == "Name" {
                    if let AttributeValue::Name(name, name_type) = attr.value() {
                        match name_type {
                            NameType::UninterpretedTextString => {
                                priv_attrs.push(Attribute::Label(name.0.as_bytes().to_vec()));
                            }
                            _ => {
                                return Err((
                                    ResultReason::InvalidField,
                                    "Key name attributes must be uninterpreted text strings"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    let Some(mechanism) = mechanism else {
        return Err((
            ResultReason::FeatureNotSupported,
            "Only ECDSA and RSA key types can be generated".to_string(),
        ));
    };

    if matches!(mechanism, Mechanism::RsaPkcsKeyPairGen) {
        if let Some(modulus) = modulus {
            pub_attrs.push(Attribute::ModulusBits(
                (modulus as usize).try_into().unwrap(),
            ));
        }
    }

    // TODO: Detect sign mask in the above and push it as an attr.

    let CreatedKeyPair {
        public_key_id,
        private_key_id,
    } = create_key_pair(pkcs11conn, pub_attrs, priv_attrs, mechanism).map_err(|err| {
        (
            ResultReason::CryptographicFailure,
            format!("Failed to create key pair: {err}"),
        )
    })?;

    Ok(ResBatchItem {
        operation: Some(*batch_item.operation()),
        unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
        result_status: ResultStatus::Success,
        result_reason: None,
        result_message: None,
        payload: Some(ResponsePayload::CreateKeyPair(
            CreateKeyPairResponsePayload {
                public_key_unique_identifier: public_key_id,
                private_key_unique_identifier: private_key_id,
            },
        )),
        message_extension: None,
    })
}
