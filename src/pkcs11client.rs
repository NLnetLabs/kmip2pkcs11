// TODO: Re-use PKCS#11 sessions.
// TODO: Cache PKCS#11 object handles by key IDs? OpenDNSSEC keeps the object
// handle in memory.
use std::time::SystemTime;

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
};
use kmip::types::common::{
    CryptographicAlgorithm, CryptographicParameters, Data, KeyFormatType, KeyMaterial,
    TransparentRSAPublicKey, UniqueIdentifier,
};
use log::{debug, info};

use crate::config::Cfg;
use core::fmt::Display;
use core::num::NonZeroUsize;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::KeyType;
use kmip::types::response::{KeyBlock, KeyValue};

pub enum Error {
    /// A problem occurred interacting with the PKCS#11 library or while
    /// communicating with the underlying cryptographic device.
    DeviceFailure(cryptoki::error::Error),

    /// An operation failed potentially due to incorrect user supplied
    /// configuration details.
    #[allow(dead_code)]
    UnusableConfig(String),

    /// An attempt to locate data in the device failed. This error notes the
    /// type of data that was looked for (e.g. private key), the type of
    /// identifier used to locate it (e.g. id attribute, label attribute,
    /// object handle) and the identifier used
    DataNotFound {
        data_type: String,
        id_type: String,
        id_value: String,
    },

    /// PKCS#11 data was encountered of a type that we do not support.
    #[allow(dead_code)]
    UnsupportedAttribute(Attribute),

    /// PKCS#11 data was encountered of a type that we do not support.
    UnsupportedKeyType(KeyType),

    /// PKCS#11 data was encountered of a type that we do not support.
    UnsupportedMechanismType(MechanismType),

    /// PKCS#11 data was encountered of a type that we do not support.
    UnsupportedObjectClass(ObjectClass),
}

impl Error {
    pub fn not_found<A, B, C>(data_type: A, id_type: B, data_id: C) -> Self
    where
        A: ToString,
        B: ToString,
        C: ToString,
    {
        Self::DataNotFound {
            data_type: data_type.to_string(),
            id_type: id_type.to_string(),
            id_value: data_id.to_string(),
        }
    }

    #[allow(dead_code)]
    pub fn unsupported_attribute(attribute: Attribute) -> Self {
        Self::UnsupportedAttribute(attribute)
    }

    pub fn unsupported_key_type(key_type: KeyType) -> Self {
        Self::UnsupportedKeyType(key_type)
    }

    pub fn unsupported_mechanism_type(mechanism_type: MechanismType) -> Self {
        Self::UnsupportedMechanismType(mechanism_type)
    }

    pub fn unsupported_object_class(object_class: ObjectClass) -> Self {
        Self::UnsupportedObjectClass(object_class)
    }
}

impl From<cryptoki::error::Error> for Error {
    fn from(err: cryptoki::error::Error) -> Self {
        Self::DeviceFailure(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DeviceFailure(cryptoki::error::Error::LibraryLoading(e)) => write!(
                f,
                "Relay failed to load the configured PKCS#11 library: {e}"
            ),
            Error::DeviceFailure(cryptoki::error::Error::Pkcs11(e, func)) => {
                write!(f, "Relay failed to invoke PKCS#11 function '{func}': {e}")
            }
            Error::DeviceFailure(e) => write!(f, "Relay PKCS#11 Rust abstraction layer error: {e}"),
            Error::UnusableConfig(e) => write!(f, "Relay settings may be incorrect: {e}"),
            Error::DataNotFound {
                data_type,
                id_type,
                id_value,
            } => write!(
                f,
                "Relay could not find data of type {data_type} with id {id_type} {id_value} could be found"
            ),
            Error::UnsupportedAttribute(attribute) => write!(
                f,
                "Relay lacks support for PKCS#11 attribute of type '{}'",
                attribute.attribute_type()
            ),
            Error::UnsupportedKeyType(key_type) => {
                write!(f, "Relay lacks support for PKCS#11 key type '{key_type}'")
            }
            Error::UnsupportedMechanismType(mechanism_type) => write!(
                f,
                "Relay lacks support for PKCS#11 mechanism type '{mechanism_type}'"
            ),
            Error::UnsupportedObjectClass(object_class) => write!(
                f,
                "Relay lacks support for PKCS#11 object class '{object_class}'"
            ),
        }
    }
}

fn init_pkcs11(cfg: &Cfg) -> Result<Session, Error> {
    let pkcs11 = Pkcs11::new(&cfg.lib_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    let slot = get_slot(&pkcs11, cfg)?;
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, cfg.user_pin.as_ref())?;
    Ok(session)
}

pub fn get_public_key(cfg: &Cfg, id: &UniqueIdentifier) -> Result<Option<KeyBlock>, Error> {
    let session = init_pkcs11(cfg)?;
    let id_bytes = hex::decode(&id.0).unwrap();
    let id_as_str = String::from_utf8_lossy(&id_bytes);
    info!("Get key: ID: {} [{}]", id.0, id_as_str);

    // Don't use session.find_objects() as it will request up to 10 results, and the actual
    // underlying C_FindObjects() call is not exposed via the Cryptoki crate.
    let mut iter = session
        .iter_objects_with_cache_size(&[Attribute::Id(id_bytes.clone())], NonZeroUsize::MIN)?;

    if let Some(Ok(key_handle)) = iter.next() {
        debug!("Getting attributes for key {key_handle:?}...");
        Ok(Some(get_key_details(&session, key_handle)?))
    } else {
        Ok(None)
    }
}

// pub fn get_keys(cfg: &Cfg) -> Result<Vec<Key>, Error> {
//     let session = init_pkcs11(cfg)?;

//     let mut keys = Vec::new();

//     for key_handle in session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])? {
//         debug!("Getting attributes for private key {key_handle:?}...");
//         let key = internal_get_key(&session, key_handle, vec![])?;
//         keys.push(key);
//     }

//     for key_handle in session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])? {
//         debug!("Getting attributes for public key {key_handle:?}...");
//         let key = internal_get_key(&session, key_handle, vec![])
//             .map_err(|err| Error::not_found("public key", "key handle", key_handle))?;
//         keys.push(key);
//     }

//     keys.sort_by_key(|v| v.id.clone());

//     debug!("Found {} keys", keys.len());
//     Ok(keys)
// }

pub struct CreatedKeyPair {
    pub public_key_id: UniqueIdentifier,
    pub private_key_id: UniqueIdentifier,
}

pub fn create_key_pair(
    cfg: &Cfg,
    mut pub_attrs: Vec<Attribute>,
    mut priv_attrs: Vec<Attribute>,
    mechanism: Mechanism,
) -> Result<CreatedKeyPair, Error> {
    // TODO: Consider what strategy to use for ID generation.
    // - Is it an option and is it useful to NOT supply an ID and get an
    //   autogenerated ID from the HSM?
    //
    // - Do we need IDs to be in some way recognizably ours (so as to know in
    //   an HSM which keys were generated by Nameshed vs some other means)?
    //
    // - Should IDs even be specific to a given Nameshed deployment (so as to
    //   be able to distinguish keys generated say by development and
    //   pre-production deployments using the same HSM)?
    //
    // - Do we need separate public and private key IDs? OpenDNSSEC uses the
    //   same ID and same label for both the public and the private key.
    //   Regardless of whether we use the same ID or two separate IDs, the
    //   KMIP response has mandatory fields for separate IDs for the public
    //   and private key. In the OpenDNSSEC case when CKA_TOKEN is false for
    //   the public key the ID is useless anyway presumably as the key will be
    //   discarded at the end of the PKCS#11 session. OpenDNSSEC even calls
    //   C_DestroyObject on the public key to discard it immediately if
    //   CKA_TOKEN is false for the public key.
    //
    // - Should we do as OpenDNSSEC does which is to use the PKCS#11
    //   C_GenerateRandom() function to generate a random sequence of 16 bytes
    //   to use as the CKA_ID, then check using the PKCS#11 C_FindObjects()
    //   API if that key ID is already taken, and if so repeat the process?
    //   OpenDNSSEC then uses a 33 byte CKA_LABEL to store the hex
    //   representation of the generated ID.
    //
    // - Should we do as Krill does which is to use OpenSSL to generate a
    //   random sequence of 20 bytes as the CKA_ID, and "Krill" as the
    //   CKA_LABEL.
    //
    // - What do PowerDNS, Knot, etc do?

    // TODO: Consider which PKCS#11 attributes to use for the keys, and which
    // of these should be determined here vs which should be determined by the
    // details of the KMIP Create Key Pair request.
    //
    // - OpenDNSSEC uses:
    //    Public key:
    //      CKA_ID               Random HSM generated not-already-used 16 byte
    //                           sequence.
    //      CKA_LABEL            Hex representation of CKA_ID.
    //      CKA_KEY_TYPE         CKK_RSA
    //      CKA_VERIFY           True
    //      CKA_ENCRYPT          False
    //      CKA_WRAP             False
    //      CKA_TOKEN            Configurable.
    //      CKA_MODULUS_BITS     Set to the RSA key size to generate, e.g.
    //                           2048, based on the KMIP request.
    //      CKA_PUBLIC_EXPONENT  [1, 0, 1]
    //
    //    Private key:
    //      CKA_ID               Same as public key.
    //      CKA_LABEL            Same as public key.
    //      CKA_KEY_TYPE         Same as public key.
    //      CKA_SIGN             True
    //      CKA_DECRYPT          False
    //      CKA_UNWRAP           False
    //      CKA_SENSITIVE        True
    //      CKA_TOKEN            True
    //      CKA_PRIVATE          True
    //      CKA_EXTRACTABLE      Configurable.
    //
    //     Mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN
    //
    // - Krill uses:
    //   Same as OpenDNSSEC with the following exceptions:
    //     CKA_ID                Random OpenSSL generated 20 byte sequence.
    //     CKA_LABEL             "Krill".
    //     CKA_TOKEN             Always set to true for public keys.
    //     CKA_MODULUS_BITS      Always set to 2048.
    //     CKA_SENSITIVE         Not set by default.
    //     CKA_PRIVATE           Configurable.
    //     CKA_SENSITIVE         Configurable.
    //     CKA_EXCTRACTABLE      Not set by default.
    //
    //     Krill also allows extra attributes to be defined in config,
    //     separately for public and private keys.
    //
    //     Krill maintains a persistent mapping of RFC 5280 Subject Key
    //     Identifiers to generated 20 byte random IDs.
    //
    // - What do PowerDNS, Knot, etc do?

    let epoch_time_now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let base_name = format!("nameshed_{epoch_time_now}");
    let pub_id = format!("{base_name}_pub").as_bytes().to_vec();
    let priv_id = format!("{base_name}_priv").as_bytes().to_vec();

    let mut pub_key_template = vec![
        Attribute::Id(pub_id.clone()),
        Attribute::Verify(true),
        Attribute::Encrypt(false),
        Attribute::Wrap(false),
        Attribute::Token(true),
    ];
    pub_key_template.append(&mut pub_attrs);

    let mut priv_key_template = vec![
        Attribute::Id(priv_id.clone()),
        Attribute::Sign(true),
        Attribute::Decrypt(false),
        Attribute::Unwrap(false),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
    ];
    priv_key_template.append(&mut priv_attrs);

    eprintln!("Public key ID: {pub_id:?}");
    eprintln!("Private key ID: {priv_id:?}");

    // TODO: The error returned is a bit useless when Display'd, e.g.:
    //
    //   ERROR ThreadId(02) domain::crypto::kmip::sign: KMIP request failed:
    //   Server error: Operation CreateKeyPair failed: Failed to create key
    //   pair: Relay failed to invoke PKCS#11 function
    //   'Function::GenerateKeyPair': An invalid value was specified for a
    //   particular attribute in a template.  See Section 4.1 for more
    //   information.
    //
    // Firstly, that "Function::GenerateKeyPair" should say C_GenerateKeyPair.
    //
    // Secondly, section 4.1 of which document?
    //
    // This output comes from the cryptoki crate I think.
    //
    // In the particular case above the issue was that the requested RSA key
    // size of 1048 is apparently not permitted by the YubiHSM, with 2048 the
    // error goes away. That is completely not obvious from this error
    // message.
    let session = init_pkcs11(cfg)?;
    session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    Ok(CreatedKeyPair {
        public_key_id: UniqueIdentifier(hex::encode_upper(pub_id)),
        private_key_id: UniqueIdentifier(hex::encode_upper(priv_id)),
    })
}

fn get_key_details(session: &Session, key_handle: ObjectHandle) -> Result<KeyBlock, Error> {
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

    let attrs = session.get_attributes(key_handle, &request_attrs)?;

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

fn get_slot(pkcs11: &Pkcs11, cfg: &Cfg) -> std::result::Result<Slot, Error> {
    fn has_token_label(pkcs11: &Pkcs11, slot: Slot, slot_label: &str) -> bool {
        pkcs11
            .get_token_info(slot)
            .map(|info| info.label().trim_end() == slot_label)
            .unwrap_or(false)
    }

    let slot = match (&cfg.slot_id, &cfg.slot_label) {
        // Match slot by label then id.
        (Some(id), Some(label)) => {
            let slot = pkcs11
                .get_slots_with_initialized_token()?
                .into_iter()
                .find(|&slot| has_token_label(pkcs11, slot, label))
                .ok_or(Error::not_found("slot", "slot label", label))?;

            if slot.id() != *id {
                return Err(Error::not_found("slot", "slot id", id));
            }

            slot
        }

        // Match slot by label.
        (None, Some(label)) => pkcs11
            .get_slots_with_initialized_token()?
            .into_iter()
            .find(|&slot| has_token_label(pkcs11, slot, label))
            .ok_or(Error::not_found("slot", "slot label", label))?,

        // Match slot by id.
        (Some(id), None) => pkcs11
            .get_all_slots()?
            .into_iter()
            .find(|&slot| slot.id() == *id)
            .ok_or(Error::not_found("slot", "slot id", id))?,

        // Match slot by default id zero.
        (None, None) => pkcs11
            .get_all_slots()?
            .into_iter()
            .find(|&slot| slot.id() == 0)
            .ok_or(Error::not_found("slot", "slot id", 0))?,
    };

    Ok(slot)
}

pub fn sign(
    cfg: &Cfg,
    id: &UniqueIdentifier,
    cryptographic_parameters: &Option<CryptographicParameters>,
    data: &Data,
) -> Result<Vec<u8>, Error> {
    let session = init_pkcs11(cfg)?;
    let mechanism;

    let id_bytes = hex::decode(&id.0).unwrap();
    let id_as_str = String::from_utf8_lossy(&id_bytes);
    println!("Get key: ID: {} [{}]", id.0, id_as_str);
    let res = session.find_objects(&[Attribute::Id(id_bytes.clone())])?;

    if res.len() != 1 {
        return Err(Error::not_found("Key", "Id", id_as_str));
    }

    let key_handle = res[0];

    if let Some(cryptographic_algorithm) =
        cryptographic_parameters.and_then(|cp| cp.cryptographic_algorithm)
    {
        mechanism = match cryptographic_algorithm {
            CryptographicAlgorithm::RSA => Mechanism::RsaPkcs,
            CryptographicAlgorithm::ECDSA => Mechanism::Ecdsa,
            _ => todo!(),
        }
    } else {
        debug!("Getting attributes for key {key_handle:?}...");
        let attrs = session.get_attributes(key_handle, &[AttributeType::KeyGenMechanism])?;

        if attrs.len() != 1 {
            return Err(Error::not_found("Key", "ObjectHandle", key_handle));
        }

        if let Attribute::KeyGenMechanism(mechanism_type) = attrs[0] {
            if mechanism_type == MechanismType::RSA_PKCS_KEY_PAIR_GEN {
                mechanism = Mechanism::RsaPkcs;
            } else if matches!(
                mechanism_type,
                MechanismType::ECDSA | MechanismType::ECC_KEY_PAIR_GEN
            ) {
                mechanism = Mechanism::Ecdsa
            } else {
                return Err(Error::unsupported_mechanism_type(mechanism_type));
            }
        } else {
            return Err(Error::not_found(
                "Attribute::MechanismType",
                "ObjectHandle",
                key_handle,
            ));
        }
    }

    let signature_data = session.sign(&mechanism, key_handle, &data.0)?;

    Ok(signature_data)
}
