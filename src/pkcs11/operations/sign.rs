use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use kmip::types::common::{
    CryptographicAlgorithm, CryptographicParameters, Data, UniqueIdentifier,
};
use log::debug;

use crate::config::Cfg;
use crate::pkcs11::error::Error;
use crate::pkcs11::util::{init_pkcs11, kmip_unique_identifier_to_pkcs11_cka_id};

pub fn sign(
    cfg: &Cfg,
    id: &UniqueIdentifier,
    cryptographic_parameters: &Option<CryptographicParameters>,
    data: &Data,
) -> Result<Vec<u8>, Error> {
    let session = init_pkcs11(cfg)?;
    let mechanism;

    // Only private keys can be used for signing.
    let cka_id = kmip_unique_identifier_to_pkcs11_cka_id(id, true);
    let res = session.find_objects(&[
        Attribute::Id(cka_id),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
    ])?;

    // Warning: CKA_ID is not unique. Firstly, by default it is empty.
    // Secondly, "the key identifier for a public key and its corresponding
    // private key should be the same.". Thirdly, "In the case of public and
    // private keys, this field assists in handling multiple keys held by the
    // same subject" and "Since the keys are distinguished by subject name as
    // well as identifier, it is possible that keys for different subjects may
    // have the same CKA_ID value without introducing any ambiguity."
    if res.len() != 1 {
        return Err(Error::not_found("Key", "Id", id.0.clone()));
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
