use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType};
use kmip::types::common::{
    CryptographicAlgorithm, CryptographicParameters, Data, UniqueIdentifier,
};
use log::debug;

use crate::config::Cfg;
use crate::pkcs11::error::Error;
use crate::pkcs11::util::init_pkcs11;

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
