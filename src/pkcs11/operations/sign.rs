use bcder::Mode;
use bcder::encode::{PrimitiveContent, Values};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType};
use domain::crypto::common::{DigestBuilder, DigestType};
use kmip::types::common::{
    CryptographicAlgorithm, CryptographicParameters, Data, HashingAlgorithm, PaddingMethod,
    UniqueIdentifier,
};
use log::debug;

use crate::pkcs11::error::Error;
use crate::pkcs11::pool::Pkcs11Connection;
use crate::pkcs11::util::get_cached_handle_for_key;

pub fn sign(
    pkcs11conn: Pkcs11Connection,
    id: &UniqueIdentifier,
    cryptographic_parameters: &Option<CryptographicParameters>,
    data: &Data,
) -> Result<Vec<u8>, Error> {
    // Only private keys can be used for signing.
    let Some(key_handle) = get_cached_handle_for_key(&pkcs11conn, id) else {
        return Err(Error::not_found("Key", "Id", id.0.clone()));
    };

    // Warning: CKA_ID is not unique. Firstly, by default it is empty.
    // Secondly, "the key identifier for a public key and its corresponding
    // private key should be the same.". Thirdly, "In the case of public and
    // private keys, this field assists in handling multiple keys held by the
    // same subject" and "Since the keys are distinguished by subject name as
    // well as identifier, it is possible that keys for different subjects may
    // have the same CKA_ID value without introducing any ambiguity."

    let mechanism = if let Some(CryptographicParameters {
        padding_method,
        hashing_algorithm,
        cryptographic_algorithm,
        ..
    }) = cryptographic_parameters
    {
        if *hashing_algorithm != Some(HashingAlgorithm::SHA256) {
            return Err(Error::unsupported_cryptographic_parameters(
                "Only hashing algorithm SHA256 is supported for signing",
            ));
        }
        match (cryptographic_algorithm, padding_method) {
            (Some(CryptographicAlgorithm::RSA), Some(PaddingMethod::PKCS1_v1_5)) => {
                Ok(Mechanism::RsaPkcs)
            }
            (Some(CryptographicAlgorithm::RSA), _) => {
                Err(Error::unsupported_cryptographic_parameters(
                    "Only padding method PKCS#1 v1.5 is supported when signing with RSA",
                ))
            }
            (Some(CryptographicAlgorithm::ECDSA), None) => Ok(Mechanism::Ecdsa),
            _ => {
                return Err(Error::unsupported_cryptographic_parameters(
                    "Only RSA with PKCS#1 v1.5 padding, or ECDSA, are supported for signing",
                ));
            }
        }?
    } else {
        debug!("Getting attributes for key handle {key_handle}...");
        let attrs = pkcs11conn
            .session()
            .get_attributes(key_handle, &[AttributeType::KeyGenMechanism])?;

        if attrs.len() != 1 {
            return Err(Error::not_found("Key", "ObjectHandle", key_handle));
        }

        if let Attribute::KeyGenMechanism(mechanism_type) = attrs[0] {
            if mechanism_type == MechanismType::RSA_PKCS_KEY_PAIR_GEN {
                Mechanism::RsaPkcs
            } else if matches!(
                mechanism_type,
                MechanismType::ECDSA | MechanismType::ECC_KEY_PAIR_GEN
            ) {
                Mechanism::Ecdsa
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
    };

    // Note: OpenDNSSEC does its own hashing. Trying to do SHA256
    // hashing ourselves and then not passing a hashing algorithm to
    // the Sign operation below results (with Fortanix at least) in
    // error "Must specify HashingAlgorithm". OpenDNSSEC code comments
    // say this is done because "some HSMs don't really handle
    // CKM_SHA1_RSA_PKCS well".

    let mut ctx = DigestBuilder::new(DigestType::Sha256);
    ctx.update(&data.0);
    let digest = ctx.finish();
    let mut data = digest.as_ref();

    // OpenDNSSEC says that for RSA the prefix must be added to the
    // buffer manually first as "CKM_RSA_PKCS does the padding, but
    // cannot know the identifier prefix, so we need to add that
    // ourselves."
    let mut new_data;
    if matches!(mechanism, Mechanism::RsaPkcs) {
        // https://www.rfc-editor.org/rfc/rfc5702#section-3.1
        // 3.1.  RSA/SHA-256 RRSIG Resource Records
        //   ...
        //   "The prefix is the ASN.1 DER SHA-256 algorithm designator prefix,
        //    as specified in PKCS #1 v2.1 [RFC3447]:
        //
        //    hex 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20"
        //
        // [RFC3447]: https://www.rfc-editor.org/rfc/rfc3447#section-9.2
        new_data = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        new_data.extend_from_slice(data);
        data = &new_data;
    }

    let signature_data = pkcs11conn.session().sign(&mechanism, key_handle, &data)?;

    if matches!(mechanism, Mechanism::Ecdsa) {
        // Check that the signature is of the form r | s (where | denotes
        // concatenation) where both r and s are 32 bytes long. (as
        // ECDSAP256SHA256 uses 256-bit i.e. 32 byte values, and we're
        // assuming that ECDSA here means ECDSAP256SHA256...)
        if signature_data.len() != 64 {
            return Err(Error::MalformedDataReceived(format!(
                "Expected 64 byte ECDSAP256SHA256 signature but received {} bytes: {}",
                signature_data.len(),
                hex::encode_upper::<Vec<u8>>(signature_data)
            )));
        }

        // Encode it as expected by the KMIP client, e.g. this is the ECDSA
        // signature received from a Fortanix DSM:
        //
        //   $ echo '<hex encoded signature data>' | xxd -r -p | dumpasn1 -
        //     0  69: SEQUENCE {
        //     2  33:   INTEGER
        //          :     00 C6 A7 D1 2E A1 0C B4 96 BD D9 A5 48 2C 9B F4
        //          :     0C EC 9F FC EF 1A 0D 59 BB B9 24 F3 FE DA DC F8
        //          :     9E
        //    37  32:   INTEGER
        //          :     4B A7 22 69 F2 F8 65 88 63 D0 25 D3 A9 D5 92 4F
        //          :     A2 21 BD 59 CD 27 60 6D 16 C3 79 EF B4 0A CA 33
        //          : }
        //
        // Where the two integer values are known as 'r' and 's'.

        Ok(bcder::encode::sequence((
            bcder::Unsigned::from_slice(&signature_data[0..32])
                .unwrap()
                .encode(),
            bcder::Unsigned::from_slice(&signature_data[32..])
                .unwrap()
                .encode(),
        ))
        .to_captured(Mode::Der)
        .to_vec())
    } else {
        Ok(signature_data)
    }
}
