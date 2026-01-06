use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType};
use kmip::types::common::{CryptographicParameters, UniqueIdentifier};
use log::{debug, info};
use rand::Rng;

use crate::pkcs11::error::Error;
use crate::pkcs11::pool::Pkcs11Connection;

/// Result of encryption: ciphertext and optional IV
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub iv: Option<Vec<u8>>,
}

/// AES block size in bytes
const AES_BLOCK_SIZE: usize = 16;

/// Encrypt data using a key identified by its label (UniqueIdentifier).
///
/// This implements KMIP Encrypt operation by translating to PKCS#11 C_Encrypt.
/// Uses AES-CBC with PKCS#7 padding for compatibility with SoftHSM.
pub fn encrypt_data(
    pkcs11conn: Pkcs11Connection,
    id: &UniqueIdentifier,
    _crypto_params: Option<&CryptographicParameters>,
    plaintext: &[u8],
    iv: Option<&[u8]>,
) -> Result<EncryptResult, Error> {
    let label = id.0.as_str();
    info!("Encrypting data with key label: {}", label);

    // Find key by label (CKA_LABEL)
    let handles = pkcs11conn
        .session()
        .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])?;

    if handles.is_empty() {
        return Err(Error::not_found("Key", "label", label));
    }

    let key_handle = handles[0];
    debug!("Found encryption key handle: {:?}", key_handle);

    // Get key type to verify it's AES
    let attrs = pkcs11conn.session().get_attributes(
        key_handle,
        &[AttributeType::KeyType],
    )?;

    let key_type = attrs
        .iter()
        .find_map(|a| {
            if let Attribute::KeyType(kt) = a {
                Some(*kt)
            } else {
                None
            }
        })
        .ok_or_else(|| Error::internal("Key has no KeyType attribute"))?;

    if key_type != cryptoki::object::KeyType::AES {
        return Err(Error::not_supported(&format!(
            "Key type {:?} for encryption",
            key_type
        )));
    }

    // Prepare IV - either use provided or generate random 16-byte IV for CBC
    // Note: OpenBao sends 12-byte IVs (GCM style), so we pad to 16 bytes for CBC
    let iv_bytes: [u8; AES_BLOCK_SIZE] = match iv {
        Some(provided_iv) => {
            let mut arr = [0u8; AES_BLOCK_SIZE];
            if provided_iv.len() >= AES_BLOCK_SIZE {
                // Use first 16 bytes if longer
                arr.copy_from_slice(&provided_iv[..AES_BLOCK_SIZE]);
            } else {
                // Pad shorter IVs (like 12-byte GCM IVs) with zeros
                arr[..provided_iv.len()].copy_from_slice(provided_iv);
                // Remaining bytes are already zero from initialization
            }
            arr
        }
        None => {
            let mut rng = rand::rng();
            let mut random_iv = [0u8; AES_BLOCK_SIZE];
            rng.fill(&mut random_iv[..]);
            random_iv
        }
    };

    debug!("Using AES-CBC-PAD with 16-byte IV");

    // Use AES-CBC with PKCS#7 padding - handles arbitrary length data
    let mechanism = Mechanism::AesCbcPad(iv_bytes);

    // Perform encryption
    let ciphertext = pkcs11conn.session().encrypt(&mechanism, key_handle, plaintext)?;

    debug!("Encrypted {} bytes to {} bytes", plaintext.len(), ciphertext.len());

    Ok(EncryptResult {
        ciphertext,
        iv: Some(iv_bytes.to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_result_structure() {
        let result = EncryptResult {
            ciphertext: vec![1, 2, 3, 4],
            iv: Some(vec![5, 6, 7, 8]),
        };
        assert_eq!(result.ciphertext.len(), 4);
        assert!(result.iv.is_some());
    }
}
