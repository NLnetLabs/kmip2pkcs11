use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType};
use kmip::types::common::{CryptographicParameters, UniqueIdentifier};
use log::{debug, info};

use crate::pkcs11::error::Error;
use crate::pkcs11::pool::Pkcs11Connection;

/// AES block size in bytes
const AES_BLOCK_SIZE: usize = 16;

/// Decrypt data using a key identified by its label (UniqueIdentifier).
///
/// This implements KMIP Decrypt operation by translating to PKCS#11 C_Decrypt.
/// Uses AES-CBC with PKCS#7 padding for compatibility with SoftHSM.
pub fn decrypt_data(
    pkcs11conn: Pkcs11Connection,
    id: &UniqueIdentifier,
    _crypto_params: Option<&CryptographicParameters>,
    ciphertext: &[u8],
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let label = id.0.as_str();
    info!("Decrypting data with key label: {}", label);

    // Find key by label (CKA_LABEL)
    let handles = pkcs11conn
        .session()
        .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])?;

    if handles.is_empty() {
        return Err(Error::not_found("Key", "label", label));
    }

    let key_handle = handles[0];
    debug!("Found decryption key handle: {:?}", key_handle);

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
            "Key type {:?} for decryption",
            key_type
        )));
    }

    // IV is required for CBC decryption
    let Some(iv_slice) = iv else {
        return Err(Error::invalid_param("IV is required for AES-CBC decryption"));
    };

    // Convert IV to fixed-size array for CBC
    // Note: OpenBao sends 12-byte IVs (GCM style), so we pad to 16 bytes for CBC
    let mut iv_bytes = [0u8; AES_BLOCK_SIZE];
    if iv_slice.len() >= AES_BLOCK_SIZE {
        // Use first 16 bytes if longer
        iv_bytes.copy_from_slice(&iv_slice[..AES_BLOCK_SIZE]);
    } else {
        // Pad shorter IVs (like 12-byte GCM IVs) with zeros
        iv_bytes[..iv_slice.len()].copy_from_slice(iv_slice);
        // Remaining bytes are already zero from initialization
    }

    debug!("Padded {}-byte IV to 16 bytes for CBC", iv_slice.len());

    debug!("Using AES-CBC-PAD with 16-byte IV for decryption");

    // Use AES-CBC with PKCS#7 padding
    let mechanism = Mechanism::AesCbcPad(iv_bytes);

    // Perform decryption
    let plaintext = pkcs11conn.session().decrypt(&mechanism, key_handle, ciphertext)?;

    debug!("Decrypted {} bytes to {} bytes", ciphertext.len(), plaintext.len());

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    // Integration tests would require a real PKCS#11 token
    // Unit tests for helper functions can be added here
}
