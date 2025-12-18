use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::result::Result;
use std::sync::{Arc, RwLock};

use cryptoki::context::{CInitializeArgs, Function, Pkcs11};
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::slot::Slot;
use kmip::types::common::UniqueIdentifier;
use kmip2pkcs11_cfg::Config;
use log::info;
use rand::RngCore;

use crate::pkcs11::error::Error;
use crate::pkcs11::pool::{Pkcs11Connection, Pkcs11Pool};

// Create a collection of PKCS#11 pools, one per PKCS#11 slot as defined in
// the KMIP username of incoming requests. This collection will need to be
// modified at runtime as requests are received. As requests are handled by
// whichever Tokio thread handles the spawned task we must be able to modify
// the collection of pools from any thread at any time.
#[derive(Clone)]
pub struct Pkcs11Pools {
    pkcs11: Pkcs11,
    pools: Arc<RwLock<HashMap<String, Pkcs11Pool>>>,
}

impl Pkcs11Pools {
    pub fn get(&self, slot_str: &str) -> Result<Pkcs11Pool, Error> {
        let mut pools = self.pools.write().unwrap();
        match pools.entry(slot_str.to_string()) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let slot = get_slot(&self.pkcs11, slot_str)?;
                let pool = Pkcs11Pool::new(self.pkcs11.clone(), slot)?;
                let _ = entry.insert(pool.clone());
                Ok(pool)
            }
        }
    }

    pub fn new(pkcs11: Pkcs11) -> Self {
        Self {
            pkcs11,
            pools: Default::default(),
        }
    }
}

pub fn init_pkcs11(cfg: &mut Config) -> Result<Pkcs11, Error> {
    let pkcs11 = Pkcs11::new(&cfg.lib_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    for f in [
        Function::FindObjects,
        Function::GenerateKeyPair,
        Function::GetAttributeValue,
        Function::GetSlotInfo,
        Function::GetSlotInfo,
        Function::GetTokenInfo,
        Function::Login,
        Function::Sign,
    ] {
        if !pkcs11.is_fn_supported(f) {
            return Err(Error::UnusableConfig(
                "Configured PKCS#11 library lacks support for {f}".to_string(),
            ));
        }
    }
    Ok(pkcs11)
}

/// Locate a PKCS#11 slot by token label, slot id or slot index, in that
/// order.
pub fn get_slot(pkcs11: &Pkcs11, slot_str: &str) -> Result<Slot, Error> {
    fn has_token_label(pkcs11: &Pkcs11, slot: Slot, slot_label: &str) -> bool {
        pkcs11
            .get_token_info(slot)
            .map(|info| info.label().trim_end() == slot_label)
            .unwrap_or(false)
    }

    // First try finding a slot with a matching token label.
    if let Some(slot) = pkcs11
        .get_slots_with_initialized_token()?
        .into_iter()
        .find(|&slot| has_token_label(pkcs11, slot, slot_str))
    {
        return Ok(slot);
    }

    // Next try finding a slot with a matching id
    if let Ok(slot_id) = slot_str.parse::<u64>() {
        if let Some(slot) = pkcs11
            .get_slots_with_initialized_token()?
            .into_iter()
            .find(|&slot| slot.id() == slot_id)
        {
            return Ok(slot);
        }
    }

    // Lastly, try finding a slot by index
    if let Ok(slot_index) = slot_str.parse::<usize>() {
        if let Some(slot) = pkcs11.get_all_slots()?.get(slot_index) {
            return Ok(*slot);
        }
    }

    Err(Error::not_found(
        "slot",
        "slot label, id or index",
        slot_str,
    ))
}

pub fn generate_cka_id() -> [u8; 20] {
    // Generate 16 byte random CKA_ID values because:
    //   - Neither the PKCS#11 v2.40 nor KMIP 1.2 standards define any limit
    //     on the length of CKA_ID or Unique Identifier values respectively.
    //   - Implementations definitely have limits however, e.g. early versions
    //     of the YubiKey HSM 2 limited CKA_ID to 2 bytes. [1]
    //   - OpenDNSSEC goes even further, limiting IDs to 16 bytes, possibly
    //     because during testing issues were found with longer values with
    //     some PKCS#11 implementations. [2]
    //   - The field was originally intended to store the X.509 Key Identifier
    //     [3] which RFC 5280 [4] defines to be a 160-bit value i.e. 20 bytes
    //     so if it weren't for OpenDNSSEC this might have been a good limit
    //     to choose.
    //   - The CKA_ID defaults to empty and the only way to set it to the Key
    //     Identifier value is to first generate the key, then determine its
    //     Key Identifier, then call C_SetAttributeValue, but not all HSMs
    //     implement support for C_SetAttributeValue(), e.g. AWS CloudHSM
    //     doesn't include CKA_ID in the set of attributes that it allows to
    //     be changed. [5]
    //
    // [1]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-pkcs11-guide.html#version-2-4-0-or-later
    // [2]: https://github.com/opendnssec/opendnssec/blob/1f1bea259f55ccf3841184b3ba504a5d1f4639b8/libhsm/src/lib/libhsm.c#L2592
    // [3]: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959712
    // [4]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
    // [5]: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-v3-modify-attr.html
    let mut id: [u8; 20] = [0; 20];

    // TODO: OpenDNSSEC uses the HSM to generate a random value. Should we?
    rand::rng().fill_bytes(&mut id);

    id
}

pub fn pkcs11_cka_id_to_kmip_unique_identifier(cka_id: &[u8], private: bool) -> UniqueIdentifier {
    let hex = hex::encode_upper(cka_id);
    UniqueIdentifier(match private {
        true => format!("{hex}_priv"),
        false => format!("{hex}_pub"),
    })
}

pub fn kmip_unique_identifier_to_pkcs11_cka_id(id: &UniqueIdentifier) -> Vec<u8> {
    let id_len = match id.ends_with("_priv") {
        true => id.len() - 5,  // subtract _priv
        false => id.len() - 4, // subtract _pub
    };
    // The hex encoding in the UniqueIdentifier takes twice as many bytes as
    // the decoded form, so divide by two, e.g. "FF" is two bytes but
    // represents the single byte value 0xFF aka 0b1111_1111 aka 255.
    let mut cka_id = Vec::with_capacity(id_len / 2);
    cka_id.append(&mut hex::decode(&id.0[..id_len]).unwrap());
    cka_id
}

pub fn get_cached_handle_for_key(
    pkcs11conn: &Pkcs11Connection,
    id: &UniqueIdentifier,
) -> Option<ObjectHandle> {
    pkcs11conn
        .handle_cache()
        .optionally_get_with_by_ref(&id.0, || {
            let cka_id = kmip_unique_identifier_to_pkcs11_cka_id(id);
            let object_class = match id.ends_with("_priv") {
                true => ObjectClass::PRIVATE_KEY,
                false => ObjectClass::PUBLIC_KEY,
            };
            info!("Finding objects for key... {}", hex::encode(&cka_id));
            if let Ok(res) = pkcs11conn
                .session()
                .find_objects(&[Attribute::Id(cka_id), Attribute::Class(object_class)])
            {
                if res.len() == 1 {
                    info!("Found");
                    return Some(res[0]);
                }
            }

            info!("Missing or more than one match");
            None
        })
}

pub fn get_pkcs11_info(pkcs11pool: &Pkcs11Pool, cfg: &Config) -> Result<String, Error> {
    let pkcs11 = pkcs11pool.pkcs11();
    let slot = pkcs11pool.slot();
    let token_info = pkcs11.get_token_info(slot)?;
    let slot_info = pkcs11.get_slot_info(slot)?;
    let lib_name = cfg.lib_path.file_name().unwrap();
    Ok(format!(
        "PKCS#11 token with label {} in slot {} via library {}",
        token_info.label(),
        slot_info.slot_description(),
        lib_name.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_round_trip_with_short_prefix() {
        let cka_id = generate_cka_id();
        let kmip_id = pkcs11_cka_id_to_kmip_unique_identifier(&cka_id, false);
        assert!(kmip_id.ends_with("_pub"));
        let round_trip_cka_id = kmip_unique_identifier_to_pkcs11_cka_id(&kmip_id);
        assert_eq!(cka_id.as_slice(), round_trip_cka_id.as_slice());

        let cka_id = generate_cka_id();
        let kmip_id = pkcs11_cka_id_to_kmip_unique_identifier(&cka_id, true);
        assert!(kmip_id.ends_with("_priv"));
        let round_trip_cka_id = kmip_unique_identifier_to_pkcs11_cka_id(&kmip_id);
        assert_eq!(cka_id.as_slice(), round_trip_cka_id.as_slice());
    }

    #[test]
    fn id_round_trip_with_long_prefix() {
        let cka_id = generate_cka_id();
        let kmip_id = pkcs11_cka_id_to_kmip_unique_identifier(&cka_id, false);
        assert!(kmip_id.ends_with("_pub"));
        let round_trip_cka_id = kmip_unique_identifier_to_pkcs11_cka_id(&kmip_id);
        assert_eq!(cka_id.as_slice(), round_trip_cka_id.as_slice());

        let cka_id = generate_cka_id();
        let kmip_id = pkcs11_cka_id_to_kmip_unique_identifier(&cka_id, true);
        assert!(kmip_id.ends_with("_priv"));
        let round_trip_cka_id = kmip_unique_identifier_to_pkcs11_cka_id(&kmip_id);
        assert_eq!(cka_id.as_slice(), round_trip_cka_id.as_slice());
    }
}
