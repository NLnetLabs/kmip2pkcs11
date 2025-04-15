use anyhow::{Result, bail};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
};

use crate::{
    config::Cfg,
    key::{Key, KeyType},
};

pub(crate) fn get_keys(cfg: &Cfg) -> Result<Vec<Key>> {
    let pkcs11 = Pkcs11::new(&cfg.lib_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    let slot = get_slot(&pkcs11, cfg)?;
    println!("Using PKCS#11 slot id {} ({:#x})", slot.id(), slot.id());

    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, cfg.user_pin.as_ref())?;

    let mut keys = Vec::new();
    for key_handle in session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])? {
        eprintln!("Getting attributes for private key {key_handle:?}...");
        match get_key(&session, key_handle) {
            Ok(key) => keys.push(key),
            Err(err) => eprintln!(
                "Error retrieving attributes for private key {:?}: {}",
                key_handle, err
            ),
        }
    }
    for key_handle in session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])? {
        eprintln!("Getting attributes for public key {key_handle:?}...");
        match get_key(&session, key_handle) {
            Ok(key) => keys.push(key),
            Err(err) => eprintln!(
                "Error retrieving attributes for public key {:?}: {}",
                key_handle, err
            ),
        }
    }

    keys.sort_by_key(|v| v.id.clone());

    eprintln!("Found {} keys", keys.len());
    Ok(keys)
}

fn get_key(session: &Session, key_handle: ObjectHandle) -> Result<Key> {
    let mut key = Key {
        id: Default::default(),
        typ: KeyType::Private,
        name: Default::default(),
        alg: Default::default(),
        len: Default::default(),
    };

    let request_attrs = [
        AttributeType::Class,
        AttributeType::Id,
        AttributeType::ModulusBits,
        AttributeType::KeyType,
        AttributeType::Label,
    ];
    let attrs = session.get_attributes(key_handle, &request_attrs)?;

    for attr in attrs {
        match attr {
            Attribute::Class(class) => {
                if class == ObjectClass::PRIVATE_KEY {
                    key.typ = KeyType::Private;
                } else if class == ObjectClass::PUBLIC_KEY {
                    key.typ = KeyType::Public;
                } else {
                    bail!("Unsupported object class");
                }
            }
            Attribute::Id(id) => {
                key.id = hex::encode_upper(&id);
            }
            Attribute::KeyType(typ) => {
                if typ == cryptoki::object::KeyType::RSA {
                    key.alg = "RSA".to_string();
                } else {
                    key.alg = "Non-RSA".to_string();
                }
            }
            Attribute::Label(label) => {
                key.name = String::from_utf8_lossy(&label).to_string();
            }
            Attribute::ModulusBits(bits) => {
                key.len = bits.to_string();
            }
            _ => {
                // ignore unexpected attributes
            }
        }
    }

    Ok(key)
}

fn get_slot(pkcs11: &Pkcs11, cfg: &Cfg) -> Result<Slot> {
    fn has_token_label(pkcs11: &Pkcs11, slot: Slot, slot_label: &str) -> bool {
        pkcs11
            .get_token_info(slot)
            .map(|info| info.label().trim_end() == slot_label)
            .unwrap_or(false)
    }

    let slot = match (&cfg.slot_id, &cfg.slot_label) {
        (Some(id), None) => {
            match pkcs11
                .get_all_slots()?
                .into_iter()
                .find(|&slot| slot.id() == *id)
            {
                Some(slot) => slot,
                None => bail!("Cannot find slot with id {}", id),
            }
        }
        (None, Some(label)) => {
            match pkcs11
                .get_slots_with_initialized_token()?
                .into_iter()
                .find(|&slot| has_token_label(pkcs11, slot, label))
            {
                Some(slot) => slot,
                None => bail!("Cannot find slot with label '{}'", label),
            }
        }
        (Some(_), Some(_)) => bail!("Cannot specify both slot id and slot label"),
        (None, None) => bail!("Must specify at least one of slot id or slot label"),
    };

    Ok(slot)
}
