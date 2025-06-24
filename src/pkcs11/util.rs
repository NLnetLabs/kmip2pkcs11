use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;

use crate::config::Cfg;
use crate::pkcs11::error::Error;

pub fn init_pkcs11(cfg: &Cfg) -> Result<Session, Error> {
    let pkcs11 = Pkcs11::new(&cfg.lib_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    let slot = get_slot(&pkcs11, cfg)?;
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, cfg.user_pin.as_ref())?;
    Ok(session)
}

pub fn get_slot(pkcs11: &Pkcs11, cfg: &Cfg) -> std::result::Result<Slot, Error> {
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
