// Based on https://github.com/spruceid/r2d2-cryptoki but limited to just the
// RwUser type, as we don't need the other user types, and because we always
// respect CK_TOKEN_INFO ulMaxSessionCount.

use std::ops::Deref;
use std::thread::available_parallelism;

use cryptoki::context::{Function, Pkcs11};
use cryptoki::error::RvError;
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::{Limit, Slot};
use cryptoki::types::AuthPin;
use r2d2::ManageConnection;
use tracing::{debug, info};

use crate::client_request_handler::HandleCache;
use crate::pkcs11::error::Error;

pub type Pkcs11Connection = r2d2::PooledConnection<Pkcs11ConnectionManager>;

const DEFAULT_CONCURRENCY: u32 = 8;

#[derive(Clone)]
pub struct Pkcs11Pool {
    pkcs11: Pkcs11,
    slot: Slot,
    // TODO: This application is async, why am I using the sync (r2d2) pool
    // instead of the async (bb8) pool? Or alternatively don't use a pool at
    // all but instead have a fixed number of request handling worker threads
    // each with their own PKCS#11 session.
    pool: r2d2::Pool<Pkcs11ConnectionManager>,
}

impl Pkcs11Pool {
    pub fn new(pkcs11: Pkcs11, slot: Slot) -> Result<Self, Error> {
        fn log_prop(desc: &'static str, opt: Option<u32>) {
            let v = opt.map(|v| v.to_string()).unwrap_or("Unknown".to_string());
            info!("{desc}: {v}");
        }

        // Determine and log OS and token properties that limit concurrency.
        // TODO: If the PKCS#11 session has to make a network connection it may
        // be possible to use more PKCS#11 sessions concurrently than O/S CPU
        // cores.
        let max_os_concurrency = max_os_concurrency();
        log_prop("Available parallelism", max_os_concurrency);

        let max_token_concurrency = max_token_concurrency(&pkcs11, slot)?;
        log_prop("Max token concurrency", max_token_concurrency);

        // Use the smallest of the found limits, or fallback to a default.
        let max_os_concurrency = max_os_concurrency.unwrap_or(DEFAULT_CONCURRENCY);
        let max_token_concurrency = max_token_concurrency.unwrap_or(DEFAULT_CONCURRENCY);
        let min_pool_size = 1;
        let max_pool_size = max_token_concurrency.min(max_os_concurrency);

        // Create the PKCS#11 connection pool using the established limits.
        info!("Chosen PKCS#11 connection pool limits: min={min_pool_size}, max={max_pool_size}");
        let manager = Pkcs11ConnectionManager::new(pkcs11.clone(), slot);
        let pool = r2d2::Builder::new()
            .max_size(max_pool_size)
            .min_idle(Some(min_pool_size))
            .test_on_check_out(true)
            .build(manager)
            .map_err(|err| Error::UnusableConfig(err.to_string()))?;

        Ok(Self { pkcs11, slot, pool })
    }

    pub fn pkcs11(&self) -> Pkcs11 {
        self.pkcs11.clone()
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }
}

fn max_token_concurrency(pkcs11: &Pkcs11, slot: Slot) -> Result<Option<u32>, Error> {
    let token_info = pkcs11.get_token_info(slot)?;
    if let Limit::Max(v) = token_info.max_rw_session_count() {
        if let Ok(v) = u32::try_from(v) {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

fn max_os_concurrency() -> Option<u32> {
    if let Ok(v) = available_parallelism() {
        if let Ok(v) = u32::try_from(v.get()) {
            return Some(v);
        }
    }
    None
}

impl Deref for Pkcs11Pool {
    type Target = r2d2::Pool<Pkcs11ConnectionManager>;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

pub struct Pkcs11ConnectionManager {
    pkcs11: Pkcs11,
    slot: Slot,
}

impl Pkcs11ConnectionManager {
    pub fn new(pkcs11: Pkcs11, slot: Slot) -> Self {
        Self { pkcs11, slot }
    }
}

pub struct PoolConnection {
    session: Session,
    handle_cache: HandleCache,
}

impl PoolConnection {
    pub fn new(session: Session, handle_cache: HandleCache) -> Self {
        Self {
            session,
            handle_cache,
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn handle_cache(&self) -> &HandleCache {
        &self.handle_cache
    }

    pub fn ensure_logged_in(&self, pin: AuthPin) -> Result<(), Error> {
        if self.session.get_session_info()?.session_state() != SessionState::RwUser {
            debug!("Login required");
            self.session.login(UserType::User, Some(&pin))?;
        }
        Ok(())
    }
}

impl ManageConnection for Pkcs11ConnectionManager {
    type Connection = PoolConnection;

    type Error = cryptoki::error::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let session = self.pkcs11.open_rw_session(self.slot)?;
        let handle_cache = HandleCache::new(100);
        Ok(PoolConnection::new(session, handle_cache))
    }

    fn is_valid(&self, conn: &mut PoolConnection) -> Result<(), Self::Error> {
        debug!("Testing session validity");
        match conn.session().get_session_info().is_ok() {
            true => Ok(()),
            false => {
                debug!("Session is no longer valid (not logged in as a R/W user");
                Err(Self::Error::Pkcs11(
                    RvError::UserNotLoggedIn,
                    Function::GetSessionInfo,
                ))
            }
        }
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}
