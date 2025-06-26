// TODO: Cache PKCS#11 object handles by key IDs? OpenDNSSEC keeps the object
// handle in memory.
pub mod error;
pub mod operations;
pub mod util;
pub mod pool;