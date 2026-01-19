//! Test the full path between KMIP clients and PKCS#11 HSM.
//!
//! This is a full-system test: it initializes `kmip2pkcs11` with [SoftHSMv2]
//! and queries it from a KMIP client. The full breadth of supported KMIP
//! operations is tested.
//!
//! [SoftHSMv2]: https://github.com/softhsm/SoftHSMv2
//!
//! # Process
//!
//! A single `kmip2pkcs11` server is initialized using [SoftHSMv2]. It is
//! configured to store all filesystem state in a temporary directory, so that
//! distinct invocations do not affect each other. Multiple tests are executed
//! against that server. If any of them fail, they can be run in isolation.

// Only available on Unix machines.
#![cfg(unix)]

fn main() {}
