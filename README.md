> (!) _This project is at an experimental stage and is very much a work-in-progress. It should not be used in production deployments at this time. Furthermore the functionality and interfaces offered should be considered unstable._

# KMIP to PKCS#11 bridge

This Rust application accepts [KMIP](https://groups.oasis-open.org/communities/tc-community-home2?CommunityKey=39d0c648-0a66-4f46-b343-018dc7d3f19c) requests, converts them to [PKCS#11](https://groups.oasis-open.org/communities/tc-community-home2?CommunityKey=922ef643-1e10-4d65-a5ea-018dc7d3f0a4) format and executes them against a loaded PKCS#11 library.

## Use cases

### Intended use case: shielding an application against an untrusted PKCS#11 library

The use case for which this application is primarily being developed is to enable an application that wishes to make use of a Hardware Security Module (HSM) via a PKCS#11 interface to do so without having to load an untrusted 3rd party PKCS#11 library into its process.

This is particularly important for a Rust application as the PKCS#11 interface exposes the application to code that is likely not protected by the guarantees provided by the Rust compiler, as the PKCS#11 is a foreign function interface beyond which the Rust compiler cannot see.

If the PKCS#11 library experiences a fatal error that may not be reason to exit the parent application, whether or not that is appropriate is highly dependent on the purpose of that application. Any STDOUT and STDERR output produced by the PKCS#11 library may also become mixed with output from the application itself which can be confusing.

### Other use cases

This application may also be of interest as a general purpose solution for enabling a KMIP capable application to communicate with a PKCS#11 only capable HSM.

Note however that at the time of writing, and for the foreseeable future, this application implements support for only a limited fraction of the entire interface defined by the applicable versions of the KMIP and PKCS#11 specifications, specifically whatever is needed to power our own projects.

This application also currently only supports KMIP via the TCP+TLS+TTLV transport. There is no support for the HTTPS+XML or HTTPS+JSON transports defined by the KMIP profiles specification.

## Technical foundations

This application is possible thanks to the following foundational Rust crates on which it builds:

- [cryptoki](https://crates.io/crates/cryptoki)
- [kmip-protocol](https://crates.io/crates/kmip-protocol)
- [kmip-ttlv](https://crates.io/crates/kmip-ttlv)
- [rustls](https://crates.io/crates/rustls)
- [tokio](https://crates.io/crates/tokio)

The code of the [keyls](https://github.com/ximon18/keyls) tool served as a very useful starting point as it already supported both KMIP and PKCS#11 albeit only as a client and not as a server.

# Prerequisites

- A TLS certificate and key such as the example ones available here: https://github.com/rustls/hyper-rustls/blob/main/examples/. Note: This application may be updated in future to use a pre-shared key approach instead.

- A PKCS#11 library and associated HSM to interact with, either a real hardware device or a virtual HSM such as https://www.softhsm.org/.

# Supported operations

The following operations are supported by this application at present:

| KMIP Operation | PKCS#11 Function  | Limitations |
| -------------- | ----------------- | ----------- |
| [Locate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216)         | [`C_FindObjects()`](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323205460) | KMIP request payload fields are currently ignored. Will locate PKCS#11 objects having class `PUBLIC_KEY` or `PRIVATE_KEY`. |

# Usage

```
$ kmip2pkcs11
error: the following required arguments were not provided:
  --server-cert <SERVER_CERT_PATH>
  --server-key <SERVER_KEY_PATH>
  --lib-path <LIB_PATH>

Usage: kmip2pkcs11 --server-cert <SERVER_CERT_PATH> --server-key <SERVER_KEY_PATH> --lib-path <LIB_PATH>

For more information, try '--help'.
```