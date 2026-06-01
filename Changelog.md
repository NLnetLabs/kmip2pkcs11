# Changelog

<!-- Changelog template (remove empty sections on release of a version)
## Unreleased version

Released yyyy-mm-dd.

### Breaking changes
### New
### Bug fixes
### Other changes
### Documentation improvements
### Known issues
### Acknowledgements
-->

## 0.1.0-beta

Released yyyy-mm-dd.

### Breaking changes

- Address config file deficiences and related documentation weaknesses. ([#18]
  by @ximon18)
- Don't force systemd users to use syslog. ([#21] by @ximon18)
- Rename `kmip2pkcs11` to `cascade-hsm-bridge`. ([#37] by @ximon18)i
- Add git commit hash to version string. ([#38] by @ximon18)

### Bug fixes

- Invalid configuration file: invalid type: map, expected path string, when
  'file:' was used in the log target. (by @ximon18)
- Refer to correct payload type in error message. ([#26] by @ximon18)
- Providing a non-PKCS#11 module .so file as lib-path causes panic ([#35] by
  @bal-e)
- Fix ECDSA signature parsing. (via e8fac24 in domain-kmip by @bal-e)

### Other changes

- Use 'kmip::ttlv::FastScanner' for scanning. (by @bal-e)
- Actually include man pages in built packages. (352d7410, feea13f0 and
  c4b8504e by @mozzieongit)
- Disable 'aws-lc-rs' entirely. (by @bal-e)
- Specify MSRV (1.88). (by @bal-e)
- Update versions of dependencies used to newest compatible versions.

[#18]: https://github.com/NLnetLabs/kmip2pkcs11/pull/18
[#21]: https://github.com/NLnetLabs/kmip2pkcs11/pull/21
[#26]: https://github.com/NLnetLabs/kmip2pkcs11/pull/26
[#35]: https://github.com/NLnetLabs/kmip2pkcs11/pull/35
[#37]: https://github.com/NLnetLabs/kmip2pkcs11/pull/37
[#38]: https://github.com/NLnetLabs/kmip2pkcs11/pull/38

## 0.1.0-alpha

Released 2025-10-22.

### Bug fixes

- Skip packaging for Ubuntu Focal due to compilation error. (by @ximon18)
- Correct the default log file name in the sample config file. (by @ximon18)
- Systemd ProtectSystem=strict prevents access to HSM module related resources.
  (by @ximon18)
- Remove duplicate 'using' in vendor ID string. (by @ximon18)
- Upgrade to the release version of daemonbase. (by @ximon18)

### Documentation improvements

- Add docs and man pages. ([#11] by @mozzieongit)

[#11]: https://github.com/NLnetLabs/kmip2pkcs11/pull/11

## 0.1.0-rc1

Released 2025-09-03

Initial release.
