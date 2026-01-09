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

## Unreleased version

Released yyyy-mm-dd.

### Breaking changes

- Address config file deficiencies and related documentation weaknesses. ([#18] by @ximon18)

[#18]: https://github.com/NLnetLabs/kmip2pkcs11/pull/18

## 0.1.0-alpha

Released 2025-10-22.

### Bug fixes

- Skip packaging for Ubuntu Focal due to compilation error. (by @ximon18)
- Correct the default log file name in the sample config file. (by @ximon18)
- Systemd ProtectSystem=strict prevents access to HSM module related resources. (by @ximon18)
- Remove duplicate 'using' in vendor ID string. (by @ximon18)
- Upgrade to the release version of daemonbase. (by @ximon18)

### Documentation improvements

- Add docs and man pages. ([#11] by @mozzieongit)

[#11]: https://github.com/NLnetLabs/kmip2pkcs11/pull/11

## 0.1.0-rc1

Released 2025-09-03

Initial release.

Initial release.
