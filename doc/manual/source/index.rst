A KMIP to PKCS#11 Relay
=======================

.. only:: html

   |lastupdated| |mastodon|

   .. |lastupdated| image:: https://img.shields.io/github/last-commit/NLnetLabs/kmip2pkcs11?path=%2Fdoc%2Fmanual&label=last%20updated
      :alt: Last docs update
      :target: https://github.com/NLnetLabs/kmip2pkcs11/commits/main/doc/manual/source

   .. |mastodon| image:: https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social
      :alt: Mastodon
      :target: https://social.nlnetlabs.nl/@nlnetlabs

.. warning::

    This project is at an experimental stage and is very much
    a work-in-progress. It should not be used in production deployments at this
    time. Furthermore, the functionality and interfaces offered should be
    considered unstable.

This Rust application accepts `KMIP
<https://groups.oasis-open.org/communities/tc-community-home2?CommunityKey=39d0c648-0a66-4f46-b343-018dc7d3f19c>`_
requests, converts them to `PKCS#11
<https://groups.oasis-open.org/communities/tc-community-home2?CommunityKey=922ef643-1e10-4d65-a5ea-018dc7d3f0a4>`_
format and executes them against a loaded PKCS#11 library.

Installing or building
----------------------

As the KMIP to PKCS#11 relay (:program:`kmip2pkcs11`) is currently only intended for use
with `Cascade`_, please refer to the
installation or building instructions of Cascade `here
<https://cascade.docs.nlnetlabs.nl/en/latest/installation.html>`_.

Use Cases
---------

Shielding Cascade against an untrusted PKCS#11 library (intended use case)
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

The use case for which this application is primarily being developed is to
enable `Cascade <https://github.com/NLnetLabs/cascade/>`_ to make use of
a Hardware Security Module (HSM) via a PKCS#11 interface without having to load
an untrusted 3rd party PKCS#11 library into its process.

This is particularly important for a Rust application as the PKCS#11 interface
exposes the application to code that is likely not protected by the guarantees
provided by the Rust compiler, as the PKCS#11 is a foreign function interface
beyond which the Rust compiler cannot see.

If the PKCS#11 library experiences a fatal error that may not be reason to exit
the parent application, whether that is appropriate is highly dependent
on the purpose of that application. Any STDOUT and STDERR output produced by
the PKCS#11 library may also become mixed with output from the application
itself which can be confusing.

Other use cases
"""""""""""""""

This project could potentially act as the basis for a general purpose KMIP to
PKCS#11 relay. However, at present and for the foreseeable future we plan only
to implement the tiny fraction of the KMIP specification needed by the Cascade
project, and the only KMIP client that will be tested against will be Cascade.

However, the supported requests cover only the small fraction of the KMIP
specification this application implements support for only a limited fraction
of the entire interface defined by the applicable versions of the KMIP and
PKCS#11 specifications, specifically whatever is needed to power our own
projects.

Technical foundations
"""""""""""""""""""""

This application is possible thanks to the following foundational Rust crates
on which it builds:

- `cryptoki <https://crates.io/crates/cryptoki>`_
- `kmip-protocol <https://crates.io/crates/kmip-protocol>`_
- `kmip-ttlv <https://crates.io/crates/kmip-ttlv>`_
- `rustls <https://crates.io/crates/rustls>`_
- `tokio <https://crates.io/crates/tokio>`_

The code of the `keyls <https://github.com/ximon18/keyls>`_ tool served as
a very useful starting point as it already supported both KMIP and PKCS#11
albeit only as a client and not as a server.

Supported protocols
-------------------

This application currently only supports a subset of KMIP 1.2 via the
TCP+TLS+TTLV transport. There is no support for the HTTPS+XML or HTTPS+JSON
transports defined by the KMIP profiles specification.

The loaded PKCS#11 module should conform to the PKCS#11 v2.40 specification.

Supported operations
--------------------

+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| KMIP Operation                                                                                           | PKCS#11 Function                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Limitations                                                         |
+==========================================================================================================+=========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================+=====================================================================+
| `Activate <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613546>`_         | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Returns with success as PKCS#11 has no notion of object activation. |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Create Key Pair <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613529>`_  | `C_GenerateKeyPair <https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc235002392>`_                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Only supports RSA and ECDSA at present.                             |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| Discover Versions                                                                                        | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Get <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613538>`_              | `C_FindObjectsInit <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002352>`_, `C_FindObjects <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002353>`_, `C_FindObjectsFinal <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002354>`_ & `C_GetAttributeValue <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002350>`_                                                                                                                                                                                              |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Modify Attribute <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613542>`_ | C_SetAttributeValue                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Query <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613552>`_            | C_GetSlotInfo, C_GetTokenInfo                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Sign <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558>`_             | `C_FindObjectsInit <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002352>`_, `C_FindObjects <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002353>`_, `C_FindObjectsFinal <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002354>`_, `C_SignInit <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002372>`_, `C_Sign <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002373>`_ & `C_SignFinal <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc2350023753>`_ |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| N/A                                                                                                      | C_GetFunctionList, C_GetInfo, C_Initialize                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Getting Started
   :name: toc-getting-started

   usage

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Manual Pages
   :name: toc-manual-pages

   man/kmip2pkcs11
   man/kmip2pkcs11-config.toml
