kmip2pkcs11 Daemon
==================

Synopsis
--------

:program:`kmip2pkcs11` ``[OPTIONS]``

Description
-----------

.. only:: html

    **kmip2pkcs11** is a KMIP to PKCS#11 relay used primarily by `Cascade
    <https://cascade.docs.nlnetlabs.nl>`_ to access PKCS#11 compatible HSMs.

.. only:: man or text or latex or epub

    **kmip2pkcs11** is a KMIP to PKCS#11 relay used primarily by **cascaded**\
    (1) to access PKCS#11 compatible HSMs.

For more information about Cascade, please refer to the Cascade documentation
at https://cascade.docs.nlnetlabs.nl.

Options
-------

.. option:: --check-config

          Check the configuration and exit with code 0 if the configuration
          is valid, or code 1 if the configuration is invalid.

.. option:: -c, --config <PATH>

          The configuration file to load. Defaults to
          ``/etc/kmip2pkcs11/config.toml``.

.. option:: --log-level <LEVEL>

          The minimum severity of messages to log [possible values: trace,
          debug, info, warning, error, critical].

          Defaults to ``info``, unless set in the config file.

.. option:: -l, --log <TARGET>

          Where logs should be written to [possible values: stderr,
          file:<PATH>, syslog].

.. option:: -d, --daemonize

          Whether **kmip2pkcs11** should fork on startup. This option changes
          the working directory to the root directory and as such influences
          where files are looked for. Use absolute path names in configuration
          to avoid ambiguities.

.. option:: -h, --help

          Print the help text (short summary with ``-h``, long help with
          ``--help``).

.. option:: -V, --version

          Print version.


Files
-----

/etc/kmip2pkcs11/config.toml
    Default kmip2pkcs11 config file


See Also
--------

https://cascade.docs.nlnetlabs.nl/projects/kmip2pkcs11/
    **kmip2pkcs11** online documentation.

**kmip2pkcs11-config.toml**\ (5)
    :doc:`kmip2pkcs11-config.toml`

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation.

**cascade**\ (1)
    Cascade CLI.

**cascaded**\ (1)
    Cascade Daemon.
