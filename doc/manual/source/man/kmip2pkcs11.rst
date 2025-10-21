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

General Options
---------------

.. option:: -c, --config <PATH>

    The configuration file to load. Defaults to
    ``/etc/kmip2pkcs11/config.toml``.

.. option:: --d, --detach

    Detach from terminal; default is to remain in the foreground

.. option:: -h, --help

    Print the help text (short summary with ``-h``, long help with ``--help``).
          
.. option:: -V, --version

    Print version.

Logging Options
---------------

.. option:: -v, --verbose

    Log more information, twice for even more

.. option:: -q, --quiet

    Log less information, twice for no information

.. option:: --stderr

    Log to stderr

.. option:: --syslog

    Log to syslog

.. option:: --syslog-facility <FACILITY>

    Facility to use for syslog logging. Sensible values are: ``user``,
    ``daemon``, or one of ``local0``--``local7``. See the :program:`syslog` or
    :program:`logger` man pages for a full list of facility values.
          

.. option:: --logfile <PATH>

    File to log to

Process Options
---------------

.. option:: --pid-file <PATH>

    The file for keep the daemon process's PID in

.. option:: --working-dir <PATH>

    The working directory of the daemon process

.. option:: --chroot <PATH>

    Root directory for the daemon process

.. option:: --user <UID>

    User for the daemon process

.. option:: --group <GID>

    Group for the daemon process

Files
-----

/etc/kmip2pkcs11/config.toml
    Default kmip2pkcs11 config file

See Also
--------

https://kmip2pkcs11.docs.nlnetlabs.nl
    kmip2pkcs11 online documentation

**kmip2pkcs11-config.toml**\ (5)
    :doc:`kmip2pkcs11-config.toml`

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascade**\ (1)
    Cascade CLI

**cascaded**\ (1)
    Cascade Daemon
