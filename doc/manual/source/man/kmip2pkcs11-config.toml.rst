Configuration File Format
=========================

:program:`kmip2pkcs11` uses the TOML format for its configuration file. The provided
values to the options below are the default values and are serving as a hint to
the option's format.

Example
-------

.. code-block:: text

    lib_path = "/path/to/your/pkcs11.so"
    log_target = "syslog"
    log_facility = "daemon"
    log_file = "/var/log/kmip2pkcs11-relay.log"
    log_level = "info"
    addr = "127.0.0.1"
    port = 5696

Options
-------

.. option:: lib_path = ""

    The PKCS#11 module to use to communicate with an HSM. (REQUIRED)

    .. todo:: Set this to the actual path to the PKCS#11 module to use.

.. option:: log_target = "stderr"

   The location the daemon writes logs to.

   - type ``file``: Logs are appended line-by-line to the file specified with
     the :option:`file_path <log_file = "">` option.

   - type ``stderr``: Logs are written to stderr.

   - type ``syslog``: Logs are written to the UNIX syslog.

     This option is only supported on UNIX systems.

   .. note:: 
        When using systemd, ``syslog`` and ``stderr`` are the most reliable
        options. Systemd environments are often heavily isolated, making
        file-based logging difficult.

.. option:: log_file = ""

    When logging to file, the path to write to.

.. option:: log_level = "warn"

   The minimum severity of the messages logged by the daemon.

   Messages at or above the specified severity level will be logged. The
   following levels are defined:

   - ``trace``: A function or variable was interacted with, for debugging.
   - ``debug``: Something occurred that may be relevant to debugging.
   - ``info``: Things are proceeding as expected.
   - ``warn``: Something does not appear to be correct.
   - ``error``: Something went wrong (but kmip2pksc11 can recover).

.. option:: log_facility = "daemon"

    Facility to use for syslog logging. Sensible values are: ``user``,
    ``daemon``, or one of ``local0``--``local7``. See the :program:`syslog` or
    :program:`logger` man pages for a full list of facility values.

.. option:: addr = "127.0.0.1"
.. option:: port = 5696

    The network address and port to listen on for incoming KMIP TLS requests.

.. option:: cert_path = "/path/to/cert/file"
.. option:: key_path = "/path/to/key/file"

    Optional path to a TLS certificate and key to use (in PEM format).
    
    When one or both settings are NOT specified, a self-signed TLS certificate
    will be generated automatically.


Files
-----

/etc/kmip2pkcs11/config.toml
    Default kmip2pkcs11 config file

See Also
--------

https://kmip2pkcs11.docs.nlnetlabs.nl
    kmip2pkcs11 online documentation

**kmip2pkcs11**\ (1)
    :doc:`kmip2pkcs11`
