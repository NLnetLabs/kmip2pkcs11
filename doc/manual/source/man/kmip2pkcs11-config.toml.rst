Configuration File Format
=========================

:program:`kmip2pkcs11` uses the TOML format for its configuration file. The provided
values to the options below are the default values and are serving as a hint to
the option's format.

.. Note::

   ``kmip2pkcs11`` must be restarted for config file changes to take effect.

Example
-------

.. code-block:: text

    version = "v1"

    [daemon]
    log-level = "info"
    log-target = { type = "stdout" }
    daemonize = false

    [pkcs11]
    lib-path = "/path/to/your/pkcs11.so"

    [server]
    log_target = "syslog"
    log_facility = "daemon"
    log_fileB = "/var/log/kmip2pkcs11-relay.log"
    log_level = "info"
    addr = "127.0.0.1"
    port = 5696

Options
-------

Global Options
++++++++++++++

.. option:: version = "v1"

   The configuration file version. (REQUIRED)

   - ``v1``: This format.



.. option:: lib-path = ""

    The PKCS#11 module to use to communicate with an HSM. (REQUIRED)

Settings relevant to any deamon program.
++++++++++++++++++++++++++++++++++++++++

The ``[daemon]`` section.

.. option:: log-level = "info"

   The minimum severity of the messages logged by the daemon.

   Messages at or above the specified severity level will be logged.  The
   following levels are defined:

   - ``trace``: A function or variable was interacted with, for debugging.
   - ``debug``: Something occurred that may be relevant to debugging.
   - ``info``: Things are proceeding as expected.
   - ``warning``: Something does not appear to be correct.
   - ``error``: Something went wrong.

.. option:: log-target = { type = "stderr" }
.. option:: log-target = { type = "syslog" }
.. option:: log-target = { type = "file", path = "kmip2pkcs11.log" }

   The location the daemon writes logs to.

   - type ``file``: Logs are appended line-by-line to the specified file path.

     If it is a terminal, ANSI escape codes may be used to style the output.

   - type ``stderr``: Logs are written to stderr.

     If it is a terminal, ANSI escape codes may be used to style the output.

   - type ``syslog``: Logs are written to the UNIX syslog.

     This option is only supported on UNIX systems.

   .. note::
        When using systemd, ``syslog`` and ``stderr`` are the most reliable
        options. Systemd environments are often heavily isolated, making
        file-based logging difficult.

.. option:: daemonize = false

   Whether to apply internal daemonization.

   'Daemonization' involves several steps:

   - Forking the process to disconnect it from the terminal
   - Tracking the new process' PID (by storing it in a file)
   - Binding privileged ports (below 1024) as configured
   - Dropping administrator privileges

   These features may be provided by an external system service manager, such
   as systemd.  If no such service manager is being used, kmip2pkcs11 can
   provide such features itself, by setting this option to ``true``.  This
   will also enable the ``pid-file`` and ``identity`` settings (although they
   remain optional).

   If this option is set to ``true``, the server changes its
   working directory to the root directory and as such influences
   where files are looked for. Use absolute path names in configuration
   to avoid ambiguities.

.. TODO: Link to a dedicated systemd / daemonization guide for kmip2pkcs11.

.. option:: pid-file = "/var/run/kmip2pkcs11.pid"

   The path to a PID file to maintain, if any.

   If specified, kmip2pkcs11 will maintain a PID file at this location; it
   will be a simple plain-text file containing the PID number of the daemon
   process. This option is only supported if ``daemonize`` is true.

.. option:: identity = "kmip2pkcs11:kmip2pkcs11"

   An identity (user and group) to assume after startup.

   kmip2pkcs11 will assume the specified identity after initialization.  Note that
   this will fail if kmip2pkcs11 is started without administrator privileges.  This
   option is only supported if ``daemonize`` is ``true``.

   The identity must be specified as ``<user>:<group>``. Numeric IDs are also
   supported.

   .. NOTE:: When using systemd, you should rely on its 'User=' and 'Group='
       options instead.  See <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#User=>.

PKCS#11 settings
++++++++++++++++

The ``[pkcs11]`` section.

KMIP server TCP settings.
+++++++++++++++++++++++++

The ``[server]`` section.

.. option:: addr = "127.0.0.1:5696"

    The network address and port to listen on for incoming KMIP TLS requests.

KMIP server TLS settings.

The ``[server.identity]`` section.

.. option:: cert_path = "/path/to/cert/file"
.. option:: key_path = "/path/to/key/file"

    Optional path to a TLS certificate and key to use (in PEM format).
    
    When NOT specified, a self-signed TLS certificate will be generated
    automatically.


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
