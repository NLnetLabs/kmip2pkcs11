Configuration File Format
=========================

:program:`cascade-hsm-bridge` uses the TOML format for its configuration file. The provided
values to the options below are the default values and are serving as a hint to
the option's format.

.. Note::

   **cascade-hsm-bridge** must be restarted for config file changes to take effect.

Example
-------

.. code-block:: text

    version = "v1"

    [daemon]
    log-level = "info"
    log-target = { type = "syslog" }
    daemonize = true
    pid-file = "/var/run/cascade-hsm-bridge.pid"
    identity = "cascade-hsm-bridge:cascade-hsm-bridge"

    [pkcs11]
    lib-path = "/path/to/your/pkcs11.so"

    [server]
    addr = "127.0.0.1:5696"

    [server.identity]
    cert-path = "/path/to/cert.pem"
    key-path = "/path/to/key.pem"

Options
-------

Global Options
++++++++++++++

.. option:: version = "v1"

   The configuration file version. (REQUIRED)

   - ``v1``: This format.


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
.. option:: log-target = { type = "file", path = "cascade-hsm-bridge.log" }

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
   as systemd.  If no such service manager is being used, **cascade-hsm-bridge** can
   provide such features itself, by setting this option to ``true``.  This
   will also enable the ``pid-file`` and ``identity`` settings (although they
   remain optional).

   If this option is set to ``true``, the server changes its
   working directory to the root directory and as such influences
   where files are looked for. Use absolute path names in configuration
   to avoid ambiguities.

.. TODO: Link to a dedicated systemd / daemonization guide for **cascade-hsm-bridge**.

.. option:: pid-file = "/var/run/cascade-hsm-bridge.pid"

   The path to a PID file to maintain, if any.

   If specified, cascade-hsm-bridge will maintain a PID file at this location; it
   will be a simple plain-text file containing the PID number of the daemon
   process. This option is only supported if ``daemonize`` is true.

.. option:: identity = "cascade-hsm-bridge:cascade-hsm-bridge"

   An identity (user and group) to assume after startup.

   **cascade-hsm-bridge** will assume the specified identity after initialization.
   Note that this will fail if cascade-hsm-bridge is started without administrator
   privileges.  This option is only supported if ``daemonize`` is ``true``.

   The identity must be specified as ``<user>:<group>``. Numeric IDs are also
   supported.

   .. NOTE:: When using systemd, you should rely on its 'User=' and 'Group='
       options instead.  See <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#User=>.


PKCS#11 settings.
+++++++++++++++++

The ``[pkcs11]`` section.

.. option:: lib-path = "/path/to/your/pkcs11/module.so"

    The path to the PKCS#11 module (e.g. a .so file on Linux systems) to load
    in order to communicate with an HSM. (REQUIRED)


KMIP server TCP settings.
+++++++++++++++++++++++++

The ``[server]`` section.

.. option:: addr = "127.0.0.1:5696"

    The network address and port to listen on for incoming KMIP TLS requests.


KMIP server TLS settings.
+++++++++++++++++++++++++

The ``[server.identity]`` section.

.. option:: cert-path = "/path/to/cert/file"
.. option:: key-path = "/path/to/key/file"

    Optional path to a TLS certificate and key to use (in PEM format).
    
    When NOT specified, a self-signed TLS certificate will be generated
    automatically.


Files
-----

/etc/cascade-hsm-bridge/config.toml
    Default **cascade-hsm-bridge** config file.


See Also
--------

https://cascade.docs.nlnetlabs.nl/projects/cascade-hsm-bridge/
    **cascade-hsm-bridge** online documentation.

**cascade-hsm-bridge**\ (1)
    :doc:`cascade-hsm-bridge`
