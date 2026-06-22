cascade-hsm-bridge Daemon
=========================

Synopsis
--------

:program:`cascade-hsm-bridge` ``[OPTIONS]``

Description
-----------

.. only:: html

    **cascade-hsm-bridge** is a KMIP to PKCS#11 bridge used primarily
    by `Cascade <https://cascade.docs.nlnetlabs.nl>`_ to access PKCS#11
    compatible HSMs.

.. only:: man or text or latex or epub

    **cascade-hsm-bridge** is a KMIP to PKCS#11 bridge used primarily by
    **cascaded**\ (1) to access PKCS#11 compatible HSMs.

For more information about Cascade, please refer to the Cascade documentation
at https://cascade.docs.nlnetlabs.nl.

Options
-------

.. option:: --check-config

          Check the configuration and exit with code 0 if the configuration
          is valid, or code 1 if the configuration is invalid.

.. option:: -c, --config <PATH>

          The configuration file to load. Required unless ``--lib-path``
		  is specified.

.. option:: --log-level <LEVEL>

          The minimum severity of messages to log [possible values: trace,
          debug, info, warning, error, critical].

          Defaults to ``info``, unless set in the config file.

.. option:: -l, --log <TARGET>

          Where logs should be written to [possible values: stderr,
          file:<PATH>, syslog].

.. option:: -d, --daemonize

          Whether **cascade-hsm-bridge** should fork on startup. This option changes
          the working directory to the root directory and as such influences
          where files are looked for. Use absolute path names in configuration
          to avoid ambiguities.

.. option:: --lib-path

          The PKCS#11 library file to load. If specified the ``--config`` file
		  argument can be omitted in which case the default configuration settings
		  will be used with the exception that the PKCS#11 file to load will be
		  taken from the value of this command line argument.

		  .. note:: You can also supply this command line argument value by seting
		            the CASCADE_HSM_BRIDGE_PKCS11_LIB_PATH environment variable.`

.. option:: -h, --help

          Print the help text (short summary with ``-h``, long help with
          ``--help``).

.. option:: -V, --version

          Print version.


Files
-----

/etc/cascade-hsm-bridge/config.toml
    Default cascade-hsm-bridge config file


See Also
--------

https://cascade.docs.nlnetlabs.nl/projects/cascade-hsm-bridge/
    **cascade-hsm-bridge** online documentation.

**cascade-hsm-bridge-config.toml**\ (5)
    :doc:`cascade-hsm-bridge-config.toml`

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation.

**cascade**\ (1)
    Cascade CLI.

**cascaded**\ (1)
    Cascade Daemon.
