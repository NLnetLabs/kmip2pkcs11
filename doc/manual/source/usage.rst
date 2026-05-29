Usage
=====

Prerequisites
-------------

Before starting **cascade-hsm-bridge** you MUST specify in the configuration
file the path to the PKCS#11 module to load. The module will communicate
with your HSM, either a hardware device or a virtual HSM such as
https://www.softhsm.org/.

.. note::

   **cascade-hsm-bridge** does NOT come with any PKCS#11 modules pre-supplied.
   The PKCS#11 module to use must match the HSM you wish to bridge connections
   to. The PKCS#11 module is normally supplied by the HSM vendor. Please
   contact your HSM vendor for assistance if needed.

.. tip::

   When installed via a package a sample configuration file should have been
   created at ``/etc/cascade-hsm-bridge/config.toml`` which you can edit and
   use.

For **cascade-hsm-bridge** to be able to use your PKCS#11 module to
communicate with your HSM you MUST ensure that any configuration files,
environment variables or other prerequisites needed by your PKCS#11 module
have been setup correctly. Please consult the documentation for your PKCS#11
module to determine what setup is required.

Once the configuration file has been correctly setup you can launch
``cascade-hsm-bridge --config /path/to/your/config/file``. Either launch it as
the correct user that has the necessary access rights required by your PKCS#11
module, or launch it as root and configure it to change user and group to
become the required user and group immediately after startup.

The expected usage is to run **cascade-hsm-bridge** as a background daemon
process, either by having it daemonize itself, or by running it via a service
manager sucih as systemd. Logs are typically sent to syslog or the systemd
journal.

Behaviour
---------

On startup **cascade-hsm-bridge** will load the configured PKCS#11 module and
will report information provided by the library at INFO level logging. It will
then wait for incoming KMIP TCP connections and convert supported requests
into the corresponding PKCS#11 request, then convert the PKCS#11 response to
the corresponding KMIP response.

Startup log output should look something like this: (with details of YOUR
PKCS#11 module and HSM, the Yubico output here is just an example)::

     [INFO] Loading and initializing PKCS#11 library /usr/lib64/pkcs11/yubihsm_pkcs11.so
     [INFO] Loaded Yubico (www.yubico.com) PKCS#11 library v2.70 supporting Cryptoki v3.1: YubiHSM PKCS#11 Library
     [WARN] Generating self-signed server identity certificate
     [INFO] Listening on 127.0.0.1:5696

Authentication
--------------

Requests to the PKCS#11 module are authenticated by "slot" and "PIN". The
"slot" and "PIN" values to use are taken from the username and password
supplied by the received KMIP request.

Further reading
---------------

  - Read the configuration file documentation at :doc:`man/cascade-hsm-bridge-config.toml`.
  - Learn about supported command line options at :doc:`man/cascade-hsm-bridge`.

