#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    echo -e "\nKMIP2PKCS#11 VERSION:"
    cascade-hsm-bridge --version

    echo -e "\nKMIP2PKCS#11 CONF:"
    cat /etc/cascade-hsm-bridge/config.toml

    echo -e "\nKMIP2PKCS#11 SERVICE STATUS:"
    systemctl status cascade-hsm-bridge || true

    #echo -e "\nKMIP2PKCS#11 MAN PAGE (first 20 lines only):"
    #man -P cat cascade-hsm-bridge | head -n 20 || true
    ;;

  post-upgrade)
    echo -e "\nKMIP2PKCS#11 VERSION:"
    cascade-hsm-bridge --version
    
    echo -e "\nKMIP2PKCS#11 CONF:"
    cat /etc/cascade-hsm-bridge/config.toml
    
    echo -e "\nKMIP2PKCS#11 SERVICE STATUS:"
    systemctl status cascade-hsm-bridge || true
    
    #echo -e "\nKMIP2PKCS#11 MAN PAGE:"
    #man -P cat cascade-hsm-bridge
    ;;
esac
