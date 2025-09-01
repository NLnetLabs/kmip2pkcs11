#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    #echo -e "\nKMIP2PKCS#11 VERSION:"
    #VER=$(routinator --version)
    #echo $VER

    echo -e "\nKMIP2PKCS#11 CONF:"
    cat /etc/kmip2pkcs11.conf

    echo -e "\nKMIP2PKCS#11 SERVICE STATUS:"
    systemctl status kmip2pkcs11 || true

    #echo -e "\nKMIP2PKCS#11 MAN PAGE (first 20 lines only):"
    #man -P cat kmip2pkcs11 | head -n 20 || true
    ;;

  post-upgrade)
    #echo -e "\nKMIP2PKCS#11 VERSION:"
    #kmip2pkcs11 --version
    
    echo -e "\nKMIP2PKCS#11 CONF:"
    cat /etc/kmip2pkcs11.conf
    
    echo -e "\nKMIP2PKCS#11 SERVICE STATUS:"
    systemctl status kmip2pkcs11 || true
    
    #echo -e "\nKMIP2PKCS#11 MAN PAGE:"
    #man -P cat kmip2pkcs11
    ;;
esac
