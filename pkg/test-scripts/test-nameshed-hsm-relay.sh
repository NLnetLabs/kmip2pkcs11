#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    #echo -e "\nNAMESHED-HSM-RELAY VERSION:"
    #VER=$(routinator --version)
    #echo $VER

    echo -e "\nNAMESHED-HSM-RELAY CONF:"
    cat /etc/nameshed-hsm-relay.conf

    echo -e "\nNAMESHED-HSM-RELAY SERVICE STATUS:"
    systemctl status nameshed-hsm-relay || true

    #echo -e "\nNAMESHED-HSM-RELAY MAN PAGE (first 20 lines only):"
    #man -P cat nameshed-hsm-relay | head -n 20 || true
    ;;

  post-upgrade)
    #echo -e "\nNAMESHED-HSM-RELAY VERSION:"
    #nameshed-hsm-relay --version
    
    echo -e "\nNAMESHED-HSM-RELAY CONF:"
    cat /etc/nameshed-hsm-relay.conf
    
    echo -e "\nNAMESHED-HSM-RELAY SERVICE STATUS:"
    systemctl status nameshed-hsm-relay || true
    
    #echo -e "\nNAMESHED-HSM-RELAY MAN PAGE:"
    #man -P cat nameshed-hsm-relay
    ;;
esac
