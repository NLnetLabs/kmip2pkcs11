#!/bin/bash
rm -R ~/softhsm/var/lib/softhsm/tokens/*
~/softhsm/bin/softhsm2-util --init-token --label Cascade --pin 1234 --so-pin 1234 --free
