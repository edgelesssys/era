#!/bin/bash

set -e

mkdir -p /opt/intel/pccs/config/
cd /opt/intel/pccs/config/

if [ -n "$APIKEY" ]; then
    apikey="$APIKEY"
    sed -i "s/\"ApiKey\"[ ]*:[ ]*\"\",/\"ApiKey\": \"$apikey\",/" default.json
else
    echo "ERROR: You need to submit an APIKEY, otherwise your PCCS can not connect to the PCS"
    exit 1
fi

if [ -n "$USERPASS" ]; then
    userpass="$USERPASS"
else
    userpass="12345"
fi
userhash=$(echo -n "$userpass" | sha512sum | tr -d '[:space:]-')
sed -i "s/\"UserTokenHash\"[ ]*:[ ]*\"\",/\"UserTokenHash\": \"$userhash\",/" default.json

if [ -n "$ADMINPASS" ]; then
    adminpass="$ADMINPASS"
else
    adminpass="54321"
fi
adminhash=$(echo -n "$adminpass" | sha512sum | tr -d '[:space:]-')
sed -i "s/\"AdminTokenHash\"[ ]*:[ ]*\"\",/\"AdminTokenHash\": \"$adminhash\",/" default.json

sed -i 's/\"hosts\"[ ]*:[ ]*\"127.0.0.1\",/\"hosts\": \"0.0.0.0\",/' default.json
cd ..
/usr/bin/node -r esm /opt/intel/pccs/pccs_server.js
