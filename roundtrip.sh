#!/usr/bin/env bash

# create hash from data
openssl dgst -sha256 -binary < data.txt > hash

# sign and verify with dgst
openssl dgst -sha256 -sign private.pem data.txt > signature
openssl dgst -sha256 -verify public.pem -signature signature data.txt > /dev/null

function boolToString() {
    [[ $1 -eq 0 ]] && echo "true"
    [[ $1 -eq 1 ]] && echo "false"
}

echo "SHA256    : $(cat hash | base64 --wrap=0)"
echo "OK        : $( boolToString $? )"
echo "Signature : $(cat signature | base64 --wrap=0)"
