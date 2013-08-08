#!/bin/bash


# create hash from data
openssl dgst -sha1 -binary < data.txt > hash


## create DER from hash with asn1parse ...
## https://www.openssl.org/docs/crypto/ASN1_generate_nconf.html
# HEX=$(hexdump -e '1/1 "%02X"' hash)
# cat> hash.asn1 <<EOF
# asn1=SEQUENCE:seq_all
# 
# [seq_all]
# field1=SEQUENCE:seq_type
# field2=FORMAT:HEX,OCT:${HEX}
# 
# [seq_type]
# field1=OBJECT:sha1
# field2=NULL
# EOF

# openssl asn1parse -genconf hash.asn1 -out hash.DER > /dev/null

## ... or use i2d_X509_SIG() ...
# ./digest2DER hash > hash.DER

## ... or write the DER directly
# echo -ne "\\x30\\x21\\x30\\x09\\x06\\x05\\x2B\\x0E\\x03\\x02\\x1A\\x05\\x00\\x04\\x14" > hash.DER
# cat hash >> hash.DER


## sign and verify with rsautl
# openssl rsautl -sign -inkey private.pem -keyform PEM -in hash.DER > signature
# openssl rsautl -verify -inkey public.pem -keyform PEM -pubin -in signature > verified.DER
# diff verified.DER hash.DER


# sign and verify with dgst
openssl dgst -sha1 -sign private.pem data.txt > signature
openssl dgst -sha1 -verify public.pem -signature signature data.txt > /dev/null


function boolToString() {
  case $1 in
    1) echo "false" ;;
    0) echo "true" ;;
  esac
}

echo "SHA1      : $(cat hash | base64 --wrap=0)"
echo "OK        : $( boolToString $? )"
echo "Signature : $(cat signature | base64 --wrap=0)"

