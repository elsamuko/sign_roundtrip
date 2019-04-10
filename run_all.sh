#!/bin/bash

# cleanup
[ -d tmp ] && rm -rf tmp
mkdir tmp

# prepare binaries
g++ -std=c++11 roundtrip.cpp -o tmp/roundtrip.bin -lcrypto
cp roundtrip.sh tmp
cp roundtrip.groovy tmp

cd tmp

# generate key pair for testing
openssl genrsa -out private.pem 2048 2> /dev/null
openssl rsa -in private.pem -out public.pem -outform PEM -pubout 2> /dev/null

# some test data
fortune > data.txt

echo
echo "C++: "
./roundtrip.bin

echo
echo "Groovy: "
./roundtrip.groovy 2> /dev/null

echo
echo "Bash: "
./roundtrip.sh

echo
