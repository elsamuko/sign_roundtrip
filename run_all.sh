#!/bin/bash

# cleanup
if [ -e tmp ]
then
    rm -rf tmp
fi
mkdir tmp

CWD=$(pwd)


# test if bouncycastle libs are available
groovy -e "org.bouncycastle.util.io.pem.PemReader var = null" 2> /dev/null
if [ $? -eq 1 ]
then
    echo "Downloading missing bcprov-jdk15on-149.jar"
    mkdir -p ~/.groovy/lib
    cd ~/.groovy/lib
    wget -q http://www.bouncycastle.org/download/bcprov-jdk15on-149.jar
    cd "${CWD}"
fi

groovy -e "org.bouncycastle.openssl.PEMParser var = null" 2> /dev/null
if [ $? -eq 1 ]
then
    echo "Downloading missing bcpkix-jdk15on-149.jar"
    mkdir -p ~/.groovy/lib
    cd ~/.groovy/lib
    wget -q http://www.bouncycastle.org/download/bcpkix-jdk15on-149.jar
    cd "${CWD}"
fi


# prepare binaries
g++ -std=c++11 digest2DER.cpp -o tmp/digest2DER -lcrypto
g++ -std=c++11 roundtrip.cpp -o tmp/roundtrip.bin -lcrypto
cp roundtrip.sh tmp
cp roundtrip.groovy tmp

cd tmp


# generate key pair for testing
openssl genrsa -out private.pem 1024 2> /dev/null
openssl rsa -in private.pem -out public.pem -outform PEM -pubout 2> /dev/null

# some test data
fortune > data.txt

echo
echo "C++: "
./roundtrip.bin

echo
echo "Groovy: "
groovy roundtrip.groovy

echo
echo "Bash: "
./roundtrip.sh

echo

cd ..


