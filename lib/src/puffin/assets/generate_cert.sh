#!/bin/bash

set -e

python create_self-signed.py -u alice -c alice
python create_self-signed.py -u bob -c bob
python create_self-signed.py -u mallory -c mallory
python create_self-signed.py -u oscar -c oscar

echo "Convert certs to PEM"
openssl x509 -in alice_cert.der -inform DER -out alice_cert.pem -outform PEM
openssl x509 -in bob_cert.der -inform DER -out bob_cert.pem -outform PEM
openssl x509 -in mallory_cert.der -inform DER -out mallory_cert.pem -outform PEM
openssl x509 -in oscar_cert.der -inform DER -out oscar_cert.pem -outform PEM

echo "Convert keys to PEM"
openssl rsa -in alice_key.der -inform DER -out alice_key.pem -outform PEM
openssl rsa -in bob_key.der -inform DER -out bob_key.pem -outform PEM
openssl rsa -in mallory_key.der -inform DER -out mallory_key.pem -outform PEM
openssl rsa -in oscar_key.der -inform DER -out oscar_key.pem -outform PEM
