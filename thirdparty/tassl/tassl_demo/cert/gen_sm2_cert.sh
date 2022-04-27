#!/bin/sh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/root/tassl/lib
OPENSSL_DIR=/root/tassl
CERT_DIR=/root/tassl/tassl_demo/cert/

# Path to the openssl program
OPENSSL_CMD=$OPENSSL_DIR/bin/openssl
# Option to find configuration file
OPENSSL_CNF="-config ./openssl.cnf"
# Directory where certificates are stored
CERTS_DIR=./certs
# Directory where private key files are stored
KEYS_DIR=$CERTS_DIR
# Directory where combo files (containing a certificate and corresponding
# private key together) are stored
COMBO_DIR=$CERTS_DIR
# cat command
CAT=/bin/cat
# rm command
RM=/bin/rm

$RM -rf ./certs

# mkdir command
MKDIR=/bin/mkdir
# The certificate will expire these many days after the issue date.
DAYS=1500
TEST_CA_CURVE=SM2
TEST_CA_FILE=CA
TEST_CA_DN="/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=SORB of TASS/CN=Test CA (SM2)"

TEST_SERVER_CURVE=SM2
TEST_SERVER_FILE=SS
TEST_SERVER_DN="/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=BSRC of TASS/CN=server sign (SM2)"

TEST_SERVER_ENC_FILE=SE
TEST_SERVER_ENC_DN="/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=BSRC of TASS/CN=server enc (SM2)"

TEST_CLIENT_CURVE=SM2
TEST_CLIENT_FILE=CS
TEST_CLIENT_DN="/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=BSRC of TASS/CN=client sign (SM2)"

TEST_CLIENT_ENC_FILE=CE
TEST_CLIENT_ENC_DN="/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=BSRC of TASS/CN=client enc(SM2)"


rm -rf /root/openssl-1.1.1/Tassl_demo/tls_cert/certs/*
# Generating an EC certificate involves the following main steps
# 1. Generating curve parameters (if needed)
# 2. Generating a certificate request
# 3. Signing the certificate request 
# 4. [Optional] One can combine the cert and private key into a single
#    file and also delete the certificate request

$MKDIR -p $CERTS_DIR
$MKDIR -p $KEYS_DIR
$MKDIR -p $COMBO_DIR

echo "Generating self-signed CA certificate (on curve $TEST_CA_CURVE)"
echo "==============================================================="
$OPENSSL_CMD ecparam -name $TEST_CA_CURVE -out $TEST_CA_CURVE.pem

# Generate a new certificate request in $TEST_CA_FILE.csr. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_CA_CURVE.pem and the private key is saved in $TEST_CA_FILE.key
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_CA_DN" \
    -keyout $KEYS_DIR/$TEST_CA_FILE.key \
    -newkey ec:$TEST_CA_CURVE.pem -new \
    -out $CERTS_DIR/$TEST_CA_FILE.csr



# Sign the certificate request in $TEST_CA_FILE.csr using the
# private key in $TEST_CA_FILE.key and include the CA extension.
# Make the certificate valid for 1500 days from the time of signing.
# The certificate is written into $TEST_CA_FILE.crt
$OPENSSL_CMD x509 -sm3 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_CA_FILE.csr \
    -extfile $CERT_DIR/openssl.cnf \
    -extensions v3_ca \
    -signkey $KEYS_DIR/$TEST_CA_FILE.key \
    -out $CERTS_DIR/$TEST_CA_FILE.crt

# Display the certificate
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CA_FILE.crt -text

# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CA_FILE.crt -issuer -subject \
	 > $COMBO_DIR/$TEST_CA_FILE.pem
$CAT $KEYS_DIR/$TEST_CA_FILE.key >> $COMBO_DIR/$TEST_CA_FILE.pem

# Remove the cert request file (no longer needed)
$RM $CERTS_DIR/$TEST_CA_FILE.csr

echo "GENERATING A TEST SERVER CERTIFICATE (on elliptic curve $TEST_SERVER_CURVE)"
echo "=========================================================================="
# Generate a new certificate request in $TEST_SERVER_FILE.csr. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_SERVER_CURVE.pem and the private key is saved in 
# $TEST_SERVER_FILE.key
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_SERVER_DN" \
    -keyout $KEYS_DIR/$TEST_SERVER_FILE.key \
    -newkey ec:$TEST_SERVER_CURVE.pem -new \
    -out $CERTS_DIR/$TEST_SERVER_FILE.csr

# Sign the certificate request in $TEST_SERVER_FILE.csr using the
# CA certificate in $TEST_CA_FILE.crt and the CA private key in
# $TEST_CA_FILE.key. Since we do not have an existing serial number
# file for this CA, create one. Make the certificate valid for $DAYS days
# from the time of signing. The certificate is written into 
# $TEST_SERVER_FILE.crt
$OPENSSL_CMD x509 -sm3 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_SERVER_FILE.csr \
    -CA $CERTS_DIR/$TEST_CA_FILE.crt \
    -CAkey $KEYS_DIR/$TEST_CA_FILE.key \
	-extfile $CERT_DIR/openssl.cnf \
	-extensions v3_req \
    -out $CERTS_DIR/$TEST_SERVER_FILE.crt -CAcreateserial

# Display the certificate 
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_SERVER_FILE.crt -text

# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_SERVER_FILE.crt -issuer -subject \
	 > $COMBO_DIR/$TEST_SERVER_FILE.pem
$CAT $KEYS_DIR/$TEST_SERVER_FILE.key >> $COMBO_DIR/$TEST_SERVER_FILE.pem

# Remove the cert request file (no longer needed)
$RM $CERTS_DIR/$TEST_SERVER_FILE.csr

echo "	GENERATING A TEST SERVER ENCRYPT CERTIFICATE (on elliptic curve $TEST_SERVER_CURVE)"
echo "  ==================================================================================="
# Generate a new certificate request in $TEST_SERVER_FILE.csr. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_SERVER_CURVE.pem and the private key is saved in 
# $TEST_SERVER_FILE.key
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_SERVER_ENC_DN" \
    -keyout $KEYS_DIR/$TEST_SERVER_ENC_FILE.key \
    -newkey ec:$TEST_SERVER_CURVE.pem -new \
    -out $CERTS_DIR/$TEST_SERVER_ENC_FILE.csr

# Sign the certificate request in $TEST_SERVER_FILE.csr using the
# CA certificate in $TEST_CA_FILE.crt and the CA private key in
# $TEST_CA_FILE.key. Since we do not have an existing serial number
# file for this CA, create one. Make the certificate valid for $DAYS days
# from the time of signing. The certificate is written into 
# $TEST_SERVER_FILE.crt
$OPENSSL_CMD x509 -sm3 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_SERVER_ENC_FILE.csr \
    -CA $CERTS_DIR/$TEST_CA_FILE.crt \
    -CAkey $KEYS_DIR/$TEST_CA_FILE.key \
	-extfile $CERT_DIR/openssl.cnf \
	-extensions v3enc_req \
    -out $CERTS_DIR/$TEST_SERVER_ENC_FILE.crt -CAcreateserial

# Display the certificate 
$OPENSSL_CMD x509 -sm3 -in $CERTS_DIR/$TEST_SERVER_ENC_FILE.crt -text

# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_SERVER_ENC_FILE.crt -issuer -subject \
	 > $COMBO_DIR/$TEST_SERVER_ENC_FILE.pem
$CAT $KEYS_DIR/$TEST_SERVER_ENC_FILE.key >> $COMBO_DIR/$TEST_SERVER_ENC_FILE.pem

# Remove the cert request file (no longer needed)
$RM $CERTS_DIR/$TEST_SERVER_ENC_FILE.csr



echo "GENERATING A TEST CLIENT CERTIFICATE (on elliptic curve $TEST_CLIENT_CURVE)"
echo "=========================================================================="
# Generate a new certificate request in $TEST_CLIENT_FILE.csr. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_CLIENT_CURVE.pem and the private key is saved in 
# $TEST_CLIENT_FILE.key
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_CLIENT_DN" \
	     -keyout $KEYS_DIR/$TEST_CLIENT_FILE.key \
	     -newkey ec:$TEST_CLIENT_CURVE.pem -new \
	     -out $CERTS_DIR/$TEST_CLIENT_FILE.csr

# Sign the certificate request in $TEST_CLIENT_FILE.csr using the
# CA certificate in $TEST_CA_FILE.crt and the CA private key in
# $TEST_CA_FILE.key. Since we do not have an existing serial number
# file for this CA, create one. Make the certificate valid for $DAYS days
# from the time of signing. The certificate is written into 
# $TEST_CLIENT_FILE.crt
$OPENSSL_CMD x509 -sm3 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_CLIENT_FILE.csr \
    -CA $CERTS_DIR/$TEST_CA_FILE.crt \
    -CAkey $KEYS_DIR/$TEST_CA_FILE.key \
	-extfile $CERT_DIR/openssl.cnf \
	-extensions v3_req \
    -out $CERTS_DIR/$TEST_CLIENT_FILE.crt -CAcreateserial

# Display the certificate 
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CLIENT_FILE.crt -text

# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CLIENT_FILE.crt -issuer -subject \
	 > $COMBO_DIR/$TEST_CLIENT_FILE.pem
$CAT $KEYS_DIR/$TEST_CLIENT_FILE.key >> $COMBO_DIR/$TEST_CLIENT_FILE.pem

# Remove the cert request file (no longer needed)
$RM $CERTS_DIR/$TEST_CLIENT_FILE.csr


echo "	GENERATING A TEST CLIENT ENCRYPT CERTIFICATE (on elliptic curve $TEST_CLIENT_CURVE)"
echo "	==================================================================================="
# Generate a new certificate request in $TEST_CLIENT_FILE.csr. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_CLIENT_CURVE.pem and the private key is saved in 
# $TEST_CLIENT_FILE.key
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_CLIENT_ENC_DN" \
	     -keyout $KEYS_DIR/$TEST_CLIENT_ENC_FILE.key \
	     -newkey ec:$TEST_CLIENT_CURVE.pem -new \
	     -out $CERTS_DIR/$TEST_CLIENT_ENC_FILE.csr

# Sign the certificate request in $TEST_CLIENT_FILE.csr using the
# CA certificate in $TEST_CA_FILE.crt and the CA private key in
# $TEST_CA_FILE.key. Since we do not have an existing serial number
# file for this CA, create one. Make the certificate valid for $DAYS days
# from the time of signing. The certificate is written into 
# $TEST_CLIENT_FILE.crt
$OPENSSL_CMD x509 -sm3 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_CLIENT_ENC_FILE.csr \
    -CA $CERTS_DIR/$TEST_CA_FILE.crt \
    -CAkey $KEYS_DIR/$TEST_CA_FILE.key \
	-extfile $CERT_DIR/openssl.cnf \
	-extensions v3enc_req \
    -out $CERTS_DIR/$TEST_CLIENT_ENC_FILE.crt -CAcreateserial

# Display the certificate 
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CLIENT_ENC_FILE.crt -text

# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CLIENT_ENC_FILE.crt -issuer -subject \
	 > $COMBO_DIR/$TEST_CLIENT_ENC_FILE.pem
$CAT $KEYS_DIR/$TEST_CLIENT_ENC_FILE.key >> $COMBO_DIR/$TEST_CLIENT_ENC_FILE.pem

# Remove the cert request file (no longer needed)
$RM $CERTS_DIR/$TEST_CLIENT_ENC_FILE.csr


$RM $TEST_CA_CURVE.pem
