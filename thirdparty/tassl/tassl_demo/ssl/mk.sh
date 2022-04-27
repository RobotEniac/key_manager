#!/bin/sh
LIB_DIR=/root/tassl/lib
INC_DIR=/root/tassl/include
PROGRAMES="sslsvr sslcli"

if [ $1"X" == "cleanX" ]; then
printf "cleaning the programe %s.....\n" $PROGRAMES
        rm -rf ${PROGRAMES}
else
printf "compiling the programe.....\n"
gcc -ggdb3 -O0 -o sslsvr sslsvr.c -I${INC_DIR}  ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
gcc -ggdb3 -O0 -o sslcli sslcli.c -I${INC_DIR}  ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
fi
