#!/bin/bash

# Configuration variables
# (do not edit these, or your changes will be lost at every update:
# instead put your customisations in a separate anon_certificate.local)

pushd `dirname $0` > /dev/null
CA_DIR=`pwd`
popd > /dev/null
CA_NAME="ca"
CA_KEY="${CA_DIR}/ca.key"
CA_CRT="${CA_DIR}/ca.pem"
CA_CRL="${CA_DIR}/crl.pem"
CA_SERIAL="${CA_DIR}/serial.txt"
CA_INDEX="${CA_DIR}/certindex.txt"
CA_CERTS="${CA_DIR}/certs"
CA_SERIAL_START="100001"

CRT_DURATION=3650 # days
CRL_DURATION=10   # days
RSA_KEYSIZE=4096
OPENSSL_CNF="${CA_DIR}/openssl.cnf"
DIGEST_ALGO=sha256

# Bash "safe" mode
set -euo pipefail

function confirm_prompt {
    read -r -n1 -p "${1:-Continue?} [y/N] " yn
    echo
    case $yn in
        [yY]) return 0 ;;
        *) return 1 ;;
    esac
}

function show_usage {
    echo "Usage: $0 init [-c local_conf.sh] [-y]" >&2
    echo "       $0 issue-server <alphanumeric_id> [-c local_conf.sh] [-y] " >&2
    echo "       $0 issue-client <alphanumeric_id> [-c local_conf.sh] [-y] " >&2
    echo "       $0 revoke <alphanumeric_id> [-c local_conf.sh] [-y] " >&2
    echo "       $0 cleanup [-y] " >&2
}

function die {
    echo "Error: $1" >&2
    exit 1
}

function gen_openssl_cnf {
    cat <<EOF
#
# OpenSSL configuration file
#

[ ca ]
default_ca                   = CA_default                # Default CA section (override with openssl ca -name)

[ CA_default ]
serial                       = ${CA_SERIAL}
database                     = ${CA_INDEX}
certs                        = ${CA_CERTS}
new_certs_dir                = \$certs
certificate                  = ${CA_CRT}
private_key                  = ${CA_KEY}
crl                          = ${CA_CRL}
default_days                 = ${CRT_DURATION}
default_crl_days             = ${CRL_DURATION}
default_md                   = ${DIGEST_ALGO}
preserve                     = no                        # Allow DN reordering
email_in_dn                  = no
nameopt                      = default_ca
certopt                      = default_ca
policy                       = policy_match

[ policy_match ]
commonName                   = supplied

# How to generate CSRs
[ req ]
default_bits                 = ${RSA_KEYSIZE}
default_keyfile              = client.key
default_md                   = ${DIGEST_ALGO}
string_mask                  = nombstr
distinguished_name           = req_distinguished_name
x509_extensions              = v3_ca

[ req_distinguished_name ]
commonName                   = Common Name (hostname, IP, or your name)
commonName_max               = 64
commonName_default           = ${CA_NAME}

[ v3_ca ]
basicConstraints             = CA:TRUE, pathlen:0
subjectKeyIdentifier         = hash
authorityKeyIdentifier       = keyid:always,issuer:always
keyUsage                     = keyCertSign,cRLSign

[ req_server ]
basicConstraints             = CA:FALSE
subjectKeyIdentifier         = hash
authorityKeyIdentifier       = keyid:always,issuer:always
keyUsage                     = digitalSignature,keyAgreement
extendedKeyUsage             = serverAuth

[ req_client ]
basicConstraints             = CA:FALSE
subjectKeyIdentifier         = hash
authorityKeyIdentifier       = keyid:always,issuer:always
keyUsage                     = digitalSignature,keyAgreement
extendedKeyUsage             = clientAuth
EOF
}

function ca_exists {
    [ -f ${OPENSSL_CNF} ] && return 0
    [ -f ${CA_CRT} ] && return 0
    [ -f ${CA_KEY} ] && return 0
    [ -d ${CA_CERTS} ] && return 0
    return 1
}

function ca_cleanup {
    if ! [ $BATCH -eq 1 ] && ! confirm_prompt "About to remove CA. Continue?"; then
        die "user abort, no modification."
    fi
    rm -rf "${OPENSSL_CNF}" ${CA_DIR}/*.pem ${CA_DIR}/*.key "${CA_CERTS}"
    rm -f ${CA_INDEX}* ${CA_SERIAL}*
}

function ca_init {
    if ca_exists; then
        ca_cleanup || die "user abort, no modification."
    fi
    gen_openssl_cnf > ${OPENSSL_CNF}
    echo "${CA_SERIAL_START}" > ${CA_SERIAL}
    touch "${CA_INDEX}"
    mkdir "${CA_CERTS}"
    openssl genrsa -out "${CA_KEY}" ${RSA_KEYSIZE}
    openssl req -new -batch -x509 -key "${CA_KEY}" -config "${OPENSSL_CNF}" -out "${CA_CRT}"
    openssl ca -gencrl -out "${CA_CRL}" -config "${OPENSSL_CNF}" -extensions v3_ca
    chmod 0600 "${CA_KEY}"
}

function ca_issue_server {
    CSR=$(mktemp)
    openssl req -new -batch -nodes -keyout "${CA_DIR}/${CERTID}.key" -out "${CSR}" -config "${OPENSSL_CNF}"
    openssl ca -batch -subj "/CN=${CERTID}/" -in "${CSR}" -out "${CA_DIR}/${CERTID}.pem" -config "${OPENSSL_CNF}" -extensions req_server
    chmod 0600 "${CA_DIR}/${CERTID}.key"
    rm -f "${CSR}"
}

function ca_issue_client {
    CSR=$(mktemp)
    openssl req -new -batch -nodes -keyout "${CA_DIR}/${CERTID}.key" -out "${CSR}" -config "${OPENSSL_CNF}"
    openssl ca -batch -subj "/CN=${CERTID}/" -in "${CSR}" -out "${CA_DIR}/${CERTID}.pem" -config "${OPENSSL_CNF}" -extensions req_client
    chmod 0600 "${CA_DIR}/${CERTID}.key"
    rm -f "${CSR}"
}

function ca_revoke {
    die "not implemented yet. Sorry"
}

# Check that OpenSSL is installed
which openssl >/dev/null 2>&1 || die "please install OpenSSL before proceeding"

# Read command from first argument
[ $# -gt 0 ] || die "command keyword needed"
CMD=$1
shift
CERTID=''
case $CMD in
    issue-client|issue-server|revoke)
        [ $# -gt 0 ] || die "command $CMD requires an alphanumeric argument"
	[[ "$1" =~ ^[a-zA-Z0-9]+$ ]] || die "invalid argument for command $CMD"
        CERTID=$1
	shift ;;
    init|cleanup) ;;
    *)
        die "unknown command $CMD"
esac

# Read optional arguments
OPTIND=1
BATCH=0
while getopts ":hyc:" opt; do
    case $opt in
        h)
            show_usage
            exit 0 ;;
        y)
            BATCH=1 ;;
        c)
            if ! [ -z "$OPTARG" ]; then
                [ -r "$OPTARG" ] || die "could not read configuration file $OPTARG"
                source "$OPTARG"
            fi ;;
        :)
            die "Option -c requires an argument" ;;
	*)
            die "Invalid option: -$OPTARG" ;;
    esac
done

# Call the appropriate function
case $CMD in
    init) ca_init ;;
    issue-server) ca_issue_server ;;
    issue-client) ca_issue_client ;;
    revoke) ca_revoke ;;
    cleanup) ca_cleanup ;;
esac

