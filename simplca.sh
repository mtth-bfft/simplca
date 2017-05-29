#!/bin/sh

# simplca.sh standalone script, Copyright (c) 2016 Matthieu Buffet
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Configuration variables
# (do not edit these, or your changes will be lost at every update:
# instead put your customisations in a separate simplca.local.sh script)

set -euo pipefail

CA_DIR=`pwd`
CA_NAME="ca"
CA_SERIAL="${CA_DIR}/serial.txt"
CA_INDEX="${CA_DIR}/certindex.txt"
CA_CERTS="${CA_DIR}/certs"
CA_KEYS="${CA_DIR}/keys"
CA_KEY="${CA_KEYS}/ca.key"
CA_CRT="${CA_CERTS}/ca.pem"
CA_CRL="${CA_DIR}/crl.pem"
CA_CONFIG="${CA_DIR}/openssl.cnf"
CA_SERIAL_START="100001"

CRT_DURATION=3650 # days
CRL_DURATION=10   # days
RSA_KEYSIZE=4096
DIGEST_ALGO="sha256"

[ -r ${CA_DIR}/simplca.local.sh ] && source ${CA_DIR}/simplca.local.sh

function confirm_prompt {
    [ $BATCH -eq 1 ] && return 0
    echo -n "${1:-Continue?} [y/N] " >&2
    read -r -n1 yn
    echo >&2
    case $yn in
        [yY]) return 0 ;;
        *) return 1 ;;
    esac
}

function show_usage {
    echo "Usage: $0 init [-y]" >&2
    echo "       $0 issue-server <alphanumeric_id> [-y] " >&2
    echo "       $0 issue-client <alphanumeric_id> [-y] " >&2
    echo "       $0 get-cert <alphanumeric_id> " >&2
    echo "       $0 get-key <alphanumeric_id> " >&2
    echo "       $0 list " >&2
    echo "       $0 gen-crl " >&2
    echo "       $0 revoke <alphanumeric_id> [-y] " >&2
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
    [ -f ${CA_CONFIG} ] && return 0
    [ -f ${CA_CRT} ] && return 0
    [ -f ${CA_KEY} ] && return 0
    [ -d ${CA_CERTS} ] && return 0
    [ -d ${CA_KEYS} ] && return 0
    return 1
}

# Takes an alphanumeric ID or serial number, gives the serial number
function ca_get_index {
    ca_exists || die "please initialise your CA first"
    [ -f "${CA_CERTS}/$1.pem" ] && echo "$1" && return
    grep -iE "/CN=$1$" "${CA_INDEX}" | awk '{ print $(NF-2) }'
}

# Takes an alphanumeric ID or serial number, gives the entier /CN= subject
function ca_get_subject {
    ca_exists || die "please initialise your CA first"
    cat "$(ca_get_cert "$1")" | openssl x509 -subject -noout | \
        sed -re 's/subject= //' -e 's#^/CN=##'
}

# Takes an alphanumeric ID or serial number, gives the certificate path
function ca_get_cert {
    ca_exists || die "please initialise your CA first"
    [ -f "${CA_CERTS}/$1.pem" ] && echo "${CA_CERTS}/$1.pem" && return
    INDEX=$(ca_get_index "$1") || die "identifier not found."
    echo "${CA_CERTS}/${INDEX}.pem"
}

# Takes an alphanumeric ID or serial number, gives the private key path
function ca_get_key {
    ca_exists || die "please initialise your CA first"
    [ -f "${CA_KEYS}/$1.key" ] && echo "${CA_KEYS}/$1.key" && return
    INDEX=$(ca_get_index "$1") || die "identifier not found."
    echo "${CA_KEYS}/${INDEX}.key"
}

# Takes an alphanumeric ID or serial number, gives the certificate type amongst ca/server/client
function ca_get_cert_type {        
    ca_exists || die "please initialise your CA first"
    CERT="$(cat "$(ca_get_cert "$1")" | openssl x509 -text)"
    if echo "$CERT" | grep -qi "ca:true"; then
        echo "ca"
    elif echo "$CERT" | grep -qi "server authentication"; then
        echo "server"
    else
        echo "client"
    fi
}

# Returns 0 if certificate is found and valid, 1 if certificate was not found, 2 if it was revoked
function ca_get_status {
    ca_exists || die "please initialise your CA first"
    CERT=$(ca_get_cert "$1") || die "identifier not found"
    if cat "$CA_CRT" "$CA_CRL" | openssl verify -crl_check -CAfile /dev/stdin "$CERT" >&2; then
        echo "ok"; return 0
    else
        echo "revoked"; return 2
    fi
}

function ca_cleanup {
    if ca_exists && ! confirm_prompt "About to remove all CA certificates and keys. Continue?"; then
        die "user abort, no modification."
    fi
    rm -rf "${CA_CONFIG}" "${CA_CERTS}" "${CA_KEYS}" ${CA_DIR}/*.pem ${CA_DIR}/*.key ${CA_INDEX}* ${CA_SERIAL}*
    echo "CA successfully reset to an empty state" >&2
}

function ca_init {
    ca_cleanup
    gen_openssl_cnf > ${CA_CONFIG}
    echo "${CA_SERIAL_START}" > ${CA_SERIAL}
    touch "${CA_INDEX}"
    mkdir "${CA_CERTS}" "${CA_KEYS}"
    openssl genrsa -out "${CA_KEY}" ${RSA_KEYSIZE}
    openssl req -new -batch -x509 -key "${CA_KEY}" -config "${CA_CONFIG}" -out "${CA_CRT}"
    chmod 0600 "${CA_KEY}"
    ca_gen_crl >/dev/null
    echo "CA successfully initialised" >&2
}

function ca_list {
    ca_exists || die "please initialise your CA first"
    echo -e "type\tstatus\tidentifier"
    for CERTID in $(cat "${CA_INDEX}" | awk '{print $(NF-2)}'); do
        INDEX="$(ca_get_index "$CERTID")" || continue
        ca_get_status "$INDEX" &>/dev/null && status="valid" || status="revoked"
        echo -e "$(ca_get_cert_type $INDEX)\t${status}\t$(ca_get_subject $INDEX)"
    done
}

function ca_issue_server {
    ca_exists || die "please initialise your CA first"
    ca_get_index "$1" >/dev/null && die "identifier already in use. Please choose another one." || /bin/true
    confirm_prompt "About to issue a server certificate for '$1'. Continue?" || exit 1
    CSR=`mktemp`
    TMPKEY=`mktemp`
    openssl req -new -batch -nodes -keyout "$TMPKEY" -out "${CSR}" -config "${CA_CONFIG}" >&2
    openssl ca -batch -subj "/CN=$1/" -in "${CSR}" -notext -config "${CA_CONFIG}" -extensions req_server >&2
    INDEX="$(ca_get_index "$1")"
    CERT="${CA_CERTS}/${INDEX}.pem"
    KEY="${CA_KEYS}/${INDEX}.key"
    mv "$TMPKEY" "$KEY"
    chmod 0600 "$KEY"
    rm -f "$CSR" "$TMPKEY"
    cat "$CERT" "$KEY"
    echo "Server certificate successfully written to ${CERT} and key to ${KEY}" >&2
}

function ca_issue_client {
    ca_exists || die "please initialise your CA first"
    ca_get_index "$1" >/dev/null && die "identifier already in use. Please choose another one." || /bin/true
    confirm_prompt "About to issue a client certificate for '$1'. Continue?" || exit 1
    CSR=`mktemp`
    TMPKEY=`mktemp`
    openssl req -new -batch -nodes -keyout "$TMPKEY" -out "${CSR}" -config "${CA_CONFIG}" >&2
    openssl ca -batch -subj "/CN=$1/" -in "${CSR}" -notext -config "${CA_CONFIG}" -extensions req_client >&2
    INDEX="$(ca_get_index "$1")"
    CERT="${CA_CERTS}/${INDEX}.pem"
    KEY="${CA_KEYS}/${INDEX}.key"
    mv "$TMPKEY" "$KEY"
    chmod 0600 "$KEY"
    rm -f "$CSR" "$TMPKEY"
    cat "$CERT" "$KEY"
    echo "Client certificate successfully written to ${CERT} and key to ${KEY}" >&2
}

function ca_gen_crl {
    ca_exists || die "please initialise your CA first"
    openssl ca -batch -gencrl -keyfile "${CA_KEY}" -cert "${CA_CRT}" -out "${CA_CRL}" -config "${CA_CONFIG}" >&2
    echo "CRL successfully written to ${CA_CRL}" >&2
    cat "${CA_CRL}"
}

function ca_revoke {
    ca_exists || die "please initialise your CA first"
    INDEX="$(ca_get_index "$1")" || die "identifier not found."
    TYPE="$(ca_get_cert_type "$1")"
    [ "$TYPE" = "ca" ] && die "cannot revoke CA itself, only child certificates"
    confirm_prompt "About to revoke $TYPE certificate for '$1'. Continue?" || exit 1
    openssl ca -revoke "${CA_CERTS}/${INDEX}.pem" -config "${CA_CONFIG}"
    ca_gen_crl >/dev/null
    echo "Certificate successfully revoked, CRL updated." >&2    
}

function ca_main {
    [ $# -gt 0 ] || { show_usage ; exit 1 ; }

    # Read one arg as the main command
    CMD=$1
    CERTID=''
    shift
    case $CMD in
        issue-client|issue-server|revoke|get-key|get-cert|get-status)
            [ $# -gt 0 ] || die "command $CMD requires an alphanumeric argument"
            echo "$1" | grep -qE '^[a-zA-Z0-9_-]+$' || die "invalid argument for command $CMD"
            CERTID="$1"
            shift
    esac

    # Read optional arguments
    BATCH=0
    while [ $# -gt 0 ]; do
        case $1 in
            -h|--help) show_usage; exit 0 ;;
            -y|--yes) BATCH=1 ;;
            *) die "unknown option '$1'" ;;
        esac
        shift
    done

    # Call the appropriate function
    case $CMD in
        init) ca_init ;;
        issue-server) ca_issue_server "$CERTID" ;;
        issue-client) ca_issue_client "$CERTID" ;;
        revoke) ca_revoke "$CERTID" ;;
        get-key) ca_get_key "$CERTID" ;;
        get-cert) ca_get_cert "$CERTID" ;;
        get-status) ca_get_status "$CERTID" ;;
        list) ca_list ;;
        gen-crl) ca_gen_crl ;;
        cleanup) ca_cleanup ;;
        *) show_usage ; exit 1 ;;
    esac
}

which openssl >/dev/null 2>&1 || die "please install OpenSSL before proceeding"
case "$0" in
    *simplca.sh*) ca_main $@ ;;
esac # otherwise, script is being sourced
