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
CA_NAME="ca"
CA_CERTS="certs"
CA_KEYS="keys"
CA_INDEX="index"
CA_CERTINDEX="${CA_INDEX}/certindex.txt"
CA_SERIAL="${CA_INDEX}/serial.txt"
CA_KEY="${CA_KEYS}/ca.key"
CA_CRT="${CA_CERTS}/ca.pem"
CA_CRL="crl.pem"
CA_CONFIG="openssl.cnf"
CA_SERIAL_START="100001"
CA_CRT_DURATION=3650 # days
CA_CRL_DURATION=10   # days
CA_RSA_KEYSIZE=4096
CA_DIGEST_ALGO="sha256"

# Site-local customisations
[ -r simplca.local.sh ] && source simplca.local.sh

# Lists options and arguments on stderr
function ca_show_usage {
    echo "Usage: $0 init" >&2
    echo "       $0 issue <client|server> <alphanumeric_id>" >&2
    echo "       $0 revoke <alphanumeric_id>" >&2
    echo "       $0 get-status <alphanumeric_id>" >&2
    echo "       $0 list" >&2
    echo "       $0 gen-crl" >&2
    echo "       $0 cleanup" >&2
}

# Prompts for y/N confirmation if shell is interactive, otherwise assumes yes
function ca_confirm_prompt {
    [ -t 0 ] || return 0
    case "$-" in
        *i*) return 0 ;;
    esac
    echo -n "${1:-Continue?} [y/N] " >&2
    read -r -n1 yn
    echo >&2
    case $yn in
        [yY]) return 0 ;;
    esac
    return 1
}

# Displays the given error message on stderr
function ca_warn {
    echo "Error: $@" >&2
}

# Outputs an OpenSSL configuration file on stdout, given global variables
function ca_gen_openssl_cnf {
    cat <<EOF
#
# OpenSSL configuration file
#

[ ca ]
default_ca                   = CA_default                # Default CA section (override with openssl ca -name)

[ CA_default ]
serial                       = ${CA_SERIAL}
database                     = ${CA_CERTINDEX}
certs                        = ${CA_CERTS}
new_certs_dir                = \$certs
certificate                  = ${CA_CRT}
private_key                  = ${CA_KEY}
crl                          = ${CA_CRL}
default_days                 = ${CA_CRT_DURATION}
default_crl_days             = ${CA_CRL_DURATION}
default_md                   = ${CA_DIGEST_ALGO}
preserve                     = no                        # Allow DN reordering
email_in_dn                  = no
nameopt                      = default_ca
certopt                      = default_ca
policy                       = policy_match

[ policy_match ]
commonName                   = supplied

# How to generate CSRs
[ req ]
default_bits                 = ${CA_RSA_KEYSIZE}
default_keyfile              = private.key
default_md                   = ${CA_DIGEST_ALGO}
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

# Takes an alphanumeric ID, outputs the certificate type amongst
# ca/server/client on stdout. Returns 0 if and only if successful.
function ca_get_cert_type {        
    if ! [ $# -eq 1 -a -r "${CA_CERTS}/$1.pem" ]; then
        ca_warn "certificate not found"
        return 1
    fi
    if ! local cert=$(cat "${CA_CERTS}/$1.pem" | openssl x509 -text); then
        ca_warn "could not read certificate"
        return 2
    fi
    if echo "$cert" | grep -qi "ca:true"; then
        echo "ca"
    elif echo "$cert" | grep -qi "server authentication"; then
        echo "server"
    elif echo "$cert" | grep -qi "client authentication"; then
        echo "client"
    else
        ca_warn "unknown certificate type"
        return 3
    fi
}

# Takes an alphanumeric ID or serial number, outputs the status amongst
# ok/revoked/expired on stdout. Returns 0 if and only if certificate is valid.
function ca_get_status {
    if ! [ $# -eq 1 -a -r "${CA_CERTS}/$1.pem" -a -r "$CA_CRT" -a -r "$CA_CRL" ]; then
        ca_warn "certificate not found"
        return 1
    fi
    if cat "$CA_CRT" "$CA_CRL" | openssl verify -crl_check -CAfile /dev/stdin "${CA_CERTS}/$1.pem" >&2; then
        echo "valid"
        return 0
    else
        echo "revoked"
        return 2
    fi
}

# Removes all state (configuration files, keys, certificates) from the current
# folder.
function ca_cleanup {
    [ -f "$CA_CONFIG" -o -d "$CA_CERTS" -o -d "$CA_KEYS" -o -d "$CA_INDEX" ] || return 0
    ca_confirm_prompt "About to REMOVE ALL CA CERTIFICATES AND KEYS. Continue?" || return 1
    rm -rf "$CA_CONFIG" "$CA_CERTS" "$CA_KEYS" "$CA_INDEX" "$CA_CRL"
    echo "CA successfully reset to an empty state" >&2
}

# Overwrites all existing configuration files/keys/certificates and
# initialises a new certification authority.
function ca_init {
    ca_cleanup || return $?
    ca_gen_openssl_cnf > "$CA_CONFIG"
    mkdir "$CA_CERTS" "$CA_KEYS" "$CA_INDEX"
    touch "${CA_CERTINDEX}"
    echo "$CA_SERIAL_START" > "$CA_SERIAL"
    openssl genrsa -out "$CA_KEY" "$CA_RSA_KEYSIZE"
    openssl req -new -batch -x509 -key "$CA_KEY" -config "$CA_CONFIG" -out "$CA_CRT"
    chmod -R 0600 "$CA_KEYS"
    chmod -R 0640 "$CA_CERTS" "$CA_INDEX"
    ca_gen_crl >/dev/null
    echo "CA successfully initialised" >&2
}

# Outputs a list of all emitted certificates on stdout. Always returns 0
function ca_list {
    echo -e "type\tstatus\tidentifier"
    [ -d "$CA_CERTS" ] || return 0
    for cert in ${CA_CERTS}/*.pem; do
        local certid=$(basename "$cert" | sed 's/.pem//')
        local status=$(ca_get_status "$certid" 2>/dev/null) || /bin/true
        local type=$(ca_get_cert_type "$certid")
        [ "$type" == "ca" ] && continue
        echo -e "${type}\t${status}\t${certid}"
    done
}

# Takes a certificate type amongst "server" or "client" and an alphanumeric
# identifier, and issues a new certificate. Returns 0 if and only if successful.
function ca_issue {
    [ $# -eq 2 ] || { ca_warn "ca_issue requires a type and ID"; return 1; }
    case "$1" in
        server|client) break ;;
        *) ca_warn "unknown certificate type '$1'" && return 1 ;;
    esac
    echo "$2" | grep -qE '^[a-zA-Z0-9_-]+$' || \
            { ca_warn "ca_issue takes an alphanumeric identifier"; return 1; }
    [ -f "$CA_CONFIG" ] || ca_init || return 1
    local crt="${CA_CERTS}/$2.pem"
    local key="${CA_KEYS}/$2.key"
    [ -f "$crt" -o -f "$key" ] && ca_warn "identifier already in use, choose another one." && return 1
    ca_confirm_prompt "About to issue a $1 certificate for '$2'. Continue?" || return 1
    local tmp=`mktemp -d`
    local csr="$tmp/req.csr"
    openssl req -new -batch -nodes -keyout "$key" -out "$csr" -config "$CA_CONFIG" >&2 || return $?
    openssl ca -batch -subj "/CN=$2/" -in "$csr" -out "$crt" -outdir "$tmp" -notext -config "$CA_CONFIG" -extensions "req_$1" >&2 || return $?
    chmod 0600 "$key"
    rm -rf "$tmp"
    cat "$crt" "$key"
    echo "Server certificate successfully written to $crt and key to $key" >&2
}

# Generates a certificate revocation list in PEM format, outputs it on stdout
# and saves it to $CA_CRL. Returns 0 if and only if successful.
function ca_gen_crl {
    if ! [ -r "$CA_KEY" -a -r "$CA_CRT" -a -r "$CA_CONFIG" ]; then
        ca_warn "please initialise your CA first"
        return 1
    fi
    openssl ca -batch -gencrl -keyfile "$CA_KEY" -cert "$CA_CRT" -out "$CA_CRL" -config "$CA_CONFIG" >&2 || return $?
    chmod 0644 "$CA_CRL"
    cat "$CA_CRL"
    echo "CRL successfully written to $CA_CRL" >&2
}

# Takes an alphanumeric ID or serial number and revokes the certificate.
# Returns 0 if and only if successful.
function ca_revoke {
    [ $# -eq 1 ] && [ -n "$1" ] || { ca_warn "ca_revoke requires an ID"; return 1; }
    [ -f "${CA_CERTS}/$1.pem" ] || { ca_warn "certificate not found"; return 1; }
    local type="$(ca_get_cert_type "$1")" || return 1
    [ "$type" = "ca" ] && ca_warn "cannot revoke CA itself" && return 2
    ca_confirm_prompt "About to REVOKE $type certificate '$1'. Continue?" || return 1
    openssl ca -revoke "${CA_CERTS}/$1.pem" -config "$CA_CONFIG" || return $?
    ca_gen_crl >/dev/null
    echo "Certificate successfully revoked, CRL updated." >&2    
}

function ca_main {
    [ $# -gt 0 ] || { ca_show_usage ; exit 1 ; }
    case "$1" in
        revoke|get-status) [ $# -eq 2 ] || { ca_show_usage ; exit 2; };;
        issue) [ $# -eq 3 ] || { ca_show_usage; exit 2; };;
        *) [ $# -eq 1 ] || { ca_show_usage; exit 2; };;
    esac
    case "$1" in
        init) ca_init ;;
        issue) ca_issue "$2" "$3" ;;
        revoke) ca_revoke "$2" ;;
        get-status) ca_get_status "$2" ;;
        list) ca_list ;;
        gen-crl) ca_gen_crl ;;
        cleanup) ca_cleanup ;;
        *) ca_warn "unknown command '$1'"; ca_show_usage ; exit 1 ;;
    esac
}

if ! openssl version &>/dev/null; then
    ca_warn "please install OpenSSL before proceeding"
    exit 1
fi
case "$0" in
    *simplca.sh*) ca_main $@ ;;
esac # otherwise, script is being sourced
