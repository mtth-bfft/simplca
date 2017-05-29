# simplca

This standalone script allows you to manage a simple certification authority without fiddling with intermediate authorities, OpenSSL commands, or x509 extensions designed at the time Netscape was still a thing.

Unlike its predecessors, it does not rely on easy-rsa, it is fairly straightforward to parse and understand (< 300 lines), and doesn't try to cover all your possible needs with dozens of commandline options. Instead, you are given a "sane" OpenSSL configuration file, which you are encouraged to read and understand, and which you can edit without it being overwritten at every update.

## Usage

Get the code using Git, or simply download (*and read*) the [simplca.sh script](https://raw.githubusercontent.com/mtth-bfft/simplca/master/simplca.sh):

    git clone https://github.com/mtth-bfft/simplca.git my_ca
    cd my_ca

Initialise an empty certification authority in the same directory:

    ./simplca.sh init

Issue server and/or client certificates as you need. Server and client certificates are what you expect to see in a mutually-authenticated TLS connection. Each command generates a certificate (.pem) and private key (.key) in the CA directory with the associated name and sane permissions. Identifiers should only contain letters, digits, underscores and dashes (you don't want to handle UTF-8 in x509 and OpenSSL's configurations):

    ./simplca.sh issue server "my-private-web-server"
    ./simplca.sh issue client "my-authenticated-client"
    ./simplca.sh issue client "another-self-explanatory-id"

If a private key leaks, or if you password-protect one and lose the password, you might want to revoke an issued certificate (server or client):

    ./simplca.sh revoke "my-authenticated-client"

If you use this script to manage a CA used by software like OpenVPN, you will probably want to generate a certificate revocation list (CRL) periodically. The following command generates it in a crl.pem file in the CA directory:

    ./simplca.sh gen-crl

If you need to restart from scratch after your tests, the following command will erase *all certificates and private keys* (like all other commands, it will prompt you before modifying anything, except if you use the -y option):

    ./simplca.sh cleanup

## Recommendations:

1. OpenSSL's manual is painful to read, but [read the fine manual](https://www.feistyduck.com/books/openssl-cookbook/)
   before using this software;
2. Read the contents of this script, and understand at least its basic steps;
3. Handle CA operations offline, or at least move private keys offline once
   they are generated.
