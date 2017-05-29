#!/bin/sh

set -euo -x pipefail

exec 0<&-

./simplca.sh cleanup
! ./simplca.sh revoke notfound
! ./simplca.sh issue bug myid
./simplca.sh init
./simplca.sh issue server server1
! ./simplca.sh issue server server1
! ./simplca.sh issue client server1
./simplca.sh issue server server2
./simplca.sh issue client client1
./simplca.sh issue client client2
./simplca.sh list | grep server1 | grep server | grep valid
./simplca.sh list | grep client1 | grep client | grep valid
./simplca.sh revoke client2
./simplca.sh gen-crl
./simplca.sh list | grep client2 | grep revoke
./simplca.sh cleanup

source ./simplca.sh
ca_cleanup
! ca_revoke notfound
! ca_issue bug myid
ca_init
ca_issue server server1
! ca_issue server server1
! ca_issue client server1
ca_issue server server2
ca_issue client client1
ca_issue client client2
ca_list | grep server1 | grep server | grep valid
ca_list | grep client1 | grep client | grep valid
ca_revoke client2
ca_gen_crl
ca_list | grep client2 | grep revoke
ca_cleanup

echo " [+] All tests passed"
