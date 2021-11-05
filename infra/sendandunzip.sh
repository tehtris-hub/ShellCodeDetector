#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [ "$#" -ne 5 ]; then
 echo "usage: ${0} <VM Name> <source> <dest> <USER> <PASSWORD>"
 exit 1
fi
source "${DIR}/vars.env"

echo "creating VM: ${1}"


set -x
set -e

VMNAME="${1}"
SOURCE="${2}"
DEST="${3}"
USERNAME="${4}"
PASSWORD="${5}"

waitfordesktop "${USERNAME}" "${PASSWORD}"

${VBOXMANAGE} guestcontrol "${VMNAME}" --username "${USERNAME}" --password "${PASSWORD}" copyto --target-directory "C:\\Users\\${USERNAME}\\$(filename ${SOURCE})" "${SOURCE}"
${VBOXMANAGE} guestcontrol "${VMNAME}" --username "${USERNAME}" --password "${PASSWORD}" run --exe "C:\\Windows\\System32\\cmd.exe" -- cmd.exe /c powershell -command Expand-Archive -Force "C:\\Users\\${USERNAME}\\$(filename ${SOURCE})" "${DEST}"
${VBOXMANAGE} guestcontrol "${VMNAME}" --username "${USERNAME}" --password "${PASSWORD}" removefile "C:\\Users\\${USERNAME}\\$(filename ${SOURCE})"
