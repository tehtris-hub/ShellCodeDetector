#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [ "$#" -ne 1 ]; then
 echo "usage: ${0} <VM Name>"
 exit
fi
echo "creating VM: ${1}"

set -x
set -e

VMNAME="${1}"
source "${DIR}/vars.env"

#Get latest virtualbox guest additions
ADDITIONS=$(curl -s https://download.virtualbox.org/virtualbox/LATEST.TXT)
if [ ! -f "${TEMPDIR}/VBoxGuestAdditions_${ADDITIONS}.iso" ]
then
    rm -f "${TEMPDIR}/VBoxGuestAdditions_*iso"
    curl -# -o "${TEMPDIR}/VBoxGuestAdditions_${ADDITIONS}.iso" "https://download.virtualbox.org/virtualbox/${ADDITIONS}/VBoxGuestAdditions_${ADDITIONS}.iso"
fi
ADDITIONS="${TEMPDIR}/VBoxGuestAdditions_${ADDITIONS}.iso"

if [ ! -f "${WINISO}" ]
then
    echo "Windows ISO ${WINISO} not found. Get it from https://www.microsoft.com/fr-fr/software-download/windows10"
    exit 1
fi

if [ ! -f "${TEMPDIR}/${PINVERSION}.zip" ]
then
  curl -o "${TEMPDIR}/${PINVERSION}.zip" "https://software.intel.com/sites/landingpage/pintool/downloads/${PINVERSION}.zip"
  if [ $? -ne 0 ]
  then
    echo "failed to download: https://software.intel.com/sites/landingpage/pintool/downloads/${PINVERSION}.zip"
    exit 1
  fi
fi


#Remove old VM if exists
set +e
${VBOXMANAGE} unregistervm --delete "${VMNAME}"
${VBOXMANAGE} natnetwork remove --netname internet
set -e

#VM
${VBOXMANAGE} createvm --name "${VMNAME}" --ostype Windows10_64 --basefolder "${VM_LOCATION}" --register
${VBOXMANAGE} modifyvm "${VMNAME}" --memory ${MEM} --cpus 2 --vram 128 --acpi on --boot1 dvd
${VBOXMANAGE} modifyvm "${VMNAME}" --audio none

#network
${VBOXMANAGE} natnetwork add --netname internet --network "192.168.15.0/24" --enable --dhcp on

#storage
${VBOXMANAGE} createhd --filename "${VM_LOCATION}/${VMNAME}.vdi" --size ${DISKSIZE}
${VBOXMANAGE} storagectl "${VMNAME}" --name "SATA" --add sata
${VBOXMANAGE} storageattach "${VMNAME}" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "${VM_LOCATION}/${VMNAME}.vdi"
${VBOXMANAGE} storagectl "${VMNAME}" --name "IDE" --add ide
${VBOXMANAGE} storageattach "${VMNAME}" --storagectl "IDE" --port 0 --device 0 --type dvddrive --medium "${WINISO}"

#install
${VBOXMANAGE} unattended install "${VMNAME}" --user="${ADMINUSERNAME}" --password="${ADMINPASSWORD}" --image-index="${INDEX}" --locale=fr_FR --country=FR --time-zone=FR --hostname="test.com" --iso="${WINISO}" --install-additions --additions-iso="${ADDITIONS}" --post-install-command="shutdown /p" --script-template "${UNATTENDEDSCRIPTPATH}" --post-install-template "${UNATTENDEDPOSTINSTALLSCRIPTPATH}" --start-vm=headless

#Tweak
set +e
set +x
val=0
echo "waiting for installation to finish. This can take up to 30min depending of your hardware"
while [ $val -eq 0 ]
do
    ${VBOXMANAGE} list runningvms | grep "${VMNAME}" >/dev/null 2>&1
    val=$?
    sleep 10
done
set -x
set -e


waitfordesktop "${ADMINUSERNAME}" "${ADMINPASSWORD}"
echo "Finish configuration"
${VBOXMANAGE} guestcontrol "${VMNAME}" --username "${ADMINUSERNAME}" --password "${ADMINPASSWORD}" copyto --target-directory "C:\\Users\\"${ADMINUSERNAME}"\\Desktop" "${DIR}/postinstall.bat"
${VBOXMANAGE} guestcontrol "${VMNAME}" --username "${ADMINUSERNAME}" --password "${ADMINPASSWORD}" run --exe "C:\\Windows\\System32\\cmd.exe" -- cmd.exe /c "C:\\Users\\"${ADMINUSERNAME}"\\Desktop\\postinstall.bat"
${VBOXMANAGE} guestcontrol "${VMNAME}" --username "${ADMINUSERNAME}" --password "${ADMINPASSWORD}" run --exe "C:\\Windows\\System32\\cmd.exe" -- cmd.exe /c shutdown -r -t 0

waitfordesktop "${USERNAME}" "${USERPASSWORD}"
waitfordesktop "${USERNAME}" "${USERPASSWORD}"
${DIR}/sendandunzip.sh "${VMNAME}" "${TEMPDIR}/${PINVERSION}.zip" "C:\\" "${USERNAME}" "${USERPASSWORD}"
rm -f "${TEMPDIR}/${PINVERSION}.zip"
${VBOXMANAGE} guestcontrol "${VMNAME}" --username "${USERNAME}" --password "${USERPASSWORD}" run --exe "C:\\Windows\\System32\\cmd.exe" -- cmd.exe /c shutdown -t 0 /s

#set interface hostonly and spanshot
waitforshutdown

${VBOXMANAGE} modifyvm "${VMNAME}" --nic1 none
${VBOXMANAGE} storageattach "${VMNAME}" --storagectl SATA  --port 1 --device 0 --medium none
${VBOXMANAGE} storageattach "${VMNAME}" --storagectl IDE  --port 0 --device 0 --medium none

waitfordesktop "${USERNAME}" "${USERPASSWORD}"

#take snapshot
${VBOXMANAGE} snapshot "${VMNAME}" take freshinstall
${VBOXMANAGE} controlvm "${VMNAME}" poweroff
${VBOXMANAGE} snapshot "${VMNAME}" restore freshinstall
