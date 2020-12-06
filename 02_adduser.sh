#!/bin/bash
if [ $# -eq 0 ]; then
	echo "Add a user to the system"
	echo
	echo "usage: ${0} user"
	echo
	exit 1
fi
newuser=${1}
adduser "${newuser}"
mkdir -p "/home/${newuser}/.ssh/"
cp /root/.ssh/authorized_keys "/home/${newuser}/.ssh/."
chmod 700 "/home/${newuser}/.ssh"
chmod 600 "/home/${newuser}/.ssh/authorized_keys"
chown "${newuser}" -R "/home/${newuser}/.ssh"
chgrp "${newuser}" -R "/home/${newuser}/.ssh"
restorecon -R -v "/home/${newuser}/.ssh"
# usermod -aG wheel "${newuser}"
