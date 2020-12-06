#!/bin/bash

## ssh
yum install -y openssh
rm -r /etc/ssh/*
ssh-keygen -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key # re-generate public key
yum -y install policycoreutils-python-utils

# COPY CONFIGURATION FILES
mkdir -p /etc
mkdir -p /etc/ssh
mkdir -p /usr
mkdir -p /usr/local
mkdir -p /usr/local/sbin
cat > /etc/ssh/sshd_config << PASTECONFIGURATIONFILE
# change port, obscurity is a valid security layer!
Port 226

# VERBOSE login to log user's key fingerprints on login.
LogLevel VERBOSE
SyslogFacility AUTHPRIV

Protocol 2

HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile %h/.ssh/authorized_keys
#RevokedKeys /etc/ssh/revokeyd_keys # TODO: check if this works

PermitRootLogin prohibit-password # NOTE: change to 'no' for multiuser system
UsePAM yes

AuthenticationMethods publickey #,keyboard-interactive # TODO: do 2FA
PubkeyAuthentication yes
PermitEmptyPasswords no
HostbasedAuthentication no
PasswordAuthentication no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
#ExposeAuthenticationMethods never

X11Forwarding no
IgnoreRhosts yes

StrictModes yes
UsePrivilegeSeparation sandbox

MaxAuthTries 1

PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-ssh_change_port << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -ne 1  ]; then
	echo "Change SSH port"
	echo
	echo "usage: \${0} <SSH_PORT>"
	echo
	echo "Changes SSH port to SSH_PORT."
	echo
	exit 1
fi
NEW_SSH_PORT="\${1}"
OLD_SSH_PORT="\$(grep -E '^Port [0-9]+' /etc/ssh/sshd_config | grep -oE '[0-9]+' | head -n1)"

sed 's/Port [0-9]\\+/Port '\${NEW_SSH_PORT}'/' -i /etc/ssh/sshd_config

firewall-cmd --permanent --add-port=\${NEW_SSH_PORT}/tcp --zone=public
firewall-cmd --reload
/usr/local/sbin/el-firewall_ssh_add_ratelimit \${NEW_SSH_PORT}
semanage port -a -t ssh_port_t -p tcp \${NEW_SSH_PORT}
systemctl --no-pager reload sshd
systemctl --no-pager status sshd

if [ "\${OLD_SSH_PORT}" -ne "22" ]; then
	firewall-cmd --permanent --delete-port=\${OLD_SSH_PORT}/tcp --zone=public
	semanage port -d -t ssh_port_t -p tcp \${OLD_SSH_PORT}
fi
/usr/local/sbin/el-firewall_ssh_rem_ratelimit \${OLD_SSH_PORT}

echo "WARNING!!! BEFORE DISCONNECTING YOUR CURRENT SSH SESSION TRY THE NEW PORT IN PARALLEL!!!"

PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-firewall_ssh_ratelimit_add_exception_ip << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -gt 1 ]; then
	echo "Whitelist the SSH IP"
	echo
	echo "usage: \${0} [IP]"
	echo
	echo "If IP is not given IP from \\\$SSH_CLIENT will be used."
	echo
	exit 1
fi
if [ \$# -eq 0 ]; then
	IP="\$(echo \$SSH_CLIENT | cut -d' ' -f1)"
	echo "No IP given using IP from \\\$SSH_CLIENT (\${IP})"
	SSH_PORT="\$(echo \$SSH_CLIENT | cut -d' ' -f3)"
else
	IP="\${1}"
	SSH_PORT="\$(grep -E '^Port [0-9]+' /etc/ssh/sshd_config | grep -oE '[0-9]+' | head -n1)"
fi
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 0 -p tcp -s "\${IP}" --dport "\${SSH_PORT}" -m state --state NEW -j ACCEPT
firewall-cmd --reload
systemctl restart fail2ban

PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-firewall_ssh_ratelimit_rem_exception_ip << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -gt 2 ]; then
	echo "Remove SSH IP from white list"
	echo
	echo "usage: \${0} [IP] [SSH_PORT]"
	echo
	echo "If IP and/or SSH_PORT are not given IP and/or SSH_PORT from \\\$SSH_CLIENT will be used."
	echo
	exit 1
fi
if [ \$# -eq 0 ]; then
	IP="\$(echo \$SSH_CLIENT | cut -d' ' -f1)"
	echo "No IP given using IP from \\\$SSH_CLIENT (\${IP})"
	SSH_PORT="\$(echo \$SSH_CLIENT | cut -d' ' -f3)"
elif [ \$# -eq 1 ]; then
	IP="\${1}"
	SSH_PORT="\$(echo \$SSH_CLIENT | cut -d' ' -f3)"
	#SSH_PORT="\$(grep -E '^Port [0-9]+' /etc/ssh/sshd_config | grep -oE '[0-9]+' | head -n1)"
else
	IP="\${1}"
	SSH_PORT="\${2}"
fi
firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT_direct 0 -p tcp -s "\${IP}" --dport "\${SSH_PORT}" -m state --state NEW -j ACCEPT
firewall-cmd --reload
systemctl restart fail2ban

PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-firewall_ssh_rem_ratelimit << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -gt 1 ]; then
	echo "Remove SSH rate limiting"
	echo
	echo "usage: \${0} [SSH_PORT]"
	echo
	echo "If SSH_PORT is not given SSH_PORT in /etc/ssh/sshd_config will be used."
	echo
	exit 1
fi
if [ \$# -eq 0 ]; then
	echo "No SSH_PORT given. Using SSH_PORT from /etc/ssh/sshd_config"
	SSH_PORT="\$(grep -E '^Port [0-9]+' /etc/ssh/sshd_config | grep -oE '[0-9]+' | head -n1)"
else
	SSH_PORT="\${1}"
	#SSH_PORT="\$(echo \$SSH_CLIENT | cut -d' ' -f3)"
fi
firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT_direct 10 -p tcp --dport \${SSH_PORT} -m state --state NEW -m recent --set --name SSH_RATELIMIT
firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT_direct 11 -p tcp --dport \${SSH_PORT} -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j REJECT --reject-with tcp-reset --name SSH_RATELIMIT
firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT_direct 10 -p tcp --dport \${SSH_PORT} -m state --state NEW -m recent --set --name SSH_RATELIMIT
firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT_direct 11 -p tcp --dport \${SSH_PORT} -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j REJECT --reject-with tcp-reset --name SSH_RATELIMIT
firewall-cmd --reload

PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-firewall_ssh_add_ratelimit << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -gt 1 ]; then
	echo "Add SSH rate limiting"
	echo
	echo "usage: \${0} [SSH_PORT]"
	echo
	echo "If SSH_PORT is not given SSH_PORT in /etc/ssh/sshd_config will be used."
	echo
	exit 1
fi
if [ \$# -eq 0 ]; then
	echo "No SSH_PORT given. Using SSH_PORT from /etc/ssh/sshd_config"
	SSH_PORT="\$(grep -E '^Port [0-9]+' /etc/ssh/sshd_config | grep -oE '[0-9]+' | head -n1)"
else
	SSH_PORT="\${1}"
	#SSH_PORT="\$(echo \$SSH_CLIENT | cut -d' ' -f3)"
fi
TRIES_PER_MINUTE=3
N=\$((TRIES_PER_MINUTE+1))
# rate limit tcp connections to SSH on \${SSH_PORT}/tcp to \${NPM} per minute
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 10 -p tcp --dport \${SSH_PORT} -m state --state NEW -m recent --set --name SSH_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 11 -p tcp --dport \${SSH_PORT} -m state --state NEW -m recent --update --seconds 60 --hitcount \${N} -j REJECT --reject-with tcp-reset --name SSH_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT_direct 10 -p tcp --dport \${SSH_PORT} -m state --state NEW -m recent --set --name SSH_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT_direct 11 -p tcp --dport \${SSH_PORT} -m state --state NEW -m recent --update --seconds 60 --hitcount \${N} -j REJECT --reject-with tcp-reset --name SSH_RATELIMIT
firewall-cmd --reload

PASTECONFIGURATIONFILE
# COPY CONFIGURATION FILES

# make el- scripts executable
chmod u+x /usr/local/sbin/el-*

SSH_PORT="$(grep -E '^Port [0-9]+' /etc/ssh/sshd_config | grep -oE '[0-9]+' | head -n1)"

firewall-cmd --permanent --add-port=${SSH_PORT}/tcp --zone=public
semanage port -a -t ssh_port_t -p tcp ${SSH_PORT}

# rate limit tcp connections to SSH on ${SSH_PORT}/tcp to 3 per minute
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 10 -p tcp --dport ${SSH_PORT} -m state --state NEW -m recent --set --name SSH_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 11 -p tcp --dport ${SSH_PORT} -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j REJECT --reject-with tcp-reset --name SSH_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT_direct 10 -p tcp --dport ${SSH_PORT} -m state --state NEW -m recent --set --name SSH_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT_direct 11 -p tcp --dport ${SSH_PORT} -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j REJECT --reject-with tcp-reset --name SSH_RATELIMIT
systemctl --no-pager start sshd
systemctl --no-pager enable sshd
systemctl --no-pager reload sshd
systemctl --no-pager status sshd # check status [optional]
firewall-cmd --reload
firewall-cmd --list-all # list rules [optional]
firewall-cmd --direct --get-all-rules # list rate limiting rules [optional]

