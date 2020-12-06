#!/bin/bash

yum install -y xorg-x11-xauth # xorg-x11-server-Xorg

sed 's/X11Forwarding no/X11Forwarding yes/g' -i /etc/ssh/sshd_config

cat << EOF
X11Forwarding yes
X11UseLocalhost no
EOF

systemctl restart sshd


