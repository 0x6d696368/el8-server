#!/bin/bash
yum -y install epel-release
yum -y install byobu
# fix for kimsufi dedecated servers that mount devpts without gid=5, see: 
sed '/^devpts/d' -i /etc/fstab
# apply fix without reboot
mount -o remount,gid=5,mode=620 /dev/pts
byobu-enable-prompt
byobu-enable
