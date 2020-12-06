mkdir -p /etc
mkdir -p /etc/fail2ban
cat > /etc/fail2ban/jail.local << PASTECONFIGURATIONFILE
[DEFAULT]
ignoreip = 127.0.0.1/8 ; 95.90.200.0/22 46.114.0.0/15 77.20.128.0/17 77.20.0.0/17 79.192.0.0/10 62.224.0.0/14
banaction = firewallcmd-ipset[actiontype=""]

[sshd]
enabled = true
mode = aggressive
bantime = 86400 # 24h*3600s = 86400s
findtime = 600s
maxretry = 9

PASTECONFIGURATIONFILE
cat > /etc/fail2ban/fail2ban.local << PASTECONFIGURATIONFILE
[Definition]
loglevel = NOTICE
PASTECONFIGURATIONFILE
