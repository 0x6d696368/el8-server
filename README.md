**DEPRECATED! BECAUSE RED HAT/CENTOS DECIDED TO KILL CENTOS 8 I'M MOVING TO UBUNTU 20.04 LTS: <https://github.com/0x6d696368/u2004-server>**

# CENTOS 8 SERVER SCRIPTS

Bootstrap a base CentOS 8 server system starting from a Minimal Install.

Tested on/with:

- Kimsufi Server

## Base install

**TODO: Verify this!**

1. `WELCOME TO CENTOS 8`: `English > English (United States)` -> `Continue`
2. `INSTALLATION SUMMARY`:
	1. `NETWORK & HOST NAME`: 1. `ON`; 2. `Configure...`, `General`, `[X] Automatically connect to this network`; 3. `Host name:` "example.com"; 4. `DONE`
	2. `DATE & TIME`: 1. `Network Time` = `ON`; 3. `DONE`
	3. `INSTALLATION SOURCE`: 1. `On the network:` "http://mirror.centos.org/centos/8/BaseOS/x86_64/"; 2. `DONE`
	4. `INSTALLATION DESTINATION`: 1. `I will configure partitioning.`; 2. `DONE`; 3. `Standard Partition`; 4. `-`; 5. `+`; 6. `ADD A NEW MOUNT POINT`, "swap", "2GiB" (depending on your needs; recommended: same size as RAM); 7. `+`; 8. `ADD A NEW MOUNT POINT`, "/", (leave blank to allocate the rest); 9. `DONE`; 10. `Accept Changes`
	5. `SOFTWARE SELECTION`: 1. `Minimal Install`; 2. `DONE`
	6. `KDUMP`: 1. `[ ] Enable kdump`; 2. `DONE`
	7. `Begin Installation`
	8. `ROOT PASSWORD`: 1. Set password; 2. `DONE`
	9. Wait for installation to finish.
	10. `Reboot`

## (Re-)Generate the scripts

```
./00_generate_all.sh
```

## The scripts

The scripts themselves can be installed individually, however, it is recommended
to at least install 01* script before installing any 02* script.

Either run directly on server as `./03_install_http.sh` or run remotely
via SSH as `cat 03_install_http.sh | ssh root@yourserver`

**Note:** In the examples `example.com` and `192.168.42.42` are your servers
domain and/or IP.

### 01_install_base.sh

This sets up auto-updates, remove hosting monitoring, install default kernel, etc.

1. Install `01_install_base.sh` by running (on your local machine):

```
cat 01_install_base.sh | ssh root@192.168.42.42
```

The `01_install_base.sh` installs and configures:

- Standard kernel (to ensure security updates) 
- Time (UTC all the way!)
- Auto updates (set timing in `[base]/usr/lib/systemd/system/dnf-automatic.timer`) with auto reboots on library and kernel updates (see `[base]/etc/cron.hourly/9needs-restarting.cron`)
- firewall

#### Logging

- yum: `/var/log/yum.log` (displays the last updated packages)
- cron: `/var/log/cron` (should contain hourly entries of `starting 9needs-restarting.cron`)

### 02_install_ssh.sh

This sets up private key only SSH login over an alternate SSH port
(to keep the logs clean and not have your SSH listed on Shodan.)

**NOTE:** Please follow these instructions closely, otherwise you may lock
yourself out of your server!

1. Generate a suitable SSH key and copy it onto the machine via:

```
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_hostname
ssh root@192.168.42.42 'mkdir ~/.ssh/'
scp ~/.ssh/id_ed25519_hostname.pub root@192.168.42.42:~/.ssh/authorized_keys
```

2. Open a SSH connection to the server **and keep it open** and perform the following tasks over different SSH connections (so you can recover in case something fails with the SSH setup).

3. Install `02_install_ssh.sh` by running (on your local machine):

```
cat 02_install_ssh.sh | ssh root@192.168.42.42
```

4. After installing the `02_install_ssh.sh` script login in via (**replace `226` with your SSH port configured in `[ssh]/etc/ssh/sshd_config`**):

```
ssh root@192.168.42.42 -i ~/.ssh/id_ed25519_hostname -p 226
```

5. If step 4 works you can close the backup SSH connection from step 2.

It is recommended you add the following to your **client-side** `~/.ssh/config` (**replace `226` with your SSH port configured in `[ssh]/etc/ssh/sshd_config`**):

```
host myhostalias
	HostName 192.168.42.42
	Port 226
	IdentityFile ~/.ssh/id_ed25519_hostname
	User root
```

And then simply login via:

```
ssh myhostalias
```

The `02_install_ssh.sh` installs and configures:

- SSH (pubkey only, ed25519 only, and port 226 (for additional security))
- firewall
- rate limiting connection attempts to SSH to 3 / min per IP

**WARNING:** The SSH configuration is very restrictive. Take care to not
accidentally lock yourself out of your system. Make sure you have placed a
suitable SSH key (see above) on the machine.

**ADVICE:** It is advised you keep a second SSH connection open to the server
so you can rescue the setup in case you lock yourself out of the system. Only close this second SSH connection when you can connect to the server via the above provided SSH configuration.

- To remove the rate limiting run: `/usr/local/sbin/el-firewall_ssh_rem_ratelimit`
- To see the recent list of IP addresses of this SSH rate-limiting rule run: `cat /proc/net/xt_recent/SSH_RATELIMIT`
- To see possible active rate limiting rules run: `firewall-cmd --direct --get-all-rules`
- To add a rate limiting exception for a SSH IP run: `/usr/local/sbin/el-firewall_ssh_ratelimit_add_exception_ip`
- To remove a rate limiting exception for a SSH IP run: `/usr/local/sbin/el-firewall_ssh_ratelimit_rem_exception_ip`
- To change the SSH port run: `/usr/local/sbin/el-ssh_change_port <NEW_SSH_PORT>`

**NOTE:** You can change your SSH port in `[ssh]/etc/ssh/sshd_config`. Please note scripts rely on `Port 321` syntax. Adding more spaces or something else will break the scripts. In case you have multiple ports, e.g., `Port 123 432` only the first will be used. Also `/usr/local/sbin/el-ssh_change_port` will only change first port.

#### Logging

- SSH: `cat /var/log/secure | grep sshd` (see ssh login attempts, etc.)

#### TODOs

* Setup knockd: https://www.digitalocean.com/community/tutorials/how-to-use-port-knocking-to-hide-your-ssh-daemon-from-attackers-on-ubuntu

### 02_install_fail2ban.sh (Fail2Ban)

`02_install_fail2ban.sh` installs and configures fail2ban for:

- sshd

### Banned IPs

```
fail2ban-client status
fail2ban-client status sshd
ipset list
```

#### Unbanning

```
fail2ban-client set <jail> unbanip <ip>
fail2ban-client set sshd unbanip <ip>
```

#### Logging

```
cat /var/log/fail2ban.log
```

### 03_install_http.sh (Apache and Let's Encrypt)

Installs and configures Apache.

After install edit `/etc/httpd/conf.d/vhost.conf` and add your desired virtual
hosts where it says `# INSERT VHOSTS HERE` as follows:

1. `Use noSSLVhost example.com` gives you a plain HTTP VHost for domain example.com with its webroot being `/var/www/html/example.com`.
2. To generate the webroot run `cp -R /var/www/html/blank/ /var/www/html/example.com`. This copies a standard `robots.txt` and `index.html` file to the new domain.
3. Get a Let's Encrypt certificate for example.com domain via `/usr/local/sbin/el-letsencrypt_setup example.com`.
4. Change the previous configuration to `Use Vhost example.com`. The domain is now using HTTPS with the configured Let's Encrypt certificate.
5. `systemctl reload httpd`

To get a domain redirection change the configuration in step 3 above to `Use redirVHost example.com example.org` which will redirect example.com to example.org (both using HTTPS!).


**NOTE:** When connecting to the server without `Host:` header or to its IP or an unknown domain in the `Host:` header it will point to `/var/www/html/blank/` which contains a `robots.txt` which denials all robots. Connecting via HTTPS in addition serves an deliberately weak and outdated certificate. You can change this behavior by editing `/etc/httpd/conf/httpd.conf` yourself.

#### Remove a Let's Encrypt certificate

```
/usr/local/sbin/el-letsencrypt_delete example.com
```

#### Logging

- Access logs for domains: `/var/log/http/example.com-access_log`
- Access logs to accesses directly to the server IP: `/var/log/http/access_log`
- General log directory: `/var/log/http/*`
	- Error logs: `example.com-error_log`, `error_log`

#### Troubleshooting

If (for whatever reason) after a certificate update certificates stop working you can run `/usr/local/sbin/el-letsencrypt_fix` to delete the new (not working certificates) and use the last certificates before the update.

#### TODO

- FIXME: Stapling on the IP host with the self signed SSL cert does not work and floods error_log (`ssl_stapling_init_cert: can't retrieve issuer certificate!`)
- TODO: deal with FQDN trailing dots; this leads to TLS failing as `example.com` != `example.com.`
- TODO: Automate vhost creation.


### 03_install_ns{1,2}.sh (BIND name server)

Installs and configures BIND name server.

**NOTE:** In case you only want a local recursive nameserver (e.g. to run RBL DNS queries as prerequisite to `03_install_mx.sh`) just run `03_install_ns1.sh` and you don't need to do any post install configuration.

In case you want a ns1 (primary) and ns2 (secondary) nameserver setup do the following:

1. On ns1 run `03_install_ns1.sh`. On ns2 run `03_install_ns2.sh`.
2. Edit `/etc/named/zones` to add your zones (do this on both ns1 and ns2)
3. Edit your zones, for `example.com` the file would be in  `/var/named/example.com` etc. (only on ns1, ns2 gets the updates via DNS update mechanism)
4. On ns1 and ns2 run `/usr/local/sbin/el-bind_config <IP of ns1> <IP of ns2>` to configure the ns1 and ns2 IPs in `/etc/named.conf`.
5. Optionally, follow DNSSEC setup below.

#### DNSSEC

To sign your zones in `/var/named/example.com` (only available on ns1) do:

1. To setup DNSSEC for a zone, i.e., generate (or regenerate) keys, etc. run: `/usr/local/sbin/el-dnssec_setup example.com`
2. To (re-)sign a zone, run: `/usr/local/sbin/el-dnssec_sign example.com`

#### Debugging

Check your zone via:

```
named-checkzone example.com /var/named/example.com
```

#### Logging

- General log: `/var/log/named/named.log`
- Query log: `/var/log/named/queries.log`

#### TODOs

- CDS
- Automate zone generation / changes
- Automated zone resigning; currently zones are signed with a validity of 1 year
- Query response logging via dnstap

#### Fixes / Issues

##### Journal errors

Delete journals:

```
systemctl stop named
rm -f /var/named/*.jnl
systemctl start named
```

##### `setsockopt(25, TCP_FASTOPEN) failed with Protocol not available`

In case your named doesn't work and you get:

```
# systemctl status named | grep TCP_FASTOPEN
Feb 17 19:00:37 spamtrap named[381]: setsockopt(24, TCP_FASTOPEN) failed with Protocol not available
```

Your system does not support `TCP_FASTOPEN`. 
Unfortunately, there doesn't seem to be a workaround as this only happens when you run
this on a deprecated kernel that CentOS 7 does not support anymore. Most likely scenario
is you run inside a container, e.g. OpenVZ. Get new hosting!

### 03_install_mx.sh (Postfix + Dovecot mail server)

**TODO: MX SETUP IS UNTESTED!**

Requires: `03_install_http.sh` (to acquire certificate from Let's Encrypt), **optional** `03_install_ns1.sh` (**without** running `/usr/local/sbin/el-bind_config` to make Spamhaus RBL DNS queries work)

This sets up:

- SMTP (25/tcp)
- SMTPs (465/tcp)
- POP3s (995/tcp)
- firewall config with rate limiting connection attempts to POP3s to 3 / min per IP

#### Setup

1. **Optional:** Get a Let's Encrypt certificate for your mx domain by following the `03_install_http.sh` setup.
2. Run `/usr/local/sbin/el-mx_config mx.example.com` to configure the MX domain `mx.example.com`

#### Add a mail box (user)

Run:

```
/usr/local/sbin/el-mx_add_user user@example.com
```

This will prompt for a password you would like to set for `user@example.com`.

This will generate a postfix mailbox as well as a POP3 Dovecot mailbox by editing the following files:

- `/etc/postfix/vhosts`
- `/etc/postfix/vmaps` (and (re-)generating `/etc/postfix/vmaps.db`)
- `/etc/dovecot/users`
- `/etc/dovecot/passwd`

Mail user can then use:

- SMPTs on 465/tcp with (CRAM-MD5) encrypted password and username `user@example.com`.
- POP3s on 995/tcp with (CRAM-MD5) encrypted password and username `user@example.com`.
- SMTP on 25/tcp to receive mail addressed to `user@example.com`.

#### Delete a mail box (user)

```
/usr/local/sbin/el-mx_delete_user user@example.com
```

This deletes the postfix and Dovecot mailbox of `user@example.com`.
**NOTE:** `/etc/postfix/vhosts` will continue to hold the domain and must be removed manually if desired.

#### DKIM

Run `/usr/local/sbin/el-mx_dkim` and follow the instructions.

TODO: automate this

#### Greylisting

To enable greylisting uncomment `# check_policy_service unix:postgrey/socket,` in `/etc/postfix/main.cf`.

Also to further decrese spam by being more strict on rejecting incoming senders - this may cause delivery problems! -
you can uncomment:

- `# reject_unknown_reverse_client_hostname,`
- `# reject rhsbl_client dbl.spamhaus.org,`
- `# reject_unknown_reverse_client_hostname,`
- `# reject_unknown_client_hostname,`

#### TODOs

- FIXME: dhparam <http://www.postfix.org/FORWARD_SECRECY_README.html>
- Document: `/etc/postfix/smtpd_sender_login_maps.regexp`

Make these work:

- Set the recipient whitelist (these addresses will always receive mail regardless of RBL status) in `/etc/postfix/check_recipient_access`
- Set the sender whitelist (email from these addresses will always be delivered regardless of sender domain, etc.) in `/etc/postfix/check_sender_access`

- Whitelists: https://www.howtoforge.com/how-to-whitelist-hosts-ip-addresses-in-postfix

- Rate limiting: http://www.postfix.org/TUNING_README.html#conn_limit
- Backup MX: https://www.howtoforge.com/postfix_backup_mx
- Squirrelmail (as a separate script)
- NS add: `_adsp._domainkey IN TXT "dkim=all"`

- Local problems:
	- `smtp_check_headers` doesn't clean private stuff when sending from one local email to another local email account :/
	- mail send from one local user to another local user are not DKIM signed :/

- Make work with `/etc/selinux/config`: `SELINUX=enforcing`
- Spamassassin: https://www.akadia.com/services/postfix_spamassassin.html

#### Logging

- Postfix: `/var/log/maillog`
- Dovecot: `/var/log/dovecot`, `/var/log/dovecot.info`

#### Debugging

-SMTP

```
nc mx.example.com 25
```

- SMTPS

```
openssl s_client -crlf -connect mx.example.com:465 -servername mx.example.com
```

- POP3s

```
openssl s_client -crlf -connect mx.example.com:995 -servername mx.example.com
```

### `06_install_cockpit.sh`

Installs Cockpit. Does not allow access to Cockpit HTTPs interface directly via firewall. Must tunnel via SSH to access Cockpit HTTPs interface.

#### Usage

To connect to Cockpit:

```
ssh -N -L 9090:127.0.0.1:9090 myhostalias
```

Then on the local machine use a web browser to go to `localhost:9090`.

#### Add ISO to VM

- Attach:

```
mv disk.iso /var/lib/libvirt/images/disk.iso
chown qemu:qemu /var/lib/libvirt/images/disk.iso
chown go-rwx /var/lib/libvirt/images/disk.iso
virsh attach-disk <vm> /var/lib/libvirt/images/disk.iso sdc
```

- Detach:

```
virsh detach-disk <vm> sdc
```
#### Enable nested VMs

```
cat /proc/cpuinfo | grep " vmx | etp " # check if vmx and etp supported
dmesg | grep 'DMAR: IOMMU enabled' && echo IOMMU supported # check if IOMMU supported
sed 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="intel_iommu=on/g' -i /etc/default/grub
grub2-mkconfig --output=/boot/grub2/grub.cfg
```

Check:

```
virt-host-validate
```

#### Virtual networks

```
virsh net-edit <network>
virsh net-destroy <network>
virsh net-start <network>
```

### `80_install_xpra.sh`

- Start a session on display `100`:

```
xpra --ssh=ssh start ssh://sshserver/100 --dpi 96
```

Then you can start graphical applications from the Xpra menu, or directly start, e.g., `xterm`, when starting a session via:

```
xpra --ssh=ssh start ssh://sshserver/100 --start=xterm --dpi 96
```

Detach session via `CTRL+C` (or `Disconnect` in Xpra menu).

Attach to session on display `100` again:

```
xpra --ssh=ssh attach ssh://sshserver/100 --dpi 96
```

Tunnel via proxy jump:

```
xpra --ssh=ssh attach ssh://target-user@target-host:22/20?proxy=proxy-user@proxy-host --dpi 96
```

## Admin tasks

### Block IP

**Block:**

```
firewall-cmd --zone=drop --add-source=<CIDR>
```

**Show blocked:**

```
firewall-cmd --zone=drop --list-all
```

**Unblock:**

```
firewall-cmd --zone=drop --remove-source=<CIDR>
```

## Trouble shooting

### firewall-cmd

- If `firewall-cmd --reload` returns `Error: COMMAND_FAILED: Direct: '/usr/sbin/iptables-restore -w -n' failed: iptables-restore: line x failed` you can delete all direct rules via `rm /etc/firewalld/direct.xml`.

### rsyslog

- If you changed the timezone and `journalctl` receives logs, e.g. `journalctl -u postfix`, but `rsyslog` doesn't anymore, e.g. `/var/log/maillog`, you can try (see <https://bugzilla.redhat.com/show_bug.cgi?id=1088021>):

```
rm -f /var/lib/rsyslog/imjournal.state
systemctl restart rsyslog
```
- To test logging you can issue log events, e.g. into log `mail.info` via: `logger -p mail.info Testing`

### journal

If you don't have logs and also the journal stopped working try:

```
rm -rf /var/log/journal/*
reboot
```

### yum

If yum stops working try:

```
package-cleanup --dupes
package-cleanup --cleandupes
yum clean all
yum check
```
or
```
yum-complete-transaction
yum-complete-transaction --cleanup-only
yum clean all
yum check
```

## Future proofing 

- Periodically run and adapt accordingly:
	- `testssl domain` and `testssl --mx mx.domain`
	- <https://ssllabs.com/>
	- <https://securityheaders.com/>
	- <https://internet.nl/>
	- <https://www.hardenize.com>
	- <https://mxtoolbox.com/domain/example.com>
- Keep up with:
	- <https://cipherli.st/>

## Key integrity

Make sure to check the integrity of the repository keys!

```
TODO: List keys
```

