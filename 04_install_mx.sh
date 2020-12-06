#!/bin/bash
yum -y install epel-release openssl
yum -y install postfix dovecot postfix-pcre opendkim opendmarc postgrey
rm -rf /etc/dovecot/conf.d

# SPF ... this is a bit ugly
yum -y install python34 python34-pip
pip3.4 install -U pypolicyd-spf==2.0.2 pyspf==2.0.11 py3dns==3.2.0 pip

rm -rf /etc/postfix/*

# COPY CONFIGURATION FILES
mkdir -p /usr
mkdir -p /usr/local
mkdir -p /usr/local/sbin
mkdir -p /etc
mkdir -p /etc/dovecot
mkdir -p /etc/postfix
mkdir -p /etc/logrotate.d
mkdir -p /etc/opendkim
mkdir -p /etc/opendkim/keys
mkdir -p /etc/opendkim/keys/example.com
mkdir -p /etc/python-policyd-spf
cat > /usr/local/sbin/el7-mx_add_user << PASTECONFIGURATIONFILE
#!/bin/sh

if [ ! \$# = 1 ];  then
	echo "Usage: \${0} username@domain"
	exit 1
fi
username=\$(echo "\${1}" | cut -f1 -d "@")
domain=\$(echo "\${1}" | cut -s -f2 -d "@")
if [ -z "\$domain" ] || [ -z "\$username" ]; then
	echo "No domain and/or username given."
	echo "Usage: \${0} username@domain"
	exit 2
fi

echo "Adding domain to /etc/postfix/vhosts"
echo "\${domain}" >> /etc/postfix/vhosts
sort -u /etc/postfix/vhosts -o /etc/postfix/vhosts # remove dups

echo "Adding user \$username@\$domain to /etc/dovecot/users"
echo "\$username@\$domain::5000:5000::/home/vmail/\$domain/\$username/:/bin/false::" >> /etc/dovecot/users
sort -u /etc/dovecot/users -o /etc/dovecot/users # remove dups

echo "Creating user directory /home/vmail/\$domain/\$username/"
mkdir -p /home/vmail/\$domain/\$username/
chown -R 5000:5000 /home/vmail
chmod 700 /home/vmail/\$domain

echo "Adding user to /etc/postfix/vmaps"
echo "\${1}  \$domain/\$username/" >> /etc/postfix/vmaps
sort -u /etc/postfix/vmaps -o /etc/postfix/vmaps # remove dups
new_vmaps=\$(grep -v "^@" /etc/postfix/vmaps; grep "^@" /etc/postfix/vmaps) # sort
echo "\${new_vmaps}" > /etc/postfix/vmaps
postmap /etc/postfix/vmaps
postfix reload

if [ -n "\$(cat /etc/dovecot/passwd | grep "\$username@\$domain:")" ]; then
	echo "A password already exists for \$username@\$domain"
	read -n1 -p "Update password? [Y/N]? " UPDATE
	case \$UPDATE in
		y | Y)
			echo "Deleting old password from /etc/dovecot/passwd"
			tmp=\$(mktemp)
			grep -v "\$username@\$domain:" /etc/dovecot/passwd > \$tmp
			mv \$tmp /etc/dovecot/passwd
			;;
		*)
			echo "Keeping current password for \$username@\$domain in /etc/dovecot/passwd"
			systemctl reload dovecot
			exit 0
			;;
	esac
fi	
echo "Create a password for the new email user"
passwd=\`doveadm pw -u \$username\`
echo "Adding password for \$username@\$domain to /etc/dovecot/passwd"
touch /etc/dovecot/passwd
echo  "\$username@\$domain:\$passwd" >> /etc/dovecot/passwd
chmod 640 /etc/dovecot/passwd
chown dovecot:dovecot /etc/dovecot/passwd

systemctl reload dovecot

PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el7-mx_delete_user << PASTECONFIGURATIONFILE
#!/bin/bash
#
# deldovecotuser - for deleting virtual dovecot users
#
if [ ! \$# = 1 ]
 then
  echo -e "Usage: \$0 username@domain"
  exit 1
 else
  user=\`echo "\$1" | cut -f1 -d "@"\`
  domain=\`echo "\$1" | cut -s -f2 -d "@"\`
  if [ -z "\$domain" ]
   then
    echo -e "No domain given\\nUsage: \$0 username@domain: "
    exit 2
  fi
fi
read -n 1 -p "Delete user \$user@\$domain from dovecot? [Y/N]? "
echo
case \$REPLY in
 y | Y)
  new_users=\`grep -v "^\$user@\$domain" /etc/dovecot/users\`
  new_passwd=\`grep -v "^\$user@\$domain" /etc/dovecot/passwd\`
  new_vmaps=\`grep -v "^\$user@\$domain" /etc/postfix/vmaps\`
  echo "Deleting \$user@\$domain from /etc/dovecot/users"
  echo "\$new_users" > /etc/dovecot/users
  echo "Deleting \$user@\$domain from /etc/dovecot/passwd"
  echo "\$new_passwd" > /etc/dovecot/passwd
  echo "Deleting \$user@\$domain from /etc/postfix/vmaps"
  echo "\$new_vmaps" > /etc/postfix/vmaps
  postmap /etc/postfix/vmaps
  postfix reload
  read -n1 -p "Delete all files in /home/vmail/\$domain/\$user? [Y/N]? " DELETE
  echo
  case \$DELETE in
   y | Y)
	if grep -q "\$domain/\$user/\$" /etc/postfix/vmaps; then
		echo "Not deleting files in /home/vmail/\$domain/\$user because mailbox is still used"
	else
		echo "Deleting files in /home/vmail/\$domain/\$user"
		rm -fr /home/vmail/\$domain/\$user
		rmdir --ignore-fail-on-non-empty /home/vmail/\$domain
	fi
   ;;
   * )
    echo "Not deleting files in /home/vmail/\$domain/\$user"
   ;;
  esac
 ;;
 * )
  echo "Aborting..."
 ;;
esac
PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el7-mx_dkim << PASTECONFIGURATIONFILE
#!/bin/sh

if [ ! \$# = 1 ];  then
	echo "Add DKIM key for domain"
	echo "Usage: \${0} <domain>"
	exit 1
fi
domain="\${1}"
selector=\$(date +%Y%m%dT%H%M%S)
mkdir -p /etc/opendkim/keys/\${domain}
opendkim-genkey -b 2048 -d \${domain} -s \${selector} -a -D /etc/opendkim/keys/\${domain}/
chown opendkim:opendkim -R /etc/opendkim/keys
echo
echo "Put the following DKIM key into your zone file:"
cat /etc/opendkim/keys/\${domain}/\${selector}.txt
echo
echo "/etc/opendkim/KeyTable"
echo "\${selector}._domainkey.\${domain} \${domain}:\${selector}:/etc/opendkim/keys/\${domain}/\${selector}.private"
echo "/etc/opendkim/SigningTable"
echo "*@\${domain} \${selector}._domainkey.\${domain}"
echo
PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el7-mx_config << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -ne 1 ]; then
	echo "Configure MX server"
	echo
	echo "usage: \${0} <mx.example.com>"
	echo
	exit 1
fi

domain="\${1}"

fullchain="/etc/letsencrypt/live/\${domain}/fullchain.pem"
privkey="/etc/letsencrypt/live/\${domain}/privkey.pem"

if [ ! -f "\${fullchain}" ] || [ ! -f "\${privkey}"]; then
	echo "WARNING: No Let's Encrypt certificates found! Generating self-signed certs."
	mkdir -p /etc/pki/selfsigned
	fullchain="/etc/pki/selfsigned/\${domain}-fullchain.pem"
	privkey="/etc/pki/selfsigned/\${domain}-privkey.pem"
	openssl req -newkey rsa:4096 -nodes -sha512 -x509 -days 3650 -nodes -out \${fullchain} -keyout \${privkey} -subj "/CN=\${domain}/C=XX/L= /O= "
fi

sed 's#^smtpd_tls_cert_file = .*\$#smtpd_tls_cert_file = '"\${fullchain}"'#' -i /etc/postfix/main.cf
sed 's#^smtpd_tls_key_file = .*\$#smtpd_tls_key_file = '"\${privkey}"'#' -i /etc/postfix/main.cf
sed 's#^myhostname = .*\$#myhostname = '"\${domain}"'#' -i /etc/postfix/main.cf

sed 's#^	ssl_cert=<.*\$#	ssl_cert=<'"\${fullchain}"'#' -i /etc/dovecot/dovecot.conf
sed 's#^	ssl_key=<.*\$#	ssl_key=<'"\${privkey}"'#' -i /etc/dovecot/dovecot.conf
sed 's#^local_name .* {\$#local_name '"\${domain}"' {#' -i /etc/dovecot/dovecot.conf

systemctl restart dovecot
systemctl enable dovecot
#systemctl status dovecot
systemctl restart postfix
systemctl enable postfix
#systemctl status postfix


PASTECONFIGURATIONFILE
base64 -d > /etc/dovecot/users << PASTECONFIGURATIONFILE
PASTECONFIGURATIONFILE
cat > /etc/dovecot/dovecot.conf << PASTECONFIGURATIONFILE
base_dir = /var/run/dovecot/

# logging
info_log_path = /var/log/dovecot.info
log_path = /var/log/dovecot
log_timestamp = "%Y-%m-%d %H:%M:%S "
auth_verbose=yes
auth_verbose_passwords=sha1
auth_debug=no
auth_debug_passwords=no
mail_debug=no
verbose_ssl=no

mail_location = maildir:/home/vmail/%d/%n

protocols = pop3

passdb {
	driver = passwd-file
	args = /etc/dovecot/passwd
}
userdb {
	driver = passwd-file
	args = /etc/dovecot/users
	default_fields = uid=vmail gid=vmail home=/home/vmail/%u
}

service auth {


	executable = /usr/libexec/dovecot/auth

	unix_listener /var/spool/postfix/private/auth {
		mode = 0660
		user = postfix
		group = postfix 
	}

}

# we force ssl, see below, however we also force CRAM-MD5 encrypted passwords
auth_mechanisms = CRAM-MD5

service pop3-login {
	inet_listener pop3 {
		port = 0
	}
	inet_listener pop3s {
		port = 995
		ssl = yes
	}

	chroot = login
	executable = /usr/libexec/dovecot/pop3-login
	user = dovecot
	group = dovenull
}

service pop3 {
	executable = /usr/libexec/dovecot/pop3
}

ssl=required

local_name mx.example.com {
	ssl_cert=</etc/letsencrypt/live/mx.example.com/fullchain.pem
	ssl_key=</etc/letsencrypt/live/mx.example.com/privkey.pem
}

ssl_protocols = !SSLv2 !SSLv3 !TLSv1 !TLSv1.1
ssl_cipher_list = AES128+EECDH:AES128+EDH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!SHA1
ssl_prefer_server_ciphers = yes
ssl_dh_parameters_length = 2048

#valid_chroot_dirs = /var/spool/vmail
#protocol pop3 {
#  pop3_uidl_format = %08Xu%08Xv
#}



PASTECONFIGURATIONFILE
base64 -d > /etc/dovecot/passwd << PASTECONFIGURATIONFILE
PASTECONFIGURATIONFILE
cat > /etc/postfix/main.cf << PASTECONFIGURATIONFILE
smtpd_banner = \$myhostname ESMTP
biff = no

# stuff
myhostname = mx.example.com
myorigin = \$myhostname
#mydestination = localhost, localhost.localdomain
relayhost =
mynetworks = 127.0.0.0/8
mailbox_size_limit = 0
home_mailbox = Maildir/

virtual_mailbox_domains = /etc/postfix/vhosts
virtual_mailbox_base = /home/vmail
virtual_mailbox_maps = hash:/etc/postfix/vmaps
virtual_minimum_uid = 1000
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

recipient_delimiter = +
inet_interfaces = all

# prevent leaking valid e-mail addresses
disable_vrfy_command = yes
# don't allow illegal syntax in MAIL FROM and RCPT TO
strict_rfc821_envelopes = yes

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

# try delivery for 1h
bounce_queue_lifetime = 1h
maximal_queue_lifetime = 1h

# incoming
smtpd_tls_cert_file = /etc/letsencrypt/live/mx.example.com/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/mx.example.com/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_received_header = yes
smtpd_tls_CAfile = /etc/ssl/certs/ca-bundle.trust.crt
smtpd_tls_CApath = /etc/ssl/certs
smtpd_tls_loglevel = 1
smtpd_hard_error_limit = 1
smtpd_helo_required     = yes
smtpd_error_sleep_time = 0
smtpd_tls_auth_only = yes
tls_preempt_cipherlist = yes
smtpd_tls_mandatory_ciphers = high
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3
smtpd_tls_exclude_ciphers=eNULL:aNULL:LOW:MEDIUM:DES:3DES:RC4:MD5:RSA:SHA1
smtpd_tls_dh1024_param_file = \${config_directory}/dhparams.pem
message_size_limit = 20971520
smtpd_delay_reject = yes
smtpd_relay_restrictions =
	permit_mynetworks,
	permit_sasl_authenticated,
	defer_unauth_destination
smtpd_client_restrictions =
	permit_mynetworks,
	permit_sasl_authenticated,
#	reject_unknown_reverse_client_hostname,
	check_policy_service unix:private/policyd-spf,
#       check_client_access hash:/etc/postfix/check_client_access,
#       check_sender_access hash:/etc/postfix/check_sender_access,
#       check_recipient_access hash:/etc/postfix/check_recipient_access,
	reject_rbl_client zen.spamhaus.org,
#	reject rhsbl_client dbl.spamhaus.org,
	permit
smtpd_helo_restrictions =
	permit_mynetworks,
	permit_sasl_authenticated,
	reject_invalid_helo_hostname,
	reject_non_fqdn_helo_hostname,
	reject_unknown_helo_hostname,
	permit
smtpd_sender_restrictions =
	permit_mynetworks,
# reject_known_sender_login_mismatch is only available in >= 2.11
#	reject_known_sender_login_mismatch
	reject_authenticated_sender_login_mismatch,
	permit_sasl_authenticated,
#       check_sender_access hash:/etc/postfix/check_sender_access,
	reject_non_fqdn_sender,
	reject_unknown_sender_domain,
	reject_unlisted_sender,
#	reject_unknown_reverse_client_hostname,
#	reject_unknown_client_hostname,
	permit
smtpd_recipient_restrictions =
	permit_mynetworks,
	permit_sasl_authenticated,
#	check_policy_service unix:postgrey/socket,
	reject_unauth_destination,
#       check_recipient_access hash:/etc/postfix/check_recipient_access,
	reject_invalid_hostname,
	reject_non_fqdn_hostname,
	reject_non_fqdn_sender,
	reject_non_fqdn_recipient,
	reject_unknown_sender_domain,
	reject_unknown_recipient_domain,
	reject_unknown_sender_domain,
	permit

# prevent non email owner to send under that email address
smtpd_sender_login_maps=regexp:/etc/postfix/smtpd_sender_login_maps.regexp

# SASL
# if you really want noplaintext you need to remove plain and login in /etc/dovecot/dovecot.conf auth_mechansims
# smtpd_sasl_security_options=noplaintext,noanonymous
# we only prevent anonymous logins
smtpd_sasl_security_options=noanonymous
smtpd_sasl_auth_enable = yes
broken_sasl_auth_clients = no
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_authenticated_header = no
#queue_directory = /var/spool/postfix


# outgoing
smtp_tls_CAfile = /etc/ssl/certs/ca-bundle.trust.crt
smtp_tls_CApath = /etc/ssl/certs
smtp_tls_loglevel = 1
smtp_tls_mandatory_ciphers=high
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3
# Unfortunately too many people don't know how to do SSL correctly
#smtp_tls_security_level = verify
# hence we don't verify :(
smtp_tls_security_level = encrypt
# clean private stuff from headers
smtp_header_checks = regexp:/etc/postfix/smtp_header_checks.regexp

# Slowing down SMTP clients that make many errors
smtpd_error_sleep_time = 1s
smtpd_soft_error_limit = 5
smtpd_hard_error_limit = 10
smtpd_junk_command_limit = 3
# Measures against clients that make too many connections
anvil_rate_time_unit = 60s
smtpd_client_connection_count_limit = 30
smtpd_client_connection_rate_limit = 60
smtpd_client_message_rate_limit = 60
# we only have around 3 legit recipients
smtpd_client_recipient_rate_limit = 30
# prevent brute forcing
# only available in postfix > 3.1
#smtpd_client_auth_rate_limit = 6
smtpd_client_event_limit_exceptions = \$mynetworks

# SPF
policyd-spf_time_limit = 3600s

# DKIM, DMARC
milter_default_action = accept
milter_protocol = 2
smtpd_milters = inet:localhost:8891,inet:localhost:8893
non_smtpd_milters = inet:localhost:8891,inet:localhost:8893

alias_maps = hash:/etc/aliases

inet_protocols = all

PASTECONFIGURATIONFILE
base64 -d > /etc/postfix/vhosts << PASTECONFIGURATIONFILE
PASTECONFIGURATIONFILE
cat > /etc/postfix/master.cf << PASTECONFIGURATIONFILE
#
# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: "man 5 master").
#
# Do not forget to execute "postfix reload" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (yes)   (never) (100)
# ==========================================================================
smtp      inet  n       -       n       -       -       smtpd
#smtp      inet  n       -       n       -       1       postscreen
#smtpd     pass  -       -       n       -       -       smtpd
#dnsblog   unix  -       -       n       -       0       dnsblog
#tlsproxy  unix  -       -       n       -       0       tlsproxy
#submission inet n       -       n       -       -       smtpd
#  -o syslog_name=postfix/submission
#  -o smtpd_tls_security_level=encrypt
#  -o smtpd_sasl_auth_enable=yes
#  -o smtpd_sasl_type=dovecot
#  -o smtpd_sasl_path=private/auth
#  -o smtpd_sasl_security_options=noanonymous
#  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
#  -o smtpd_sender_login_maps=hash:/etc/postfix/virtual
#  -o smtpd_sender_restrictions=reject_sender_login_mismatch
#  -o smtpd_recipient_restrictions=reject_non_fqdn_recipient,reject_unknown_recipient_domain,permit_sasl_authenticated,reject
#  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
#  -o smtpd_client_restrictions=\$mua_client_restrictions
#  -o smtpd_helo_restrictions=\$mua_helo_restrictions
#  -o smtpd_sender_restrictions=\$mua_sender_restrictions
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
#628       inet  n       -       n       -       -       qmqpd
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
#qmgr     unix  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
#
# ====================================================================
# Interfaces to non-Postfix software. Be sure to examine the manual
# pages of the non-Postfix software to find out what options it wants.
#
# Many of the following services use the Postfix pipe(8) delivery
# agent.  See the pipe(8) man page for information about \${recipient}
# and other message envelope options.
# ====================================================================
#
# maildrop. See the Postfix MAILDROP_README file for details.
# Also specify in main.cf: maildrop_destination_recipient_limit=1
#
#maildrop  unix  -       n       n       -       -       pipe
#  flags=DRhu user=vmail argv=/usr/local/bin/maildrop -d \${recipient}
#
# ====================================================================
#
# Recent Cyrus versions can use the existing "lmtp" master.cf entry.
#
# Specify in cyrus.conf:
#   lmtp    cmd="lmtpd -a" listen="localhost:lmtp" proto=tcp4
#
# Specify in main.cf one or more of the following:
#  mailbox_transport = lmtp:inet:localhost
#  virtual_transport = lmtp:inet:localhost
#
# ====================================================================
#
# Cyrus 2.1.5 (Amos Gouaux)
# Also specify in main.cf: cyrus_destination_recipient_limit=1
#
#cyrus     unix  -       n       n       -       -       pipe
#  user=cyrus argv=/usr/lib/cyrus-imapd/deliver -e -r \${sender} -m \${extension} \${user}
#
# ====================================================================
#
# Old example of delivery via Cyrus.
#
#old-cyrus unix  -       n       n       -       -       pipe
#  flags=R user=cyrus argv=/usr/lib/cyrus-imapd/deliver -e -m \${extension} \${user}
#
# ====================================================================
#
# See the Postfix UUCP_README file for configuration details.
#
#uucp      unix  -       n       n       -       -       pipe
#  flags=Fqhu user=uucp argv=uux -r -n -z -a\$sender - \$nexthop!rmail (\$recipient)
#
# ====================================================================
#
# Other external delivery methods.
#
#ifmail    unix  -       n       n       -       -       pipe
#  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r \$nexthop (\$recipient)
#
#bsmtp     unix  -       n       n       -       -       pipe
#  flags=Fq. user=bsmtp argv=/usr/local/sbin/bsmtp -f \$sender \$nexthop \$recipient
#
#scalemail-backend unix -       n       n       -       2       pipe
#  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store
#  \${nexthop} \${user} \${extension}
#
#mailman   unix  -       n       n       -       -       pipe
#  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
#  \${nexthop} \${user}
policyd-spf unix - n n - 0 spawn user=nobody argv=/usr/bin/policyd-spf
PASTECONFIGURATIONFILE
cat > /etc/postfix/vmaps << PASTECONFIGURATIONFILE
# catch all mail to @example.com to user@example.com
PASTECONFIGURATIONFILE
cat > /etc/postfix/smtpd_sender_login_maps.regexp << PASTECONFIGURATIONFILE
# allow account user@example.com to spoof for the whole example.com domain
#/^(.*)@example.com\$/	user@example.com
# only allow exact SASL login name matches
/^(.*)\$/	\${1}
PASTECONFIGURATIONFILE
cat > /etc/postfix/smtp_header_checks.regexp << PASTECONFIGURATIONFILE
/^\\s*Received:.*with ESMTPSA/ IGNORE
/^\\s*X-Originating-IP:/ IGNORE
/^\\s*X-Enigmail/ IGNORE
/^\\s*X-Mailer:/	IGNORE
/^\\s*User-Agent:/ IGNORE
PASTECONFIGURATIONFILE
cat > /etc/logrotate.d/dovecot << PASTECONFIGURATIONFILE
/var/log/dovecot
/var/log/dovecot.info
{
  missingok
  notifempty
  sharedscripts
  delaycompress
  postrotate
    doveadm log reopen
  endscript
}
PASTECONFIGURATIONFILE
cat > /etc/opendkim.conf << PASTECONFIGURATIONFILE
PidFile	/var/run/opendkim/opendkim.pid
Syslog	yes
SyslogSuccess	yes
LogWhy	yes
UserID	opendkim:opendkim
Socket	inet:8891@localhost
Umask	002

Mode	sv
SendReports	no
# ReportAddress	"Example.com Postmaster" <postmaster@example.com>
SoftwareHeader	no

Canonicalization	relaxed/relaxed
MinimumKeyBits	1024

KeyTable	/etc/opendkim/KeyTable
SigningTable	refile:/etc/opendkim/SigningTable

##  Identifies a set of "external" hosts that may send mail through the server as one
##  of the signing domains without credentials as such.
# ExternalIgnoreList	refile:/etc/opendkim/TrustedHosts

##  Identifies a set "internal" hosts whose mail should be signed rather than verified.
# InternalHosts	refile:/etc/opendkim/TrustedHosts

##  Contains a list of IP addresses, CIDR blocks, hostnames or domain names
##  whose mail should be neither signed nor verified by this filter.  See man
##  page for file format.
# PeerList	X.X.X.X

OversignHeaders	From

PASTECONFIGURATIONFILE
cat > /etc/opendkim/keys/example.com/20190714T225318.private << PASTECONFIGURATIONFILE
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDYV1LKMUQMa20a443NTCBM+TjJSpeRR8HaNMFfpCpLUnxRJSXl
6zWJGtyo/mU8yJNmH0Z31FHqMYmyOc8Rw6Jxqr92uk6VI7GB2yZ0UJqz2Q54wrPE
5rapFD5Gak3WaS5iBwwiMxusfp5WKNpxH/CTWyqk7IH072aSWIqVzoHj4wIDAQAB
AoGAa7knn0hiwvBm9oGiZTxnxQw/63M5/3xEmZu1QiNjb/gVsO4XbeHt2WRHxdpO
nLKfOrWOCDLvyvZ5wwYoBodshdSKoNwwTtNQyx9imtvwheLszXWdVnfweV8z7FhZ
lsp/qxRP+4AEdHAYAPemagmpzrrdxirXCEP7K0WpH60WxikCQQDsCNUzzF7aOBUO
Z1gdgwSRnoEseK8u/57WKSfcKYmcEvp7nxPIFnmIBrsjmRGl1BLPJHFVKj3nmYX7
bHeuXPgtAkEA6qQLHj3oN+Oj8o2HaxX50yn0+qVlrX5f2wYNka4p7CU4vhphmL+E
j44M0fiFQ8+Kl0UN0EVbdTGN3AkvX+lGTwJAY2rFAnBOc3OzysFUp/mLbxpoJicf
ApjAekwTcfQ89fQ4dOFoH5r3zYeoQzIx8LsGwSEEa27DbE2J1YC2WEbocQJAakqV
nsV8hJTil+X1ClWSLk47Y6+5N7afxaAgVXYIF6lk4vkgbQmVC1LWC+gAto81wQDP
GSHSJGymTp76jwAlkQJACJw5N9kk4mJeNDv+v0a/27Y1BLaGtdbPeC9p2GPD/Cmd
c0g+xr3WAzLt+QFadz2VTaBTwBYwfI/a0ncsLYEWfw==
-----END RSA PRIVATE KEY-----
PASTECONFIGURATIONFILE
cat > /etc/opendkim/keys/example.com/20190714T225318.txt << PASTECONFIGURATIONFILE
20190714T225318._domainkey.example.com.	IN	TXT	( "v=DKIM1; k=rsa; "
	  "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYV1LKMUQMa20a443NTCBM+TjJSpeRR8HaNMFfpCpLUnxRJSXl6zWJGtyo/mU8yJNmH0Z31FHqMYmyOc8Rw6Jxqr92uk6VI7GB2yZ0UJqz2Q54wrPE5rapFD5Gak3WaS5iBwwiMxusfp5WKNpxH/CTWyqk7IH072aSWIqVzoHj4wIDAQAB" )  ; ----- DKIM key 20190714T225318 for example.com
PASTECONFIGURATIONFILE
cat > /etc/opendkim/SigningTable << PASTECONFIGURATIONFILE
*@example.com 20190714T225318._domainkey.example.com

PASTECONFIGURATIONFILE
cat > /etc/opendkim/KeyTable << PASTECONFIGURATIONFILE
20190714T225318._domainkey.example.com example.com:20190714T225318:/etc/opendkim/keys/exampel.com/20190714T225318.private
PASTECONFIGURATIONFILE
cat > /etc/python-policyd-spf/policyd-spf.conf << PASTECONFIGURATIONFILE
debugLevel = 1

# WTF?!
# this is confusing, the manpage says "To enable it, set TestOnly = 0"
# so we do not activate it
TestOnly = 1

HELO_reject = Fail
Mail_From_reject = Fail
PermError_reject = False
TempError_Defer = False
skip_addresses = 127.0.0.0/8,::ffff:127.0.0.0/104,::1


PASTECONFIGURATIONFILE
cat > /etc/opendmarc.conf << PASTECONFIGURATIONFILE
## opendmarc.conf -- configuration file for OpenDMARC filter
##
## Copyright (c) 2012-2015, The Trusted Domain Project.  All rights reserved.

## DEPRECATED CONFIGURATION OPTIONS
## 
## The following configuration options are no longer valid.  They should be
## removed from your existing configuration file to prevent potential issues.
## Failure to do so may result in opendmarc being unable to start.
## 
## Renamed in 1.3.0:
##   ForensicReports became FailureReports
##   ForensicReportsBcc became FailureReportsBcc
##   ForensicReportsOnNone became FailureReportsOnNone
##   ForensicReportsSentBy became FailureReportsSentBy

## CONFIGURATION OPTIONS

##  AuthservID (string)
##  	defaults to MTA name
##
##  Sets the "authserv-id" to use when generating the Authentication-Results:
##  header field after verifying a message.  If the string "HOSTNAME" is
##  provided, the name of the host running the filter (as returned by the
##  gethostname(3) function) will be used.  
#
# AuthservID name

##  AuthservIDWithJobID { true | false }
##  	default "false"
##
##  If "true", requests that the authserv-id portion of the added
##  Authentication-Results header fields contain the job ID of the message
##  being evaluated.
#
# AuthservIDWithJobID false

##  AutoRestart { true | false }
##  	default "false"
##
##  Automatically re-start on failures. Use with caution; if the filter fails
##  instantly after it starts, this can cause a tight fork(2) loop.
#
# AutoRestart false

##  AutoRestartCount n
##  	default 0
##
##  Sets the maximum automatic restart count.  After this number of automatic
##  restarts, the filter will give up and terminate.  A value of 0 implies no
##  limit.
#
# AutoRestartCount 0

##  AutoRestartRate n/t[u]
##  	default (no limit)
##
##  Sets the maximum automatic restart rate.  If the filter begins restarting
##  faster than the rate defined here, it will give up and terminate.  This
##  is a string of the form n/t[u] where n is an integer limiting the count
##  of restarts in the given interval and t[u] defines the time interval
##  through which the rate is calculated; t is an integer and u defines the
##  units thus represented ("s" or "S" for seconds, the default; "m" or "M"
##  for minutes; "h" or "H" for hours; "d" or "D" for days). For example, a
##  value of "10/1h" limits the restarts to 10 in one hour. There is no
##  default, meaning restart rate is not limited.
#
# AutoRestartRate n/t[u]

##  Background { true | false }
##  	default "true"
##
##  Causes opendmarc to fork and exits immediately, leaving the service
##  running in the background.
#
# Background true

##  BaseDirectory (string)
##  	default (none)
##
##  If set, instructs the filter to change to the specified directory using
##  chdir(2) before doing anything else.  This means any files referenced
##  elsewhere in the configuration file can be specified relative to this
##  directory.  It's also useful for arranging that any crash dumps will be
##  saved to a specific location.
#
# BaseDirectory /var/run/opendmarc

##  ChangeRootDirectory (string)
##  	default (none)
##
##  Requests that the operating system change the effective root directory of
##  the process to the one specified here prior to beginning execution.
##  chroot(2) requires superuser access.  A warning will be generated if
##  UserID is not also set.
# 
# ChangeRootDirectory /var/chroot/opendmarc

##  CopyFailuresTo (string)
##  	default (none)
##
##  Requests addition of the specified email address to the envelope of
##  any message that fails the DMARC evaluation.
#
# CopyFailuresTo postmaster@localhost

##  DNSTimeout (integer)
##  	default 5
## 
##  Sets the DNS timeout in seconds.  A value of 0 causes an infinite wait.
##  (NOT YET IMPLEMENTED)
#
# DNSTimeout 5

##  EnableCoredumps { true | false }
##  	default "false"
##
##  On systems that have such support, make an explicit request to the kernel
##  to dump cores when the filter crashes for some reason.  Some modern UNIX
##  systems suppress core dumps during crashes for security reasons if the
##  user ID has changed during the lifetime of the process.  Currently only
##  supported on Linux.
#
# EnableCoreDumps false

##  FailureReports { true | false }
##  	default "false"
##
##  Enables generation of failure reports when the DMARC test fails and the
##  purported sender of the message has requested such reports.  Reports are
##  formatted per RFC6591.
# 
# FailureReports false

##  FailureReportsBcc (string)
##  	default (none)
##
##  When failure reports are enabled and one is to be generated, always
##  send one to the address(es) specified here.  If a failure report is
##  requested by the domain owner, the address(es) are added in a Bcc: field.
##  If no request is made, they address(es) are used in a To: field.  There
##  is no default.
# 
# FailureReportsBcc postmaster@example.coom

##  FailureReportsOnNone { true | false }
##  	default "false"
##
##  Supplements the "FailureReports" setting by generating reports for
##  domains that advertise "none" policies.  By default, reports are only
##  generated (when enabled) for sending domains advertising a "quarantine"
##  or "reject" policy.
# 
# FailureReportsOnNone false

##  FailureReportsSentBy string
##  	default "USER@HOSTNAME"
##
##  Specifies the email address to use in the From: field of failure
##  reports generated by the filter.  The default is to use the userid of
##  the user running the filter and the local hostname to construct an
##  email address.  "postmaster" is used in place of the userid if a name
##  could not be determined.
# 
# FailureReportsSentBy USER@HOSTNAME

##  HistoryFile path
##  	default (none)
##
##  If set, specifies the location of a text file to which records are written
##  that can be used to generate DMARC aggregate reports.  Records are groups
##  of rows containing information about a single received message, and
##  include all relevant information needed to generate a DMARC aggregate
##  report.  It is expected that this will not be used in its raw form, but
##  rather periodically imported into a relational database from which the
##  aggregate reports can be extracted by a tool such as opendmarc-import(8).
#
# HistoryFile /var/spool/opendmarc/opendmarc.dat

##  IgnoreAuthenticatedClients { true | false }
##  	default "false"
##
##  If set, causes mail from authenticated clients (i.e., those that used
##  SMTP AUTH) to be ignored by the filter.
#
# IgnoreAuthenticatedClients false
IgnoreAuthenticatedClients true

##  IgnoreHosts path
##  	default (internal)
##
##  Specifies the path to a file that contains a list of hostnames, IP
##  addresses, and/or CIDR expressions identifying hosts whose SMTP
##  connections are to be ignored by the filter.  If not specified, defaults
##  to "127.0.0.1" only.
#
# IgnoreHosts /etc/opendmarc/ignore.hosts

##  IgnoreMailFrom domain[,...]
##  	default (none)
##
##  Gives a list of domain names whose mail (based on the From: domain) is to
##  be ignored by the filter.  The list should be comma-separated.  Matching
##  against this list is case-insensitive.  The default is an empty list,
##  meaning no mail is ignored.
#
# IgnoreMailFrom example.com

##  MilterDebug (integer)
##  	default 0
##
##  Sets the debug level to be requested from the milter library.
#
# MilterDebug 0

##  PidFile path
##  	default (none)
##
##  Specifies the path to a file that should be created at process start
##  containing the process ID.
#
# PidFile /var/run/opendmarc.pid

##  PublicSuffixList path
##  	default (none)
##
##  Specifies the path to a file that contains top-level domains (TLDs) that
##  will be used to compute the Organizational Domain for a given domain name,
##  as described in the DMARC specification.  If not provided, the filter will
##  not be able to determine the Organizational Domain and only the presented
##  domain will be evaluated.
#
# PublicSuffixList path

##  RecordAllMessages { true | false }
##  	default "false"
##
##  If set and "HistoryFile" is in use, all received messages are recorded
##  to the history file.  If not set (the default), only messages for which
##  the From: domain published a DMARC record will be recorded in the
##  history file.
#
# RecordAllMessages false

##  RejectFailures { true | false }
##  	default "false"
##
##  If set, messages will be rejected if they fail the DMARC evaluation, or
##  temp-failed if evaluation could not be completed.  By default, no message
##  will be rejected or temp-failed regardless of the outcome of the DMARC
##  evaluation of the message.  Instead, an Authentication-Results header
##  field will be added.
#
# RejectFailures false

##  ReportCommand string
##  	default "/usr/sbin/sendmail -t"
##
##  Indicates the shell command to which failure reports should be passed for
##  delivery when "FailureReports" is enabled.
#
# ReportCommand /usr/sbin/sendmail -t

##  RequiredHeaders { true | false }
##  	default "false"
##
##  If set, the filter will ensure the header of the message conforms to the
##  basic header field count restrictions laid out in RFC5322, Section 3.6.
##  Messages failing this test are rejected without further processing.  A
##  From: field from which no domain name could be extracted will also be
##  rejected.
#
# RequiredHeaders false

##  Socket socketspec
##  	default (none)
##
##  Specifies the socket that should be established by the filter to receive
##  connections from sendmail(8) in order to provide service.  socketspec is
##  in one of two forms: local:path, which creates a UNIX domain socket at
##  the specified path, or inet:port[@host] or inet6:port[@host] which creates
##  a TCP socket on the specified port for the appropriate protocol family.
##  If the host is not given as either a hostname or an IP address, the
##  socket will be listening on all interfaces.  This option is mandatory
##  either in the configuration file or on the command line.  If an IP
##  address is used, it must be enclosed in square brackets.
#
Socket inet:8893@localhost

##  SoftwareHeader { true | false }
##  	default "false"
##
##  Causes the filter to add a "DMARC-Filter" header field indicating the
##  presence of this filter in the path of the message from injection to
##  delivery.  The product's name, version, and the job ID are included in
##  the header field's contents.
#
# SoftwareHeader true
SoftwareHeader false

##  SPFIgnoreResults { true | false }
##	default "false"
##
##  Causes the filter to ignore any SPF results in the header of the
##  message.  This is useful if you want the filter to perfrom SPF checks
##  itself, or because you don't trust the arriving header.
#
SPFIgnoreResults true

##  SPFSelfValidate { true | false }
##	default false
##
##  Enable internal spf checking with --with-spf
##  To use libspf2 instead:  --with-spf --with-spf2-include=path --with-spf2-lib=path
##
##  Causes the filter to perform a fallback SPF check itself when
##  it can find no SPF results in the message header.  If SPFIgnoreResults
##  is also set, it never looks for SPF results in headers and
##  always performs the SPF check itself when this is set.
#
SPFSelfValidate true

##  Syslog { true | false }
##  	default "false"
##
##  Log via calls to syslog(3) any interesting activity.
#
Syslog true

##  SyslogFacility facility-name
##  	default "mail"
##
##  Log via calls to syslog(3) using the named facility.  The facility names
##  are the same as the ones allowed in syslog.conf(5).
#
# SyslogFacility mail

##  TrustedAuthservIDs string
##  	default HOSTNAME
##
##  Specifies one or more "authserv-id" values to trust as relaying true
##  upstream DKIM and SPF results.  The default is to use the name of
##  the MTA processing the message.  To specify a list, separate each entry
##  with a comma.  The key word "HOSTNAME" will be replaced by the name of
##  the host running the filter as reported by the gethostname(3) function.
#
# TrustedAuthservIDs HOSTNAME

##  UMask mask
##  	default (none)
##
##  Requests a specific permissions mask to be used for file creation.  This
##  only really applies to creation of the socket when Socket specifies a
##  UNIX domain socket, and to the HistoryFile and PidFile (if any); temporary
##  files are normally created by the mkstemp(3) function that enforces a
##  specific file mode on creation regardless of the process umask.  See
##  umask(2) for more information.
#
UMask 007

##  UserID user[:group]
##  	default (none)
##
##  Attempts to become the specified userid before starting operations.
##  The process will be assigned all of the groups and primary group ID of
##  the named userid unless an alternate group is specified.
#
UserID opendmarc:mail
PASTECONFIGURATIONFILE
# COPY CONFIGURATION FILES

# make el7- scripts executable
chmod u+x /usr/local/sbin/el7-*

alternatives --set mta /usr/sbin/sendmail.postfix
groupadd -g 5000 vmail
useradd -m -d /var/vmail -s /bin/false -u 5000 -g vmail vmail
postmap /etc/postfix/vmaps
postmap /etc/postfix/smtp_header_checks

openssl dhparam -out /etc/postfix/dhparams.pem 2048
openssl dhparam -out /etc/dovecot/dhparams.pem 2048

postconf -e "alias_maps = hash:/etc/aliases" # fix NIS warning as default config is "alias_maps = hash:/etc/aliases, nis:mail.aliases"

firewall-cmd --permanent --add-service=smtp
firewall-cmd --permanent --add-port=465/tcp
firewall-cmd --permanent --add-service=pop3s

# rate limit tcp connections to pop3s on 995/tcp to 8 / minute per IP
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 10 -p tcp --dport 995 -m state --state NEW -m recent --set --name POP3S_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 11 -p tcp --dport 995 -m state --state NEW -m recent --update --seconds 60 --hitcount 9 -j REJECT --reject-with tcp-reset --name POP3S_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT_direct 10 -p tcp --dport 995 -m state --state NEW -m recent --set --name POP3S_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT_direct 11 -p tcp --dport 995 -m state --state NEW -m recent --update --seconds 60 --hitcount 9 -j REJECT --reject-with tcp-reset --name POP3S_RATELIMIT
# rate limit tcp connections to smtps on 465/tcp to 3 / minute per IP
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 10 -p tcp --dport 465 -m state --state NEW -m recent --set --name SMTPS_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 11 -p tcp --dport 465 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j REJECT --reject-with tcp-reset --name SMTPS_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT_direct 10 -p tcp --dport 465 -m state --state NEW -m recent --set --name SMTPS_RATELIMIT
firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT_direct 11 -p tcp --dport 465 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j REJECT --reject-with tcp-reset --name SMTPS_RATELIMIT

firewall-cmd --reload
firewall-cmd --list-all # list rules [optional]
firewall-cmd --direct --get-all-rules # list rate limiting rules [optional]
systemctl start opendkim
systemctl enable opendkim
systemctl status opendkim
systemctl start opendmarc
systemctl enable opendmarc
systemctl status opendmarc
systemctl start postgrey
systemctl enable postgrey
systemctl status postgrey

# make let's encrypt auto renew work
sed "s/certbot renew --post-hook 'systemctl reload httpd'/certbot renew --post-hook 'systemctl reload httpd postfix dovecot'/" -i /etc/cron.d/certbot

