#!/bin/bash
# yum -y install epel-release
yum -y install bind bind-utils #haveged
# yum -y install rng-tools
# cat /dev/random | rngtest -c 1000
# systemctl enable haveged
# COPY CONFIGURATION FILES
mkdir -p /etc
mkdir -p /etc/named
mkdir -p /etc/logrotate.d
mkdir -p /var
mkdir -p /var/named
mkdir -p /usr
mkdir -p /usr/local
mkdir -p /usr/local/sbin
cat > /etc/named/zones << PASTECONFIGURATIONFILE
/*
zone "example.com" IN {
	type master;
	file "example.com.signed";
};
*/
PASTECONFIGURATIONFILE
cat > /etc/named.conf << PASTECONFIGURATIONFILE
options {
	version none;
	listen-on port 53 { localhost; };
	listen-on-v6 port 53 { localhost; };
	directory         "/var/named";
	allow-query       { localhost; };
	allow-update      { none; }; # IP of ns1
	allow-notify      { none; }; # IP of ns1
	notify yes;
	allow-transfer    { none; }; # IP of ns2
	allow-query-cache { localhost; };
	allow-recursion   { localhost; };
	recursion yes;
	auth-nxdomain yes;
	rate-limit {
		all-per-second 20;
		errors-per-second 5;
		exempt-clients { localhost; };
		log-only no;
		nodata-per-second 5;
		nxdomains-per-second 5;
		qps-scale 250;
		referrals-per-second 5;
		responses-per-second 5;
		slip 2;
		window 15;
	};

	dnssec-enable yes;
	dnssec-validation yes;
	dnssec-lookaside auto;
};

// logging config

logging {
        channel ns_log {
                file "/var/log/named/named.log";
                severity dynamic;
                print-time yes;
                print-severity yes;
                print-category yes;
        };
	channel queries_log {
 		file "/var/log/named/queries.log";
		print-time yes;
		print-category yes;
		print-severity yes;
		severity info;
	};
        category default { ns_log; };
        category general { ns_log; };
        category config { ns_log; };
	category notify { ns_log; };
	category xfer-in { ns_log; };
	category xfer-out { ns_log; };
	category update { ns_log; };
	category rate-limit { ns_log; };
	category queries { queries_log; };
	category query-errors { queries_log; };
};

// eog logging config



zone "." IN {
	type hint;
	file "named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
include "/etc/named/zones";


PASTECONFIGURATIONFILE
cat > /etc/logrotate.d/named << PASTECONFIGURATIONFILE
/var/named/data/named.run {
    missingok
    su named named
    create 0644 named named
    postrotate
        /usr/bin/systemctl reload named.service > /dev/null 2>&1 || true
        /usr/bin/systemctl reload named-chroot.service > /dev/null 2>&1 || true
        /usr/bin/systemctl reload named-sdb.service > /dev/null 2>&1 || true
        /usr/bin/systemctl reload named-sdb-chroot.service > /dev/null 2>&1 || true
        /usr/bin/systemctl reload named-pkcs11.service > /dev/null 2>&1 || true
    endscript
}

/var/log/named/*.log {
  create 0644 named named
  missingok
  notifempty
  sharedscripts
  postrotate
    /usr/sbin/rndc reconfig > /dev/null 2>/dev/null || true
  endscript
}
PASTECONFIGURATIONFILE
cat > /var/named/example.com << PASTECONFIGURATIONFILE
\$ORIGIN example.com.
\$TTL 1d
@ IN SOA ns1.example.com. hostmaster.example.com. (
	2019011301 ; serial
	12h ; refresh
	1h ; retry
	4w ; expire
	1d ; nx ttl
)

@	IN NS ns1.example.com.
@	IN NS ns2.example.com.
ns1	IN A 1.1.1.1
ns1	IN AAAA 0:0:0:0:0:ffff:404:404
ns2	IN A 2.2.2.2
ns2	IN AAAA 0:0:0:0:0:ffff:404:404

@	IN CAA 128 issue "letsencrypt.org"

@	IN MX 1 mx.example.com.
@	IN TXT "v=spf1 mx -all"
_dmarc  IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-asjhgoeahfgsdf@example.com; ruf=mailto:dmarc-asfjsafjsadf@example.comi; fo=1;"

*._report._dmarc IN TXT "v=DMARC1;"

@	IN A 3.3.3.3
@	IN AAAA 0:0:0:0:0:ffff:404:404
mx	IN A 4.4.4.4
mx	IN AAAA 0:0:0:0:0:ffff:404:404

_mta-sts IN TXT "v=STSv1; id=2019011301"

PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-bind_config << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -ne 2 ]; then
	echo "Configure BIND ns IPs"
	echo
	echo "usage: \${0} <IP of ns1> <IP of ns2>"
	echo
	exit 1
fi
ns1="\${1}"
ns2="\${2}"
sed '/listen-on port/ s/^.*\$/\\tlisten-on port 53 { any; };/' -i /etc/named.conf
sed '/listen-on-v6 port/ s/^.*\$/\\tlisten-on-v6 port 53 { any; };/' -i /etc/named.conf
sed '/allow-query / s/^.*\$/\\tallow-query       { any; };/' -i /etc/named.conf
sed '/allow-update/ s/^.*\$/\\tallow-update      { '"\${ns1}"'; };/' -i /etc/named.conf
sed '/allow-notify/ s/^.*\$/\\tallow-notify      { '"\${ns1}"'; };/' -i /etc/named.conf
sed '/allow-transfer/ s/^.*\$/\\tallow-transfer    { '"\${ns2}"'; };/' -i /etc/named.conf
sed '/masters/ s/^.*\$/\\tmasters { '"\${ns1}"'; };/' -i /etc/named/zones

firewall-cmd --permanent --add-service=dns
firewall-cmd --reload
firewall-cmd --list-all # list rules [optional]
systemctl reload named

PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-dnssec_setup << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -eq 0 ]; then
	echo "Setup DNSSEC for a zone"
	echo
	echo "usage: \${0} zone"
	echo
	exit 1
fi
zone="\${1}"
cd /var/named/
dnssec-keygen -r /dev/urandom -a NSEC3RSASHA1 -b 2048 -n ZONE \${zone}
dnssec-keygen -r /dev/urandom -f KSK -a NSEC3RSASHA1 -b 4096 -n ZONE \${zone}
echo
echo "**************************************************************"
echo "* Now use /usr/local/sbin/el7-dnssec-sign to sign your zone! *"
echo "**************************************************************"

PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-dnssec_sign << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -eq 0 ]; then
	echo "DNSSEC sign a zone"
	echo
	echo "usage: \${0} zone"
	echo
	exit 1
fi
zone="\${1}"
cd /var/named/
rm \${zone}.signed.jnl
dnssec-signzone -t -S -A -3 \$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-16) -e +7776000 -o "\${zone}" "\${zone}"
echo "*********************************************"
echo "* The following goes into your parent zone: *"
echo "*********************************************"
cat "dsset-\${zone}."

PASTECONFIGURATIONFILE
# COPY CONFIGURATION FILES
# make el- scripts executable
chmod u+x /usr/local/sbin/el-*
chown named:named -R /var/named
mkdir -p /var/log/named
chown named:named -R /var/log/named
systemctl --no-pager start named
systemctl --no-pager enable named
systemctl --no-pager status named # check status [optional]

