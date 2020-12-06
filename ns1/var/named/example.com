$ORIGIN example.com.
$TTL 1d
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

