#!/bin/bash
yum -y install epel-release openssl
yum -y install httpd python3-certbot-apache mod_ssl mod_security
rm -rf /etc/httpd/conf/*
rm -rf /etc/httpd/conf.d/*
# COPY CONFIGURATION FILES
mkdir -p /etc
mkdir -p /etc/httpd
mkdir -p /etc/httpd/conf
mkdir -p /etc/httpd/conf.d
mkdir -p /var
mkdir -p /var/www
mkdir -p /var/www/html
mkdir -p /var/www/html/blank
mkdir -p /usr
mkdir -p /usr/local
mkdir -p /usr/local/sbin
cat > /etc/httpd/conf/httpd.conf << PASTECONFIGURATIONFILE
ServerRoot "/etc/httpd"

Listen 80 443

Include conf.modules.d/*.conf

User apache
Group apache

Define server_name localhost 

ServerAdmin " "
ServerName "\${server_name}"

ErrorLog "logs/error_log"
LogLevel warn
#ForensicLog "logs/forensic_log"
<IfModule log_config_module>
	LogFormat "\\"%A\\",\\"%v\\",\\"%{%Y%m%dT%H%M%S}t.%{msec_frac}t%{%z}t\\",\\"%{uniqueid}i\\",\\"%L\\",\\"%l\\",\\"%a\\",\\"%h\\",\\"%{c}a\\",\\"%{c}h\\",\\"%u\\",\\"%{remote}p\\",\\"%{local}p\\",\\"%H\\",\\"%{SSL_PROTOCOL}x\\",\\"%{SSL_CIPHER}x\\",\\"%m\\",\\"%s\\",\\"%>s\\",\\"%{Host}i\\",\\"%U\\",\\"%q\\",\\"%{Referer}i\\",\\"%{User-Agent}i\\",\\"%k\\",\\"%f\\"" paranoid
	LogFormat "\\"%A\\",\\"%v\\",\\"%{%Y%m%dT%H%M%S}t.%{msec_frac}t%{%z}t\\",\\"%{uniqueid}i\\",\\"%L\\",\\"%l\\",\\"%a\\",\\"%h\\",\\"%{c}a\\",\\"%{c}h\\",\\"%u\\",\\"%{remote}p\\",\\"%{local}p\\",\\"%H\\",\\"%{SSL_PROTOCOL}x\\",\\"%{SSL_CIPHER}x\\",\\"%m\\",\\"%s\\",\\"%>s\\",\\"%{Host}i\\",\\"%U\\",\\"%q\\",\\"%{Referer}i\\",\\"%{User-Agent}i\\",\\"%k\\",\\"%f\\",\\"%{Cookie}i\\",\\"%{Set-Cookie}o\\"" fullparanoid

	CustomLog "logs/access_log" paranoid
</IfModule>

<VirtualHost *:80>
	ServerName "\${server_name}"
	DocumentRoot "/var/www/html/blank"
	<Directory "/var/www/html/blank">
        	AllowOverride None
	        Require all granted
	</Directory>
</VirtualHost>

<VirtualHost *:443>
	ServerName "\${server_name}"
	DocumentRoot "/var/www/html/blank"
	SSLEngine on
	SSLCertificateFile ssl/snakeoil.crt
	SSLCertificateKeyFile ssl/snakeoil.key
	<Directory "/var/www/html/blank">
        	AllowOverride None
	        Require all granted
	</Directory>
</VirtualHost>

<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>


AddDefaultCharset UTF-8

<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>

#
# Customizable error responses come in three flavors:
# 1) plain text 2) local redirects 3) external redirects
#
# Some examples:
#ErrorDocument 500 "The server made a boo boo."
#ErrorDocument 404 /missing.html
#ErrorDocument 404 "/cgi-bin/missing_handler.pl"
#ErrorDocument 402 http://www.example.com/subscription_info.html
#

#
# EnableMMAP and EnableSendfile: On systems that support it, 
# memory-mapping or the sendfile syscall may be used to deliver
# files.  This usually improves server performance, but must
# be turned off when serving from networked-mounted 
# filesystems or if support for these functions is otherwise
# broken on your system.
# Defaults if commented: EnableMMAP On, EnableSendfile Off
#
#EnableMMAP off
EnableSendfile on

# Supplemental configuration
#
# Load config files in the "/etc/httpd/conf.d" directory, if any.
IncludeOptional conf.d/*.conf

ServerSignature Off
ServerTokens Prod


HostnameLookups On

PASTECONFIGURATIONFILE
cat > /etc/httpd/conf/magic << PASTECONFIGURATIONFILE
# Magic data for mod_mime_magic Apache module (originally for file(1) command)
# The module is described in /manual/mod/mod_mime_magic.html
#
# The format is 4-5 columns:
#    Column #1: byte number to begin checking from, ">" indicates continuation
#    Column #2: type of data to match
#    Column #3: contents of data to match
#    Column #4: MIME type of result
#    Column #5: MIME encoding of result (optional)

#------------------------------------------------------------------------------
# Localstuff:  file(1) magic for locally observed files
# Add any locally observed files here.

#------------------------------------------------------------------------------
# end local stuff
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Java

0	short		0xcafe
>2	short		0xbabe		application/java

#------------------------------------------------------------------------------
# audio:  file(1) magic for sound formats
#
# from Jan Nicolai Langfeldt <janl@ifi.uio.no>,
#

# Sun/NeXT audio data
0	string		.snd
>12	belong		1		audio/basic
>12	belong		2		audio/basic
>12	belong		3		audio/basic
>12	belong		4		audio/basic
>12	belong		5		audio/basic
>12	belong		6		audio/basic
>12	belong		7		audio/basic

>12	belong		23		audio/x-adpcm

# DEC systems (e.g. DECstation 5000) use a variant of the Sun/NeXT format
# that uses little-endian encoding and has a different magic number
# (0x0064732E in little-endian encoding).
0	lelong		0x0064732E	
>12	lelong		1		audio/x-dec-basic
>12	lelong		2		audio/x-dec-basic
>12	lelong		3		audio/x-dec-basic
>12	lelong		4		audio/x-dec-basic
>12	lelong		5		audio/x-dec-basic
>12	lelong		6		audio/x-dec-basic
>12	lelong		7		audio/x-dec-basic
#                                       compressed (G.721 ADPCM)
>12	lelong		23		audio/x-dec-adpcm

# Bytes 0-3 of AIFF, AIFF-C, & 8SVX audio files are "FORM"
#					AIFF audio data
8	string		AIFF		audio/x-aiff	
#					AIFF-C audio data
8	string		AIFC		audio/x-aiff	
#					IFF/8SVX audio data
8	string		8SVX		audio/x-aiff	

# Creative Labs AUDIO stuff
#					Standard MIDI data
0	string	MThd			audio/unknown	
#>9 	byte	>0			(format %d)
#>11	byte	>1			using %d channels
#					Creative Music (CMF) data
0	string	CTMF			audio/unknown	
#					SoundBlaster instrument data
0	string	SBI			audio/unknown	
#					Creative Labs voice data
0	string	Creative\\ Voice\\ File	audio/unknown	
## is this next line right?  it came this way...
#>19	byte	0x1A
#>23	byte	>0			- version %d
#>22	byte	>0			\\b.%d

# [GRR 950115:  is this also Creative Labs?  Guessing that first line
#  should be string instead of unknown-endian long...]
#0	long		0x4e54524b	MultiTrack sound data
#0	string		NTRK		MultiTrack sound data
#>4	long		x		- version %ld

# Microsoft WAVE format (*.wav)
# [GRR 950115:  probably all of the shorts and longs should be leshort/lelong]
#					Microsoft RIFF
0	string		RIFF		
#					- WAVE format
>8	string		WAVE		audio/x-wav
# MPEG audio.
0   beshort&0xfff0  0xfff0  audio/mpeg
# C64 SID Music files, from Linus Walleij <triad@df.lth.se>
0   string      PSID        audio/prs.sid

#------------------------------------------------------------------------------
# c-lang:  file(1) magic for C programs or various scripts
#

# XPM icons (Greg Roelofs, newt@uchicago.edu)
# ideally should go into "images", but entries below would tag XPM as C source
0	string		/*\\ XPM		image/x-xbm	7bit

# this first will upset you if you're a PL/1 shop... (are there any left?)
# in which case rm it; ascmagic will catch real C programs
#					C or REXX program text
0	string		/*		text/plain
#					C++ program text
0	string		//		text/plain

#------------------------------------------------------------------------------
# compress:  file(1) magic for pure-compression formats (no archives)
#
# compress, gzip, pack, compact, huf, squeeze, crunch, freeze, yabba, whap, etc.
#
# Formats for various forms of compressed data
# Formats for "compress" proper have been moved into "compress.c",
# because it tries to uncompress it to figure out what's inside.

# standard unix compress
0	string		\\037\\235	application/octet-stream	x-compress

# gzip (GNU zip, not to be confused with [Info-ZIP/PKWARE] zip archiver)
0       string          \\037\\213        application/octet-stream	x-gzip

# According to gzip.h, this is the correct byte order for packed data.
0	string		\\037\\036	application/octet-stream
#
# This magic number is byte-order-independent.
#
0	short		017437		application/octet-stream

# XXX - why *two* entries for "compacted data", one of which is
# byte-order independent, and one of which is byte-order dependent?
#
# compacted data
0	short		0x1fff		application/octet-stream
0	string		\\377\\037	application/octet-stream
# huf output
0	short		0145405		application/octet-stream

# Squeeze and Crunch...
# These numbers were gleaned from the Unix versions of the programs to
# handle these formats.  Note that I can only uncrunch, not crunch, and
# I didn't have a crunched file handy, so the crunch number is untested.
#				Keith Waclena <keith@cerberus.uchicago.edu>
#0	leshort		0x76FF		squeezed data (CP/M, DOS)
#0	leshort		0x76FE		crunched data (CP/M, DOS)

# Freeze
#0	string		\\037\\237	Frozen file 2.1
#0	string		\\037\\236	Frozen file 1.0 (or gzip 0.5)

# lzh?
#0	string		\\037\\240	LZH compressed data

#------------------------------------------------------------------------------
# frame:  file(1) magic for FrameMaker files
#
# This stuff came on a FrameMaker demo tape, most of which is
# copyright, but this file is "published" as witness the following:
#
0	string		\\<MakerFile	application/x-frame
0	string		\\<MIFFile	application/x-frame
0	string		\\<MakerDictionary	application/x-frame
0	string		\\<MakerScreenFon	application/x-frame
0	string		\\<MML		application/x-frame
0	string		\\<Book		application/x-frame
0	string		\\<Maker		application/x-frame

#------------------------------------------------------------------------------
# html:  file(1) magic for HTML (HyperText Markup Language) docs
#
# from Daniel Quinlan <quinlan@yggdrasil.com>
# and Anna Shergold <anna@inext.co.uk>
#
0   string      \\<!DOCTYPE\\ HTML    text/html
0   string      \\<!doctype\\ html    text/html
0   string      \\<HEAD      text/html
0   string      \\<head      text/html
0   string      \\<TITLE     text/html
0   string      \\<title     text/html
0   string      \\<html      text/html
0   string      \\<HTML      text/html
0   string      \\<!--       text/html
0   string      \\<h1        text/html
0   string      \\<H1        text/html

# XML eXtensible Markup Language, from Linus Walleij <triad@df.lth.se>
0   string      \\<?xml      text/xml

#------------------------------------------------------------------------------
# images:  file(1) magic for image formats (see also "c-lang" for XPM bitmaps)
#
# originally from jef@helios.ee.lbl.gov (Jef Poskanzer),
# additions by janl@ifi.uio.no as well as others. Jan also suggested
# merging several one- and two-line files into here.
#
# XXX - byte order for GIF and TIFF fields?
# [GRR:  TIFF allows both byte orders; GIF is probably little-endian]
#

# [GRR:  what the hell is this doing in here?]
#0	string		xbtoa		btoa'd file

# PBMPLUS
#					PBM file
0	string		P1		image/x-portable-bitmap	7bit
#					PGM file
0	string		P2		image/x-portable-greymap	7bit
#					PPM file
0	string		P3		image/x-portable-pixmap	7bit
#					PBM "rawbits" file
0	string		P4		image/x-portable-bitmap
#					PGM "rawbits" file
0	string		P5		image/x-portable-greymap
#					PPM "rawbits" file
0	string		P6		image/x-portable-pixmap

# NIFF (Navy Interchange File Format, a modification of TIFF)
# [GRR:  this *must* go before TIFF]
0	string		IIN1		image/x-niff

# TIFF and friends
#					TIFF file, big-endian
0	string		MM		image/tiff
#					TIFF file, little-endian
0	string		II		image/tiff

# possible GIF replacements; none yet released!
# (Greg Roelofs, newt@uchicago.edu)
#
# GRR 950115:  this was mine ("Zip GIF"):
#					ZIF image (GIF+deflate alpha)
0	string		GIF94z		image/unknown
#
# GRR 950115:  this is Jeremy Wohl's Free Graphics Format (better):
#					FGF image (GIF+deflate beta)
0	string		FGF95a		image/unknown
#
# GRR 950115:  this is Thomas Boutell's Portable Bitmap Format proposal
# (best; not yet implemented):
#					PBF image (deflate compression)
0	string		PBF		image/unknown

# GIF
0	string		GIF		image/gif

# JPEG images
0	beshort		0xffd8		image/jpeg

# PC bitmaps (OS/2, Windoze BMP files)  (Greg Roelofs, newt@uchicago.edu)
0	string		BM		image/bmp
#>14	byte		12		(OS/2 1.x format)
#>14	byte		64		(OS/2 2.x format)
#>14	byte		40		(Windows 3.x format)
#0	string		IC		icon
#0	string		PI		pointer
#0	string		CI		color icon
#0	string		CP		color pointer
#0	string		BA		bitmap array

0	string		\\x89PNG		image/png
0	string		FWS		application/x-shockwave-flash
0	string		CWS		application/x-shockwave-flash

#------------------------------------------------------------------------------
# lisp:  file(1) magic for lisp programs
#
# various lisp types, from Daniel Quinlan (quinlan@yggdrasil.com)
0	string	;;			text/plain	8bit
# Emacs 18 - this is always correct, but not very magical.
0	string	\\012(			application/x-elc
# Emacs 19
0	string	;ELC\\023\\000\\000\\000	application/x-elc

#------------------------------------------------------------------------------
# mail.news:  file(1) magic for mail and news
#
# There are tests to ascmagic.c to cope with mail and news.
0	string		Relay-Version: 	message/rfc822	7bit
0	string		#!\\ rnews	message/rfc822	7bit
0	string		N#!\\ rnews	message/rfc822	7bit
0	string		Forward\\ to 	message/rfc822	7bit
0	string		Pipe\\ to 	message/rfc822	7bit
0	string		Return-Path:	message/rfc822	7bit
0	string		Path:		message/news	8bit
0	string		Xref:		message/news	8bit
0	string		From:		message/rfc822	7bit
0	string		Article 	message/news	8bit
#------------------------------------------------------------------------------
# msword: file(1) magic for MS Word files
#
# Contributor claims:
# Reversed-engineered MS Word magic numbers
#

0	string		\\376\\067\\0\\043			application/msword
0	string		\\333\\245-\\0\\0\\0			application/msword

# disable this one because it applies also to other
# Office/OLE documents for which msword is not correct. See PR#2608.
#0	string		\\320\\317\\021\\340\\241\\261	application/msword



#------------------------------------------------------------------------------
# printer:  file(1) magic for printer-formatted files
#

# PostScript
0	string		%!		application/postscript
0	string		\\004%!		application/postscript

# Acrobat
# (due to clamen@cs.cmu.edu)
0	string		%PDF-		application/pdf

#------------------------------------------------------------------------------
# sc:  file(1) magic for "sc" spreadsheet
#
38	string		Spreadsheet	application/x-sc

#------------------------------------------------------------------------------
# tex:  file(1) magic for TeX files
#
# XXX - needs byte-endian stuff (big-endian and little-endian DVI?)
#
# From <conklin@talisman.kaleida.com>

# Although we may know the offset of certain text fields in TeX DVI
# and font files, we can't use them reliably because they are not
# zero terminated. [but we do anyway, christos]
0	string		\\367\\002	application/x-dvi
#0	string		\\367\\203	TeX generic font data
#0	string		\\367\\131	TeX packed font data
#0	string		\\367\\312	TeX virtual font data
#0	string		This\\ is\\ TeX,	TeX transcript text	
#0	string		This\\ is\\ METAFONT,	METAFONT transcript text

# There is no way to detect TeX Font Metric (*.tfm) files without
# breaking them apart and reading the data.  The following patterns
# match most *.tfm files generated by METAFONT or afm2tfm.
#2	string		\\000\\021	TeX font metric data
#2	string		\\000\\022	TeX font metric data
#>34	string		>\\0		(%s)

# Texinfo and GNU Info, from Daniel Quinlan (quinlan@yggdrasil.com)
#0	string		\\\\input\\ texinfo	Texinfo source text
#0	string		This\\ is\\ Info\\ file	GNU Info text

# correct TeX magic for Linux (and maybe more)
# from Peter Tobias (tobias@server.et-inf.fho-emden.de)
#
0	leshort		0x02f7		application/x-dvi

# RTF - Rich Text Format
0	string		{\\\\rtf		application/rtf

#------------------------------------------------------------------------------
# animation:  file(1) magic for animation/movie formats
#
# animation formats, originally from vax@ccwf.cc.utexas.edu (VaX#n8)
#						MPEG file
0	string		\\000\\000\\001\\263	video/mpeg
#
# The contributor claims:
#   I couldn't find a real magic number for these, however, this
#   -appears- to work.  Note that it might catch other files, too,
#   so BE CAREFUL!
#
# Note that title and author appear in the two 20-byte chunks
# at decimal offsets 2 and 22, respectively, but they are XOR'ed with
# 255 (hex FF)! DL format SUCKS BIG ROCKS.
#
#						DL file version 1 , medium format (160x100, 4 images/screen)
0	byte		1			video/unknown
0	byte		2			video/unknown
# Quicktime video, from Linus Walleij <triad@df.lth.se>
# from Apple quicktime file format documentation.
4   string      moov        video/quicktime
4   string      mdat        video/quicktime

PASTECONFIGURATIONFILE
cat > /etc/httpd/conf.d/vhost.conf << PASTECONFIGURATIONFILE




<Macro VHost \${domain}>

<VirtualHost *:80 *:443>
ServerName \${domain}
ServerAlias \${domain}.

RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteCond %{REQUEST_URI} !\\.well-known/acme-challenge/.*
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [END,NE,R=permanent]


ErrorLog "logs/\${domain}-error_log"
#ForensicLog logs/\${domain}-forensic_log
LogLevel warn
<IfModule log_config_module>
	CustomLog "logs/\${domain}-access_log" paranoid
</IfModule>

SSLEngine on
SSLCertificateFile /etc/letsencrypt/live/\${domain}/cert.pem
SSLCertificateKeyFile /etc/letsencrypt/live/\${domain}/privkey.pem
SSLCertificateChainFile /etc/letsencrypt/live/\${domain}/chain.pem

SSLCompression off

# test stapling via:
# echo | openssl s_client -servername \${domain} -connect \${domain}:443 -tls1_2  -tlsextdebug  -status | grep "OCSP response: no response sent" && echo FAIL || echo OK
SSLUseStapling on
SSLStaplingResponderTimeout 2
SSLStaplingReturnResponderErrors off
SSLStaplingFakeTryLater off
SSLStaplingStandardCacheTimeout 86400

# test headers via:
# testssl \${domain}
# curl -v https://\${domain}
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" env=HTTPS
Header always set Expect-CT "enforce, max-age=30" env=HTTPS
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "upgrade-insecure-requests;"
Header always set X-XSS-Protection "1; mode=block"
Header always set Feature-Policy "geolocation 'none'; midi 'none'; notifications 'none'; push 'none'; sync-xhr 'none'; microphone 'none'; camera 'none'; magnetometer 'none'; gyroscope 'none'; speaker 'none'; vibrate 'none'; fullscreen 'self'; payment 'none';"
Header always set Permissions-Policy "geolocation=();midi=();notifications=();push=();sync-xhr=();microphone=();camera=();magnetometer=();gyroscope=();speaker=();vibrate=();fullscreen=(self);payment=();"
Header always set Referrer-Policy "no-referrer"
Header always unset "X-Powered-By"
Header unset "X-Powered-By"
Header always unset "Server"
Header unset "Server"

DocumentRoot "/var/www/html/\${domain}"

<Directory "/var/www/html/\${domain}">
	AllowOverride None
	Require all granted
</Directory>

<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>

<Files ".ht*">
	Require all denied
</Files>


<Files ~ "\\.(cgi|shtml|phtml|php3?)\$">
    SSLOptions +StdEnvVars
</Files>
<Directory "/var/www/cgi-bin">
    SSLOptions +StdEnvVars
</Directory>

BrowserMatch "MSIE [2-5]" \\
         nokeepalive ssl-unclean-shutdown \\
         downgrade-1.0 force-response-1.0

</VirtualHost>               

</Macro>









<Macro VHostHT \${domain}>

<VirtualHost *:80 *:443>
ServerName \${domain}
ServerAlias \${domain}.

RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteCond %{REQUEST_URI} !\\.well-known/acme-challenge/.*
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [END,NE,R=permanent]


ErrorLog "logs/\${domain}-error_log"
#ForensicLog logs/\${domain}-forensic_log
LogLevel warn
<IfModule log_config_module>
	CustomLog "logs/\${domain}-access_log" paranoid
</IfModule>

SSLEngine on
SSLCertificateFile /etc/letsencrypt/live/\${domain}/cert.pem
SSLCertificateKeyFile /etc/letsencrypt/live/\${domain}/privkey.pem
SSLCertificateChainFile /etc/letsencrypt/live/\${domain}/chain.pem

SSLCompression off

# test stapling via:
# echo | openssl s_client -servername \${domain} -connect \${domain}:443 -tls1_2  -tlsextdebug  -status | grep "OCSP response: no response sent" && echo FAIL || echo OK
SSLUseStapling on
SSLStaplingResponderTimeout 2
SSLStaplingReturnResponderErrors off
SSLStaplingFakeTryLater off
SSLStaplingStandardCacheTimeout 86400

# test headers via:
# testssl \${domain}
# curl -v https://\${domain}
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" env=HTTPS
Header always set Expect-CT "enforce, max-age=30" env=HTTPS
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
Header always set Content-Security-Policy "upgrade-insecure-requests;"
Header always set X-XSS-Protection "1; mode=block"
Header always set Feature-Policy "geolocation 'none'; midi 'none'; notifications 'none'; push 'none'; sync-xhr 'none'; microphone 'none'; camera 'none'; magnetometer 'none'; gyroscope 'none'; speaker 'none'; vibrate 'none'; fullscreen 'self'; payment 'none';"
Header always set Permissions-Policy "geolocation=();midi=();notifications=();push=();sync-xhr=();microphone=();camera=();magnetometer=();gyroscope=();speaker=();vibrate=();fullscreen=(self);payment=();"
Header always set Referrer-Policy no-referrer
Header always unset "X-Powered-By"
Header unset "X-Powered-By"
Header always unset "Server"
Header unset "Server"

DocumentRoot "/var/www/html/\${domain}"

<Directory "/var/www/html/\${domain}">
	AllowOverride Options=Indexes AuthConfig
	Require all granted
</Directory>

<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>

<Files ".ht*">
	Require all denied
</Files>


<Files ~ "\\.(cgi|shtml|phtml|php3?)\$">
    SSLOptions +StdEnvVars
</Files>
<Directory "/var/www/cgi-bin">
    SSLOptions +StdEnvVars
</Directory>

BrowserMatch "MSIE [2-5]" \\
         nokeepalive ssl-unclean-shutdown \\
         downgrade-1.0 force-response-1.0

</VirtualHost>               

</Macro>











<Macro noSSLVHost \${domain}>

<VirtualHost *:80>
ServerName \${domain}
ServerAlias \${domain}.

DocumentRoot "/var/www/html/\${domain}"

<Directory "/var/www/html/\${domain}">
	AllowOverride None
	Require all granted
</Directory>

<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>

<Files ".ht*">
	Require all denied
</Files>

</VirtualHost>

</Macro>
















<Macro redirVHost \${domain} \${rdomain}>

<VirtualHost *:80 *:443>
ServerName \${domain}
ServerAlias \${domain}.

RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteCond %{REQUEST_URI} !\\.well-known/acme-challenge/.*
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [END,NE,R=permanent]
RewriteCond %{REQUEST_URI} !\\.well-known/acme-challenge/.*
RewriteRule ^ https://\${rdomain}%{REQUEST_URI} [END,NE,R=permanent]

ErrorLog "logs/\${domain}-error_log"
#ForensicLog logs/\${domain}-forensic_log
LogLevel warn
<IfModule log_config_module>
	CustomLog "logs/\${domain}-access_log" paranoid
</IfModule>

SSLEngine on
SSLCertificateFile /etc/letsencrypt/live/\${domain}/cert.pem
SSLCertificateKeyFile /etc/letsencrypt/live/\${domain}/privkey.pem
SSLCertificateChainFile /etc/letsencrypt/live/\${domain}/chain.pem



# test stapling via:
# echo | openssl s_client -servername \${domain} -connect \${domain}:443 -tls1_2  -tlsextdebug  -status | grep "OCSP response: no response sent" && echo FAIL || echo OK
SSLUseStapling on
SSLStaplingResponderTimeout 2
SSLStaplingReturnResponderErrors off
SSLStaplingFakeTryLater off
SSLStaplingStandardCacheTimeout 86400

# test headers via:
# testssl \${domain}
# curl -v https://\${domain}
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" env=HTTPS
Header always set Expect-CT "enforce, max-age=30" env=HTTPS
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
Header always set Content-Security-Policy "upgrade-insecure-requests;"
Header always set X-XSS-Protection "1; mode=block"
Header always set Feature-Policy "geolocation 'none'; midi 'none'; notifications 'none'; push 'none'; sync-xhr 'none'; microphone 'none'; camera 'none'; magnetometer 'none'; gyroscope 'none'; speaker 'none'; vibrate 'none'; fullscreen 'self'; payment 'none';"
Header always set Permissions-Policy "geolocation=();midi=();notifications=();push=();sync-xhr=();microphone=();camera=();magnetometer=();gyroscope=();speaker=();vibrate=();fullscreen=(self);payment=();"
Header always set Referrer-Policy no-referrer
Header always unset "X-Powered-By"
Header unset "X-Powered-By"
Header always unset "Server"
Header unset "Server"




DocumentRoot "/var/www/html/\${domain}"

<Directory "/var/www/html/\${domain}">
	AllowOverride None
	Require all granted
</Directory>

<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>

<Files ".ht*">
	Require all denied
</Files>

</VirtualHost>               

</Macro>


# INSERT VHOSTS HERE

#Use noSSLVHost example.com


UndefMacro VHost
UndefMacro VHostHT
UndefMacro noSSLVHost
UndefMacro redirVHost



PASTECONFIGURATIONFILE
cat > /etc/httpd/conf.d/ssl.conf << PASTECONFIGURATIONFILE
Listen 443 https

SSLPassPhraseDialog exec:/usr/libexec/httpd-ssl-pass-dialog

SSLSessionCache         shmcb:/run/httpd/sslcache(512000)
SSLSessionCacheTimeout  300

SSLRandomSeed startup file:/dev/urandom  256
SSLRandomSeed connect builtin

SSLCryptoDevice builtin

# openssl ciphers -v 'ALL:!eNULL:!aNULL:!LOW:!MEDIUM:!DES:!3DES:!RC4:!MD5:!RSA:!SHA1:@STRENGTH'
SSLCipherSuite ALL:!eNULL:!aNULL:!LOW:!MEDIUM:!DES:!3DES:!RC4:!MD5:!RSA:!SHA1:@STRENGTH

# NOTE: if there is some concern switch to these (highest securirty)
#SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256

# NOTE: Recommended by ssllab.com ... but aren't that good
#SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256

SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder On
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" env=HTTPS
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
Header always set Content-Security-Policy "upgrade-insecure-requests;"
SSLCompression off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
# Requires Apache >= 2.4.11
#SSLSessionTickets Off


PASTECONFIGURATIONFILE
cat > /var/www/html/blank/index.html << PASTECONFIGURATIONFILE
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title></title><meta name="robots" content="noindex, nofollow, noarchive"><meta http-equiv="content-type" content="text/html; charset=us-ascii"></head><body></body></html>
PASTECONFIGURATIONFILE
cat > /var/www/html/blank/robots.txt << PASTECONFIGURATIONFILE
User-agent: *
Disallow: /
PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-letsencrypt_delete << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -eq 0 ]; then
	echo "Delete a Let's Encrypt certificate for a domain"
	echo
	echo "usage: \${0} <domain>"
	echo
	exit 1
fi
domain=\${1}
certbot delete --cert-name "\${domain}"
PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-letsencrypt_fix << PASTECONFIGURATIONFILE
#!/bin/bash
cd /etc/letsencrypt/live
ls | grep -v README | while read domain; do
rm -f \${domain}/cert.pem
ln -s ../\$(ls ../archive/\${domain}/cert*.pem | tail -n1) \${domain}/cert.pem
rm -f \${domain}/chain.pem
ln -s ../\$(ls ../archive/\${domain}/chain*.pem | tail -n1) \${domain}/chain.pem
rm -f \${domain}/fullchain.pem
ln -s ../\$(ls ../archive/\${domain}/fullchain*.pem | tail -n1) \${domain}/fullchain.pem
rm -f \${domain}/privkey.pem
ln -s ../\$(ls ../archive/\${domain}/privkey*.pem | tail -n1) \${domain}/privkey.pem
done
PASTECONFIGURATIONFILE
cat > /usr/local/sbin/el-letsencrypt_setup << PASTECONFIGURATIONFILE
#!/bin/bash
if [ \$# -eq 0 ]; then
	echo "Gets a Let's Encrypt certificate for a domain"
	echo
	echo "usage: \${0} <domain>"
	echo
	exit 1
fi
domain=\${1}
certbot certonly -n --webroot -w "/var/www/html/\${domain}" -d "\${domain}" --register-unsafely-without-email --rsa-key-size 4096 --agree-tos
PASTECONFIGURATIONFILE
# COPY CONFIGURATION FILES

# make el- scripts executable
chmod u+x /usr/local/sbin/el-*

mkdir -p /etc/httpd/ssl/
openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout /etc/httpd/ssl/snakeoil.key -out /etc/httpd/ssl/snakeoil.crt -subj "/C=XX/L= /O= "
mkdir -p /root/.config/letsencrypt/
echo "rsa-key-size = 4096" > /root/.config/letsencrypt/cli.ini
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
firewall-cmd --list-all # list rules [optional]
systemctl --no-pager start httpd
systemctl --no-pager enable httpd
systemctl --no-pager status httpd
##
## LETS ENCRYPT STUFF
##
mkdir -p /root/.config/letsencrypt/
echo "rsa-key-size = 4096" > /root/.config/letsencrypt/cli.ini
echo "$(expr $RANDOM \% 60) 0,12 * * * root perl -e 'sleep int(rand(3600))'; certbot renew --post-hook 'systemctl reload httpd'" > /etc/cron.d/certbot

