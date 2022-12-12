---
layout: single
title: Tentacle - Hack The Box
excerpt: ""
date: 2022-12-12
classes: wide
header:
  teaser: /assets/images/htb-writeup-tentacle/tentacle1.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:
  - 

---

![](/assets/images/htb-writeup-tentacle/tentacle1.png)

## Portscan
```bash
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 8d:dd:18:10:e5:7b:b0:da:a3:fa:14:37:a7:52:7a:9c (RSA)
|   256 f6:a9:2e:57:f8:18:b6:f4:ee:03:41:27:1e:1f:93:99 (ECDSA)
|_  256 04:74:dd:68:79:f4:22:78:d8:ce:dd:8b:3e:8c:76:3b (ED25519)
53/tcp   open  domain       ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
| dns-nsid:
|_  bind.version: 9.11.20-RedHat-9.11.20-5.el8
88/tcp   open  kerberos-sec MIT Kerberos (server time: 2022-12-12 12:09:50Z)
3128/tcp open  http-proxy   Squid http proxy 4.11
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.11
Service Info: Host: REALCORP.HTB; OS: Linux; CPE: cpe:/o:redhat:enterprise_linux:8
```

```bash
❯ dig @10.129.3.71 realcorp.htb

; <<>> DiG 9.16.33-Debian <<>> @10.129.3.71 realcorp.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27006
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: cb50954eeb322148ee7647ad6397204d8fc60b5fc5912b3e (good)
;; QUESTION SECTION:
;realcorp.htb.                  IN      A

;; AUTHORITY SECTION:
realcorp.htb.           86400   IN      SOA     realcorp.htb. root.realcorp.htb. 199609206 28800 7200 2419200 86400

;; Query time: 53 msec
;; SERVER: 10.129.3.71#53(10.129.3.71)
;; WHEN: Mon Dec 12 13:36:49 CET 2022
;; MSG SIZE  rcvd: 110
```

```bash
❯ dig @10.129.3.71 realcorp.htb ns

; <<>> DiG 9.16.33-Debian <<>> @10.129.3.71 realcorp.htb ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53159
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 6f51e431f038a1a427cac3f363972061952025222c91ae8c (good)
;; QUESTION SECTION:
;realcorp.htb.                  IN      NS

;; ANSWER SECTION:
realcorp.htb.           259200  IN      NS      ns.realcorp.htb.

;; ADDITIONAL SECTION:
ns.realcorp.htb.        259200  IN      A       10.197.243.77

;; Query time: 49 msec
;; SERVER: 10.129.3.71#53(10.129.3.71)
;; WHEN: Mon Dec 12 13:37:08 CET 2022
;; MSG SIZE  rcvd: 102
```

```bash
❯ dig @10.129.3.71 realcorp.htb mx 
❯ dig @10.129.3.71 realcorp.htb axfr 
```
I have to uncomment quiet_mode to only receive opened ports in __/etc/proxychains.conf__
```bash
#Quiet mode (no output from library)
quiet_mode
```

```bash
❯ proxychains nmap -sT -Pn -v -n 127.0.0.1
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
749/tcp  open  kerberos-adm
3128/tcp open  squid-http
```
```bash
❯ dnsenum --dnsserver 10.129.3.71 --threads 20 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt realcorp.htb
dnsenum VERSION:1.2.6

-----   realcorp.htb   -----


Host's addresses:
__________________



Name Servers:
______________

ns.realcorp.htb.                         259200   IN    A        10.197.243.77


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: ns.realcorp.htb at /usr/bin/dnsenum line 900 thread 1.

Trying Zone Transfer for realcorp.htb on ns.realcorp.htb ...
AXFR record query failed: no nameservers


Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:
______________________________________________________________________________________

ns.realcorp.htb.                         259200   IN    A        10.197.243.77
proxy.realcorp.htb.                      259200   IN    CNAME    ns.realcorp.htb.
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
wpad.realcorp.htb.                       259200   IN    A        10.197.243.31


realcorp.htb class C netranges:
________________________________



Performing reverse lookup on 0 ip addresses:
_____________________________________________


0 results out of 0 IP addresses.


realcorp.htb ip blocks:
________________________


done.

```

```bash
❯ echo -n 'ns.realcorp.htb.                         259200   IN    A        10.197.243.77
proxy.realcorp.htb.                      259200   IN    CNAME    ns.realcorp.htb.
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
wpad.realcorp.htb.                       259200   IN    A        10.197.243.31
' | awk '{print $5 " " $1}' | xclip -selection -clipboard
```

```bash
vim /etc/hosts
10.129.3.71 realcorp.htb srv01.realcorp.htb root.realcorp.htb
10.197.243.77 ns.realcorp.htb proxy.realcorp.htb
10.197.243.31 wpad.realcorp.htb
```
```bash
❯ proxychains nmap -sT -Pn -v -n 10.197.243.77
```
It seems that is not working. Maybe we can pivot through the localhost of the 10.129.3.71 to see if we are able to reach 10.197.243.77 configuring __/etc/proxychains.conf__
```bash
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4     127.0.0.1 9050
http 10.129.3.71 3128
http 10.197.243.77 3128
```






























