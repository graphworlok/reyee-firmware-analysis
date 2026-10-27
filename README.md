# ReyeeOS firmware analysis

Static analysis of Ruijie Reyee firmware: the **Easydisc / SON
EasyDiscovery** discovery protocol, and a platform security audit of the
services around it.

> **Handling: not for publication.**
>
> This repository exists to support **coordinated disclosure to Ruijie
> PSIRT**, and onward to a CNA or CISA ICS-CERT if they take it. It
> contains live credential material extracted from shipping firmware and
> an undisclosed remote code-execution chain against a current product.
>
> Nothing here is to be posted publicly, pasted into a public issue
> tracker, or shared outside that channel without an explicit decision.
> The repository is private and must stay private until disclosure is
> agreed and complete.

## Contents

| file | what it is |
|---|---|
| [`easydisc-protocol.md`](easydisc-protocol.md) | The protocol specification — framing, the salted-MD5 gate, the 460-byte header field map, the message-type table, the `0x61` command surface, and the input validator's per-field coverage. Written to be handed to a vendor or CERT. |
| [`firmware-audit.md`](firmware-audit.md) | The platform audit — shared broker keys and credentials, the MQTT bus ACL, the shell-exec surface, and **§3.12**, a remote root command-injection and unverified-firmware-install chain reachable over that bus. |

## Scope and provenance

Four vendor images, obtained from Ruijie:

| build | product | arch |
|---|---|---|
| ReyeeOS 2.430.0.1924 (`EG_3.0(1)B11P430`) | RG-EG1510XS | `aarch64_cortex-a53` |
| ReyeeOS 2.388 | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) |
| ReyeeOS 2.380 | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) |
| ReyeeOS 2.248.0.2216 (`EG_3.0(1)B11P248`) | RG-EG305GH-P-E | `aarch64_cortex-a53` |
| ReyeeOS 2.388 / 2.410 / 2.430 | RG-EG305GH-P-E | `aarch64_cortex-a53` |
| ReyeeOS 2.388 / 2.410 / 2.430 | RG-EG210G-P-V3 | `ramips_24kec` (MIPS32 LE) |

The fourth image (RG-EG305GH-E, 2.248) was audited 2026-10-27
(`firmware-audit.md` §3.14), followed the same day by six more — later
RG-EG305GH-E builds and a **third product line, RG-EG210G-P-V3** — folded
into the cross-build matrix in `firmware-audit.md` §3.15. Headline from
that pass: the shared root hash, broker private keys, ACL and cloud
credentials are **byte-identical across three product lines and current
(2.430) firmware**; and of every build examined, **2.248 is the only one
whose network-merge sink is `system()` with no input validator** — the
others run the merge through an `execvp`-style wrapper, which is the
control that actually blocks the in-the-wild payload. A seventh bundle,
an RG-WALL NGFW (different OS), is noted but out of scope.

Method is static throughout: unpacked rootfs inspection plus Ghidra on
`easyson.elf` and the support libraries. Findings are tagged `[proven]`
or `[inferred]` individually, and each document has a section stating
what is *not* claimed.

**What was deliberately not done**, and should stay not done without a
separate decision:

- No device was operated, and no exploit was built, run or tested.
- No credential was cracked. The root hash is identified by algorithm
  only; no plaintext appears in either document.
- No Ruijie endpoint was contacted — not the cloud API, not the MQTT
  broker, not the update service.

## What is not in this repository

- **No firmware images, rootfs trees or binaries.** `.gitignore` blocks
  them. They live outside version control on the analysis host; the
  documents reference them by path and hash.
- **No malware analysis.** The family observed exploiting this protocol
  in the wild is tracked separately in the `cve-2021-35394-ecosystem`
  repository. That repository is *research* material with a different
  audience; this one is *vendor disclosure* material. The split exists
  so this can be handed over without exposing unrelated work.

## Status

| step | state |
|---|---|
| Protocol specified | done |
| Platform audit | done |
| Prior-art / CVE check | done — see `firmware-audit.md` §3.15 |
| Vendor contact | **not yet initiated** |
| CNA / CVE | not yet |
| Public write-up | blocked pending the above |

Prior-art note: the **MQTT/cloud** findings here overlap the published
2024 Reyee cluster (Claroty "Open Sesame"; CISA ICSA-24-338-01;
CVE-2024-45722/-47791/-46874/-52324), whose disclosed affected range
(ReyeeOS 2.206–2.320) includes 2.248. The **Easydisc UDP
discovery-protocol merge RCE** (§3.14) has no matching CVE, advisory or
release-note entry and appears undisclosed — it is the item most
warranting a CVE.

Nothing has been sent to Ruijie yet. Contacting them is the next step
and is a deliberate decision, not a default.
