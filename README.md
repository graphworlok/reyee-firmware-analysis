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

Vendor images obtained from Ruijie, across five router product lines:

| build | product | arch |
|---|---|---|
| ReyeeOS 2.410 / 2.430.0 / 2.430.1 (`EG_3.0(1)B11P{410,430}`) | RG-EG1510XS (flagship) | `aarch64_cortex-a53` |
| ReyeeOS 2.388 | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) |
| ReyeeOS 2.380 | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) |
| ReyeeOS 2.248.0.2216 (`EG_3.0(1)B11P248`) | RG-EG305GH-P-E | `aarch64_cortex-a53` |
| ReyeeOS 2.388 / 2.410 / 2.430 | RG-EG305GH-P-E | `aarch64_cortex-a53` |
| ReyeeOS 2.388 / 2.410 / 2.430 | RG-EG210G-P-V3 | `ramips_24kec` (MIPS32 LE) |
| ReyeeOS 2.248.0.2212 (`EG_3.0(1)B11P248`) | RG-EG105G-V2 / -P-V2 (low-cost) | `ramips_24kec` (MIPS32 LE) |
| ReyeeOS 2.280 / 2.300 / 2.340 | RG-EG105G-V2 / -P-V2 | `ramips_24kec` (MIPS32 LE) |

The RG-EG305GH-E 2.248 image was audited 2026-10-27
(`firmware-audit.md` §3.14), with six more that day (later RG-EG305GH-E
builds and RG-EG210G-P-V3) and, on 2026-10-28, the full RG-EG1510XS
flagship stream and the low-cost RG-EG105G-V2 stream — all folded into the
cross-build matrix in `firmware-audit.md` §3.15. Headlines:

- the shared root hash, broker private keys, ACL and cloud credentials are
  **byte-identical across five product lines and the latest flagship
  firmware** (RG-EG1510XS 2.430.1, released ~two weeks before writing);
- the both-barriers-down `system()`-sink merge RCE is **not a single
  anomalous image** — it is the 2.248 split-daemon posture, reproduced on
  a second product line and a second architecture (**RG-EG105G-V2 2.248,
  MIPS**, where the `system()` sink is decompiled and proven); every
  unified-`easyson.elf` build (≥2.280 EG105G-V2, ≥2.388 EG305GH/EG210G,
  all EG1510XS/EG105GW) runs the merge through an `execvp`-style wrapper,
  which is the control that actually blocks the in-the-wild payload. The
  low-cost EG105G-V2 ≤2.248 is a practical hardware-verification target;
- the **flagship boots an unsigned kernel** (`firmware-audit.md` §3.16):
  the RG-EG1510XS kernel FIT is **hash-only** (crc32 + sha1, no signature
  node, no key), so U-boot enforces no kernel signature; its recovery
  fetch is **unauthenticated** (cloud recovery pulls both the firmware URL
  and its "expected" SHA-256 from `deviceapi.ruijienetworks.com` over
  plaintext HTTP; factory recovery is TFTP). Boot/update trust is transport
  + integrity hash, not image authenticity — at the U-boot layer. A
  BROM/efuse hardware secure-boot chain can't be ruled out from firmware,
  but it wouldn't help: the kernel stage is verified only by hash. A new
  `upgrade_crypt_boot!@2024` recovery container appears here too.

An RG-WALL NGFW bundle (different OS) is noted but out of scope.

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
