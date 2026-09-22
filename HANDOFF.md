# Handoff — ReyeeOS / Easydisc

Session-continuity doc. **Read this first** in a fresh session to pick
up this work without re-deriving it. Last updated 2026-09-20
(MIPS validator scope and message-type mapping resolved; several §4
method traps corrected — two of them were themselves wrong).

This repository is deliberately self-contained: a session can be
dedicated entirely to it without loading the malware research it was
split out of.

> **Handling: not for publication.** Coordinated disclosure to Ruijie
> PSIRT only. Live credential material and an undisclosed RCE chain
> are in `firmware-audit.md`. Keep this repo private.

## 1. Where everything is

**Firmware, on the Windows analysis host** — `C:\Users\orlock\reyee-firmware\`:

| path | contents |
|---|---|
| `binaries\` | `easyson.elf` (2.430 aarch64), `easyson_2380.elf`, `easyson_2388.elf` (MIPS32 LE), `enet_disp.elf`, `liblib_c.so`, `liblib_c_2380.so`, `liblib_c_2388.so`, `libeasyson_utils.so`, `sd_crypto`, `libsd_crypto.so`, `sd-upgrade-crypto` |
| `fw\` | the 2.430 image + `sysup\` |
| `fw2380\`, `fw2388\` | `decrypted.*` and `rootfs.squashfs` |

**Unpacked rootfs trees, on `telly`** (Linux host, `telly@192.168.242.153`):

```
/tmp/rootfs        2.430  (RG-EG1510XS, aarch64)
/tmp/rootfs2380    2.380  (RG-EG105GW(T), MIPS)
/tmp/rootfs2388    2.388  (RG-EG105GW(T), MIPS)
```

These are in `/tmp` and **will not survive a reboot of that host**. The
`.squashfs` files sit alongside them; re-unpack with `unsquashfs` if
they are gone. Decryption procedure is in `easydisc-protocol.md` §11.

**Ghidra** — project `Mirai`, programs already imported:

| program | state |
|---|---|
| `easyson.elf` | aarch64, 1,479 functions, base `0x400000`. **String xrefs resolve** — this is the build to work in. |
| `easyson_2380.elf`, `easyson_2388.elf` | MIPS32 LE, 769 functions each, 549 of them **named** from an intact `.dynsym`. Analysed, and `decompile_function` works. Ghidra instruction *search* is broken on them — see §4. |
| `liblib_c.so`, `libeasyson_utils.so`, `sd_crypto`, `libsd_crypto.so`, `sd-upgrade-crypto` | imported |

## 2. What is settled

Both documents in this repo are complete and internally cross-checked.
Do not re-derive these:

- **Protocol** (`easydisc-protocol.md`): framing, the salted-MD5 gate
  and its salt, the 460-byte header field map (cross-verified two
  ways), the 15-value message-type table, `0x61` as the command
  transport, and the validator's per-field coverage.
- **Platform** (`firmware-audit.md`): shared broker private keys and
  credentials identical across both product lines and all three
  versions, the ACL granting `#`, the shell-exec-vs-validation ratio,
  and **§3.12** — the remote root command-injection plus
  unverified-firmware-install chain over the MQTT upgrade topic.

### Function map (aarch64 `easyson.elf`, 2.430)

Recovered this far; a fresh session should start from these rather
than re-locating them.

| address | what it is |
|---|---|
| `FUN_00414968` | `son_esw_disc_recv` — UDP/43562 receiver (confirmed via `prctl(PR_SET_NAME)`) |
| `FUN_00413e98` | `son_eap_disc_recv` — UDP/43561 receiver |
| `FUN_00412d98` | **eap dispatcher**, `protocol/eap_disc.c` — the 15-value `msg_type` switch |
| `FUN_004151fc` | esw hello handler — the `reserve1 == "l3"` and auto-merge conditions |
| `FUN_004150bc` / `FUN_004111a8` | esw / eap per-message validator wrappers (called with *header+8*) |
| `FUN_0041504c` | per-field check → `param_safety_check`, logs `esw_disc.c:0xfa` |
| `FUN_004147fc` | auto-merge → `son_utils_safe_exec`, carries the embedded merge password |
| `FUN_004165f8` | `0x61` `DISC_MSG_TPYE_SH` — parses JSON `cmd`/`mid`/`sync`, `enet_event_push` |
| `FUN_0041198c` | eap `0x40` hello handler |
| `FUN_0042a2b4` | device-mode gate — true for mode ∈ {3,4,5,100} |
| `FUN_0043d4f8` | **MQTT subscribe loop** — walks the topic table, `mosquitto_subscribe` |
| `FUN_0042df3c` → `FUN_0042de30` | upgrade message shim → handler |
| `FUN_0042d934` | **upgrade JSON parser** — unvalidated `url`/`fileName`/`md5`/… |
| `FUN_0042d620` | **the injection** — `curl -L '%s%s' -o '%s'` → `system()` |
| `FUN_0042d890` → `FUN_0042d590` | upgrade thread → `/sbin/sysupgrade` |
| `FUN_0042d360` | upgrade status reporter (reads the globals, does not write them) |
| `FUN_0042d4f4` | `statfs("/tmp/")` free-space check — **not** a path builder |
| `FUN_00433ac0` | `networkId` set — the best-guarded path in the binary |
| `FUN_0041f22c` | writes `/etc/mosquitto/psk_file` and `pwfile` from embedded literals |
| `FUN_004204e0` | mosq thread setup — selects PSK path when port == `0x269b` (9883) |
| `FUN_0041f734` | TLS setup — ends in `mosquitto_tls_insecure_set(mosq, 1)` |
| `FUN_0041fa10` | `mosquitto_tls_psk_set` wrapper |
| `FUN_0040cee8`, `FUN_0040da20` | unguarded `system()` sinks fed from ubus |

### Data addresses

```
0x477cd0 / 0x477cd8   upgrade topic string / handler pointer (adjacent)
0x47a120  url        (0x400)     0x47a520  fileName (0x200)
0x47a920  md5        (0x40)      0x47a960  version  (0x20)
0x47a980  fileSize               0x47a988  delayTime
```

Thunks worth knowing, with xref counts:
`system` `0x004044c0` (57) · `son_utils_popen` `0x00404370` (21) ·
`son_utils_exec` `0x004043a0` (6) · `param_safety_check` `0x00404cd0`
(16) · `utils_param_safe_check` `0x00404b90` (2) · `sprintf`
`0x00404d50` (8) · `mosquitto_subscribe` `0x00404430` (3).

## 3. Open items, ranked

1. **Vendor contact has not been initiated.** Given §3.12 this is the
   decision that matters most. Nothing has been sent to Ruijie.
2. ~~**Version scope of `param_safety_check`.**~~ **CLOSED
   2026-09-20.** Both MIPS builds call it 11 times in 7 functions,
   **none on the eap or esw discovery path**; 2.430 calls it 16 times in
   12 functions including both disc dispatchers. So the check that
   blocks geico's packet on 2.430 does not exist on the esw hello path
   in either EG105GW build. Written up in `easydisc-protocol.md` §8 and
   `firmware-audit.md` §3.13. `gp = 0x4bb7a0` was correct; the
   `lw $t9,off($gp)` test was **not** — see §4.
3. **The MIPS PSK question.** 2.380/2.388 ship `psk_hint r#jsn#d` and
   listener 9883 but the 20-char PSK literal is not present in that
   form. They obtain the key some other way. Unresolved.
4. ~~**Name↔number mapping for the message types.**~~ **CLOSED
   2026-09-20.** All twelve handlers mapped, identically in 2.380 and
   2.388, by reading the dispatcher's local GOT slots
   `0x4b3984`–`0x4b39b0`. The three previously-anchored edges (`0x40`,
   `0x61`, `0x62`) agree, which validates the method. Table in
   `easydisc-protocol.md` §5. `0x61`/`0x62` are `sh_handle_sh` /
   `sh_handle_sh_rsp` in `protocol/protocol.c`, which is why there were
   only ten `eap_disc_handle_*` names for twelve handlers.
5. ~~**The 2.430 `*_disc_handle_*` string absence.**~~ **EXPLAINED
   2026-09-20.** The premise was wrong: those handler names are not
   `.rodata` strings in the MIPS builds, they are **`.dynsym` symbols**.
   The MIPS images ship a symbol table; the aarch64 image does not,
   which is why it shows `FUN_*` names. So this was a symbol-stripping
   difference, not a functional one, and nothing about handler presence
   follows from it either way. (The 2.430 build does independently
   retain nine other `_disc_` function-name strings via its
   `ERROR in %s [%d]` macros, as noted in the protocol doc §5.)
6. **`feature_check` / `upgrade_check_entrance.sh`** was read only in
   part; `/etc/sysupgrade.d/image_check` is a 0-byte file so the glob
   matches nothing, but the rest of that script is unread.
7. **Other daemons.** `api_service.elf`, `app_auth.elf`,
   `deep_inspection.elf`, `flow_audit.elf` all both listen and hold a
   shell primitive. None audited.

## 4. Method traps — read before touching the binaries

Every one of these produced a false negative during the original
analysis. They cost hours.

- **CORRECTED 2026-09-20 — the MIPS builds are NOT stripped.** Earlier
  notes said "stripped MIPS o32". Their *section headers* are stripped;
  `.dynsym` is intact: 587 entries, **549 named functions with
  addresses** (`eap_msg_handle`, `esw_disc_handle_hello_msg`, every
  `eap_disc_handle_*_msg`). Ghidra's 769 is the larger figure because it
  also recovers statics. Parse `PT_DYNAMIC`, not sections. This is what
  closed open items 2 and 4.
- **CORRECTED — `instructions_scanned: 0` is a Ghidra MCP bug, not
  missing disassembly.** Those programs *are* analysed
  (`analysis_status` → `analyzed: true`) and `decompile_function`
  returns correct C. Do **not** re-run analysis on account of that
  counter.
- **CORRECTED — do not use the `lw $t9,off($gp)` / `jalr $t9` test.**
  It was wrong and would have produced a confident false negative.
  These builds are unoptimised; the idiom is
  `lw v0,off(gp)` → `addu t9,v0,zero` → `jalr ra,t9`, i.e. the GOT slot
  lands in `$v0`. In `easyson_2380.elf`: **7,567 `jalr $t9` but only
  218 `lw $t9,off($gp)`** — the test misses ~97% of calls. Scan for
  `lw <any reg>, off($gp)` instead.
- **Always sanity-check a GOT scan against a predictable symbol.**
  `snprintf` → 385 sites in 75 functions, 13 in
  `esw_disc_handle_hello_msg`, which matches its decompilation exactly.
  A scan returning 0 for `snprintf` is broken — that is how the bad
  `$t9` test was caught. Working scanner:
  [`tools/mips-gotscan.py`](tools/mips-gotscan.py) (ELF parse via `PT_DYNAMIC`,
  `$gp = DT_PLTGOT + 0x7ff0`, external slots from
  `DT_PLTGOT + LOCAL_GOTNO*4`, slot *i* ↔ `dynsym[GOTSYM+(i-LOCAL_GOTNO)]`).
- **Local GOT slots (below `0x4b3d8c`) hold internal addresses.** That
  is how the §5 handler table was read: the dispatcher calls handlers
  through slots `0x4b3984`–`0x4b39b0`; read the pointer in each.
- **The `$gp`/GOT route is for *imported* symbols only.**
  `param_safety_check` lives in `liblib_c.so`, so it is reached via the
  GOT — correct. But local `.rodata` strings in the main executable use
  `lui`/`addiu` immediates and appear in **no** GOT slot; scanning for
  their pointer values returns nothing, which is not absence. To resolve
  a string reference, collect the rodata base pointers held in local GOT
  slots (e.g. `0x4a0000`) and add the `addiu` displacement.
- **Ghidra `get_function_callers` by *name* lies.** It reported "No
  callers found" for `system` against 57 real xrefs. Resolve the thunk
  address with `search_functions_enhanced`, then `get_xrefs_to` that.
- **Ghidra does not create `adrp+add` references** on the aarch64
  import. Decoding the pairs out of `.text` in ~30 lines of Python
  recovers them. String xrefs *do* work.
- **`$6$` in a double-quoted `ssh` argument** is eaten by the local
  shell as arithmetic and silently returns nothing — which looks
  exactly like a clean result. Escape it.
- **Over-precise `grep` patterns.** `grep -rl "^fn()"` missed every
  check function because they live in `/usr/lib/shell/upgrade_check.sh`
  with different spacing. Search loosely, then narrow.
- **Don't flag a `%s` template on shape alone.** `/sbin/sysupgrade -v
  %s` looks like an injection sink and is fed a hardcoded literal.

## 5. Constraints

These are standing and were honoured throughout. Do not relax them
without an explicit decision:

- **No device is operated.** No exploit has been built, run or tested.
- **No credential is cracked.** The root hash is identified by
  algorithm only.
- **No Ruijie endpoint is contacted** — not the cloud API, not the
  MQTT broker, not the update service.
- **No firmware images or binaries in git.** `.gitignore` blocks them.
- **Credential values live only in this repo**, never in
  `cve-2021-35394-ecosystem`. That repo describes mechanisms and
  withholds values; see its `analysis/README.md`.
- **Verify repo visibility before pushing anything sensitive**:
  `gh api repos/<name> --jq .private`. On 2026-09-20 the other repo was
  public while its own handoff doc claimed private.

## 6. Relationship to the other repo

`cve-2021-35394-ecosystem` (private) holds the malware research,
including `analysis/geico/README.md` — the family observed exploiting
UDP/43562 in the wild since 2026-08-13. That doc explains what the
attacker does; this repo explains what the product does. Cross-
references between them are by repository name, not relative path.

You do not need that repo loaded to work here.
