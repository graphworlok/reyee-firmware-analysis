# Easydisc merge RCE — dynamic, network-based confirmation

*Not for publication. Coordinated disclosure only. Recorded 2026-11-09.*

This records a dynamic confirmation of the Easydisc esw auto-merge command
injection (`firmware-audit.md` §3.14, `easydisc-protocol.md` §8) against
**unmodified vendor firmware**, with the trigger delivered **over the
network** rather than from inside the guest. It complements the static trace
(the sink is read, not inferred) and the earlier loopback confirmation on the
EG305GH-E aarch64 build.

## What was shown

On **ReyeeOS 2.248 (RG-EG105G-V2, little-endian o32 MIPS)**, a single crafted
UDP/43562 datagram arriving from a separate host causes the vendor discovery
daemon to run an attacker-chosen shell command as root. On **2.280** (the next
release of the same product, unified daemon) the identical delivery against a
healthy daemon produces no command execution. This is the 2.248→later
regression, reproduced dynamically on the matching architecture — the 2.248
`system()` merge sink was previously proven on MIPS by decompilation only.

## Method (sandbox framework)

Runs on the isolated `iot-detonation-sandbox` (host `.179`); no device, no
third-party traffic. The pieces added for this (all in `tools/`):

- **`mips-fpu-le` guest** — OpenWrt `malta/le` rebuilt with
  `CONFIG_MIPS_FP_SUPPORT=y` (second tree `openwrt-le`). The vendor binaries
  are hard-float o32; the stock `mipsel` kernel has no FPU support and they
  SIGILL at libc start-up (this is why the earlier 2.388 control never ran).
  `qemu-system-mipsel -M malta -cpu 24Kf` + the FP kernel runs them.
- **`tools/fwunpack.py`** — decrypts the v1 (`upgrade_crypt_v1` XOR) and v2
  (`upgrade_crypt_v2` OpenSSL) containers and extracts the rootfs squashfs.
- **`tools/easydisc_pkt.py`** — builds the esw/0x40 auto-merge datagram:
  16-byte `MD5(SALT‖body)` prefix, `msg_type=0x40`, the single-quote breakout
  command at `networkId` (+0x150), `l3` at `reserve1` (+0x171). Reproduces the
  known-good lab packet byte-for-byte. Benign command only.
- **`tools/easydisc_emu.sh`** — in-guest bootstrap: unpacks the vendor rootfs,
  provisions a minimal esw master config, brings up the SON interface
  `br-wan`, starts `ubusd` + the vendor daemon (wildcard bind on :43562),
  prints `READY_FOR_SEND`, idles, then dumps the daemon log and any artifact.
- **`sbx-run --inject`** (sandbox runner) — after the daemon is up, sends the
  packet to the guest's leased IP:43562 **from the sink namespace
  (10.200.0.1), over the bridge** — a genuine remote datagram.
- **`tools/run_easydisc_emu.sh`** — the one-line driver.

Two daemon-state gotchas, both provisioned by the bootstrap: the daemon stalls
(`set send device br-wan error`, `g_disc.imac get failed`) unless `br-wan`
exists with a MAC; the unified `easyson.elf` needs `option hardware_version`
in sysinfo or `cfg_load_sysinfo()` fails and it never binds.

## Results

| | positive | negative |
|---|---|---|
| firmware | EG105G-V2 **2.248**, `easydisc.elf` (split) | EG105G-V2 **2.280**, `easyson.elf` (unified) |
| rootfs sha256 | `db39591e…` | `10d048aa…` |
| run id | `20261109-093125-mips-fpu-le-cmd` | `20261109-095051-mips-fpu-le-cmd` |
| delivery | sink 10.200.0.1 → 10.200.0.196:43562, 4×400 B | sink 10.200.0.1 → 10.200.0.109:43562, 4×400 B |
| daemon state | master/ACP reached | master/ACP reached, periodic `master_event` |
| merge sink | **fired** | not fired |
| artifact | `/tmp/easydisc/P` = `pwn` | none |

Packet `pkt_eg105_file.bin` sha256 `d5df4c0f…` (identical to the EG305GH lab
packet; command `'; echo pwn>/tmp/easydisc/P #`). Kernel sha256 `19c19653…`.

Positive daemon log (×4, once per injected copy):

```
[esw] Exec auto merge cmd: dev_sta set -m esw_networkId_merge '{"password":"admin",
 "type":"noenc","force":"true","fromSn":[""],"fromNetworkId":"'; echo pwn>/tmp/easydisc/P #","toNetworkId":"0"}' -b 1
```

The injected `'` closes the single-quoted `fromNetworkId` value; `;` starts a
new command; `#` comments the template tail — run through `system()` as root.

## Bounds on the claim

- An OpenWrt kernel + QEMU malta, not the vendor kernel/SoC; userspace is the
  unmodified vendor rootfs.
- Config is hand-provisioned to a minimal esw master; a benign crafted packet,
  not geico's captured bytes.
- The negative shows **no execution** on 2.280; it was not dynamically
  attributed to validator-vs-`execvp` (static analysis already did — the
  unified builds carry `param_safety_check` and an `execvp`-style sink).
- Evidence (console logs, pcap, fsdiff, run.json) is on `.179` under
  `/srv/sandbox/runs/<run id>/`; the rootfs trees under `~/reyee-emu/fs/`.
