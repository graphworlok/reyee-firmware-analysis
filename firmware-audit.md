# ReyeeOS firmware audit — shared secrets and the SON message bus

**Handling: not for publication.** Coordinated disclosure to Ruijie PSIRT
only, per the same decision that governs
[`easydisc-protocol.md`](easydisc-protocol.md). This file
contains live credential material extracted from shipping firmware.
Nothing here is to be posted, pasted into a public tracker, or shared
outside that channel. §5 states plainly what is and is not a
vulnerability claim.

Companion to the Easydisc protocol spec. That document covers one
protocol and one in-the-wild exploit; this one is the answer to "what
*else* in this firmware should be defended against."

---

## 1. Scope, provenance and method

Four vendor images, obtained from Ruijie. No device was tested, no
traffic was sent to any Ruijie service, no credential was cracked or
used.

| build | product | arch | easydisc pkg |
|---|---|---|---|
| **ReyeeOS 2.430.0.1924 / 2.410 / 2.430.1.2128** (`EG_3.0(1)B11P{430,410}`, `mediatek/eg1510xs`) | RG-EG1510XS (flagship) | `aarch64_cortex-a53` | merged `easyson.elf` |
| **ReyeeOS 2.388** | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) | 4.0-0 |
| **ReyeeOS 2.380** | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) | 4.0-0 |
| **ReyeeOS 2.248.0.2216** (`EG_3.0(1)B11P248`, `mediatek/eg305gh-e`) | RG-EG305GH-P-E | `aarch64_cortex-a53` | split `mqtt.elf` + `easydisc.elf` |
| **ReyeeOS 2.388 / 2.410 / 2.430** (`EG_3.0(1)B11P{388,410,430}`, `mediatek/eg305gh-e`) | RG-EG305GH-P-E | `aarch64_cortex-a53` | merged `easyson.elf` |
| **ReyeeOS 2.388 / 2.410 / 2.430** (`EG_3.0(1)B11P{388,410,430}`, `ramips/generic`) | RG-EG210G-P-V3 | `ramips_24kec` (MIPS32 LE) | merged `easyson.elf` |
| **ReyeeOS 2.248.0.2212** (`EG_3.0(1)B11P248`) | RG-EG105G-V2 / -P-V2 (low-cost) | `ramips_24kec` (MIPS32 LE) | split `mqtt.elf` + `easydisc.elf` |
| **ReyeeOS 2.280 / 2.300 / 2.340** (`EG_3.0(1)B11P{280,300,340}`) | RG-EG105G-V2 / -P-V2 | `ramips_24kec` (MIPS32 LE) | merged `easyson.elf` |

The fourth image (2.248 EG305GH) was added 2026-10-27 and is written up
in §3.14; six further images (RG-EG305GH-E and a third product line,
**RG-EG210G-P-V3**, each at 2.388 / 2.410 / 2.430) were added the same day
and drive the cross-build matrix in **§3.15**. On 2026-10-28 the full
**RG-EG1510XS** flagship stream (2.410, latest 2.430.1, and a 2.430.0
recovery image) and the low-cost **RG-EG105G-V2** stream (2.248 / 2.280 /
2.300 / 2.340) were added: the EG105G-V2 2.248 reproduces the 2.248 merge
RCE on a second product line and a second architecture (§3.15), and the
EG1510XS recovery image introduced a new boot-recovery container tracked
as an open lead in **§3.16**. The three original images drive §3.1–§3.13
unless noted. A further bundle, an **RG-WALL 1600-Z-S** NGFW
(`NGFW_NTOS 1.0R6P1`), is a different OS — not ReyeeOS/OpenWrt, no SON
stack in the Reyee layout — and is out of scope for this document; it was
decrypted to an `INSTALL!` image and not further analysed here.

Method: static analysis of the unpacked rootfs and of `easyson.elf`
(aarch64, 2.430) — and, for the 2.248 split-daemon builds, of `mqtt.elf`
and `easydisc.elf` — in Ghidra, plus config and key-material inspection
across all trees. Vendor source filenames and line numbers quoted
below are the vendor's own, recovered from `dbg_printf` arguments
(`core/mosq_thd.c`, `interface/ubus.c`, `enet_network/enet_network.c`).

Findings are marked **[proven]** where read directly out of the binary
or the shipped file, and **[inferred]** where a step is reasoned rather
than observed.

## 2. Threat model

This matters, because it bounds almost everything below.

The default firewall is **`wan` zone `input REJECT`**, with accept rules
only for DHCP (udp/68), DHCPv6 (udp/546), ICMP and ICMPv6. `lan` is
`input ACCEPT`. So none of the services discussed here are reachable
from the internet on a default-configured EG1510XS. **[proven]**

The realistic attacker is therefore:

- a device or host already on the LAN, or
- a device already inside the SON (self-organising network) mesh, or
- someone who has extracted one firmware image — which, as §3.1–3.3
  show, is sufficient to attack *other people's* devices once they have
  any network position at all.

That last case is the reason the shared-secret findings dominate this
document. The secrets are not per-device, so compromising one device —
or simply downloading the firmware — yields the keys for every device.

Note this also partly explains geico's behaviour: it sprays UDP/43562
across the internet, where a default EG1510XS would drop it at the
firewall before `easyson.elf` ever sees it. Its viable targets are
models or deployments whose WAN filtering differs, or LAN-side
positions. **[inferred]**

## 3. Findings

Ordered by what a defender should care about first.

### 3.1 The MQTT broker's private key ships in the firmware — and is the same key on every device

`/etc/mosquitto/mosquitto_ssl.conf` runs **three listeners**, with no
`bind_address`, i.e. all interfaces: **[proven]**

```
listener 1883    tipc_server 18889   cafile/certfile/keyfile  /etc/easyson/ca/2048/
listener 8883    tipc_server 19889   cafile/certfile/keyfile  /etc/easyson/ca/1024/
listener 9883    tipc_server 19989   psk_hint r#jsn#d  psk_file /etc/mosquitto/psk_file
allow_anonymous false
password_file /etc/mosquitto/pwfile
acl_file      /etc/mosquitto/aclfile
```

The TLS material for 1883 and 8883 is **shipped in the image**,
including the private keys: **[proven]**

| file | bytes | md5 |
|---|---|---|
| `etc/easyson/ca/2048/ca.crt` | 1155 | `880bbe79a0b1c0bc0be4778802e0adc9` |
| `etc/easyson/ca/2048/server.crt` | 1159 | `8d8bfcdf3e575229c024cea9cdc2ef3e` |
| `etc/easyson/ca/2048/server.key` | 1679 | `5b60f5bf0e96d919ab13d11d29a1b966` |
| `etc/easyson/ca/1024/ca.crt` | 802 | `17e4f38cd90a767158ab7c8f1df7f8e3` |
| `etc/easyson/ca/1024/server.key` | 887 | `e9124cc8a721b036effcdeb7df38b018` |

Both `server.key` files are real `-----BEGIN RSA PRIVATE KEY-----`
files, 2048-bit and **1024-bit** respectively.

**Every md5 above is identical in 2.380, 2.388 and 2.430** — two
different product lines, two CPU architectures, three firmware
versions. The MIPS build's `server.crt` even carries the same
`notAfter` to the second (`Oct 1 13:06:19 2123 GMT`), so it is the same
certificate object, generated once and shipped to everything. **[proven]**

The certificates are **unmodified OpenSSL demo defaults**:

```
CA      subject= C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=admin
server  subject= C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=0.0.0.0
        notAfter (2048) = Oct  1 13:05:46 2123 GMT
        notAfter (1024) = Sep  3 09:26:35 2124 GMT
```

`C=AU / Some-State / Internet Widgits Pty Ltd` is the literal
`openssl req` default that appears when a developer presses Enter
through the prompts. The server CN is `0.0.0.0`. Validity is ~100 years.

**Consequence.** Anyone holding any Reyee firmware image holds the
broker's private key. They can stand up a broker that every Reyee device
will accept, and — because the PSK listener uses non-PFS suites (§3.2) —
decrypt recorded 9883 traffic. TLS on this bus provides encryption but
authenticates nobody.

### 3.2 …which is why hostname verification is switched off in the client

`easyson.elf`'s MQTT client thread, `core/mosq_thd.c`: **[proven]**

```c
mosquitto_tls_set(mosq, cafile, 0,0,0,0);
mosquitto_tls_opts_set(mosq, 1, "tlsv1.2", "ECDHE-RSA-AES256-GCM-SHA384:...");
mosquitto_tls_insecure_set(mosq, 1);          // core/mosq_thd.c:0x139
```

`mosquitto_tls_insecure_set(…, true)` **disables hostname
verification**. The cipher list and TLS-1.2 pinning above it are
otherwise sensible, which makes the last line look like an oversight —
but it is better read as a **necessary workaround**: a certificate whose
CN is `0.0.0.0` can never match a real peer name, so verification had to
be disabled for the shipped cert to work at all. **[inferred, but the
cert CN makes it the natural reading]**

The two halves compound. A shared private key means an impersonator can
present a *valid* cert; disabled hostname checking means they need not
even match the name.

### 3.3 Hardcoded PSK and broker accounts, shared across the product line

`FUN_0041f22c` writes credential files at runtime from literals baked
into the binary, then restarts the broker: **[proven]**

```c
snprintf(buf, 0x100, "%s:%s", "r#jsn#d", "1108adCf54acDf46EF19");
utlis_write_to_file("/etc/mosquitto/psk_file", buf, len);
...
memcpy(buf, "ruijie:$6$KbWNWt7D6ZzjZrUI$8NG/vhd1vhZuLEoe3Lg9MbMx8Ofj3jGr8Qx"
            "N+Jc0jf2jCpfRXacSaQPrMWdp6Y0na4Z5oPk5GQTtoyv/AH2kxA==", 0x74);   // mode 1 "ssl"
utlis_write_to_file("/etc/mosquitto/pwfile", buf, len);
system("/usr/bin/modify_mosq_conf.sh ssl");
...
system("/etc/init.d/mosquitto restart &");
```

Mode 2 (`son_close`) writes a second, different hash
`ruijie:$6$MGnq0TCSH3ZsVjo2$Qr+00E9xOBNr3/MON4q1Z/7OE/+/ADNC/p5wowAWjNmcYiUANdy2NxRjBoAbtyU7OcJQZ+P+VvD4WTdBDsSUAg==`.
Neither `psk_file` nor `pwfile` ships in the image; both are created on
first boot from these literals. **[proven]**

The client side confirms the pairing — `FUN_004204e0` selects the PSK
path when the port global equals `0x269b` (**9883**, the PSK listener)
and calls **[proven]**

```c
FUN_0041fa10(mosq, "1108adCf54acDf46EF19", "r#jsn#d");
  -> mosquitto_tls_psk_set(mosq, psk, identity, "PSK-AES256-CBC-SHA")
     or                                        "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384"
```

`PSK-AES256-CBC-SHA` has **no forward secrecy**, so possession of the
shared PSK permits decryption of captured sessions, not merely
connection.

Cross-build: the identity `r#jsn#d` and **both** `ruijie:$6$…` hashes
(same salts) are present in 2.380, 2.388 and 2.430 — so the broker
account credentials are shared across product lines *and* versions.
**[proven]**

The 20-character PSK literal `1108adCf54acDf46EF19` was found only in
2.430. The same scan over the MIPS binaries returned no 20-character
alphanumeric literal other than `periodInformInterval`, yet those builds
ship the same `psk_hint r#jsn#d` and the same 9883 listener — so they
obtain the key by some other means. **Unresolved; not asserted either
way.**

### 3.4 The broker ACL grants every authenticated user every topic

`/etc/mosquitto/aclfile`, in full: **[proven]**

```
user ruijie
topic #

user son
topic #
```

There is no topic scoping whatsoever. `allow_anonymous false` is set, so
authentication is required — but authentication uses the shared
credentials of §3.3. Combined, **any party holding the firmware can
authenticate to the SON bus of any device and read or publish every
topic on it**, which is the control plane for network membership,
`networkId` merges, device configuration and status.

This is the single most consequential finding in this document.

### 3.5 One root password hash for the entire product line, with root SSH enabled

`/etc/shadow` ships **[proven]**

```
root:$1$zOItWvpX$tKgP2GnQDoUZn16hVplYv1
```

byte-identical in all three images. `$1$` is **MD5-crypt** — long
obsolete and weak against modern cracking. Alongside it,
`/etc/config/dropbear`:

```
option PasswordAuth     'on'
option RootPasswordAuth 'on'
option Port             '54133'
```

Root password authentication is enabled by default; the non-standard
port 54133 is obscurity, not a control. A `telnetd` init script is also
present, gated on root having a password set — which it does.

**I did not attempt to crack this hash and no plaintext appears in this
document.** The findings are that it is MD5-crypt, that it is identical
across products and versions, and that password-based root login is
enabled by default.

### 3.6 Cloud API credentials in cleartext config, identical everywhere

`/etc/config/mqlink_reg` **[proven]** — identical in all three images:

```
option authurl    'https://deviceapi.ruijienetworks.com/service/api/device_maint/device/account_info'
option embdurl    'https://deviceapi.ruijienetworks.com/service/api/device_maint/ehr/embed'
option appid      'ea752413f7bbf397'
option secret     '5ef64dadaf17deffc06db9a170ccf50d'
option nonce      'b8683ed5fd7a4ff0'
option unbind_key 'e78wo7gljccpn1u6'
option unbind_url 'https://deviceapi.ruijienetworks.com/service/api/device_maint/network/unbind'
```

An `appid`/`secret` pair for the vendor's device-management API, plus a
separate `unbind_key` for an endpoint whose name suggests it detaches a
device from its owner's cloud account. Shipped in firmware means shared
by every device. The scope and privilege of these credentials cannot be
determined from the image and is the vendor's to assess — **I did not
contact any Ruijie endpoint.**

By contrast `/etc/config/mqlink` does the cloud channel properly:
`tls '1'` with a pinned CA at `/etc/mqlink/ca/ruijienetworks.com.pem`,
to `ryrcmq.ruijienetworks.com:25857`. The weakness in §3.1–3.2 is
specific to the **local/mesh** broker, not the cloud link.

### 3.7 The auto-merge credential is an active default, not a fallback

`easydisc-protocol.md` §9 records an embedded `U2FsdGVkX18…` password in
the merge path. `FUN_00433ac0` (`enet_network/enet_network.c`) shows how
it is reached: **[proven]**

```c
if (utils_read_file("/etc/sd_config/admin", buf, 0x100) != 0) {
    // read failed -> fall back to the embedded literal
    buf = "U2FsdGVkX18yODMzMjM5Offgi6OTL+KYXY1eByqCJnI=";
}
...
snprintf(cmd, 0x400, "dev_sta set -m esw_networkId_merge '{\"password\":\"%s\",...}' &", buf, ...);
system(cmd);
```

**`/etc/sd_config/admin` is not present in the image.** Until something
creates it at runtime, the hardcoded literal is what gets used — so this
is the operative credential on a fresh device, not a defensive fallback.
2.380/2.388 use a different literal
(`U2FsdGVkX18POF0/cM8IwywAcZUK8zQngpUv7C2zKng=`), so unlike §3.1/§3.5
this one *does* vary by product line. **[proven]**

Worth noting in the vendor's favour: this function is the **best-guarded
path examined in this firmware**. It calls `param_safety_check` before
anything else and then enforces real length limits — `networkId` ≤ 0x20,
`networkName` ≤ 0x40 and no `"`, `groupId` ≤ 0x10, `groupName` ≤ 0x40,
`parentGroupId` ≤ 0x10. If the esw hello path had this shape, geico's
packet would be uninteresting on structural grounds rather than by a
single character check.

### 3.8 Shell-exec surface greatly exceeds validation coverage

Thunk cross-reference counts in `easyson.elf` (2.430): **[proven]**

| primitive | address | xrefs | shell? |
|---|---|---|---|
| `system` | `0x004044c0` | **57** | yes |
| `son_utils_popen` | `0x00404370` | **21** | yes |
| `son_utils_exec` | `0x004043a0` | 6 | no (argv) |
| `son_utils_safe_exec` / `_safe_popen` | — | — | no (argv, `execvp`) |
| `param_safety_check` | `0x00404cd0` | 16 (across 12 functions) | — |
| `utils_param_safe_check` | `0x00404b90` | 2 | — |
| `sprintf` (unbounded) | `0x00404d50` | 8 | — |

Roughly **78 shell-capable call sites against 18 validation call
sites**, and two of the validation sites are the dispatchers' own
wrappers. The `execvp`-style safe variants exist and are used — the
problem is that `system()` is used four times as often.

This is the structural finding: geico's blocked path is one *guarded*
sink among many mostly unguarded ones. Defending the Easydisc hello
handler does not defend the daemon.

### 3.9 Two different validators, neither preventing path traversal

The two validators are **different implementations, not wrappers**:
**[proven]**

| | `param_safety_check` (`liblib_c.so`) | `utils_param_safe_check` (`libeasyson_utils.so`) |
|---|---|---|
| rejects | `&` `\|` `;` `$` `<` `>` `'` `` ` `` CR LF | `&` `\|` `;` `$` `>` `'` `` ` `` CR LF **`.`** **`/`** |
| misses | **`.`** **`/`** `\` whitespace `*` `?` `~` `(` `)` `"` | `<` `\` whitespace `*` `?` `~` `(` `)` `"` |
| xrefs (2.430 aarch64) | 16 | 2 |
| xrefs (2.380 / 2.388 MIPS) | 11 | 2 |

The widely used one is **shell-metacharacter-only and does not prevent
path traversal**: a field that clears `param_safety_check` may still
contain `../../`. That matters wherever a validated field reaches a file
path.

> **Resolved, 2026-09-20.** This section previously named
> `curl -L '%s%s' -o '%s'` as the place to check for that traversal.
> **It is not traversable** — the `-o` argument is a hardcoded
> `"/tmp/image.tar.gz"` literal (§3.11). The hypothesis is withdrawn.
> Chasing it did, however, surface the two *other* `%s` in that same
> template, which are unvalidated attacker-supplied JSON interpolated
> into `system()` inside single quotes. See **§3.12**, which is a
> considerably more serious finding than the one being looked for.

Neither validator rejects a backslash or whitespace.

### 3.10 Unguarded `system()` sinks fed from ubus

Two concrete examples, neither preceded by a validator call: **[proven]**

```c
// interface/ubus.c:0x192  — FUN_0040cee8
blobmsg_parse(...);                                  // from a ubus network.interface event
snprintf(buf, 0x80, "sdtipc-config -be=sdeth:%s", iface);
system(buf);

// interface/ubus.c:0x246  — FUN_0040da20
snprintf(buf, 0x100, "ubus -t 3 send %s '{\"networkId\":\"%s\"}' &", "networkid_event", arg);
system(buf);
```

These require the ability to publish ubus events (or to influence the
values that reach them), so they are a local/lateral concern rather than
a remote one. They are included because they show the prevailing
pattern: format a string from structured input, hand it to `system()`,
no validation on the path.

### 3.11 Checked and clear

Recorded so the next reader does not re-chase them:

- **`/sbin/sysupgrade -v %s 2>/dev/null`** (`FUN_0042d590`) looks like a
  remote-flash injection sink in a strings dump. It is not: the `%s` is
  a hardcoded `"/tmp/image.tar.gz"` literal. No attacker input reaches
  it. **[proven]**
- **The `curl … -o '%s'` path-traversal hypothesis from §3.9 is dead.**
  The `-o` argument is the same hardcoded `"/tmp/image.tar.gz"`
  literal, not a concatenation. **[proven]** The *other* two `%s` in
  that template are a different and much worse problem — see §3.12.
- The bare `/tmp/` literal near the upgrade code is not a path being
  built: `FUN_0042d4f4` is a `statfs("/tmp/")` free-space check.
  **[proven]**
- The **cloud** MQTT link (`mqlink`) pins a CA and enables TLS properly;
  the TLS weaknesses in §3.1–3.2 do not apply to it. **[proven]**

### 3.12 Root command injection and unverified firmware install, over the MQTT upgrade topic

**This is the most serious finding in this document.** It is a complete
chain from "holds a firmware image" to "runs code as root on someone
else's device", and every link is read out of the binary or the shipped
scripts rather than inferred.

**Step 1 — the device subscribes to an upgrade topic.** `FUN_0043d4f8`
walks the handler registration lists and, for each entry passing a
device-role check, formats the topic template and calls
`mosquitto_subscribe(mosq, 0, topic, qos)`. The subscription table pairs
the topic string with its handler at adjacent addresses: **[proven]**

```
0x477cd0 -> "sys/001/AP/+/%s/upgrade"      (topic)
0x477cd8 -> FUN_0042df3c                   (handler)
```

The `%s` is the device serial — the same pointer passed to
`mosquitto_new` as the client ID. `+` is an MQTT **subscription**
wildcard (illegal in a publish), which is independent confirmation that
this is an inbound path. `FUN_0042df3c` forwards to `FUN_0042de30`,
which refuses concurrent upgrades, parses the message, and spawns
`FUN_0042d890`.

**Step 2 — the JSON is parsed with no validation whatsoever.**
`FUN_0042d934` (`enet_upgrade/upgrade.c`) reads a `msg` object and
copies each field straight into globals: **[proven]**

```c
url      -> snprintf(&DAT_0047a120, 0x400, "%s", ...)   // 1024 B
fileName -> snprintf(&DAT_0047a520, 0x200, "%s", ...)   //  512 B
md5      -> snprintf(&DAT_0047a920, 0x40,  "%s", ...)
version  -> snprintf(&DAT_0047a960, 0x20,  "%s", ...)
fileSize, delayTime -> ints
```

No `param_safety_check`, no `utils_param_safe_check`, no URL scheme
check, no character filtering. The `snprintf`s are length-bounded, so
there is **no memory corruption** — the defect is injection, not
overflow. `FUN_0042d360` only *reads* these globals (it echoes them into
a status message), so the JSON is their sole writer.

**Step 3 — two of those fields land inside single quotes in `system()`.**
`FUN_0042d620`: **[proven]**

```c
snprintf(buf, 0x800, "curl -L '%s%s' -o '%s' >/dev/null",
         url, fileName, "/tmp/image.tar.gz");
system(buf);
```

A single `'` anywhere in `url` or `fileName` closes the quote and the
remainder is shell. `easyson.elf` is started by procd with no user
directive, so this executes as **root**. **[proven, except the root
claim, which is [inferred] from the init script]**

**Step 4 — and if you do not want injection, take the firmware instead.**
`FUN_0042d890` runs `FUN_0042d620()` (download) then `FUN_0042d590()`
(`/sbin/sysupgrade /tmp/image.tar.gz`). The integrity checks on that
path are **entirely self-referential**: **[proven]**

- `platform_check_image` checks **magic bytes only** (`ustar` at offset
  257, gzip `1f8b`, or `d00dfeed`), then delegates to
  `default_check_pkg`.
- `pkg_check` validates `*.product.ini` and `*.support_pids` **extracted
  from the supplied image** — model gating the attacker also supplies.
- `checksum_according_hash_file` → `checksum_according_hash_type` does
  `get_file_from_image "$image" *.sha256` (or `*.md5`) — it takes the
  **hash file out of the attacker's own archive** and checks the archive
  against it.
- `feature_check` runs `/etc/sysupgrade.d/image_check/*`, but that path
  is a **0-byte regular file**, not a directory, so the glob matches
  nothing.
- **`usign` and `fwtool` are never invoked** anywhere on this path,
  though both ship on the device. `/etc/opkg/keys/` holds opkg *package*
  signing keys, which do not gate sysupgrade.
- `size_check`'s `sd_crypto dec -t e` is the firmware payload
  encryption, whose key is already public
  (`BR0khBR0khsHi4MkNGrJ421Yf&j8ceh6`). A shared, known key is not a
  signature.

So nothing on the flash path authenticates the image. The `md5` field
the operator supplies in the JSON is **never compared against the
download** either — its only references are the parser's write, a log
line, and the status echo in `FUN_0042d360`.

**Why this compounds with §3.1–3.4.** Reaching the topic requires
authenticating to the SON broker. Those credentials **ship in the
firmware** and are identical across product lines and versions, and the
ACL grants `#`. So the practical precondition is *possession of any
Reyee firmware image plus network reach to the broker* — not
compromise of a device.

**Severity, stated carefully.** This is **not** internet-facing on a
default EG1510XS: the WAN zone is `input REJECT` (§2), so an attacker
needs LAN or mesh position. Within that position it is unauthenticated
in the meaningful sense — the attacker supplies credentials anyone can
extract. It has **not** been executed or tested against a device; the
chain is established statically.

### 3.13 Validation coverage differs between shipping builds

*(Established 2026-09-20.)* §3.8 measured the shell-exec-versus-validation
ratio on 2.430. Repeating that measurement on the MIPS builds shows the
validation side is not even constant across the product range.
**[proven]**

| build | product | `param_safety_check` sites | on the eap/esw discovery path? |
|---|---|---|---|
| 2.430 aarch64 | RG-EG1510XS | 16, in 12 functions | **yes** (both disc dispatchers) |
| 2.380 MIPS | RG-EG105GW(T) | 11, in 7 functions | **no** |
| 2.388 MIPS | RG-EG105GW(T) | 11, in 7 functions | **no** |

`liblib_c.so` is byte-identical between 2.380 and 2.388 and exports the
validator in both, so this is not a library difference — it is a
difference in what `easyson.elf` chooses to call. The full derivation,
the per-function breakdown and the method (including the two false-
negative traps that make a naive scan report the opposite) are in
[`easydisc-protocol.md`](easydisc-protocol.md) §8 and §11.

The defensive consequence is the one in §3.8, sharpened: the guarded
sink is not merely outnumbered by unguarded ones, **the guard itself is
present on the discovery path in one shipping product line and absent in
the other.** An operator cannot assume a control observed in one Reyee
model exists in the next.

Version, architecture and product line vary together across these three
images, so this does **not** establish "removed in older firmware" or "a
MIPS-specific defect". It establishes divergence, and that is the
question for the vendor.

**A lead, explicitly not a finding.** While mapping the merge paths in
2.380, a static function at `0x0045ace4` (immediately after
`network_merge_uf_handle`, in `enet_network/network_merge.c`) was seen to
build the esw auto-merge command with the password **baked into the
format string as a literal** rather than via `%s`:

```
dev_sta set -m esw_networkId_merge '{"password":"U2FsdGVkX18POF0/...","type":"enc",
  "fromSn":[],"fromNetworkId":"0","toNetworkId":"%s","toNetworkName":"%s",
  "toParentId":"%s"}' &
```

It parses JSON, interpolates three `%s` inside single quotes, and calls
**`system()`** — and it does not call either validator. The 2.430 build
reaches the equivalent template through `son_utils_safe_exec` (argv,
`execvp`) in the path documented at `easydisc-protocol.md` §9. **Whether
any attacker-influenced field reaches `0x0045ace4`, and by what route,
was not traced and is not claimed.** It is recorded so the next reader
starts here rather than rediscovering it.

### 3.14 A fourth build (2.248, RG-EG305GH-E) carries the same chain, with the merge password in cleartext and the broker left open

*(Added 2026-10-27.)* A fourth vendor image was obtained and audited:
**ReyeeOS 2.248.0.2216** (`EG_3.0(1)B11P248`, `mediatek/eg305gh-e`),
product **RG-EG305GH-P-E**, `aarch64_cortex-a53`, built 2023-10-10. It
is a *different* product from the three in §1 and a **lower** version
number than any of them, which widens the "same across the product line
and versions" claim rather than narrowing it. Decryption was the public
`upgrade_crypt`/`FW_KEY` procedure (`easydisc-protocol.md` §11); the
rootfs is a single squashfs. On this build the SON daemon is **split**
into `/usr/sbin/mqtt.elf` (the MQTT client and upgrade/shell handlers)
and `/usr/sbin/easydisc.elf` (the UDP discovery protocol), where 2.430
had one `easyson.elf`. Vendor source filenames below are again the
vendor's own, from `dbg_printf`/`dbg_logfile` arguments (`upgrade/upgrade.c`,
`sync/sync_exec_thd.c`, `mosq/mosq.c`, `esw_disc/esw_disc.c`). All
addresses are from the aarch64 Ghidra import of these two binaries.

**The §3.12 upgrade chain is present unchanged in substance.** `mqtt.elf`
subscribes to `sys/001/AP/+/%s/upgrade` (`FUN_00426ddc`, `%s` = serial),
the handler `FUN_004267d4` copies `url`/`fileName`/`fileSize`/`md5`/
`version`/`delayTime` straight out of the JSON `msg` with no validator,
and the download thread `FUN_004264e4` builds **[proven]**

```c
snprintf(buf, 0x800, "curl -L -k '%s%s' -o '%s' >/dev/null", url, fileName, "/tmp/image.tar.gz");
system(buf);                                            // upgrade/upgrade.c
...
snprintf(buf, 0x100, "/sbin/sysupgrade -v %s 2>/dev/null ", "/tmp/image.tar.gz");
system(buf);                                            // FUN_00426454
```

Same injection shape as §3.12 — a `'` in `url` or `fileName` closes the
quote — now with `curl -L -k` (**`-k` disables TLS certificate
verification on the download**, so an `https://` URL is no protection).
The `md5` and `version` fields are parsed and logged but **never used**:
the download loop (`FUN_004264e4`) only waits for the file to reach
`fileSize` bytes, then hands it to `sysupgrade`. So, as in §3.12, nothing
on this path authenticates the image. **[proven]**

**A second remote-root surface on the same bus: shell-command execution.**
`mqtt.elf` also subscribes to `sys/001/AP/+/%s/rpc/shell/request/+` and
`sys/001/AP/0/%s/shreq`, pulls a `cmds` string from the payload, and its
`exec_cmd_task` (`sync/sync_exec_thd.c`, `FUN_0042a90c`) runs it
directly: **[proven]**

```c
if (ctx->want_response == 0) system(ctx->cmd);          // fire-and-forget
else                         popen_capture(ctx->cmd, &out);   // FUN_00422ce8 -> popen(cmd,"r")
```

This is an *intended* remote-shell feature, not a parsing slip — which is
exactly why it matters: any party that can publish to the bus has a root
shell by design. (The same transport exists over UDP discovery:
`easydisc.elf` carries `DISC_MSG_TPYE_SH, cmd:%s` and a `check_cmd_task`
exec queue, matching the `0x61` surface in `easydisc-protocol.md` §5.)

**The on-disk broker is weaker here than in §3.1–3.4, not stronger.**
`/etc/mosquitto/mosquitto.conf` is **38 bytes in full**: **[proven]**

```
max_connections 33
socket_domain ipv4
```

No `listener` (so mosquitto 1.5.9 binds the default `0.0.0.0:1883`), no
`password_file`, no `acl_file`, no `allow_anonymous`, and **no TLS
material at all** — there is no `etc/easyson/ca/` tree on this image and
no `psk_file`. The init script (`/etc/init.d/mosquitto`, `use_uci 0`)
launches `mosquitto -c /etc/mosquitto/mosquitto.conf` verbatim, so this
static file is authoritative. With no `password_file` configured,
mosquitto 1.5.x accepts **anonymous** connections, so the §3.4 "shared
credential + `#` ACL" precondition collapses to *no credential and no
ACL* on the local bus. **[config proven; the anonymous-by-default
behaviour is the documented mosquitto 1.5.9 semantics for a config with
no password_file]** The WAN zone is still `input REJECT`
(`etc/config/firewall`), so this is LAN/mesh-reachable, not
internet-facing, exactly as in §3.12.

The client half confirms the plaintext posture: `mqtt.elf`'s
`FUN_0041adf8` (`mosq/mosq.c`) calls **[proven]**

```c
mosquitto_username_pw_set(mosq, "ruijie", "reyeeos");   // cleartext, no TLS
mosquitto_connect(mosq, master_ip_or_127.0.0.1, brokerPort /* 1883 */, 15);
```

`reyeeos` is a new cleartext broker password literal, distinct from the
`ruijie:$6$…` hashes of §3.3; with anonymous access allowed the broker
does not even enforce it.

**The auto-merge credential is plaintext `admin` and the sink is a bare
`system()`.** This is §3.13's "lead", resolved for this product.
`easydisc.elf`'s `FUN_0040f174` (`esw_disc/esw_disc.c`) is **[proven]**

```c
snprintf(buf, 0x100,
  "dev_sta set -m esw_networkId_merge "
  "'{\"password\":\"admin\",\"type\":\"noenc\",\"force\":\"true\","
  "\"fromSn\":[\"%s\"],\"fromNetworkId\":\"%s\",\"toNetworkId\":\"%s\"}' -b 1",
  fromSn, fromNetworkId, toNetworkId);
system(buf);                                            // PLT stub -> system
dbg_logfile(..., "Exec auto merge cmd: %s", buf);
```

Three fields drawn from the discovery message are interpolated inside
single quotes and passed to `system()`. Unlike 2.430 — which reaches the
equivalent template through `son_utils_safe_exec` (argv/`execvp`) and
calls `param_safety_check` first (§3.13) — `easydisc.elf` here links
`libeasydisc.so`, **not** `liblib_c.so`, and `param_safety_check` does
not appear anywhere in the daemon. The merge password is the literal
`admin` with `"type":"noenc"` and `"force":"true"`, where 2.430/2.380/
2.388 used an encrypted `U2FsdGVkX18…` blob. The caller
(`FUN_0040f548`) gates this on device mode, on the message `networkId`
differing from the device's own, and on `strncmp(reserve1, "l3", …)` —
and `fromSn`/`fromNetworkId` are read from the received message struct.
That is the reachability question left open for `0x0045ace4` in §3.13,
now answered for this build: the sink's attacker-influenced fields come
from the discovery packet and there is no validator between recv and
`system()`. **This is the geico packet's path** — see
[`easydisc-protocol.md`](easydisc-protocol.md) §8 for the match to the
in-the-wild payload (same salt, `reserve1 == "l3"`, `networkId` as the
injected field) and for the two offsets reasoned-but-not-traced-to-the-
byte. The daemon does retain the salted-MD5 framing gate (`Msg's md5 is
illegality … drop it`), which is an integrity check keyed by the same
shipped salt, not input sanitisation.

**Unchanged and identical to the other builds** (`etc/shadow`,
`etc/config/dropbear`, `etc/config/mqlink_reg`): the root hash
`root:$1$zOItWvpX$tKgP2GnQDoUZn16hVplYv1` (MD5-crypt, byte-for-byte the
§3.5 value), `RootPasswordAuth 'on'` on port `54133`, and the §3.6 cloud
`appid`/`secret`/`nonce`/`unbind_key` all identical. `etc/shadow` also
carries a second account, `admin:$1$zzg8tSF4$11/YBCBzy/ROjOY3f.jX..`
(also MD5-crypt) — not present in the earlier trees examined. No hash was
cracked; this is the algorithm and the fact of sharing only.

**Net effect.** The two findings that matter most — §3.12 (remote root
via the upgrade topic) and §3.4 (open control bus) — are both *worse* on
this shipping product: the upgrade download now also disables TLS
verification (`curl -k`), the bus requires no credential at all, and a
by-design remote-shell topic sits on the same bus. A fourth product and a
lower version number carrying the same chain is the strongest evidence
yet that this is a platform-wide design, not a per-model regression.

### 3.15 Cross-build matrix — three product lines, and which barrier actually protects the device

*(Added 2026-10-27; extended 2026-10-28 with the RG-EG1510XS and
RG-EG105G-V2 streams.)* Fourteen further ReyeeOS router images were
obtained as vendor upgrade bundles (`.zip` → gzip → tar of metadata + an
`encrypto_v1`/`v2` container; decryption per `easydisc-protocol.md` §11
for v2, the `upgrade_crypt_v1` XOR scheme of §3.14 for v1). They add two
more product lines — **RG-EG210G-P-V3** (MIPS) and the low-cost
**RG-EG105G-V2** (MIPS) — plus the full **RG-EG1510XS** flagship stream
(2.410 and the latest 2.430.1, released ~mid-October 2026), so the
shared-secret and discovery-path findings can now be read against product,
architecture **and** version separately rather than all varying together
(the caveat that bounded §3.13/§8). Five router product lines in all.

**What is byte-identical everywhere.** Across every router image examined
— RG-EG1510XS, RG-EG105GW(T), RG-EG305GH-E, RG-EG210G-P-V3 and
RG-EG105G-V2, spanning aarch64 and MIPS and ReyeeOS 2.248 through the
latest 2.430.1 — the following are the same bytes: **[proven]**

- the root hash `root:$1$zOItWvpX$tKgP2GnQDoUZn16hVplYv1` (§3.5);
- the broker private keys `server.key` md5 `5b60f5bf…` (2048-bit) and
  `e9124cc8…` (1024-bit) and `ca.crt` `880bbe79…` (§3.1) — present on the
  EG305GH and EG210G trees at 2.388/2.410/2.430, identical to the §3.1
  values;
- the ACL granting `topic #` to `ruijie` and `son` (§3.4);
- the cloud `appid`/`secret`/`unbind_key` (§3.6);
- `RootPasswordAuth 'on'` on port `54133` (§3.5);
- the Easydisc salt `03251584460325158446032515844600`
  (`easydisc-protocol.md` §3).

So §3.1, §3.4, §3.5 and §3.6 are not artefacts of three images — they
hold on five product lines and on the **latest flagship firmware
(RG-EG1510XS 2.430.1.2128), released ~two weeks before this was written**.
This is the central point: the shared-secret exposure is platform-wide
and still shipping in the newest build of the top-of-range device. The
EG105G-V2 adds the same root hash, the same `admin:$1$zzg8tSF4$…` entry
(§3.14) and the same broker keys, extending the exposure to the
lowest-cost device in the range.

**Where the builds differ: the two barriers on the discovery → merge
path.** geico's packet (`easydisc-protocol.md` §8) is stopped on 2.430
EG1510XS by *either* of two independent barriers — (1) the
`param_safety_check` shell-metacharacter blocklist on the esw hello
path, and (2) the merge sink being `son_utils_safe_exec`
(argv/`execvp`, no shell) rather than `system()`. Reading both barriers
across the builds: **[proven except where noted]**

| build | product / arch | daemon | barrier 1: `param_safety_check` on esw hello path | barrier 2: merge sink | broker |
|---|---|---|---|---|---|
| **2.248** | EG305GH aarch64 | split `easydisc.elf` + `mqtt.elf` | **absent** (daemon doesn't link `liblib_c.so`) | **`system()` / shell** (§3.14, `FUN_0040f174`) | **open / anonymous** (§3.14) |
| **2.248** | **EG105G-V2 MIPS** | split `easydisc.elf` + `mqtt.elf` | **absent** | **`system()` / shell** — proven, `FUN_00417da8`→`system` | **open / anonymous** (`max_connections 33`, no listener) |
| 2.280 / 2.300 / 2.340 | EG105G-V2 MIPS | `easyson.elf` | **present** | `son_utils_safe_exec` / `execvp` | shared-key TLS |
| 2.380 / 2.388 | EG105GW MIPS | `easyson.elf` | **absent** (§3.13) | not settled in §8 | shared-key TLS |
| 2.388 / 2.410 / 2.430 | EG305GH aarch64 | `easyson.elf` | imported; call-on-path not re-traced | `son_utils_safe_exec` (import + `type:enc` `%s` template) | shared-key TLS |
| 2.388 / 2.410 / 2.430 | EG210G MIPS | `easyson.elf` | **absent** (confirmed 2.430) | **`son_utils_safe_exec` / `execvp`** (confirmed 2.430) | shared-key TLS |
| 2.410 / 2.430.1 | EG1510XS aarch64 | `easyson.elf` | **present** | `son_utils_safe_exec` / `execvp` | shared-key TLS |
| 2.430.0 | EG1510XS aarch64 | `easyson.elf` | **present** (§3.13) | `son_utils_safe_exec` / `execvp` (§9) | shared-key TLS (§3.1) |

**Two product lines ship the vulnerable 2.248 posture, and the EG105G-V2
sink is proven on MIPS.** The split-daemon, no-validator, `system()`-sink,
open-broker design of §3.14 is not unique to the EG305GH: the low-cost
**RG-EG105G-V2** at ReyeeOS 2.248.0.2212 carries the byte-for-byte same
architecture. Its `easydisc.elf` merge builder decompiles to
`snprintf(buf, 0x100, "dev_sta set -m esw_networkId_merge '{\"password\":\"admin\", \"type\":\"noenc\",\"force\":\"true\",\"fromSn\":[\"%s\"],\"fromNetworkId\":\"%s\",\"toNetworkId\":\"%s\"…", a, b, c)` followed by a bare
`system(buf)` (`FUN_00417da8`, sink `PTR_system_0044a008`) — the same
three packet-derived `%s` inside single quotes, into `system()`, with no
`execvp` or `son_utils_safe_exec` present and no `param_safety_check` in
the daemon. This is the identical construction traced on EG305GH 2.248
(`FUN_0040f174`), now confirmed on a second product line and a second
architecture. **[proven]** On EG105G-V2 the fix lands at **2.280**: 2.280,
2.300 and 2.340 all revert to the unified `easyson.elf` with both barriers
restored. So "2.248" names a *posture* — the both-barriers-down
split-daemon era — shared by at least two product lines, not a single
anomalous image; and the EG105G-V2 is a low-cost, readily-obtainable
device on which that posture can be verified against hardware.

The EG210G 2.430 row was traced in Ghidra: `esw_disc_handle_hello_msg`
(`0x423434`) copies the 460-byte header and validates only with
`son_check_ipv4` / `strcmp` / `strncmp` / `strlen` — no
`param_safety_check` — exactly as the EG105GW MIPS builds do, and a GOT
scan places every `param_safety_check` site (16, in the same seven
`*_uf_cb` / `enetCap_*` functions as EG105GW) off the discovery path.
But its merge builder (`FUN_0042214c`) assembles the `dev_sta set -m
esw_networkId_merge` argv and calls **`son_utils_safe_exec`**, not
`system()`. So on EG210G the first barrier is absent and the second is
present. **[proven]**

**The conclusion that matters.** Both builds with the sink at `system()`
and no validator — i.e. both barriers down — are **2.248 split-daemon
builds**: EG305GH 2.248 (aarch64) and EG105G-V2 2.248 (MIPS). Every build
that runs the unified `easyson.elf` (every ≥2.280 EG105G-V2, every ≥2.388
EG305GH/EG210G, and all EG1510XS/EG105GW images) routes the merge through
`son_utils_safe_exec`/`execvp`, so geico's `'…|sh'` has no shell to break
into and is inert at the sink — even on the MIPS builds where the
blocklist is also absent. The load-bearing protection across the fleet is
therefore **the `execvp`-style sink, not the metacharacter blocklist**,
and the 2.248 era is precisely when the sink was `system()`. That sharpens
§3.14 (2.248 is a *posture*, reproduced on at least two product lines and
two architectures, not one anomalous image) and answers the §8 question of
what build geico was developed against: one shaped like 2.248. The vendor
should read the `system()` merge sink and the open broker of the 2.248
split-daemon builds as the regression to explain, and the shared secrets
of §3.15 as the platform-wide exposure that outlives any single build.

*(Method note: the v2 images decrypt with `EVP_BytesToKey(MD5, salt,
FW_KEY, iter=2023)` + AES-256-CBC after stripping the
`upgrade_crypt_v2!@2023` line and base64-decoding; the EG210G
`install_encrypto_v2.bin` is a raw install image with the rootfs
squashfs at a `hsqs` offset to be carved, not a sysupgrade tar. Scripts
in the session scratchpad `tools/`.)*

**Disclosure status of the §3.14 change — silent in the changelogs, and
unpublished as a CVE.** *(Added 2026-10-27.)* Two checks bear on whether
the move away from the 2.248 posture was ever disclosed as a security
fix:

- **The vendor release notes are silent.** The "Resolved Issues" in the
  RG-EG 2.388, 2.410 and 2.430 release notes (the PDFs shipped inside the
  upgrade bundles) list only functional defects — link-detection loss,
  factory-reset failure, topology display, DHCP pool exhaustion, a
  cloud-Portal DoS in Myanmar. **None** mentions Easydisc, SON, the
  discovery path, the network-merge command, the broker, command
  injection or any security hardening. So in the vendor's own changelogs
  the 2.248→later change is not described at all, let alone as a security
  fix. **[proven from the shipped documents]**
- **No public CVE or advisory names this vector.** A search of NVD, CISA,
  the GitHub Advisory Database, Claroty/Team82's Ruijie research and
  Ruijie's own security bulletins finds a large Reyee cluster, but every
  published item is a *different* surface: the EWEB web interface
  (CVE-2023-34644), an authenticated `updateVersion` RCE
  (CVE-2021-43164), and — most relevantly — the 2024 **MQTT/cloud**
  cluster (Claroty "Open Sesame"; CISA ICSA-24-338-01; CVE-2024-45722
  calculable MQTT credentials, -47791 partial-topic subscription, -46874
  cross-device command over MQTT, -52324 MQTT message → OS command). No
  public source ties a vulnerability to **Easydisc / SON discovery / UDP
  43561-43562 / the esw `networkId` merge**. The protocol's existence and
  ports are public (a Ruijie community forum post), but the merge-sink
  command injection is not. **Absence of a found advisory is not proof
  none exists, but the main registries were checked.**

Two consequences worth stating plainly for the vendor and any CNA:

1. **The MQTT side of this audit substantially overlaps the already-
   published 2024 cluster.** The shared/weak broker credentials (§3.3),
   the permissive topic access (§3.4) and the MQTT upgrade-topic command
   path (§3.12) correspond in kind to CVE-2024-45722 / -47791 / -46874 /
   -52324, and the disclosed affected range (Reyee OS 2.206.x–2.320.x)
   **includes 2.248**. These findings sharpen and give device-side detail
   to known issues rather than being wholly novel.
2. **The Easydisc discovery-protocol merge RCE (§3.14, `easydisc-protocol.md`
   §8) appears genuinely undisclosed.** It is a distinct transport (local
   UDP, not MQTT/cloud), it is the vector the in-the-wild *geico* family
   actually uses, and it has no matching CVE or release-note entry. If the
   2.248→later change remediated it, that remediation was silent; if it is
   merely architectural convergence, current firmware of other builds is
   protected only by the `execvp` sink (§3.15) and not by any acknowledged
   fix. This is the item that most warrants a CVE.

### 3.16 Open lead — a new 2024 boot-recovery container on the flagship, and an unauthenticated recovery fetch

*(Added 2026-10-28. This is a lead, not a settled finding; the claims are
tagged accordingly.)* The RG-EG1510XS flagship stream introduced, at the
latest build only, a **recovery image in a previously-unseen container
format**: `EG_3.0(1)B11P430_EG1510XS_…_install_recovery_encrypto.bin`,
whose magic is `upgrade_crypt_boot!@2024` followed by raw (not base64)
ciphertext — a third scheme distinct from the `upgrade_crypt_v1` XOR
(§3.14) and the `upgrade_crypt_v2` OpenSSL (§11) containers. **[proven
from the header]**

The running rootfs does not handle it: a whole-tree scan of the 2.430.1
image finds `upgrade_crypt_v2` (in `lib/upgrade/platform.sh` and
`usr/lib/shell/upgrade_check.sh`) but **no** `upgrade_crypt_boot` /
`crypt_boot!@2024` string anywhere in the OS. The handler is in **U-boot**
— which fits a recovery image applied below the OS. The bootloader ships
`v2`-encrypted (`u-boot-eg1510xs_encrypto_v2`) and decrypts with the same
FW_KEY, and the plaintext bootloader is the only component carrying
`crypt_boot!@2024`. **[proven]**

From strings in the decrypted bootloader (no Ghidra trace yet):

- it contains **no `BR0kh`** — the 2024 recovery container is keyed
  differently from the firmware key; **[proven]**
- it has **no `RSA`/`rsa`**, but does carry generic U-boot FIT
  `signature`/`Hash`/`verify` library strings — whose mere presence does
  **not** establish that secure boot is enforced; **[proven strings /
  enforcement not established]**
- its recovery paths look **integrity-checked but not authenticated**: a
  *cloud recovery* downloads a firmware bin by `wget` and compares its
  SHA-256 against a hash **supplied by the server in the same reply**
  (`download bin sha256sum: %s, not equal to reply sha256sum: %s`), and a
  *factory recovery* fetches `rgos.bin` over **TFTP** from `192.168.64.1`
  (`[SYSTEM-RECOVERY] … tftpboot %s:%s`). A server-supplied hash over
  `wget`, and TFTP, are integrity-against-corruption, **not** authenticity
  against a MITM. **[inferred from strings — the control-flow that gates
  an actual flash on these checks is not yet traced]**

**What is not yet established, and must be before any claim:** whether the
normal kernel boot enforces a FIT signature (secure boot); whether either
recovery path authenticates the image beyond the server-provided hash; and
the exact key/scheme of `upgrade_crypt_boot!@2024`. These need a Ghidra
trace of the bootloader's `system_recovery` / `cloud_recovery` / FIT-verify
functions. Flagged here because an unauthenticated recovery-flash path on
the top-of-range device is exactly the kind of bootstrap-trust gap worth
running down.

## 4. Recommendations

**For an operator running this gear now** (in priority order):

1. **Treat the SON mesh as an untrusted network — this is the one that
   matters.** Do not span it across trust boundaries. Anyone with the
   firmware can authenticate to the bus (§3.3, §3.4), and a single
   published message on that bus reaches an unvalidated `system()` as
   root and an unverified firmware flash (§3.12). Reachability of the
   broker is the control; nothing downstream of it is.
2. **Segment.** Put Reyee management interfaces on an isolated VLAN.
   Ports 1883 / 8883 / 9883 should not be reachable from general client
   networks. Nor should 43561 / 43562.
3. **Change the root password**; disable `RootPasswordAuth` if the
   deployment allows it, and do not rely on port 54133 for safety
   (§3.5).
4. **Do not expose WAN-side management.** The default `input REJECT` is
   doing real work here — verify it has not been relaxed, and check
   models other than the EG1510XS, whose defaults were not examined.
5. **Monitor** for UDP/43561 and 43562 crossing segment boundaries, and
   for connections to 1883/8883/9883 from unexpected hosts.

**For the vendor**, the questions that follow from the above:

1. Are the broker CA, server certificate and private key intended to be
   **per-device**? They are currently one shared key pair across product
   lines and versions, using OpenSSL demo-default subjects with
   `CN=0.0.0.0` and ~100-year validity.
2. Is `mosquitto_tls_insecure_set(…, 1)` deliberate, and is it a
   consequence of the `CN=0.0.0.0` certificate?
3. Why does the broker ACL grant `#` to both principals rather than
   scoping topics per role?
4. Is the 1024-bit CA on listener 8883 still required for
   backward compatibility, and can it be retired?
5. Is the shared `$1$` root hash intended to be identical across all
   devices, and can the algorithm be moved to `$6$`/yescrypt?
6. What are the privileges and scope of the `mqlink_reg` `appid` /
   `secret` / `unbind_key`?
7. `/etc/sd_config/admin` is absent from the image, so the embedded
   merge password is the operative credential on a fresh device — is
   that intended?
8. Can the ~78 `system()` / `son_utils_popen` sites be migrated to the
   `execvp`-style `son_utils_safe_exec` that already exists in the same
   codebase?
9. **(§3.12, highest priority)** Is the `url` / `fileName` pair from the
   `sys/001/AP/+/<sn>/upgrade` message intended to reach `system()`
   unvalidated? And is the firmware image expected to be
   signature-verified before `sysupgrade` runs — because on this path it
   is checked only against a hash file carried inside the image itself,
   and `usign`/`fwtool` are never invoked.

## 5. What is *not* claimed

- **Nothing here is shown to be exploitable from the WAN on a default
  configuration.** The firewall drops it (§2). §3.12 *does* establish a
  root code-execution chain, but it needs LAN or mesh reach to the
  broker, and it is established **statically** — no exploit was built,
  run, or tested against a device. "Unauthenticated" there means the
  required credentials are extractable from firmware by anyone, not that
  no credential is presented.
- **No credential was cracked, tested or used.** The root hash was
  identified by algorithm only. No Ruijie endpoint was contacted. No
  device was operated.
- **Severity of the cloud credentials is unknown** — their privilege
  cannot be read from the image.
- **The MIPS PSK question is open** (§3.3) and is not asserted in either
  direction.
- **The `curl … -o '%s'` path-traversal hypothesis is withdrawn, not
  open** (§3.9, §3.11): the `-o` argument is a hardcoded
  `"/tmp/image.tar.gz"` literal, so no field reaches it. The traversal
  gap remains a real property of `param_safety_check` (it rejects no
  `.` or `/`), but no path exercising it has been demonstrated. The
  serious defect found while chasing it is the *other* two `%s` in that
  same template — §3.12.
- **The `0x0045ace4` MIPS merge lead is untraced** (§3.13). That it uses
  `system()` with an embedded credential and no validator is read out of
  the binary; that anything attacker-controlled reaches it is **not**
  established, and no reachability claim is made.
- These are **three images of two products**. Other Reyee models,
  and configurations other than default, were not examined — most
  relevantly, models whose WAN posture may differ.

## 6. Reproduction notes

- Firmware decryption is documented in
  [`easydisc-protocol.md`](easydisc-protocol.md) §11.
- Rootfs trees used: `/tmp/rootfs` (2.430), `/tmp/rootfs2380`,
  `/tmp/rootfs2388` on `telly`; binaries also at
  `C:\Users\orlock\reyee-firmware\binaries\`.
- Ghidra string xrefs resolve in the aarch64 build and were used
  throughout. On the MIPS builds, **instruction-level search returns
  `instructions_scanned: 0`** — those programs are imported but not
  disassembled, so a "not found" there is a tooling result, not a
  finding. The other MIPS traps are recorded in
  `cve-2021-35394-ecosystem`, `analysis/geico/README.md` §11.
- `get_function_callers` by *name* returned "No callers found" for
  `system` despite 57 real xrefs. Resolve the **thunk address** with
  `search_functions_enhanced` and use `get_xrefs_to` on that instead.
- When grepping for `$6$` hashes over `ssh`, quote or escape the `$` —
  an unescaped `$6$` is consumed by the local shell as arithmetic and
  silently returns nothing, which looks exactly like a clean result.
