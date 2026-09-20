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

Three vendor images, obtained from Ruijie. No device was tested, no
traffic was sent to any Ruijie service, no credential was cracked or
used.

| build | product | arch | easydisc pkg |
|---|---|---|---|
| **ReyeeOS 2.430.0.1924** (`EG_3.0(1)B11P430`, `mediatek/eg1510xs`) | RG-EG1510XS | `aarch64_cortex-a53` | 4.0-0 |
| **ReyeeOS 2.388** | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) | 4.0-0 |
| **ReyeeOS 2.380** | RG-EG105GW(T) | `ramips_24kec` (MIPS32 LE) | 4.0-0 |

Method: static analysis of the unpacked rootfs and of `easyson.elf`
(aarch64, 2.430) in Ghidra, plus config and key-material inspection
across all three trees. Vendor source filenames and line numbers quoted
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
| xrefs | 16 | 2 |

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
- **Whether a network-controlled field reaches `curl … -o '%s'`** is
  unestablished (§3.9); the traversal gap is a property of the validator,
  not a demonstrated path.
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
