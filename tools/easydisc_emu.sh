#!/bin/sh
# In-guest bootstrap for network-based Easydisc confirmation.
#
# Runs inside a disposable OpenWrt guest (mips-fpu-le for the hard-float LE
# ReyeeOS MIPS builds). It unpacks a vendor rootfs, provisions a minimal esw
# "master" SON config, starts ubusd and the vendor discovery daemon bound on
# UDP/43562, prints the guest IP and a READY_FOR_SEND marker, then idles while
# sbx-run delivers one crafted datagram OVER THE BRIDGE from the sink
# (10.200.0.1) with --inject. At the end it reports the merge artifact and the
# daemon's own log. It never sends the packet itself.
#
# Parameters via environment (set by the caller's --cmd):
#   ROOTFS   served tarball name under /_sbx/easydisc/ (required)
#   DAEMON   discovery binary in /usr/sbin (default easydisc.elf; easyson.elf for unified builds)
#   MODEL    devModel string            (default RG-EG105G-V2)
#   SWV      software_version string     (default "ReyeeOS 2.248")
#   HOLD     seconds to hold the daemon up after READY (default 160)
set -x
S=http://10.200.0.1/_sbx/easydisc
R=/tmp/vr
: "${ROOTFS:?set ROOTFS}"
DAEMON="${DAEMON:-easydisc.elf}"
MODEL="${MODEL:-RG-EG105G-V2}"
SWV="${SWV:-ReyeeOS 2.248}"
HOLD="${HOLD:-160}"
NID_SELF="${NID_SELF:-LABNET0000000000000000000000AAAA}"
MAC="00:11:22:33:44:55"

echo "=== FETCH $ROOTFS"
wget -q -O /tmp/root.tar.gz "$S/$ROOTFS" || { echo FETCH_FAIL; exit 1; }
mkdir -p "$R" && tar -xzf /tmp/root.tar.gz -C "$R" && echo extracted || { echo EXTRACT_FAIL; exit 1; }

echo "=== OPEN FIREWALL (guest)"
/etc/init.d/firewall stop 2>/dev/null; nft flush ruleset 2>/dev/null; echo "fw flushed"

echo "=== SON discovery interface br-wan"
# The daemon binds its raw-socket / identity (imac) layer to br-wan and fails
# to stabilise without it (set send device br-wan error, g_disc.imac get
# failed). The injected hello still arrives via the wildcard UDP bind on the
# guest LAN; br-wan only needs to exist with a MAC and address.
ip link add name br-wan type bridge 2>&1
ip link set dev br-wan address "$MAC" 2>&1
ip addr add 192.168.111.1/24 dev br-wan 2>&1
ip link set dev br-wan up 2>&1
ip -o link show br-wan 2>&1 | head -1

echo "=== RUNTIME DIRS + bind /proc,/dev"
mkdir -p "$R"/tmp/easydisc "$R"/tmp/easyson "$R"/tmp/run "$R"/proc "$R"/dev "$R"/etc/config
mount -t proc proc "$R/proc" 2>/dev/null && echo "proc ok" || echo "proc FAILED"
mount -o bind /dev "$R/dev" 2>/dev/null && echo "dev ok" || echo "dev FAILED"

echo "=== PROVISION esw master config"
cat > "$R/etc/config/sysinfo" <<EOF
config sysinfo 'sysinfo'
	option serial_num 'LABSN0000001'
	option software_version '$SWV'
	option hardware_version '1.00'
	option dev_type 'esw'
	option forwardMode 'Router'
	option model '$MODEL'
	option sys_mac '$MAC'
	option support_wifi '0'
	option max_ap_num '32'
	option master_priority '1'
	option acEnable '0'
	option autoJoin '1'
EOF
cat > "$R/etc/config/networkid" <<EOF
config networkid 'networkid'
	option networkId '$NID_SELF'
	option groupId 'LABGROUP00000001'
	option networkName 'labnet'
	option groupName 'labgroup'
	option master '$MAC'
	option master_priority '1'
EOF
echo "nameserver 10.200.0.1" > "$R/etc/resolv.conf"
printf '{"networkId":"%s","master":"%s","role":"master"}\n' "$NID_SELF" "$MAC" > "$R/tmp/easydisc/master.json"
cp "$R/tmp/easydisc/master.json" "$R/tmp/easyson/master.json" 2>/dev/null

echo "=== START ubusd + $DAEMON"
( chroot "$R" /sbin/ubusd ) >"$R/tmp/ubusd.log" 2>&1 &
sleep 2
( chroot "$R" "/usr/sbin/$DAEMON" ) >"$R/tmp/daemon.out" 2>&1 &
sleep 20
echo "--- daemon.out head ---"; head -20 "$R/tmp/daemon.out" 2>&1
echo "--- UDP listeners (expect :AA2A=43562 wildcard 00000000)"; cat /proc/net/udp | awk 'NR==1 || $2 ~ /:AA2A|:AA29/'
echo "GUESTIP=$(ip -4 -o addr show 2>/dev/null | grep -o '10\.200\.0\.[0-9]*' | head -1)"
echo "READY_FOR_SEND"

sleep "$HOLD"

echo "===== MERGE ARTIFACT (P written by the injected command) ====="
find "$R/tmp" -maxdepth 3 -name P 2>/dev/null | while read f; do echo "FOUND $f:"; cat "$f"; done
ls -la "$R"/tmp/easydisc/ "$R"/tmp/easyson/ 2>&1
echo "===== FULL easydisc.log (tail 160) ====="
cat "$R"/tmp/easydisc/easydisc.log 2>/dev/null | tail -160
echo "===== easyson logs (tail 160) ====="
for f in "$R"/tmp/easyson/*.log; do [ -f "$f" ] && { echo "-- $f"; tail -160 "$f"; }; done
echo "===== daemon.out (tail 80) ====="
tail -80 "$R"/tmp/daemon.out 2>/dev/null
echo "DONE_EMU"
