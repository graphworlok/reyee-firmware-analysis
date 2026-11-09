#!/bin/sh
# Network-based Easydisc confirmation run on the iot-detonation sandbox host.
#
#   sudo sh run_easydisc_emu.sh <rootfs_tarball> <daemon> <pkt_file> [duration]
#
# Boots a disposable mips-fpu-le guest, has it run the vendor discovery daemon
# from <rootfs_tarball> (served under /_sbx/easydisc/), then delivers <pkt_file>
# to the guest's UDP/43562 OVER THE BRIDGE from the sink namespace (10.200.0.1)
# — a real remote datagram, not a loopback send. Proof lands in the run's
# sink.jsonl (the injected command's DNS callback) and console.log (the
# daemon's "Exec auto merge cmd" line and any artifact).
#
# Positive: root_eg105_2248.tar.gz easydisc.elf   (2.248 split daemon, system() sink)
# Negative: root_eg105_2280.tar.gz easyson.elf    (2.280 unified, barriers restored)
set -eu
ROOTFS=$1; DAEMON=$2; PKT=$3; DUR=${4:-360}
# HOLD is the daemon's uptime after READY; it must be short enough that the
# bootstrap's artifact/log dump prints well before sbx-run stops the console
# at detonation + DUR. Boot + bootstrap-to-READY is ~150s on TCG mipsel.
HOLD=90
URL=http://10.200.0.1/_sbx/easydisc/easydisc_emu.sh
CMD="export ROOTFS=$ROOTFS DAEMON=$DAEMON HOLD=$HOLD; wget -qO /tmp/e.sh $URL && sh /tmp/e.sh"
exec sbx-run --target mips-fpu-le --cmd "$CMD" --no-monitor \
    --inject "$PKT" --inject-port 43562 --inject-after READY_FOR_SEND \
    --inject-count 4 --inject-interval 8 --duration "$DUR"
