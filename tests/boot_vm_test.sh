#!/bin/sh
#
# boot_vm_test.sh - Boot-path regression test for mac_do_auto.
#
# Installs mac_do_auto.ko into a stock FreeBSD VM image, enables it via
# loader.conf (mac_do_auto_load="YES"), boots the image under bhyve, and
# verifies via the serial console that:
#   1. the kernel reaches multiuser (no panic during module init), and
#   2. the module loaded and /dev/autodo was created.
#
# This exercises the loader-preload path that kldload-based tests cannot:
# MAC policy registration runs at SI_SUB_MAC_POLICY, before devfs exists.
# A make_dev() at that point panics the kernel (issue #3).
#
# Requirements (host):
#   - FreeBSD with bhyve support (/dev/vmm; bare metal or a hypervisor
#     with nested virtualization exposed — vmm fails to init otherwise)
#   - root (or run via doas): mdconfig/mount/bhyve all need it
#   - xz(1), fetch(1); ~2 GB scratch space
#
# Usage:
#   doas sh tests/boot_vm_test.sh [path/to/mac_do_auto.ko] [15.1-RELEASE]
#
# Environment:
#   CACHEDIR    where the pristine VM image is kept (default: /var/tmp/mac_do_auto-boottest)
#   BOOT_TIMEOUT  seconds to wait for the boot sentinel (default: 240)
#   KEEP_VM=1   keep the working copy of the image for debugging
#

set -eu

KO_PATH="${1:-$(dirname "$0")/../src/mac_do_auto.ko}"
FBSD_REL="${2:-15.1-RELEASE}"
CACHEDIR="${CACHEDIR:-/var/tmp/mac_do_auto-boottest}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-240}"
VMNAME="macdoautoboot$$"
NMDM_N=$(( $$ % 900 + 100 ))		# high pair number, avoids collisions
NMDM_GUEST="/dev/nmdm${NMDM_N}A"
NMDM_HOST="/dev/nmdm${NMDM_N}B"

IMG_XZ="FreeBSD-${FBSD_REL}-amd64-ufs.raw.xz"
IMG_URL="https://download.freebsd.org/releases/VM-IMAGES/${FBSD_REL}/amd64/Latest/${IMG_XZ}"
PRISTINE="${CACHEDIR}/FreeBSD-${FBSD_REL}-amd64-ufs.raw"

WORKDIR=""
MDEV=""
MNTDIR=""
CATPID=""
BHYVEPID=""

log() {
	printf 'boot_vm_test: %s\n' "$*"
}

die() {
	printf 'boot_vm_test: ERROR: %s\n' "$*" >&2
	exit 1
}

cleanup() {
	set +e
	[ -n "$BHYVEPID" ] && kill "$BHYVEPID" 2>/dev/null
	bhyvectl --destroy --vm="$VMNAME" 2>/dev/null
	[ -n "$CATPID" ] && kill "$CATPID" 2>/dev/null
	if [ -n "$MNTDIR" ]; then
		umount "$MNTDIR" 2>/dev/null
		rmdir "$MNTDIR" 2>/dev/null
	fi
	[ -n "$MDEV" ] && mdconfig -d -u "$MDEV" 2>/dev/null
	if [ -n "$WORKDIR" ] && [ "${KEEP_VM:-0}" != "1" ]; then
		rm -rf "$WORKDIR"
	else
		[ -n "$WORKDIR" ] && log "KEEP_VM=1: working image left in $WORKDIR"
	fi
}
trap cleanup EXIT

# --- prerequisites -----------------------------------------------------

[ -r "$KO_PATH" ] || die "kernel module not found: $KO_PATH (build it first: make -C src)"

for tool in bhyve bhyvectl bhyveload mdconfig gpart fetch xz; do
	command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

if [ ! -c /dev/vmm ]; then
	log "loading vmm.ko"
	kldload vmm 2>/dev/null || true
fi
if [ ! -c /dev/vmm ]; then
	die "bhyve unavailable: /dev/vmm does not exist (nested virtualization not exposed?)"
fi

kldstat -q -m nmdm || kldload nmdm

# --- fetch / extract the pristine image --------------------------------

mkdir -p "$CACHEDIR"
if [ ! -f "$PRISTINE" ]; then
	log "fetching $IMG_URL"
	fetch -o "${CACHEDIR}/${IMG_XZ}" "$IMG_URL" || die "image download failed"
	log "extracting $IMG_XZ"
	xz -d -k -c "${CACHEDIR}/${IMG_XZ}" > "$PRISTINE" || die "image extract failed"
	rm -f "${CACHEDIR}/${IMG_XZ}"
fi

WORKDIR=$(mktemp -d "${CACHEDIR}/run.XXXXXX")
IMG="$WORKDIR/boottest.raw"
SERIAL_LOG="$WORKDIR/serial.log"

log "creating working copy of image"
cp "$PRISTINE" "$IMG"

# --- install module, loader.conf, and boot sentinel into the image -----

MDEV=$(mdconfig -a -t vnode -f "$IMG")
log "image attached as /dev/$MDEV"

UFSPART=$(gpart show -p "$MDEV" | awk '$4 == "freebsd-ufs" { print $3; exit }')
[ -n "$UFSPART" ] || die "no freebsd-ufs partition found in image"

MNTDIR="$WORKDIR/mnt"
mkdir -p "$MNTDIR"
mount -o rw "/dev/$UFSPART" "$MNTDIR" || die "mount /dev/$UFSPART failed"

cp "$KO_PATH" "$MNTDIR/boot/kernel/mac_do_auto.ko"

cat >> "$MNTDIR/boot/loader.conf" <<'EOF'

# mac_do_auto boot test
console="comconsole"
autoboot_delay="3"
mac_do_auto_load="YES"
EOF

# Late-boot rc script: report module state to the (serial) console.
cat > "$MNTDIR/etc/rc.d/zzboottest" <<'EOF'
#!/bin/sh
# PROVIDE: zzboottest
# REQUIRE: LOGIN
# KEYWORD: nojail

. /etc/rc.subr

name="zzboottest"
start_cmd="${name}_start"

zzboottest_start()
{
	if ! kldstat -q -m mac_do_auto; then
		echo "MAC_DO_AUTO_BOOTTEST: FAIL module not loaded" > /dev/console
		return
	fi
	if [ ! -c /dev/autodo ]; then
		echo "MAC_DO_AUTO_BOOTTEST: FAIL /dev/autodo missing" > /dev/console
		return
	fi
	enabled=$(sysctl -n security.mac.autodo.enabled 2>/dev/null) || {
		echo "MAC_DO_AUTO_BOOTTEST: FAIL sysctl tree missing" > /dev/console
		return
	}
	echo "MAC_DO_AUTO_BOOTTEST: PASS enabled=$enabled" > /dev/console
}

load_rc_config $name
run_rc_command "$1"
EOF
chmod 555 "$MNTDIR/etc/rc.d/zzboottest"

umount "$MNTDIR"
rmdir "$MNTDIR"
MNTDIR=""
mdconfig -d -u "$MDEV"
MDEV=""
log "image prepared"

# --- boot under bhyve --------------------------------------------------

# Host side of the null-modem pair: capture everything the guest writes.
# Opening the host end blocks until the guest end is opened, hence &.
cat "$NMDM_HOST" > "$SERIAL_LOG" 2>/dev/null &
CATPID=$!

bhyvectl --destroy --vm="$VMNAME" 2>/dev/null || true

log "loading guest kernel with bhyveload"
bhyveload -c "$NMDM_GUEST" -m 512M -d "$IMG" "$VMNAME" \
	> /dev/null 2>&1 || die "bhyveload failed"

log "starting VM (console on $NMDM_GUEST)"
bhyve -c 1 -m 512M -H -A -P \
	-s 0:0,hostbridge \
	-s 1:0,lpc \
	-s 2:0,ahci-hd,"$IMG" \
	-l com1,"$NMDM_GUEST" \
	"$VMNAME" > /dev/null 2>&1 &
BHYVEPID=$!

# --- wait for the sentinel ---------------------------------------------

deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
result=""
while [ "$(date +%s)" -lt "$deadline" ]; do
	if grep -q "MAC_DO_AUTO_BOOTTEST: PASS" "$SERIAL_LOG" 2>/dev/null; then
		result="PASS"
		break
	fi
	if grep -q "MAC_DO_AUTO_BOOTTEST: FAIL" "$SERIAL_LOG" 2>/dev/null; then
		result="FAIL"
		break
	fi
	if grep -qE "panic:|Fatal trap" "$SERIAL_LOG" 2>/dev/null; then
		result="PANIC"
		break
	fi
	kill -0 "$BHYVEPID" 2>/dev/null || {
		# VM exited on its own (triple fault / poweroff)
		result="DIED"
		break
	}
	sleep 2
done
[ -n "$result" ] || result="TIMEOUT"

echo "----- serial console (tail) -----"
tail -n 40 "$SERIAL_LOG" 2>/dev/null || true
echo "---------------------------------"

case "$result" in
PASS)
	log "PASS: guest booted with mac_do_auto preloaded, /dev/autodo present"
	exit 0
	;;
PANIC)
	die "FAIL: guest kernel panicked during boot (see serial log above)"
	;;
FAIL)
	die "FAIL: guest booted but module checks failed (see serial log above)"
	;;
DIED)
	die "FAIL: VM exited before reaching multiuser (see serial log above)"
	;;
*)
	die "FAIL: timed out after ${BOOT_TIMEOUT}s waiting for boot sentinel"
	;;
esac
