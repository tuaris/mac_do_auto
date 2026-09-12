#!/usr/libexec/atf-sh
#
# vmm(4) privilege tests for mac_do_auto.
#
# PRIV_VMM_PPTDEV (710) guards the PCI passthrough ioctls on /dev/vmm/<name>.
# vmm_pptdev_unbind.c reports whether the non-root wheel user passes that
# check.  Needs amd64, a loadable vmm(4) (hardware virtualization), and cc(1).
#

MODULE_DIR="$(atf_get_srcdir)/../src"
MODULE_PATH="${MODULE_DIR}/mac_do_auto.ko"
DAEMON_PATH="$(atf_get_srcdir)/../daemon/zig-out/bin/autodo-eventd"
HELPER_SRC="$(atf_get_srcdir)/vmm_pptdev_unbind.c"
TEST_USER="admin"
VM_NAME="autodo_vmm_test"

load_module() {
	kldstat -q -m mac_do_auto 2>/dev/null && return 0
	kldload "${MODULE_PATH}" || atf_fail "cannot load mac_do_auto.ko"
}

unload_module() {
	kldstat -q -m mac_do_auto 2>/dev/null && kldunload mac_do_auto
	return 0
}

kill_daemon() {
	pkill -f autodo-eventd 2>/dev/null || true
	sleep 1
}

# Build the helper where TEST_USER can execute it and create a VM whose
# device node TEST_USER owns, so that open(2) needs no privilege and only
# the ioctl's PRIV_VMM_PPTDEV check is under test.
vmm_setup() {
	[ "$(uname -p)" = "amd64" ] || atf_skip "PCI passthrough ioctls are amd64-only"
	if [ ! -c /dev/vmmctl ]; then
		kldload vmm 2>/dev/null || atf_skip "vmm(4) is unavailable"
	fi
	helper_dir=$(mktemp -d /tmp/autodo_vmm.XXXXXX) || atf_fail "mktemp failed"
	echo "${helper_dir}" > helper_dir
	chmod 755 "${helper_dir}"
	cc -o "${helper_dir}/pptdev_unbind" "${HELPER_SRC}" || \
	    atf_fail "cannot build ${HELPER_SRC}"
	bhyvectl --destroy --vm="${VM_NAME}" >/dev/null 2>&1
	bhyvectl --create --vm="${VM_NAME}" || atf_skip "cannot create a vmm(4) VM"
	chown "${TEST_USER}" "/dev/vmm/${VM_NAME}"
}

vmm_cleanup() {
	bhyvectl --destroy --vm="${VM_NAME}" >/dev/null 2>&1
	[ -f helper_dir ] && rm -rf "$(cat helper_dir)"
	return 0
}

# Assert that TEST_USER is "granted" or "denied" PRIV_VMM_PPTDEV.
check_pptdev() {
	atf_check -s exit:0 -o inline:"$1\n" \
	    su -m ${TEST_USER} -c "$(cat helper_dir)/pptdev_unbind ${VM_NAME}"
}

# Start the daemon with an inline wheel policy; $1 is the group body.
start_daemon() {
	cat > autodo.conf <<-EOF
	enabled = true;
	groups { wheel { $1 } }
	audit { enabled = false; }
	EOF
	"${DAEMON_PATH}" --config="$(pwd)/autodo.conf" &
	sleep 1
}

# --- baseline: denied without module ---

atf_test_case pptdev_baseline_denied cleanup
pptdev_baseline_denied_head() {
	atf_set "descr" "PRIV_VMM_PPTDEV is denied to the wheel user without the module"
	atf_set "require.user" "root"
	atf_set "require.progs" "bhyvectl cc"
}
pptdev_baseline_denied_body() {
	unload_module
	vmm_setup
	check_pptdev denied
}
pptdev_baseline_denied_cleanup() {
	vmm_cleanup
	unload_module
}

# --- legacy scope 'all' grants privilege 710 ---

atf_test_case pptdev_scope_all cleanup
pptdev_scope_all_head() {
	atf_set "descr" "Default scope 'all' grants PRIV_VMM_PPTDEV"
	atf_set "require.user" "root"
	atf_set "require.progs" "bhyvectl cc"
}
pptdev_scope_all_body() {
	load_module
	vmm_setup
	check_pptdev granted
}
pptdev_scope_all_cleanup() {
	vmm_cleanup
	unload_module
}

# --- misc category covers privilege 710 ---

atf_test_case pptdev_scope_misc cleanup
pptdev_scope_misc_head() {
	atf_set "descr" "The misc category grants PRIV_VMM_PPTDEV"
	atf_set "require.user" "root"
	atf_set "require.progs" "bhyvectl cc"
}
pptdev_scope_misc_body() {
	load_module
	vmm_setup
	sysctl security.mac.autodo.scope=misc
	check_pptdev granted
}
pptdev_scope_misc_cleanup() {
	sysctl security.mac.autodo.scope=all 2>/dev/null
	vmm_cleanup
	unload_module
}

# --- every other category leaves privilege 710 denied ---

atf_test_case pptdev_scope_without_misc cleanup
pptdev_scope_without_misc_head() {
	atf_set "descr" "All categories except misc leave PRIV_VMM_PPTDEV denied"
	atf_set "require.user" "root"
	atf_set "require.progs" "bhyvectl cc"
}
pptdev_scope_without_misc_body() {
	load_module
	vmm_setup
	sysctl security.mac.autodo.scope=system,audit,cred,debug,jail,kld,proc,vfs,vm,dev,net
	check_pptdev denied
}
pptdev_scope_without_misc_cleanup() {
	sysctl security.mac.autodo.scope=all 2>/dev/null
	vmm_cleanup
	unload_module
}

# --- multi-group policy grants privilege 710 ---

atf_test_case pptdev_policy_all cleanup
pptdev_policy_all_head() {
	atf_set "descr" "Multi-group policy with scope 'all' grants PRIV_VMM_PPTDEV"
	atf_set "require.user" "root"
	atf_set "require.progs" "bhyvectl cc"
}
pptdev_policy_all_body() {
	[ -x "${DAEMON_PATH}" ] || atf_skip "Daemon not built"
	load_module
	vmm_setup
	start_daemon 'scope { categories = ["all"]; }'
	check_pptdev granted
}
pptdev_policy_all_cleanup() {
	kill_daemon
	vmm_cleanup
	unload_module
}

# --- multi-group deny list removes privilege 710 ---

atf_test_case pptdev_policy_deny cleanup
pptdev_policy_deny_head() {
	atf_set "descr" "Multi-group deny list removes PRIV_VMM_PPTDEV from scope 'all'"
	atf_set "require.user" "root"
	atf_set "require.progs" "bhyvectl cc"
}
pptdev_policy_deny_body() {
	[ -x "${DAEMON_PATH}" ] || atf_skip "Daemon not built"
	load_module
	vmm_setup
	start_daemon 'scope { categories = ["all"]; } deny { privileges = ["PRIV_VMM_PPTDEV"]; }'
	check_pptdev denied
}
pptdev_policy_deny_cleanup() {
	kill_daemon
	vmm_cleanup
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case pptdev_baseline_denied
	atf_add_test_case pptdev_scope_all
	atf_add_test_case pptdev_scope_misc
	atf_add_test_case pptdev_scope_without_misc
	atf_add_test_case pptdev_policy_all
	atf_add_test_case pptdev_policy_deny
}
