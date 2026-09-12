#!/usr/libexec/atf-sh
#
# ABI handshake tests for mac_do_auto and autodo-eventd.
#
# The ioctl commands carry their parameter size, so changing a structure
# changes the command numbers: a daemon paired with a module from another
# release fails every ioctl with ENOTTY and leaves the kernel with
# whatever policy it had.  The daemon reads AUTODO_GET_VERSION at startup
# and refuses to run on a mismatch.
#

MODULE_DIR="$(atf_get_srcdir)/../src"
MODULE_PATH="${MODULE_DIR}/mac_do_auto.ko"
DAEMON_PATH="$(atf_get_srcdir)/../daemon/zig-out/bin/autodo-eventd"

load_module() {
	kldstat -q -m mac_do_auto 2>/dev/null && return 0
	kldload "${MODULE_PATH}" || atf_fail "cannot load mac_do_auto.ko"
}

unload_module() {
	kldstat -q -m mac_do_auto 2>/dev/null && kldunload mac_do_auto
	return 0
}

require_daemon() {
	if [ ! -x "${DAEMON_PATH}" ]; then
		atf_skip "Daemon not built"
	fi
}

# --- the handshake succeeds against the module it ships with ---

atf_test_case abi_matches cleanup
abi_matches_head() {
	atf_set "descr" "--check-abi accepts the module built from this tree"
	atf_set "require.user" "root"
}
abi_matches_body() {
	require_daemon
	load_module
	atf_check -s exit:0 -o match:"matches autodo-eventd" \
	    "${DAEMON_PATH}" --check-abi
}
abi_matches_cleanup() {
	unload_module
}

# --- without a module there is nothing to talk to ---

atf_test_case abi_without_module cleanup
abi_without_module_head() {
	atf_set "descr" "--check-abi fails when the module is not loaded"
	atf_set "require.user" "root"
}
abi_without_module_body() {
	require_daemon
	unload_module
	atf_check -s not-exit:0 -o empty -e match:"cannot open /dev/autodo" \
	    "${DAEMON_PATH}" --check-abi
}
abi_without_module_cleanup() {
	unload_module
}

# --- the daemon refuses to configure a kernel it cannot talk to ---

atf_test_case daemon_fails_closed cleanup
daemon_fails_closed_head() {
	atf_set "descr" "The daemon exits instead of running against no module"
	atf_set "require.user" "root"
}
daemon_fails_closed_body() {
	require_daemon
	unload_module
	atf_check -s not-exit:0 -e ignore "${DAEMON_PATH}" --config=/nonexistent
}
daemon_fails_closed_cleanup() {
	pkill -f autodo-eventd 2>/dev/null || true
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case abi_matches
	atf_add_test_case abi_without_module
	atf_add_test_case daemon_fails_closed
}
