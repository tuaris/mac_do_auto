#!/usr/libexec/atf-sh
#
# Path deny list tests for mac_do_auto.
#
# Verifies the global advisory path blacklist: non-root members of a
# managed group are denied mutating operations under denied prefixes
# even though autodo would otherwise grant them; root is exempt; reads
# and paths outside the list are unaffected.
#

MODULE_DIR="$(atf_get_srcdir)/../src"
MODULE_PATH="${MODULE_DIR}/mac_do_auto.ko"
DAEMON_PATH="$(atf_get_srcdir)/../daemon/zig-out/bin/autodo-eventd"
TEMPLATE_DIR="$(atf_get_srcdir)/../config/templates"
TEST_USER="admin"
PROTECTED="/tmp/autodo-protected"
OPEN_TMP="/tmp/autodo-open"

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

# Run a command as the wheel test user; returns its exit status.
as_user() {
	su -m ${TEST_USER} -c "$1" >/dev/null 2>&1
}

# Start the daemon with the path deny list active.
start_daemon() {
	TMPCONF=$(mktemp)
	cat > "${TMPCONF}" <<-EOF
	enabled = true;
	groups { wheel { template = "all"; } }
	deny { paths = [ "${PROTECTED}" ]; }
	audit { enabled = false; }
	template_dir = "${TEMPLATE_DIR}";
	EOF
	"${DAEMON_PATH}" --config="${TMPCONF}" >/dev/null 2>&1 &
	sleep 1
}

stop_daemon() {
	kill_daemon
	rm -f "${TMPCONF}"
}

setup_protected() {
	rm -rf "${PROTECTED}"
	mkdir -p "${PROTECTED}/sub"
	echo secret > "${PROTECTED}/file.txt"
}

teardown_protected() {
	rm -rf "${PROTECTED}"
}

require_daemon() {
	if [ ! -x "${DAEMON_PATH}" ]; then
		atf_skip "Daemon not built"
	fi
}

# --- empty by default: no path deny without daemon/config ---

atf_test_case empty_by_default cleanup
empty_by_default_head() {
	atf_set "descr" "No path deny list active by default"
	atf_set "require.user" "root"
}
empty_by_default_body() {
	load_module
	setup_protected
	atf_check -s exit:0 -o empty \
	    su -m ${TEST_USER} -c "echo x >> ${PROTECTED}/file.txt"
}
empty_by_default_cleanup() {
	teardown_protected
	unload_module
}

# --- mutating operations denied under a denied prefix ---

atf_test_case deny_mutations cleanup
deny_mutations_head() {
	atf_set "descr" "Write/create/delete/rename/chmod denied under denied prefix"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
deny_mutations_body() {
	require_daemon
	load_module
	setup_protected
	start_daemon

	# Reads still work.
	atf_check -s exit:0 -o match:"secret" \
	    su -m ${TEST_USER} -c "cat ${PROTECTED}/file.txt"

	# Mutations are all denied.
	atf_check -s not-exit:0 -o empty -e ignore \
	    su -m ${TEST_USER} -c "echo x >> ${PROTECTED}/file.txt"
	atf_check -s not-exit:0 -o empty -e ignore \
	    su -m ${TEST_USER} -c "touch ${PROTECTED}/newfile"
	atf_check -s not-exit:0 -o empty -e ignore \
	    su -m ${TEST_USER} -c "rm ${PROTECTED}/file.txt"
	atf_check -s not-exit:0 -o empty -e ignore \
	    su -m ${TEST_USER} -c "mv ${PROTECTED}/file.txt /tmp/autodo-moved"
	atf_check -s not-exit:0 -o empty -e ignore \
	    su -m ${TEST_USER} -c "mv /etc/hostname ${PROTECTED}/hostname"
	atf_check -s not-exit:0 -o empty -e ignore \
	    su -m ${TEST_USER} -c "chmod 777 ${PROTECTED}/file.txt"
	atf_check -s not-exit:0 -o empty -e ignore \
	    su -m ${TEST_USER} -c "mkdir ${PROTECTED}/newdir"

	# Nothing actually changed.
	atf_check -s exit:0 -o match:"^secret$" cat "${PROTECTED}/file.txt"
	atf_check -s not-exit:0 test -e "${PROTECTED}/newfile"

	# Root is exempt.
	atf_check -s exit:0 -o empty \
	    sh -c "echo rootwrite >> ${PROTECTED}/file.txt"

	stop_daemon
}
deny_mutations_cleanup() {
	stop_daemon 2>/dev/null || true
	teardown_protected
	rm -f /tmp/autodo-moved
	unload_module
}

# --- paths outside the deny list are unaffected ---

atf_test_case outside_allowed cleanup
outside_allowed_head() {
	atf_set "descr" "Paths outside the deny list remain writable"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
outside_allowed_body() {
	require_daemon
	load_module
	setup_protected
	start_daemon

	atf_check -s exit:0 -o empty \
	    su -m ${TEST_USER} -c "echo x > ${OPEN_TMP} && rm ${OPEN_TMP}"

	stop_daemon
}
outside_allowed_cleanup() {
	stop_daemon 2>/dev/null || true
	teardown_protected
	rm -f "${OPEN_TMP}"
	unload_module
}

# --- prefix matching does not overmatch ---

atf_test_case no_prefix_overmatch cleanup
no_prefix_overmatch_head() {
	atf_set "descr" "Sibling path sharing the prefix string is not denied"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
no_prefix_overmatch_body() {
	require_daemon
	load_module
	setup_protected
	start_daemon

	# /tmp/autodo-protected-other shares the string prefix but is not
	# under the denied directory.
	atf_check -s exit:0 -o empty \
	    su -m ${TEST_USER} -c "mkdir -p ${PROTECTED}-other && echo x > ${PROTECTED}-other/f && rm -rf ${PROTECTED}-other"

	stop_daemon
}
no_prefix_overmatch_cleanup() {
	stop_daemon 2>/dev/null || true
	teardown_protected
	rm -rf "${PROTECTED}-other"
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case empty_by_default
	atf_add_test_case deny_mutations
	atf_add_test_case outside_allowed
	atf_add_test_case no_prefix_overmatch
}
