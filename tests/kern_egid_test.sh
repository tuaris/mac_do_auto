#!/usr/libexec/atf-sh
#
# Effective GID membership tests for mac_do_auto.
#
# A credential whose effective GID is the managed group, with that group
# absent from its real GID and supplementary groups, is autodo-managed.
# Such a process is produced by running a setgid-wheel binary as the test
# user with a group list narrowed to the user's primary group.
#
# All tests run as root (required for kldload/mount).  Commands run as
# the test user via chroot(8) -u/-g/-G, which drops wheel from the group
# list that "su -m" would provide.
#

MODULE_DIR="$(atf_get_srcdir)/../src"
MODULE_PATH="${MODULE_DIR}/mac_do_auto.ko"
DAEMON_PATH="$(atf_get_srcdir)/../daemon/zig-out/bin/autodo-eventd"
PROFILE_DIR="$(atf_get_srcdir)/../config/profiles"
TEST_USER="admin"
WORK="/tmp/autodo-egid"
SGID_BIN="${WORK}/bin"
SECRET="${WORK}/secret"
PROTECTED="${WORK}/protected"

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

require_daemon() {
	if [ ! -x "${DAEMON_PATH}" ]; then
		atf_skip "Daemon not built"
	fi
}

# Start the daemon managing wheel, with the path deny list active.
start_daemon() {
	TMPCONF=$(mktemp)
	cat > "${TMPCONF}" <<-EOF
	enabled = true;
	groups { wheel { profile = "all"; } }
	deny { paths = [ "${PROTECTED}" ]; }
	audit { enabled = false; }
	profile_dir = "${PROFILE_DIR}";
	EOF
	"${DAEMON_PATH}" --config="${TMPCONF}" >/dev/null 2>&1 &
	sleep 1
}

stop_daemon() {
	kill_daemon
	rm -f "${TMPCONF}"
}

# WORK/          tmpfs 0750 root:<test group>  (tmpfs honours setgid even
#                when /tmp is mounted nosuid)
# WORK/bin/      setgid-wheel copies of cat, id and touch
# WORK/secret    0600 root:wheel, readable by the test user only through
#                an autodo grant
# WORK/protected 0777, on the path deny list in the daemon cases
#
# Sets NARROW to a command prefix running as the test user with real,
# effective and supplementary GIDs all set to its primary group, and
# verifies the setgid binaries yield wheel as the effective GID only.
setup_work() {
	TEST_GID=$(id -g ${TEST_USER}) || atf_fail "no user ${TEST_USER}"
	TEST_GROUP=$(id -gn ${TEST_USER})
	[ "${TEST_GID}" != "0" ] || \
	    atf_skip "${TEST_USER}'s primary group is wheel"
	NARROW="chroot -u ${TEST_USER} -g ${TEST_GROUP} -G ${TEST_GROUP} /"

	teardown_work
	mkdir -p "${WORK}"
	mount -t tmpfs -o mode=0750 tmpfs "${WORK}" || \
	    atf_skip "cannot mount tmpfs on ${WORK}"
	chown root:${TEST_GROUP} "${WORK}"

	mkdir -m 0755 "${SGID_BIN}"
	for prog in /bin/cat /usr/bin/id /usr/bin/touch; do
		install -o root -g wheel -m 2555 "${prog}" "${SGID_BIN}/"
	done
	echo secret > "${SECRET}"
	chown root:wheel "${SECRET}"
	chmod 0600 "${SECRET}"
	mkdir -m 0777 "${PROTECTED}"

	atf_check -o inline:"${TEST_GID}\n" ${NARROW} /usr/bin/id -g
	atf_check -o inline:"0\n" ${NARROW} "${SGID_BIN}/id" -g
	atf_check -o inline:"${TEST_GID}\n" ${NARROW} "${SGID_BIN}/id" -rg
	atf_check -o inline:"${TEST_GID}\n" ${NARROW} "${SGID_BIN}/id" -G
}

teardown_work() {
	umount "${WORK}" 2>/dev/null
	rmdir "${WORK}" 2>/dev/null
	return 0
}

# --- baseline: effective wheel alone does not grant read ---

atf_test_case baseline_denied cleanup
baseline_denied_head() {
	atf_set "descr" "Setgid-wheel process cannot read a 0600 root file without module"
	atf_set "require.user" "root"
}
baseline_denied_body() {
	unload_module
	setup_work
	atf_check -s not-exit:0 -o empty -e ignore \
	    ${NARROW} "${SGID_BIN}/cat" "${SECRET}"
}
baseline_denied_cleanup() {
	teardown_work
	unload_module
}

# --- legacy single-GID path ---

atf_test_case legacy_grant cleanup
legacy_grant_head() {
	atf_set "descr" "Effective GID matching security.mac.autodo.gid is granted"
	atf_set "require.user" "root"
}
legacy_grant_body() {
	load_module
	setup_work

	# Without wheel in any position the user is not managed.
	atf_check -s not-exit:0 -o empty -e ignore \
	    ${NARROW} /bin/cat "${SECRET}"
	# Wheel as effective GID only is managed.
	atf_check -s exit:0 -o inline:"secret\n" \
	    ${NARROW} "${SGID_BIN}/cat" "${SECRET}"
}
legacy_grant_cleanup() {
	teardown_work
	unload_module
}

# --- multi-group policy path ---

atf_test_case policy_grant cleanup
policy_grant_head() {
	atf_set "descr" "Effective GID matching a policy group is granted"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
policy_grant_body() {
	require_daemon
	load_module
	setup_work
	start_daemon

	atf_check -s not-exit:0 -o empty -e ignore \
	    ${NARROW} /bin/cat "${SECRET}"
	atf_check -s exit:0 -o inline:"secret\n" \
	    ${NARROW} "${SGID_BIN}/cat" "${SECRET}"

	stop_daemon
}
policy_grant_cleanup() {
	stop_daemon 2>/dev/null || true
	teardown_work
	unload_module
}

# --- path deny list gate ---

atf_test_case path_deny cleanup
path_deny_head() {
	atf_set "descr" "Effective GID matching a managed group is subject to the path deny list"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
path_deny_body() {
	require_daemon
	load_module
	setup_work
	start_daemon

	# Not managed: the deny list does not apply.
	atf_check -s exit:0 -o empty -e empty \
	    ${NARROW} /usr/bin/touch "${PROTECTED}/plain"
	atf_check test -e "${PROTECTED}/plain"
	# Managed through the effective GID: create is denied.
	atf_check -s not-exit:0 -o empty -e ignore \
	    ${NARROW} "${SGID_BIN}/touch" "${PROTECTED}/sgid"
	atf_check -s not-exit:0 test -e "${PROTECTED}/sgid"

	stop_daemon
}
path_deny_cleanup() {
	stop_daemon 2>/dev/null || true
	teardown_work
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case baseline_denied
	atf_add_test_case legacy_grant
	atf_add_test_case policy_grant
	atf_add_test_case path_deny
}
