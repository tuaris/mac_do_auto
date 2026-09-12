#!/usr/libexec/atf-sh
#
# kqueue(2) tests for the /dev/autodo audit ring.
#
# knlist_init_mtx() binds the knlist lock to autodo_ring_mtx, so f_event
# runs with that mutex already held.  A handler that locks it again
# recurses on a non-recursive mutex and panics an INVARIANTS kernel.
# These cases drive both call sites: the kevent(2) registration, and
# knote() delivery from the kernel.
#
# All tests run as root (required for kldload/sysctl).  Grants are
# generated as the non-root wheel user, with log_grants enabled so each
# grant pushes a ring event.
#

MODULE_DIR="$(atf_get_srcdir)/../src"
MODULE_PATH="${MODULE_DIR}/mac_do_auto.ko"
HELPER_SRC="$(atf_get_srcdir)/kq_ring_probe.c"
TEST_USER="admin"

load_module() {
	kldstat -q -m mac_do_auto 2>/dev/null && return 0
	kldload "${MODULE_PATH}" || atf_fail "cannot load mac_do_auto.ko"
}

unload_module() {
	kldstat -q -m mac_do_auto 2>/dev/null && kldunload mac_do_auto
	return 0
}

build_helper() {
	cc -I"${MODULE_DIR}" -o kq_ring_probe "${HELPER_SRC}" || \
	    atf_fail "cannot build ${HELPER_SRC}"
}

# A grant to the wheel user, which pushes one or more ring events.
generate_grant() {
	su -m ${TEST_USER} -c "cat /etc/master.passwd" >/dev/null 2>&1
}

enable_audit() {
	sysctl security.mac.autodo.log_grants=1 >/dev/null
}

# --- registration with events already in the ring ---

atf_test_case register_with_pending_events cleanup
register_with_pending_events_head() {
	atf_set "descr" "kevent registration reports events already in the ring"
	atf_set "require.user" "root"
	atf_set "require.progs" "cc"
}
register_with_pending_events_body() {
	load_module
	build_helper
	enable_audit
	generate_grant

	atf_check -s exit:0 -o match:"registered" -o match:"events=1 data=[1-9]" \
	    ./kq_ring_probe 5
}
register_with_pending_events_cleanup() {
	sysctl security.mac.autodo.log_grants=0 >/dev/null 2>&1
	unload_module
}

# --- knote() delivery into an empty ring ---

atf_test_case event_delivery cleanup
event_delivery_head() {
	atf_set "descr" "A grant wakes a registered knote through knote()"
	atf_set "require.user" "root"
	atf_set "require.progs" "cc"
}
event_delivery_body() {
	load_module
	build_helper
	enable_audit

	# The probe flushes the ring before registering, so the knote starts
	# inactive and the event has to arrive through knote().
	( sleep 2; generate_grant ) &
	atf_check -s exit:0 -o match:"registered" -o match:"events=1" \
	    ./kq_ring_probe -f 20
	wait
}
event_delivery_cleanup() {
	sysctl security.mac.autodo.log_grants=0 >/dev/null 2>&1
	unload_module
}

# --- teardown after the knote is gone ---

atf_test_case unload_after_kqueue_use cleanup
unload_after_kqueue_use_head() {
	atf_set "descr" "The module unloads cleanly once a kqueue consumer has exited"
	atf_set "require.user" "root"
	atf_set "require.progs" "cc"
}
unload_after_kqueue_use_body() {
	load_module
	build_helper
	enable_audit
	generate_grant

	atf_check -s exit:0 -o ignore ./kq_ring_probe 5
	# The device is closed and the knote detached, so the unload veto
	# no longer applies.
	atf_check -s exit:0 kldunload mac_do_auto
	atf_check -s exit:1 kldstat -q -m mac_do_auto
}
unload_after_kqueue_use_cleanup() {
	sysctl security.mac.autodo.log_grants=0 >/dev/null 2>&1
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case register_with_pending_events
	atf_add_test_case event_delivery
	atf_add_test_case unload_after_kqueue_use
}
