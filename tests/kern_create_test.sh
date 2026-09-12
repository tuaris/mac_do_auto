#!/usr/libexec/atf-sh
#
# Ownership of objects created through an autodo grant.
#
# A create that succeeds only because autodo grants write access to the
# parent directory yields an object owned by root, as under doas/mdo.
# Creates permitted by ordinary permissions keep the caller's ownership.
#
# All tests run as root (required for kldload/sysctl).  Creates run as
# the non-root wheel user via "su -m admin".
#

MODULE_DIR="$(atf_get_srcdir)/../src"
MODULE_PATH="${MODULE_DIR}/mac_do_auto.ko"
TEST_USER="admin"
WORK="/tmp/autodo-create"
JAIL_NAME="autodo_create_test"

load_module() {
	kldstat -q -m mac_do_auto 2>/dev/null && return 0
	kldload "${MODULE_PATH}" || atf_fail "cannot load mac_do_auto.ko"
}

unload_module() {
	kldstat -q -m mac_do_auto 2>/dev/null && kldunload mac_do_auto
	return 0
}

# root/   0755 root:wheel  writable by the test user only through autodo
# user/   0755 test user
# sticky/ 1777 root:wheel
# group/  0775 root:wheel  writable through wheel membership
setup_dirs() {
	rm -rf "${WORK}"
	mkdir -p "${WORK}/root" "${WORK}/user" "${WORK}/sticky" \
	    "${WORK}/group"
	chown root:wheel "${WORK}" "${WORK}/root" "${WORK}/sticky" \
	    "${WORK}/group"
	chmod 0755 "${WORK}" "${WORK}/root"
	chmod 1777 "${WORK}/sticky"
	chmod 0775 "${WORK}/group"
	chown ${TEST_USER} "${WORK}/user"
	chmod 0755 "${WORK}/user"
}

teardown_dirs() {
	rm -rf "${WORK}"
}

# Allocations of the module's malloc type (ring buffer plus live
# creation substitutes).
autodo_allocs() {
	vmstat -m | awk '$1 == "autodo" { print $2 }'
}

# --- baseline: create denied without module ---

atf_test_case baseline_denied cleanup
baseline_denied_head() {
	atf_set "descr" "Wheel user cannot create in a root-owned directory without the module"
	atf_set "require.user" "root"
}
baseline_denied_body() {
	unload_module
	setup_dirs
	atf_check -s not-exit:0 -e ignore \
	    su -m ${TEST_USER} -c "touch ${WORK}/root/file"
	atf_check -s not-exit:0 test -e "${WORK}/root/file"
}
baseline_denied_cleanup() {
	teardown_dirs
	unload_module
}

# --- regular files ---

atf_test_case file_owned_by_root cleanup
file_owned_by_root_head() {
	atf_set "descr" "Files created through a grant are owned by root"
	atf_set "require.user" "root"
}
file_owned_by_root_body() {
	load_module
	setup_dirs

	atf_check su -m ${TEST_USER} -c "touch ${WORK}/root/touched"
	atf_check su -m ${TEST_USER} -c "echo data > ${WORK}/root/redirected"
	atf_check -o inline:"0:0\n" stat -f '%u:%g' "${WORK}/root/touched"
	atf_check -o inline:"0:0\n" stat -f '%u:%g' "${WORK}/root/redirected"
	atf_check -o inline:"data\n" cat "${WORK}/root/redirected"

	# The descriptor returned by the create stays writable even when
	# the new root-owned file's mode denies the caller.
	atf_check su -m ${TEST_USER} -c \
	    "umask 0777 && echo secret > ${WORK}/root/mode0"
	atf_check -o inline:"0:0 0\n" stat -f '%u:%g %Lp' "${WORK}/root/mode0"
	atf_check -o inline:"secret\n" cat "${WORK}/root/mode0"
}
file_owned_by_root_cleanup() {
	teardown_dirs
	unload_module
}

# --- directories, FIFOs, symlinks ---

atf_test_case other_types_owned_by_root cleanup
other_types_owned_by_root_head() {
	atf_set "descr" "Directories, FIFOs and symlinks created through a grant are owned by root"
	atf_set "require.user" "root"
}
other_types_owned_by_root_body() {
	load_module
	setup_dirs

	atf_check su -m ${TEST_USER} -c "mkdir ${WORK}/root/dir"
	atf_check su -m ${TEST_USER} -c "mkfifo ${WORK}/root/fifo"
	atf_check su -m ${TEST_USER} -c "ln -s target ${WORK}/root/link"
	for obj in dir fifo link; do
		atf_check -o inline:"0:0\n" stat -f '%u:%g' "${WORK}/root/${obj}"
	done

	# The new directory is root-owned, so creates inside it are
	# escalated as well.
	atf_check su -m ${TEST_USER} -c "touch ${WORK}/root/dir/nested"
	atf_check -o inline:"0:0\n" stat -f '%u:%g' "${WORK}/root/dir/nested"
}
other_types_owned_by_root_cleanup() {
	teardown_dirs
	unload_module
}

# --- replace patterns used by pkg(8) and sqlite ---

atf_test_case replace_owned_by_root cleanup
replace_owned_by_root_head() {
	atf_set "descr" "Unlink/rename followed by create leaves a root-owned file"
	atf_set "require.user" "root"
}
replace_owned_by_root_body() {
	load_module
	setup_dirs
	echo old > "${WORK}/root/db"
	echo old > "${WORK}/root/journal"

	atf_check su -m ${TEST_USER} -c \
	    "mv ${WORK}/root/db ${WORK}/root/db-pkgtemp && echo new > ${WORK}/root/db"
	atf_check -o inline:"0:0\n" stat -f '%u:%g' "${WORK}/root/db"
	atf_check -o inline:"0:0\n" stat -f '%u:%g' "${WORK}/root/db-pkgtemp"
	atf_check -o inline:"new\n" cat "${WORK}/root/db"

	atf_check su -m ${TEST_USER} -c \
	    "rm ${WORK}/root/journal && echo new > ${WORK}/root/journal"
	atf_check -o inline:"0:0\n" stat -f '%u:%g' "${WORK}/root/journal"
}
replace_owned_by_root_cleanup() {
	teardown_dirs
	unload_module
}

# --- rename keeps the object's owner ---

atf_test_case rename_keeps_owner cleanup
rename_keeps_owner_head() {
	atf_set "descr" "Moving a caller-owned file into a root-owned directory keeps its owner, as for root"
	atf_set "require.user" "root"
}
rename_keeps_owner_body() {
	load_module
	setup_dirs
	uid=$(id -u ${TEST_USER})

	atf_check su -m ${TEST_USER} -c \
	    "echo mine > ${WORK}/user/staged && mv ${WORK}/user/staged ${WORK}/root/staged"
	atf_check -o inline:"${uid}\n" stat -f '%u' "${WORK}/root/staged"
}
rename_keeps_owner_cleanup() {
	teardown_dirs
	unload_module
}

# --- ordinary permissions keep caller ownership ---

atf_test_case writable_dirs_keep_caller cleanup
writable_dirs_keep_caller_head() {
	atf_set "descr" "Creates allowed without privilege keep the caller's ownership"
	atf_set "require.user" "root"
}
writable_dirs_keep_caller_body() {
	load_module
	setup_dirs
	uid=$(id -u ${TEST_USER})

	for d in user sticky group; do
		atf_check su -m ${TEST_USER} -c \
		    "touch ${WORK}/${d}/file && mkdir ${WORK}/${d}/dir"
		atf_check -o inline:"${uid}\n" stat -f '%u' "${WORK}/${d}/file"
		atf_check -o inline:"${uid}\n" stat -f '%u' "${WORK}/${d}/dir"
	done
}
writable_dirs_keep_caller_cleanup() {
	teardown_dirs
	unload_module
}

# --- jails ---

atf_test_case jail_owned_by_root cleanup
jail_owned_by_root_head() {
	atf_set "descr" "Escalated creates inside an autodo-enabled jail are owned by root"
	atf_set "require.user" "root"
}
jail_owned_by_root_body() {
	load_module
	setup_dirs
	jail -c name=${JAIL_NAME} path=/ host=new persist || \
	    atf_skip "cannot create jail"
	jail -m name=${JAIL_NAME} mac.autodo=new

	atf_check jexec -U ${TEST_USER} ${JAIL_NAME} touch "${WORK}/root/jailed"
	atf_check -o inline:"0:0\n" stat -f '%u:%g' "${WORK}/root/jailed"

	jail -m name=${JAIL_NAME} mac.autodo=disable
	atf_check -s not-exit:0 -e ignore \
	    jexec -U ${TEST_USER} ${JAIL_NAME} touch "${WORK}/root/denied"
	atf_check -s not-exit:0 test -e "${WORK}/root/denied"
}
jail_owned_by_root_cleanup() {
	jail -r ${JAIL_NAME} 2>/dev/null || true
	teardown_dirs
	unload_module
}

# --- substitutes are released and do not block unload ---

atf_test_case substitutes_released cleanup
substitutes_released_head() {
	atf_set "descr" "Concurrent escalated creates release their credentials and allow unload"
	atf_set "require.user" "root"
}
substitutes_released_body() {
	load_module
	setup_dirs
	before=$(autodo_allocs)

	atf_check su -m ${TEST_USER} -c \
	    "for p in 1 2 3 4; do (for i in \$(jot 100); do echo x > ${WORK}/root/p\${p}_\$i; done) & done; wait"
	atf_check -o inline:"400\n" \
	    sh -c "find ${WORK}/root -type f -uid 0 | wc -l | tr -d ' '"

	after=$(autodo_allocs)
	[ "${before}" = "${after}" ] || \
	    atf_fail "autodo allocations not released (${before} -> ${after})"
	atf_check kldunload mac_do_auto
}
substitutes_released_cleanup() {
	teardown_dirs
	unload_module
}

# --- end to end: pkg catalogue refreshed by a wheel user ---

atf_test_case pkg_catalogue_owned_by_root cleanup
pkg_catalogue_owned_by_root_head() {
	atf_set "descr" "Unprivileged pkg update writes a root-owned catalogue that pkg accepts"
	atf_set "require.user" "root"
	atf_set "require.progs" "pkg"
}
pkg_catalogue_owned_by_root_body() {
	load_module
	setup_dirs
	R="${WORK}/pkg"
	mkdir -p "${R}/src/root/usr/local/share/autodo-create" "${R}/repo" \
	    "${R}/repos.d" "${R}/db/repos"
	echo hello > "${R}/src/root/usr/local/share/autodo-create/hello"
	echo /usr/local/share/autodo-create/hello > "${R}/src/plist"
	cat > "${R}/src/+MANIFEST" <<-EOF
	name: autodo-create
	version: "1.0"
	origin: sysutils/autodo-create
	comment: mac_do_auto test package
	desc: mac_do_auto test package
	maintainer: nobody@example.org
	www: https://example.org
	prefix: /usr/local
	abi: "$(pkg config abi)"
	EOF
	atf_check -o ignore -e ignore pkg create -M "${R}/src/+MANIFEST" \
	    -p "${R}/src/plist" -r "${R}/src/root" -o "${R}/repo"
	atf_check -o ignore -e ignore pkg repo "${R}/repo"
	echo "scratch: { url: \"file://${R}/repo\", enabled: yes, signature_type: \"none\" }" \
	    > "${R}/repos.d/scratch.conf"
	chmod -R a+rX "${R}"
	chmod 0755 "${R}/db" "${R}/db/repos"

	opts="-o PKG_DBDIR=${R}/db -o REPOS_DIR=${R}/repos.d -o PKG_CACHEDIR=${R}/cache"
	atf_check -o ignore -e ignore \
	    su -m ${TEST_USER} -c "pkg ${opts} update -f -q -r scratch"
	atf_check -o inline:"0:0\n" stat -f '%u:%g' "${R}/db/repos/scratch/db"
	atf_check -o inline:"0:0\n" \
	    stat -f '%u:%g' "${R}/db/repos/scratch/db-journal"
	atf_check -o inline:"autodo-create-1.0\n" \
	    pkg ${opts} rquery -r scratch '%n-%v'
}
pkg_catalogue_owned_by_root_cleanup() {
	teardown_dirs
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case baseline_denied
	atf_add_test_case file_owned_by_root
	atf_add_test_case other_types_owned_by_root
	atf_add_test_case replace_owned_by_root
	atf_add_test_case rename_keeps_owner
	atf_add_test_case writable_dirs_keep_caller
	atf_add_test_case jail_owned_by_root
	atf_add_test_case substitutes_released
	atf_add_test_case pkg_catalogue_owned_by_root
}
