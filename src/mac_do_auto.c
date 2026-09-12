/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Daniel Morante
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * mac_do_auto - Transparent privilege escalation for authorized users.
 *
 * This MAC policy module grants privileges to processes whose credentials
 * include membership in a configured group (default: wheel/GID 0), without
 * requiring explicit use of mdo(1), sudo(8), or doas(1).
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/jail.h>
#include <sys/osd.h>
#include <sys/mount.h>
#include <sys/sx.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/filio.h>
#include <sys/event.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>

#include <security/mac/mac_policy.h>

#include "autodo.h"

/*
 * Every priv(9) constant needs a bitmap bit, and every ioctl parameter
 * must fit the IOCPARM_MASK length field of the command encoding.
 */
CTASSERT(_PRIV_HIGHEST <= AUTODO_BITMAP_BITS);
CTASSERT(sizeof(struct autodo_scope) <= IOCPARM_MASK);
CTASSERT(sizeof(struct autodo_policy) <= IOCPARM_MASK);
CTASSERT(sizeof(struct autodo_pathlist) <= IOCPARM_MASK);

/*
 * Privilege scope bitmap (legacy single-group mode).
 * A set bit means the privilege IS granted.  Default: all bits set ("all").
 */
static volatile uint64_t autodo_scope_bitmap[AUTODO_BITMAP_WORDS];

/*
 * Multi-group policy.
 * When autodo_policy_count > 0, priv_grant uses per-GID bitmaps.
 * When autodo_policy_count == 0, falls back to legacy single-GID behavior.
 * The policy array is updated atomically by the daemon via ioctl.
 */
static struct autodo_policy_entry autodo_policy_entries[AUTODO_MAX_GROUPS];
static volatile int autodo_policy_count;	/* 0 = legacy mode */

/*
 * Global path deny list.
 *
 * Written wholesale by the daemon via AUTODO_SET_PATHS under an
 * exclusive sx; readers in the vnode check hooks take it shared.
 * Empty by default.
 */
static struct sx	autodo_paths_sx;
static char	autodo_paths[AUTODO_MAX_PATHS][AUTODO_PATH_LEN];
static u_int	autodo_paths_count;
static struct timeval autodo_pathlog_lasttime;

/*
 * Per-thread marker handing a matched lookup off to check_open/setattr
 * (see autodo_vnode_check_lookup).  Single slot, advisory.
 */
static struct thread *autodo_mark_td;
static char	autodo_mark_path[AUTODO_PATH_LEN];

/*
 * Escalated object creation.
 *
 * Filesystems take the owner of a new vnode from cnp->cn_cred.  When the
 * parent directory is writable only through an autodo grant,
 * autodo_vnode_check_create() replaces cn_cred with a copy of the caller's
 * credential whose euid is 0, so the object is owned by root as it would
 * be under mdo(1) or doas(1).  Substitutes are kept on the creating thread
 * (thread OSD) and released when it returns to user mode (AUTODO_TDA AST)
 * or is destroyed.  The module claims the TDA_MOD4 AST slot.
 */
#define	AUTODO_TDA	TDA_MOD4

struct autodo_esc {
	SLIST_ENTRY(autodo_esc) ae_link;
	struct ucred	*ae_src;	/* caller credential (held) */
	struct ucred	*ae_cred;	/* euid 0 copy installed in cn_cred */
};

struct autodo_td {
	SLIST_HEAD(, autodo_esc) at_esc;
};

static u_int	autodo_td_slot;
static struct mtx autodo_esc_mtx;
static u_int	autodo_esc_count;	/* live substitutes (autodo_esc_mtx) */
static int	autodo_esc_dying;	/* unload in progress (autodo_esc_mtx) */

/*
 * Threads probing whether a directory is writable without autodo;
 * autodo_priv_grant() abstains for them.  Entries live on the probing
 * thread's stack.
 */
#define	AUTODO_PROBE_BUCKETS	32

struct autodo_probe {
	LIST_ENTRY(autodo_probe) ap_link;
	struct thread	*ap_td;
};

static struct autodo_probe_bucket {
	struct mtx	apb_mtx;
	LIST_HEAD(, autodo_probe) apb_list;
} autodo_probe_buckets[AUTODO_PROBE_BUCKETS];
static volatile u_int autodo_probe_count;

#define	AUTODO_PROBE_BUCKET(td)						\
	(&autodo_probe_buckets[(u_int)(td)->td_tid % AUTODO_PROBE_BUCKETS])

static inline int
autodo_priv_in_scope(int priv)
{
	unsigned word, bit;

	if (priv <= 0 || priv >= AUTODO_BITMAP_BITS)
		return (0);
	word = (unsigned)priv / 64;
	bit = (unsigned)priv % 64;
	return ((autodo_scope_bitmap[word] >> bit) & 1);
}

static inline void
autodo_bitmap_set(volatile uint64_t *bitmap, int priv)
{
	unsigned word, bit;

	if (priv <= 0 || priv >= AUTODO_BITMAP_BITS)
		return;
	word = (unsigned)priv / 64;
	bit = (unsigned)priv % 64;
	bitmap[word] |= (1UL << bit);
}

static void
autodo_bitmap_fill(volatile uint64_t *bitmap)
{
	int i;

	for (i = 0; i < AUTODO_BITMAP_WORDS; i++)
		bitmap[i] = ~0UL;
}

/*
 * Privilege categories for the 'scope' sysctl.
 * Categories map to ranges of priv(9) constants, and a category may hold
 * several ranges.  Every PRIV_* constant belongs to exactly one category,
 * so naming every category grants what "all" grants; the daemon's zig
 * test checks that against <sys/priv.h>.  The ranges must match
 * priv_categories in daemon/src/main.zig, which
 * tests/kern_scope_test.sh compares against this table.
 */
#define	AUTODO_CAT_SYSTEM	0x0001
#define	AUTODO_CAT_AUDIT	0x0002
#define	AUTODO_CAT_CRED		0x0004
#define	AUTODO_CAT_DEBUG	0x0008
#define	AUTODO_CAT_JAIL		0x0010
#define	AUTODO_CAT_KLD		0x0020
#define	AUTODO_CAT_PROC		0x0040
#define	AUTODO_CAT_VFS		0x0080
#define	AUTODO_CAT_VM		0x0100
#define	AUTODO_CAT_DEV		0x0200
#define	AUTODO_CAT_NET		0x0400
#define	AUTODO_CAT_MISC		0x0800
#define	AUTODO_CAT_ALL		0x0FFF

struct autodo_priv_range {
	uint32_t	cat;
	int		start;
	int		end;	/* inclusive */
};

static const struct autodo_priv_range autodo_cat_ranges[] = {
	{ AUTODO_CAT_SYSTEM, 2, 18 },	/* ACCT..SETTIMEOFDAY */
	{ AUTODO_CAT_SYSTEM, 100, 100 },	/* FIRMWARE_LOAD */
	{ AUTODO_CAT_SYSTEM, 120, 121 },	/* KENV_SET, KENV_UNSET */
	{ AUTODO_CAT_AUDIT, 40, 44 },
	{ AUTODO_CAT_CRED, 50, 62 },
	{ AUTODO_CAT_DEBUG, 80, 92 },	/* DEBUG + DTRACE */
	{ AUTODO_CAT_JAIL, 110, 112 },
	{ AUTODO_CAT_KLD, 130, 141 },	/* KLD + MAC */
	{ AUTODO_CAT_PROC, 160, 243 },	/* PROC,IPC,MQ,PMC,SCHED,SEM,SIGNAL,SYSCTL */
	{ AUTODO_CAT_VFS, 270, 273 },	/* UFS */
	{ AUTODO_CAT_VFS, 280, 282 },	/* ZFS */
	{ AUTODO_CAT_VFS, 290, 291 },	/* NFS */
	{ AUTODO_CAT_VFS, 310, 345 },	/* VFS */
	{ AUTODO_CAT_VM, 360, 364 },
	{ AUTODO_CAT_DEV, 250, 256 },	/* TTY */
	{ AUTODO_CAT_DEV, 370, 380 },	/* DEVFS, RANDOM */
	{ AUTODO_CAT_NET, 390, 540 },	/* all networking */
	{ AUTODO_CAT_MISC, 550, 710 },	/* MODULE,KMEM,RCTL,VERIEXEC,VMM,etc */
};

#define	AUTODO_NUM_RANGES	nitems(autodo_cat_ranges)

/*
 * Rebuild the scope bitmap from a category bitmask.
 */
static void
autodo_rebuild_bitmap(uint32_t cats)
{
	int i, p;

	/* Start with empty bitmap. */
	for (i = 0; i < AUTODO_BITMAP_WORDS; i++)
		autodo_scope_bitmap[i] = 0;

	if (cats == AUTODO_CAT_ALL) {
		autodo_bitmap_fill(autodo_scope_bitmap);
		return;
	}

	for (i = 0; i < (int)AUTODO_NUM_RANGES; i++) {
		if ((cats & autodo_cat_ranges[i].cat) == 0)
			continue;
		for (p = autodo_cat_ranges[i].start;
		    p <= autodo_cat_ranges[i].end; p++)
			autodo_bitmap_set(autodo_scope_bitmap, p);
	}
}

static uint32_t	autodo_scope_cats = AUTODO_CAT_ALL;

/*
 * Sysctl handler for 'scope' — accepts comma-separated category names or "all".
 */
static int
autodo_sysctl_scope(SYSCTL_HANDLER_ARGS)
{
	char buf[128];
	uint32_t new_cats;
	int error;
	char *p, *token;

	/* Build current string representation for reading. */
	if (autodo_scope_cats == AUTODO_CAT_ALL)
		strlcpy(buf, "all", sizeof(buf));
	else {
		buf[0] = '\0';
		if (autodo_scope_cats & AUTODO_CAT_SYSTEM)
			strlcat(buf, "system,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_AUDIT)
			strlcat(buf, "audit,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_CRED)
			strlcat(buf, "cred,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_DEBUG)
			strlcat(buf, "debug,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_JAIL)
			strlcat(buf, "jail,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_KLD)
			strlcat(buf, "kld,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_PROC)
			strlcat(buf, "proc,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_VFS)
			strlcat(buf, "vfs,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_VM)
			strlcat(buf, "vm,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_DEV)
			strlcat(buf, "dev,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_NET)
			strlcat(buf, "net,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_MISC)
			strlcat(buf, "misc,", sizeof(buf));
		/* Remove trailing comma. */
		p = buf + strlen(buf) - 1;
		if (p >= buf && *p == ',')
			*p = '\0';
	}

	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	/* Parse new value. */
	if (strcmp(buf, "all") == 0) {
		new_cats = AUTODO_CAT_ALL;
	} else {
		new_cats = 0;
		p = buf;
		while ((token = strsep(&p, ",")) != NULL) {
			if (*token == '\0')
				continue;
			if (strcmp(token, "system") == 0)
				new_cats |= AUTODO_CAT_SYSTEM;
			else if (strcmp(token, "audit") == 0)
				new_cats |= AUTODO_CAT_AUDIT;
			else if (strcmp(token, "cred") == 0)
				new_cats |= AUTODO_CAT_CRED;
			else if (strcmp(token, "debug") == 0)
				new_cats |= AUTODO_CAT_DEBUG;
			else if (strcmp(token, "jail") == 0)
				new_cats |= AUTODO_CAT_JAIL;
			else if (strcmp(token, "kld") == 0)
				new_cats |= AUTODO_CAT_KLD;
			else if (strcmp(token, "proc") == 0)
				new_cats |= AUTODO_CAT_PROC;
			else if (strcmp(token, "vfs") == 0)
				new_cats |= AUTODO_CAT_VFS;
			else if (strcmp(token, "vm") == 0)
				new_cats |= AUTODO_CAT_VM;
			else if (strcmp(token, "dev") == 0)
				new_cats |= AUTODO_CAT_DEV;
			else if (strcmp(token, "net") == 0)
				new_cats |= AUTODO_CAT_NET;
			else if (strcmp(token, "misc") == 0)
				new_cats |= AUTODO_CAT_MISC;
			else
				return (EINVAL);
		}
		if (new_cats == 0)
			return (EINVAL);
	}

	autodo_scope_cats = new_cats;
	autodo_rebuild_bitmap(new_cats);
	return (0);
}

static int	autodo_enabled = 1;
static int	autodo_gid = 0;
static int	autodo_log_grants = 0;
static unsigned long autodo_grant_count = 0;

static struct timeval autodo_log_lasttime;
static unsigned	autodo_osd_jail_slot;

SYSCTL_NODE(_security_mac, OID_AUTO, autodo, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "autodo policy controls");

SYSCTL_INT(_security_mac_autodo, OID_AUTO, enabled,
    CTLFLAG_RW | CTLFLAG_MPSAFE, &autodo_enabled, 0,
    "Enable transparent privilege escalation for authorized group");

SYSCTL_INT(_security_mac_autodo, OID_AUTO, gid,
    CTLFLAG_RW | CTLFLAG_MPSAFE, &autodo_gid, 0,
    "GID whose members receive implicit privileges (default: 0/wheel)");

SYSCTL_INT(_security_mac_autodo, OID_AUTO, log_grants,
    CTLFLAG_RW | CTLFLAG_MPSAFE, &autodo_log_grants, 0,
    "Log privilege grants to kernel message buffer (rate-limited)");

SYSCTL_ULONG(_security_mac_autodo, OID_AUTO, grant_count,
    CTLFLAG_RD | CTLFLAG_MPSAFE, &autodo_grant_count, 0,
    "Total number of privileges granted (read-only)");

SYSCTL_PROC(_security_mac_autodo, OID_AUTO, scope,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    autodo_sysctl_scope, "A",
    "Privilege scope: comma-separated categories or 'all' (default: all)");

SYSCTL_JAIL_PARAM_SYS_SUBNODE(mac, autodo, CTLFLAG_RW,
    "Jail MAC/autodo parameters");

/* ----------------------------------------------------------------
 * /dev/autodo character device — ring buffer + ioctl interface
 * ---------------------------------------------------------------- */

MALLOC_DEFINE(M_AUTODO, "autodo", "autodo ring buffer");

static struct mtx	autodo_ring_mtx;
static struct autodo_event *autodo_ring;
static unsigned		autodo_ring_head;	/* next write position */
static unsigned		autodo_ring_tail;	/* next read position */
static unsigned		autodo_ring_count;	/* events available */
static struct selinfo	autodo_sel;
static struct cdev	*autodo_cdev;
static int		autodo_dev_open;	/* single-open flag */
static int		autodo_dev_dying;	/* set when module is unloading */

static void
autodo_ring_push(const struct autodo_event *ev)
{

	mtx_lock(&autodo_ring_mtx);
	if (autodo_ring == NULL) {
		mtx_unlock(&autodo_ring_mtx);
		return;
	}
	autodo_ring[autodo_ring_head] = *ev;
	autodo_ring_head = (autodo_ring_head + 1) % AUTODO_RING_SIZE;
	if (autodo_ring_count < AUTODO_RING_SIZE)
		autodo_ring_count++;
	else
		autodo_ring_tail = (autodo_ring_tail + 1) % AUTODO_RING_SIZE;
	wakeup(&autodo_ring_count);
	mtx_unlock(&autodo_ring_mtx);
	selwakeup(&autodo_sel);
	KNOTE_UNLOCKED(&autodo_sel.si_note, 0);
}

static void
autodo_emit_event(struct ucred *cred, int priv, int granted)
{
	struct autodo_event ev;
	struct timespec ts;

	nanouptime(&ts);
	ev.ae_timestamp = (uint64_t)ts.tv_sec * 1000000000ULL +
	    (uint64_t)ts.tv_nsec;
	ev.ae_pid = curproc->p_pid;
	ev.ae_uid = cred->cr_uid;
	ev.ae_gid = cred->cr_rgid;
	ev.ae_priv = priv;
	ev.ae_granted = granted ? 1 : 0;
	memset(ev.ae_pad, 0, sizeof(ev.ae_pad));
	strlcpy(ev.ae_comm, curproc->p_comm, sizeof(ev.ae_comm));

	autodo_ring_push(&ev);
}

static int
autodo_dev_open_f(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td __unused)
{

	/*
	 * The dying check and the open flag are set under the same lock
	 * the MOD_QUIESCE veto holds, so an open(2) cannot slip in
	 * between the veto and destroy_dev().
	 */
	mtx_lock(&autodo_ring_mtx);
	if (autodo_dev_dying) {
		mtx_unlock(&autodo_ring_mtx);
		return (ENXIO);
	}
	if (autodo_dev_open) {
		mtx_unlock(&autodo_ring_mtx);
		return (EBUSY);
	}
	autodo_dev_open = 1;
	mtx_unlock(&autodo_ring_mtx);
	return (0);
}

static int
autodo_dev_close_f(struct cdev *dev __unused, int fflag __unused,
    int devtype __unused, struct thread *td __unused)
{

	/* Serialize with the MOD_QUIESCE veto in mac_do_auto_modevent(). */
	mtx_lock(&autodo_ring_mtx);
	autodo_dev_open = 0;
	mtx_unlock(&autodo_ring_mtx);
	return (0);
}

/*
 * Called by destroy_dev() (via devfs) with devmtx held whenever threads
 * are still inside cdevsw methods during teardown.  Wake any thread
 * sleeping in read(2) so it can observe autodo_dev_dying and exit,
 * allowing destroy_dev() to drain si_threadcount and return.
 */
static void
autodo_dev_purge(struct cdev *dev __unused)
{

	mtx_lock(&autodo_ring_mtx);
	autodo_dev_dying = 1;
	wakeup(&autodo_ring_count);
	mtx_unlock(&autodo_ring_mtx);
	selwakeup(&autodo_sel);
}

static int
autodo_dev_read(struct cdev *dev __unused, struct uio *uio,
    int ioflag __unused)
{
	struct autodo_event ev;
	int error;

	mtx_lock(&autodo_ring_mtx);
	while (autodo_ring_count == 0) {
		if (autodo_dev_dying) {
			mtx_unlock(&autodo_ring_mtx);
			return (ENXIO);
		}
		error = msleep(&autodo_ring_count, &autodo_ring_mtx,
		    PCATCH, "autodo", 0);
		if (error != 0) {
			mtx_unlock(&autodo_ring_mtx);
			return (error);
		}
	}

	while (uio->uio_resid >= (ssize_t)sizeof(ev) &&
	    autodo_ring_count > 0) {
		ev = autodo_ring[autodo_ring_tail];
		autodo_ring_tail = (autodo_ring_tail + 1) % AUTODO_RING_SIZE;
		autodo_ring_count--;
		mtx_unlock(&autodo_ring_mtx);

		error = uiomove(&ev, sizeof(ev), uio);
		if (error != 0)
			return (error);

		mtx_lock(&autodo_ring_mtx);
	}
	mtx_unlock(&autodo_ring_mtx);
	return (0);
}

static int
autodo_dev_poll(struct cdev *dev __unused, int events, struct thread *td)
{
	int revents = 0;

	mtx_lock(&autodo_ring_mtx);
	if (events & (POLLIN | POLLRDNORM)) {
		if (autodo_ring_count > 0)
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &autodo_sel);
	}
	if (autodo_dev_dying)
		revents |= POLLERR;
	mtx_unlock(&autodo_ring_mtx);
	return (revents);
}

static int
autodo_dev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td __unused)
{
	struct autodo_scope *scope;
	int i;

	switch (cmd) {
	case AUTODO_SET_SCOPE:
		scope = (struct autodo_scope *)data;
		for (i = 0; i < AUTODO_BITMAP_WORDS; i++)
			autodo_scope_bitmap[i] = scope->as_bitmap[i];
		return (0);

	case AUTODO_GET_SCOPE:
		scope = (struct autodo_scope *)data;
		for (i = 0; i < AUTODO_BITMAP_WORDS; i++)
			scope->as_bitmap[i] = autodo_scope_bitmap[i];
		return (0);

	case AUTODO_FLUSH:
		mtx_lock(&autodo_ring_mtx);
		autodo_ring_head = 0;
		autodo_ring_tail = 0;
		autodo_ring_count = 0;
		mtx_unlock(&autodo_ring_mtx);
		return (0);

	case AUTODO_SET_POLICY: {
		struct autodo_policy *pol = (struct autodo_policy *)data;
		if (pol->ap_count > AUTODO_MAX_GROUPS)
			return (EINVAL);
		/*
		 * Write entries first, then publish count.
		 * Readers see count via volatile read; entries
		 * are stable by the time count is visible.
		 */
		for (i = 0; i < (int)pol->ap_count; i++)
			autodo_policy_entries[i] = pol->ap_entries[i];
		atomic_thread_fence_rel();
		autodo_policy_count = (int)pol->ap_count;
		return (0);
	}

	case AUTODO_GET_POLICY: {
		struct autodo_policy *pol = (struct autodo_policy *)data;
		int cnt = autodo_policy_count;
		pol->ap_count = (uint32_t)cnt;
		pol->ap_pad = 0;
		for (i = 0; i < cnt && i < AUTODO_MAX_GROUPS; i++)
			pol->ap_entries[i] = autodo_policy_entries[i];
		for (; i < AUTODO_MAX_GROUPS; i++)
			memset(&pol->ap_entries[i], 0,
			    sizeof(pol->ap_entries[i]));
		return (0);
	}

	case AUTODO_SET_PATHS: {
		struct autodo_pathlist *pl = (struct autodo_pathlist *)data;
		u_int n;

		if (pl->apl_count > AUTODO_MAX_PATHS)
			return (EINVAL);

		/* Validate: force NUL termination, absolute paths only. */
		for (n = 0; n < pl->apl_count; n++) {
			pl->apl_paths[n][AUTODO_PATH_LEN - 1] = '\0';
			if (pl->apl_paths[n][0] != '/')
				return (EINVAL);
			/* Strip trailing slashes (except root "/"). */
			while (strlen(pl->apl_paths[n]) > 1 &&
			    pl->apl_paths[n][strlen(pl->apl_paths[n]) - 1] == '/')
				pl->apl_paths[n][strlen(pl->apl_paths[n]) - 1] =
				    '\0';
		}

		sx_xlock(&autodo_paths_sx);
		for (n = 0; n < pl->apl_count; n++)
			memcpy(autodo_paths[n], pl->apl_paths[n],
			    AUTODO_PATH_LEN);
		autodo_paths_count = pl->apl_count;
		autodo_mark_td = NULL;
		sx_xunlock(&autodo_paths_sx);
		return (0);
	}

	case AUTODO_GET_PATHS: {
		struct autodo_pathlist *pl = (struct autodo_pathlist *)data;

		sx_slock(&autodo_paths_sx);
		pl->apl_count = autodo_paths_count;
		pl->apl_pad = 0;
		for (i = 0; i < (int)autodo_paths_count; i++)
			memcpy(pl->apl_paths[i], autodo_paths[i],
			    AUTODO_PATH_LEN);
		sx_sunlock(&autodo_paths_sx);
		return (0);
	}

	default:
		return (ENOTTY);
	}
}

static int	autodo_kqread(struct knote *kn, long hint);
static void	autodo_kqdetach(struct knote *kn);

static const struct filterops autodo_read_filterops = {
	.f_isfd = true,
	.f_attach = NULL,
	.f_detach = autodo_kqdetach,
	.f_event = autodo_kqread,
};

static int
autodo_dev_kqfilter(struct cdev *dev __unused, struct knote *kn)
{

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &autodo_read_filterops;
		knlist_add(&autodo_sel.si_note, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

/*
 * knlist_init_mtx() binds the knlist lock to autodo_ring_mtx, so both
 * kevent(2) registration and knote() call this with the mutex already
 * held; locking it again would recurse on a non-recursive mutex.
 */
static int
autodo_kqread(struct knote *kn, long hint __unused)
{

	mtx_assert(&autodo_ring_mtx, MA_OWNED);
	kn->kn_data = autodo_ring_count * sizeof(struct autodo_event);
	return (kn->kn_data > 0);
}

static void
autodo_kqdetach(struct knote *kn)
{

	knlist_remove(&autodo_sel.si_note, kn, 0);
}

static struct cdevsw autodo_cdevsw = {
	.d_version = D_VERSION,
	.d_open = autodo_dev_open_f,
	.d_close = autodo_dev_close_f,
	.d_read = autodo_dev_read,
	.d_poll = autodo_dev_poll,
	.d_ioctl = autodo_dev_ioctl,
	.d_kqfilter = autodo_dev_kqfilter,
	.d_purge = autodo_dev_purge,
	.d_name = "autodo",
};

/*
 * Per-jail OSD stores the jail's autodo mode as an intptr_t:
 *   0 (JAIL_SYS_DISABLE) - disabled in this jail
 *   1 (JAIL_SYS_NEW)     - enabled in this jail
 *   2 (JAIL_SYS_INHERIT) - inherit from parent jail
 *
 * We encode the mode +1 in the OSD pointer to distinguish "no OSD set"
 * (NULL) from "explicitly disabled" (value 1).  Decoding: mode = ptr - 1.
 */
#define	AUTODO_OSD_ENCODE(mode)	((void *)((intptr_t)(mode) + 1))
#define	AUTODO_OSD_DECODE(ptr)	((int)((intptr_t)(ptr) - 1))

static void
autodo_osd_jail_destructor(void *value __unused)
{
	/* Nothing to free — we store encoded integers, not pointers. */
}

static int
autodo_jail_create(void *obj, void *data __unused)
{
	struct prison *pr = obj;

	/* New jails default to disabled. */
	osd_jail_set(pr, autodo_osd_jail_slot,
	    AUTODO_OSD_ENCODE(JAIL_SYS_DISABLE));
	return (0);
}

static int
autodo_jail_get(void *obj, void *data)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	void *osd_val;
	int jsys, error;

	osd_val = osd_jail_get(pr, autodo_osd_jail_slot);
	if (osd_val == NULL)
		jsys = JAIL_SYS_DISABLE;
	else
		jsys = AUTODO_OSD_DECODE(osd_val);

	error = vfs_setopt(opts, "mac.autodo", &jsys, sizeof(jsys));
	if (error != 0 && error != ENOENT)
		return (error);
	return (0);
}

static int
autodo_jail_check(void *obj __unused, void *data)
{
	struct vfsoptlist *opts = data;
	int error, jsys;

	error = vfs_copyopt(opts, "mac.autodo", &jsys, sizeof(jsys));
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (error);
	if (jsys != JAIL_SYS_DISABLE && jsys != JAIL_SYS_NEW &&
	    jsys != JAIL_SYS_INHERIT)
		return (EINVAL);
	return (0);
}

static int
autodo_jail_set(void *obj, void *data)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	int error, jsys;

	error = vfs_copyopt(opts, "mac.autodo", &jsys, sizeof(jsys));
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (error);

	osd_jail_set(pr, autodo_osd_jail_slot,
	    AUTODO_OSD_ENCODE(jsys));
	return (0);
}

static const osd_method_t autodo_osd_methods[PR_MAXMETHOD] = {
	[PR_METHOD_CREATE] = autodo_jail_create,
	[PR_METHOD_GET] = autodo_jail_get,
	[PR_METHOD_CHECK] = autodo_jail_check,
	[PR_METHOD_SET] = autodo_jail_set,
};

/*
 * Check if autodo is enabled for the given prison.
 * Walks up the jail hierarchy for JAIL_SYS_INHERIT.
 * Returns 1 if enabled, 0 if disabled.
 */
static int
autodo_jail_enabled(struct prison *pr)
{
	void *osd_val;
	int jsys;

	for (; pr != NULL; pr = pr->pr_parent) {
		osd_val = osd_jail_get(pr, autodo_osd_jail_slot);
		if (osd_val == NULL)
			return (0);
		jsys = AUTODO_OSD_DECODE(osd_val);
		switch (jsys) {
		case JAIL_SYS_NEW:
			return (1);
		case JAIL_SYS_DISABLE:
			return (0);
		case JAIL_SYS_INHERIT:
			continue;
		default:
			return (0);
		}
	}
	return (0);
}

/*
 * Check if the credential includes the authorized GID in any position:
 * real GID, effective GID (cr_gid), or supplementary groups (cr_groups).
 */
static int
autodo_cred_has_gid(struct ucred *cred, gid_t gid)
{
	int i;

	if (cred->cr_gid == gid || cred->cr_rgid == gid)
		return (1);
	for (i = 0; i < cred->cr_ngroups; i++) {
		if (cred->cr_groups[i] == gid)
			return (1);
	}
	return (0);
}

/*
 * Check if a privilege is set in a specific bitmap.
 */
static inline int
autodo_priv_in_bitmap(const uint64_t *bitmap, int priv)
{
	unsigned word, bit;

	if (priv <= 0 || priv >= AUTODO_BITMAP_BITS)
		return (0);
	word = (unsigned)priv / 64;
	bit = (unsigned)priv % 64;
	return ((bitmap[word] >> bit) & 1);
}

#define	AUTODO_ABSTAIN		0
#define	AUTODO_GRANT		1
#define	AUTODO_SCOPE_DENY	2	/* managed group, privilege out of scope */

/*
 * Policy decision for a privilege request, without accounting or audit.
 */
static int
autodo_priv_decide(struct ucred *cred, int priv)
{
	struct prison *pr;
	int i, policy_count;

	if (!autodo_enabled)
		return (AUTODO_ABSTAIN);

	/*
	 * Check jail policy.  The host (prison0) is always governed by
	 * the global 'enabled' sysctl above.  For jails, check per-jail
	 * OSD configuration.
	 */
	pr = cred->cr_prison;
	if (pr != &prison0 && !autodo_jail_enabled(pr))
		return (AUTODO_ABSTAIN);

	/*
	 * Multi-group policy path.  When the daemon has pushed a policy
	 * (policy_count > 0), the first entry whose GID the credential
	 * holds decides: grant if its bitmap includes the privilege,
	 * otherwise deny.  No matching entry abstains.
	 */
	policy_count = autodo_policy_count;
	if (policy_count > 0) {
		for (i = 0; i < policy_count; i++) {
			if (!autodo_cred_has_gid(cred,
			    autodo_policy_entries[i].ape_gid))
				continue;
			if (!autodo_priv_in_bitmap(
			    autodo_policy_entries[i].ape_bitmap, priv))
				return (AUTODO_SCOPE_DENY);
			return (AUTODO_GRANT);
		}
		return (AUTODO_ABSTAIN);
	}

	/*
	 * Legacy single-GID path (no daemon, manual sysctl use).
	 */
	if (!autodo_cred_has_gid(cred, (gid_t)autodo_gid))
		return (AUTODO_ABSTAIN);
	if (!autodo_priv_in_scope(priv))
		return (AUTODO_SCOPE_DENY);
	return (AUTODO_GRANT);
}

static int
autodo_probing(struct thread *td)
{
	struct autodo_probe_bucket *b;
	struct autodo_probe *p;
	int found;

	b = AUTODO_PROBE_BUCKET(td);
	found = 0;
	mtx_lock(&b->apb_mtx);
	LIST_FOREACH(p, &b->apb_list, ap_link) {
		if (p->ap_td == td) {
			found = 1;
			break;
		}
	}
	mtx_unlock(&b->apb_mtx);
	return (found);
}

/*
 * Returns 1 when cred can write directory dvp without an autodo grant
 * (permissions, ACLs, or another policy).  dvp must be locked.
 */
static int
autodo_dir_writable_unaided(struct ucred *cred, struct vnode *dvp)
{
	struct autodo_probe probe;
	struct autodo_probe_bucket *b;
	struct thread *td;
	int error;

	td = curthread;
	probe.ap_td = td;
	b = AUTODO_PROBE_BUCKET(td);
	mtx_lock(&b->apb_mtx);
	LIST_INSERT_HEAD(&b->apb_list, &probe, ap_link);
	mtx_unlock(&b->apb_mtx);
	atomic_add_int(&autodo_probe_count, 1);

	error = VOP_ACCESS(dvp, VWRITE, cred, td);

	atomic_subtract_int(&autodo_probe_count, 1);
	mtx_lock(&b->apb_mtx);
	LIST_REMOVE(&probe, ap_link);
	mtx_unlock(&b->apb_mtx);
	return (error == 0);
}

/*
 * Substitute record for caller credential src or substitute subst (either
 * may be NULL).
 */
static struct autodo_esc *
autodo_esc_find(struct autodo_td *atd, struct ucred *src, struct ucred *subst)
{
	struct autodo_esc *esc;

	SLIST_FOREACH(esc, &atd->at_esc, ae_link) {
		if (esc->ae_src == src || esc->ae_cred == subst)
			return (esc);
	}
	return (NULL);
}

/*
 * Map a substitute installed on curthread back to its caller credential.
 * Any other credential is returned unchanged.
 */
static struct ucred *
autodo_esc_source(struct ucred *cred)
{
	struct autodo_td *atd;
	struct autodo_esc *esc;

	if (autodo_esc_count == 0 || cred->cr_uid != 0)
		return (cred);
	atd = osd_thread_get(curthread, autodo_td_slot);
	if (atd == NULL)
		return (cred);
	esc = autodo_esc_find(atd, NULL, cred);
	return (esc != NULL ? esc->ae_src : cred);
}

/*
 * Return curthread's substitute for src, creating it if needed.  Returns
 * NULL once unload has begun.
 */
static struct ucred *
autodo_esc_get(struct ucred *src)
{
	struct thread *td;
	struct autodo_td *atd;
	struct autodo_esc *esc;
	struct uidinfo *uip;
	void **rsv;

	td = curthread;
	atd = osd_thread_get(td, autodo_td_slot);
	if (atd != NULL) {
		esc = autodo_esc_find(atd, src, NULL);
		if (esc != NULL)
			return (esc->ae_cred);
	}

	mtx_lock(&autodo_esc_mtx);
	if (autodo_esc_dying) {
		mtx_unlock(&autodo_esc_mtx);
		return (NULL);
	}
	autodo_esc_count++;
	mtx_unlock(&autodo_esc_mtx);

	esc = malloc(sizeof(*esc), M_AUTODO, M_WAITOK);
	esc->ae_src = crhold(src);
	esc->ae_cred = crdup(src);
	uip = uifind(0);
	change_euid(esc->ae_cred, uip);
	uifree(uip);

	if (atd == NULL) {
		atd = malloc(sizeof(*atd), M_AUTODO, M_WAITOK);
		SLIST_INIT(&atd->at_esc);
		rsv = osd_reserve(autodo_td_slot);
		(void)osd_thread_set_reserved(td, autodo_td_slot, rsv, atd);
	}
	SLIST_INSERT_HEAD(&atd->at_esc, esc, ae_link);
	ast_sched(td, AUTODO_TDA);
	return (esc->ae_cred);
}

/*
 * Thread OSD destructor: runs on return to user mode (autodo_ast), thread
 * destruction, and module unload.
 */
static void
autodo_td_dtor(void *value)
{
	struct autodo_td *atd = value;
	struct autodo_esc *esc;
	u_int n;

	n = 0;
	while ((esc = SLIST_FIRST(&atd->at_esc)) != NULL) {
		SLIST_REMOVE_HEAD(&atd->at_esc, ae_link);
		crfree(esc->ae_cred);
		crfree(esc->ae_src);
		free(esc, M_AUTODO);
		n++;
	}
	free(atd, M_AUTODO);
	if (n != 0) {
		mtx_lock(&autodo_esc_mtx);
		autodo_esc_count -= n;
		mtx_unlock(&autodo_esc_mtx);
	}
}

/*
 * AST on return to user mode: the system call that installed substitutes
 * no longer references them.
 */
static void
autodo_ast(struct thread *td, int tda __unused)
{

	osd_thread_del(td, autodo_td_slot);
}

/*
 * Check if the credential is subject to autodo management for the
 * purpose of the path deny list: non-root and holding a managed group
 * (legacy gid, or any group in the multi-group policy).  Root is
 * exempt — the deny list guards the implicit-elevation path only, and
 * must not impede legitimate root activity (pkg, freebsd-update, ...).
 */
static int
autodo_cred_managed(struct ucred *cred)
{
	int i, count;

	if (cred->cr_uid == 0)
		return (0);
	if (autodo_cred_has_gid(cred, (gid_t)autodo_gid))
		return (1);
	count = autodo_policy_count;
	for (i = 0; i < count; i++) {
		if (autodo_cred_has_gid(cred, autodo_policy_entries[i].ape_gid))
			return (1);
	}
	return (0);
}

/*
 * Common gate for the path deny hooks: list non-empty, module enabled,
 * jail policy permits autodo, and the credential is autodo-managed.
 * A creation substitute is judged as the caller it was copied from.
 */
static int
autodo_path_gate(struct ucred *cred)
{

	if (!autodo_enabled || autodo_paths_count == 0)
		return (0);
	cred = autodo_esc_source(cred);
	if (cred->cr_prison != &prison0 &&
	    !autodo_jail_enabled(cred->cr_prison))
		return (0);
	return (autodo_cred_managed(cred));
}

/*
 * Prefix match against the deny list strings.  Returns the entry index
 * or -1.  Caller must hold autodo_paths_sx (shared or exclusive).
 */
static int
autodo_path_match(const char *path)
{
	size_t len;
	u_int i;

	for (i = 0; i < autodo_paths_count; i++) {
		len = strlen(autodo_paths[i]);
		if (strncmp(path, autodo_paths[i], len) == 0 &&
		    (path[len] == '/' || path[len] == '\0'))
			return ((int)i);
	}
	return (-1);
}

static void
autodo_path_log_deny(struct ucred *cred, const char *path)
{

	if (ratecheck(&autodo_pathlog_lasttime, &(struct timeval){1, 0}))
		printf("mac_do_auto: deny %s (uid %u, pid %d, %s)\n",
		    path, cred->cr_uid, curproc->p_pid, curproc->p_comm);
}

/*
 * MAC hook: vnode_check_lookup
 *
 * The path deny list is enforced at lookup time, where the full path
 * string is still available (cnp->cn_pnbuf).  Mutating namei operations
 * (CREATE/DELETE/RENAME) on a denied prefix are failed immediately.
 * Plain LOOKUPs that match a denied prefix only set a per-thread
 * marker, which autodo_vnode_check_open() and the setattr hooks
 * consume to deny modification of the resolved vnode.  This avoids
 * calling vn_fullpath(9) from vnode check hooks, which is unsafe:
 * mutating hook contexts hold the target vnode exclusively locked and
 * vn_fullpath()'s fallback path re-locks it (self-deadlock).
 *
 * A deny here precedes VOP_ACCESS()/priv_check(), so it wins over an
 * autodo grant.
 */
static int
autodo_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel __unused, struct componentname *cnp)
{
	const char *path;
	int match;

	if (!autodo_path_gate(cred))
		return (0);

	path = cnp->cn_pnbuf;
	if (path[0] == '/') {
		/* Absolute path: string prefix match. */
		sx_xlock(&autodo_paths_sx);
		match = autodo_path_match(path);
		if (match >= 0 && cnp->cn_nameiop != LOOKUP) {
			autodo_path_log_deny(cred, path);
			sx_xunlock(&autodo_paths_sx);
			return (EPERM);
		}
		if (match >= 0) {
			/*
			 * LOOKUP intent: record a per-thread marker for
			 * check_open/setattr to consume.  A stale marker
			 * is only consumed by the thread that set it and
			 * is overwritten by the next match, so a syscall
			 * aborted between lookup and open can cause at
			 * most one false deny on that thread's next
			 * mutating open — acceptable for an advisory
			 * feature.
			 */
			autodo_mark_td = curthread;
			strlcpy(autodo_mark_path, path,
			    sizeof(autodo_mark_path));
		}
		sx_xunlock(&autodo_paths_sx);
		return (0);
	}

	/*
	 * Relative paths cannot be matched without resolving the process
	 * cwd to a path (unsafe here) — they are not covered.  This is
	 * advisory footgun protection, not a hard boundary.
	 */
	return (0);
}

/*
 * Consume the per-thread lookup marker.  Returns 1 when the current
 * thread's lookup matched a denied prefix (marker cleared either way
 * when it matches).
 */
static int
autodo_consume_mark(void)
{
	int hit;

	sx_xlock(&autodo_paths_sx);
	hit = autodo_mark_td == curthread;
	if (hit)
		autodo_mark_td = NULL;
	sx_xunlock(&autodo_paths_sx);
	return (hit);
}

static int
autodo_vnode_check_open(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused, accmode_t accmode)
{
	int marker;

	if (!autodo_path_gate(cred))
		return (0);

	/* Always consume a pending marker to keep it from going stale. */
	marker = autodo_consume_mark();

	if ((accmode & (VWRITE | VAPPEND | VADMIN)) == 0)
		return (0);
	if (marker) {
		autodo_path_log_deny(cred, autodo_mark_path);
		return (EPERM);
	}
	return (0);
}

static int
autodo_vnode_check_setflags(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused, u_long flags __unused)
{

	if (!autodo_path_gate(cred))
		return (0);
	if (autodo_consume_mark()) {
		autodo_path_log_deny(cred, autodo_mark_path);
		return (EPERM);
	}
	return (0);
}

static int
autodo_vnode_check_setmode(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused, mode_t mode __unused)
{

	if (!autodo_path_gate(cred))
		return (0);
	if (autodo_consume_mark()) {
		autodo_path_log_deny(cred, autodo_mark_path);
		return (EPERM);
	}
	return (0);
}

static int
autodo_vnode_check_setowner(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused, uid_t uid __unused,
    gid_t gid __unused)
{

	if (!autodo_path_gate(cred))
		return (0);
	if (autodo_consume_mark()) {
		autodo_path_log_deny(cred, autodo_mark_path);
		return (EPERM);
	}
	return (0);
}

static int
autodo_vnode_check_setutimes(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused, struct timespec atime __unused,
    struct timespec mtime __unused)
{

	if (!autodo_path_gate(cred))
		return (0);
	if (autodo_consume_mark()) {
		autodo_path_log_deny(cred, autodo_mark_path);
		return (EPERM);
	}
	return (0);
}

/*
 * MAC hook: vnode_check_create
 *
 * Reached by open(O_CREAT), mkdir(2), mknod(2), mkfifo(2), symlink(2) and
 * UNIX-domain bind(2) after lookup has authorized the create.  If cred
 * could not write dvp without autodo, the object is created with
 * cnp->cn_cred set to cred's euid 0 substitute.  vn_open_cred() retries
 * with the same componentname after ERELOOKUP, so a substitute already in
 * cn_cred is re-evaluated against the caller credential.
 */
static int
autodo_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel __unused, struct componentname *cnp,
    struct vattr *vap __unused)
{
	struct autodo_td *atd;
	struct autodo_esc *esc;
	struct ucred *subst;

	if (cnp->cn_cred != cred) {
		atd = osd_thread_get(curthread, autodo_td_slot);
		esc = atd != NULL ?
		    autodo_esc_find(atd, NULL, cnp->cn_cred) : NULL;
		if (esc == NULL || esc->ae_src != cred)
			return (0);
		cnp->cn_cred = cred;
	}

	if (cred->cr_uid == 0 ||
	    autodo_priv_decide(cred, PRIV_VFS_WRITE) != AUTODO_GRANT ||
	    autodo_dir_writable_unaided(cred, dvp))
		return (0);

	subst = autodo_esc_get(cred);
	if (subst == NULL)
		return (EACCES);	/* unloading: the grant is going away */
	cnp->cn_cred = subst;
	return (0);
}

/*
 * MAC hook: mac_priv_grant
 *
 * Called when the kernel is about to deny a privilege.  Returning 0 grants
 * the privilege.  Returning EPERM abstains (leaves the decision to other
 * policies or the default deny).
 */
static int
autodo_priv_grant(struct ucred *cred, int priv)
{

	if (autodo_probe_count != 0 && autodo_probing(curthread))
		return (EPERM);

	switch (autodo_priv_decide(cred, priv)) {
	case AUTODO_GRANT:
		atomic_add_long(&autodo_grant_count, 1);
		if (autodo_log_grants) {
			autodo_emit_event(cred, priv, 1);
			if (ratecheck(&autodo_log_lasttime,
			    &(struct timeval){1, 0}))
				printf("mac_do_auto: grant priv %d to uid %u "
				    "(pid %d, %s)\n",
				    priv, cred->cr_uid, curproc->p_pid,
				    curproc->p_comm);
		}
		return (0);
	case AUTODO_SCOPE_DENY:
		if (autodo_log_grants)
			autodo_emit_event(cred, priv, 0);
		return (EPERM);
	default:
		return (EPERM);
	}
}

static void
autodo_init(struct mac_policy_conf *mpc __unused)
{
	struct prison *pr;
	int i;

	/* Initialize scope bitmap to "all" (default). */
	autodo_bitmap_fill(autodo_scope_bitmap);
	autodo_policy_count = 0;

	/* Initialize the path deny list (empty by default). */
	sx_init(&autodo_paths_sx, "autodo paths");
	autodo_paths_count = 0;

	/* Escalated object creation state. */
	mtx_init(&autodo_esc_mtx, "autodo esc", NULL, MTX_DEF);
	autodo_esc_count = 0;
	autodo_esc_dying = 0;
	for (i = 0; i < AUTODO_PROBE_BUCKETS; i++) {
		mtx_init(&autodo_probe_buckets[i].apb_mtx, "autodo probe",
		    NULL, MTX_DEF);
		LIST_INIT(&autodo_probe_buckets[i].apb_list);
	}
	autodo_probe_count = 0;
	autodo_td_slot = osd_thread_register(autodo_td_dtor);
	ast_register(AUTODO_TDA, ASTR_ASTF_REQUIRED, 0, autodo_ast);

	/* Initialize ring buffer and chardev state. */
	mtx_init(&autodo_ring_mtx, "autodo ring", NULL, MTX_DEF);
	autodo_ring = malloc(sizeof(struct autodo_event) * AUTODO_RING_SIZE,
	    M_AUTODO, M_WAITOK | M_ZERO);
	autodo_ring_head = 0;
	autodo_ring_tail = 0;
	autodo_ring_count = 0;
	autodo_dev_open = 0;
	autodo_dev_dying = 0;
	knlist_init_mtx(&autodo_sel.si_note, &autodo_ring_mtx);

	autodo_osd_jail_slot = osd_jail_register(
	    autodo_osd_jail_destructor, autodo_osd_methods);

	/* Set host jail (prison0) to enabled. */
	osd_jail_set(&prison0, autodo_osd_jail_slot,
	    AUTODO_OSD_ENCODE(JAIL_SYS_NEW));

	/* Set all existing jails to disabled. */
	sx_slock(&allprison_lock);
	TAILQ_FOREACH(pr, &allprison, pr_list) {
		osd_jail_set(pr, autodo_osd_jail_slot,
		    AUTODO_OSD_ENCODE(JAIL_SYS_DISABLE));
	}
	sx_sunlock(&allprison_lock);
}

/*
 * Create /dev/autodo once devfs is initialized.
 *
 * This must not happen in autodo_init(): when the module is preloaded
 * by the loader, MAC policy registration runs at SI_SUB_MAC_POLICY,
 * before devfs (SI_SUB_DEVFS), and make_dev() would dereference the
 * not-yet-initialized devfs unit number allocator (devfs_inos == NULL),
 * panicking the kernel at boot.  When the module is kldloaded at
 * runtime instead, the linker runs this SYSINIT immediately after
 * MOD_LOAD, so the device appears at load time in both cases.
 */
static void
autodo_cdev_init(void *arg __unused)
{

	autodo_cdev = make_dev(&autodo_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0640, "autodo");
}
SYSINIT(autodo_cdev, SI_SUB_DEVFS, SI_ORDER_MIDDLE, autodo_cdev_init, NULL);

static void
autodo_destroy(struct mac_policy_conf *mpc __unused)
{
	int i;

	osd_jail_deregister(autodo_osd_jail_slot);

	/*
	 * mac_do_auto_modevent() refused the unload while substitutes were
	 * live and then stopped issuing them, so no thread uses one here.
	 */
	ast_deregister(AUTODO_TDA);
	osd_thread_deregister(autodo_td_slot);
	for (i = 0; i < AUTODO_PROBE_BUCKETS; i++)
		mtx_destroy(&autodo_probe_buckets[i].apb_mtx);
	mtx_destroy(&autodo_esc_mtx);

	/*
	 * Reject new opens and wake any thread sleeping in read(2).
	 * destroy_dev() waits for threads inside cdevsw methods to
	 * drain, invoking autodo_dev_purge() to prod sleepers, so no
	 * thread can be executing in this module when it returns.
	 * An idle open fd cannot exist here: MOD_QUIESCE vetoes the
	 * unload while /dev/autodo is open.
	 */
	mtx_lock(&autodo_ring_mtx);
	autodo_dev_dying = 1;
	wakeup(&autodo_ring_count);
	mtx_unlock(&autodo_ring_mtx);

	if (autodo_cdev != NULL) {
		destroy_dev(autodo_cdev);
		autodo_cdev = NULL;
	}
	seldrain(&autodo_sel);
	knlist_destroy(&autodo_sel.si_note);
	mtx_lock(&autodo_ring_mtx);
	if (autodo_ring != NULL) {
		free(autodo_ring, M_AUTODO);
		autodo_ring = NULL;
	}
	autodo_ring_count = 0;
	mtx_unlock(&autodo_ring_mtx);
	mtx_destroy(&autodo_ring_mtx);
	sx_destroy(&autodo_paths_sx);
}

static struct mac_policy_ops autodo_ops = {
	.mpo_init = autodo_init,
	.mpo_destroy = autodo_destroy,
	.mpo_priv_grant = autodo_priv_grant,
	.mpo_vnode_check_create = autodo_vnode_check_create,
	.mpo_vnode_check_lookup = autodo_vnode_check_lookup,
	.mpo_vnode_check_open = autodo_vnode_check_open,
	.mpo_vnode_check_setflags = autodo_vnode_check_setflags,
	.mpo_vnode_check_setmode = autodo_vnode_check_setmode,
	.mpo_vnode_check_setowner = autodo_vnode_check_setowner,
	.mpo_vnode_check_setutimes = autodo_vnode_check_setutimes,
};

/*
 * EBUSY while a creation substitute is live.  Otherwise, when stop is set,
 * no further substitutes are issued.
 */
static int
autodo_esc_quiesce(int stop)
{
	int error;

	mtx_lock(&autodo_esc_mtx);
	error = autodo_esc_count != 0 ? EBUSY : 0;
	if (error == 0 && stop)
		autodo_esc_dying = 1;
	mtx_unlock(&autodo_esc_mtx);
	return (error);
}

static void
autodo_esc_resume(void)
{

	mtx_lock(&autodo_esc_mtx);
	autodo_esc_dying = 0;
	mtx_unlock(&autodo_esc_mtx);
}

static void
autodo_dev_resume(void)
{

	mtx_lock(&autodo_ring_mtx);
	autodo_dev_dying = 0;
	mtx_unlock(&autodo_ring_mtx);
}

/*
 * Custom modevent wrapping mac_policy_modevent().  Veto MOD_UNLOAD
 * while /dev/autodo is open so no file descriptor can be left pointing
 * at a cdevsw in unloaded module text; set autodo_dev_dying at quiesce
 * time so an open(2) racing the unload fails instead of establishing
 * a new fd against a device that is about to be destroyed.
 *
 * Unload is also refused while a creation substitute is live.  MOD_UNLOAD
 * repeats that check and stops new substitutes, since a forced kldunload
 * skips MOD_QUIESCE.
 */
static int
mac_do_auto_modevent(module_t mod, int type, void *data)
{
	int error;

	switch (type) {
	case MOD_QUIESCE:
		mtx_lock(&autodo_ring_mtx);
		error = autodo_dev_open ? EBUSY : 0;
		if (error == 0)
			autodo_dev_dying = 1;
		mtx_unlock(&autodo_ring_mtx);
		if (error == 0 && (error = autodo_esc_quiesce(0)) != 0)
			autodo_dev_resume();
		return (error);
	case MOD_UNLOAD:
		error = autodo_esc_quiesce(1);
		if (error != 0) {
			autodo_dev_resume();
			return (error);
		}
		error = mac_policy_modevent(mod, type, data);
		if (error != 0) {
			/* Unload aborted; the device stays usable. */
			autodo_dev_resume();
			autodo_esc_resume();
		}
		return (error);
	default:
		return (mac_policy_modevent(mod, type, data));
	}
}

static struct mac_policy_conf mac_do_auto_mac_policy_conf = {
	.mpc_name = "mac_do_auto",
	.mpc_fullname = "MAC/autodo: transparent privilege escalation",
	.mpc_ops = &autodo_ops,
	.mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK,
	.mpc_field_off = NULL,
};
static moduledata_t mac_do_auto_mod = {
	"mac_do_auto",
	mac_do_auto_modevent,
	&mac_do_auto_mac_policy_conf
};
MODULE_DEPEND(mac_do_auto, kernel_mac_support, MAC_VERSION,
    MAC_VERSION, MAC_VERSION);
DECLARE_MODULE(mac_do_auto, mac_do_auto_mod, SI_SUB_MAC_POLICY,
    SI_ORDER_MIDDLE);
