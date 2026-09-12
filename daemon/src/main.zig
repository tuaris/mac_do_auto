const std = @import("std");
const ucl = @import("ucl");
const posix = std.posix;

// Mirror of src/autodo.h.  `zig build test` checks these constants, the
// struct layouts, and the ioctl numbers against the C header.
const AUTODO_BITMAP_WORDS = 16;
const AUTODO_BITMAP_BITS = AUTODO_BITMAP_WORDS * 64;
const AUTODO_MAX_GROUPS = 16;
const AUTODO_RING_SIZE = 1024;
const AUTODO_MAX_PATHS = 16;
const AUTODO_PATH_LEN = 256;

const AutodoEvent = extern struct {
    ae_timestamp: u64,
    ae_pid: u32,
    ae_uid: u32,
    ae_gid: u32,
    ae_priv: i32,
    ae_granted: u8,
    ae_pad: [3]u8,
    ae_comm: [20]u8,
};

const AutodoScope = extern struct {
    as_bitmap: [AUTODO_BITMAP_WORDS]u64,
};

const AutodoPolicyEntry = extern struct {
    ape_gid: u32,
    ape_pad: u32,
    ape_bitmap: [AUTODO_BITMAP_WORDS]u64,
};

const AutodoPolicy = extern struct {
    ap_count: u32,
    ap_pad: u32,
    ap_entries: [AUTODO_MAX_GROUPS]AutodoPolicyEntry,
};

const AutodoPathlist = extern struct {
    apl_count: u32,
    apl_pad: u32,
    apl_paths: [AUTODO_MAX_PATHS][AUTODO_PATH_LEN]u8,
};

// <sys/ioccom.h> command encoding: direction | length << 16 | group << 8 | number.
const IOCPARM_MASK = (1 << 13) - 1;
const IOC_VOID: c_ulong = 0x20000000;
const IOC_OUT: c_ulong = 0x40000000;
const IOC_IN: c_ulong = 0x80000000;

fn autodoIoc(comptime inout: c_ulong, comptime num: u8, comptime T: ?type) c_ulong {
    const len: c_ulong = if (T) |t| @sizeOf(t) else 0;
    if (len > IOCPARM_MASK) @compileError("ioctl parameter does not fit IOCPARM_MASK");
    return inout | (len << 16) | (@as(c_ulong, 'A') << 8) | num;
}

const AUTODO_SET_SCOPE = autodoIoc(IOC_IN, 1, AutodoScope);
const AUTODO_GET_SCOPE = autodoIoc(IOC_OUT, 2, AutodoScope);
const AUTODO_FLUSH = autodoIoc(IOC_VOID, 3, null);
const AUTODO_SET_POLICY = autodoIoc(IOC_IN, 4, AutodoPolicy);
const AUTODO_GET_POLICY = autodoIoc(IOC_OUT, 5, AutodoPolicy);
const AUTODO_SET_PATHS = autodoIoc(IOC_IN, 6, AutodoPathlist);
const AUTODO_GET_PATHS = autodoIoc(IOC_OUT, 7, AutodoPathlist);

const default_config_path = "/usr/local/etc/autodo/autodo.conf";
const default_log_path = "/var/log/autodo/events.json";
const default_profile_dir = "/usr/local/etc/autodo/profiles";
const dev_path = "/dev/autodo";

const PrivCategory = struct {
    name: []const u8,
    start: u16,
    end: u16,
};

// Must match autodo_cat_ranges in src/mac_do_auto.c.  A category may hold
// several ranges; every PRIV_* constant belongs to exactly one category.
const priv_categories = [_]PrivCategory{
    .{ .name = "system", .start = 2, .end = 18 },
    .{ .name = "system", .start = 100, .end = 100 },
    .{ .name = "system", .start = 120, .end = 121 },
    .{ .name = "audit", .start = 40, .end = 44 },
    .{ .name = "cred", .start = 50, .end = 62 },
    .{ .name = "debug", .start = 80, .end = 92 },
    .{ .name = "jail", .start = 110, .end = 112 },
    .{ .name = "kld", .start = 130, .end = 141 },
    .{ .name = "proc", .start = 160, .end = 243 },
    .{ .name = "vfs", .start = 270, .end = 273 },
    .{ .name = "vfs", .start = 280, .end = 282 },
    .{ .name = "vfs", .start = 290, .end = 291 },
    .{ .name = "vfs", .start = 310, .end = 345 },
    .{ .name = "vm", .start = 360, .end = 364 },
    .{ .name = "dev", .start = 250, .end = 256 },
    .{ .name = "dev", .start = 370, .end = 380 },
    .{ .name = "net", .start = 390, .end = 540 },
    .{ .name = "misc", .start = 550, .end = 710 },
};

const PrivMapping = struct {
    name: []const u8,
    value: u16,
};

// Every non-obsolete PRIV_* constant in FreeBSD 15.1 <sys/priv.h>, so that
// deny lists resolve names independently of the build host's headers.
// `zig build test` checks it against the build host's <sys/priv.h>.
const priv_names = [_]PrivMapping{
    .{ .name = "PRIV_ACCT", .value = 2 },
    .{ .name = "PRIV_MAXFILES", .value = 3 },
    .{ .name = "PRIV_MAXPROC", .value = 4 },
    .{ .name = "PRIV_KTRACE", .value = 5 },
    .{ .name = "PRIV_SETDUMPER", .value = 6 },
    .{ .name = "PRIV_REBOOT", .value = 8 },
    .{ .name = "PRIV_SWAPON", .value = 9 },
    .{ .name = "PRIV_SWAPOFF", .value = 10 },
    .{ .name = "PRIV_MSGBUF", .value = 11 },
    .{ .name = "PRIV_IO", .value = 12 },
    .{ .name = "PRIV_KEYBOARD", .value = 13 },
    .{ .name = "PRIV_DRIVER", .value = 14 },
    .{ .name = "PRIV_ADJTIME", .value = 15 },
    .{ .name = "PRIV_NTP_ADJTIME", .value = 16 },
    .{ .name = "PRIV_CLOCK_SETTIME", .value = 17 },
    .{ .name = "PRIV_SETTIMEOFDAY", .value = 18 },
    .{ .name = "PRIV_AUDIT_CONTROL", .value = 40 },
    .{ .name = "PRIV_AUDIT_FAILSTOP", .value = 41 },
    .{ .name = "PRIV_AUDIT_GETAUDIT", .value = 42 },
    .{ .name = "PRIV_AUDIT_SETAUDIT", .value = 43 },
    .{ .name = "PRIV_AUDIT_SUBMIT", .value = 44 },
    .{ .name = "PRIV_CRED_SETUID", .value = 50 },
    .{ .name = "PRIV_CRED_SETEUID", .value = 51 },
    .{ .name = "PRIV_CRED_SETGID", .value = 52 },
    .{ .name = "PRIV_CRED_SETEGID", .value = 53 },
    .{ .name = "PRIV_CRED_SETGROUPS", .value = 54 },
    .{ .name = "PRIV_CRED_SETREUID", .value = 55 },
    .{ .name = "PRIV_CRED_SETREGID", .value = 56 },
    .{ .name = "PRIV_CRED_SETRESUID", .value = 57 },
    .{ .name = "PRIV_CRED_SETRESGID", .value = 58 },
    .{ .name = "PRIV_SEEOTHERGIDS", .value = 59 },
    .{ .name = "PRIV_SEEOTHERUIDS", .value = 60 },
    .{ .name = "PRIV_SEEJAILPROC", .value = 61 },
    .{ .name = "PRIV_CRED_SETCRED", .value = 62 },
    .{ .name = "PRIV_DEBUG_DIFFCRED", .value = 80 },
    .{ .name = "PRIV_DEBUG_SUGID", .value = 81 },
    .{ .name = "PRIV_DEBUG_UNPRIV", .value = 82 },
    .{ .name = "PRIV_DEBUG_DENIED", .value = 83 },
    .{ .name = "PRIV_DEBUG_DIFFJAIL", .value = 84 },
    .{ .name = "PRIV_DTRACE_KERNEL", .value = 90 },
    .{ .name = "PRIV_DTRACE_PROC", .value = 91 },
    .{ .name = "PRIV_DTRACE_USER", .value = 92 },
    .{ .name = "PRIV_FIRMWARE_LOAD", .value = 100 },
    .{ .name = "PRIV_JAIL_ATTACH", .value = 110 },
    .{ .name = "PRIV_JAIL_SET", .value = 111 },
    .{ .name = "PRIV_JAIL_REMOVE", .value = 112 },
    .{ .name = "PRIV_KENV_SET", .value = 120 },
    .{ .name = "PRIV_KENV_UNSET", .value = 121 },
    .{ .name = "PRIV_KLD_LOAD", .value = 130 },
    .{ .name = "PRIV_KLD_UNLOAD", .value = 131 },
    .{ .name = "PRIV_MAC_PARTITION", .value = 140 },
    .{ .name = "PRIV_MAC_PRIVS", .value = 141 },
    .{ .name = "PRIV_PROC_LIMIT", .value = 160 },
    .{ .name = "PRIV_PROC_SETLOGIN", .value = 161 },
    .{ .name = "PRIV_PROC_SETRLIMIT", .value = 162 },
    .{ .name = "PRIV_PROC_SETLOGINCLASS", .value = 163 },
    .{ .name = "PRIV_IPC_READ", .value = 170 },
    .{ .name = "PRIV_IPC_WRITE", .value = 171 },
    .{ .name = "PRIV_IPC_ADMIN", .value = 172 },
    .{ .name = "PRIV_IPC_MSGSIZE", .value = 173 },
    .{ .name = "PRIV_MQ_ADMIN", .value = 180 },
    .{ .name = "PRIV_PMC_MANAGE", .value = 190 },
    .{ .name = "PRIV_PMC_SYSTEM", .value = 191 },
    .{ .name = "PRIV_SCHED_DIFFCRED", .value = 200 },
    .{ .name = "PRIV_SCHED_SETPRIORITY", .value = 201 },
    .{ .name = "PRIV_SCHED_RTPRIO", .value = 202 },
    .{ .name = "PRIV_SCHED_SETPOLICY", .value = 203 },
    .{ .name = "PRIV_SCHED_SET", .value = 204 },
    .{ .name = "PRIV_SCHED_SETPARAM", .value = 205 },
    .{ .name = "PRIV_SCHED_CPUSET", .value = 206 },
    .{ .name = "PRIV_SCHED_CPUSET_INTR", .value = 207 },
    .{ .name = "PRIV_SCHED_IDPRIO", .value = 208 },
    .{ .name = "PRIV_SCHED_DIFFJAIL", .value = 209 },
    .{ .name = "PRIV_SEM_WRITE", .value = 220 },
    .{ .name = "PRIV_SIGNAL_DIFFCRED", .value = 230 },
    .{ .name = "PRIV_SIGNAL_SUGID", .value = 231 },
    .{ .name = "PRIV_SIGNAL_DIFFJAIL", .value = 232 },
    .{ .name = "PRIV_SYSCTL_DEBUG", .value = 240 },
    .{ .name = "PRIV_SYSCTL_WRITE", .value = 241 },
    .{ .name = "PRIV_SYSCTL_WRITEJAIL", .value = 242 },
    .{ .name = "PRIV_SYSCTL_MEMLOCK", .value = 243 },
    .{ .name = "PRIV_TTY_CONSOLE", .value = 250 },
    .{ .name = "PRIV_TTY_DRAINWAIT", .value = 251 },
    .{ .name = "PRIV_TTY_DTRWAIT", .value = 252 },
    .{ .name = "PRIV_TTY_EXCLUSIVE", .value = 253 },
    .{ .name = "PRIV_TTY_STI", .value = 255 },
    .{ .name = "PRIV_TTY_SETA", .value = 256 },
    .{ .name = "PRIV_UFS_EXTATTRCTL", .value = 270 },
    .{ .name = "PRIV_UFS_QUOTAOFF", .value = 271 },
    .{ .name = "PRIV_UFS_QUOTAON", .value = 272 },
    .{ .name = "PRIV_UFS_SETUSE", .value = 273 },
    .{ .name = "PRIV_ZFS_POOL_CONFIG", .value = 280 },
    .{ .name = "PRIV_ZFS_INJECT", .value = 281 },
    .{ .name = "PRIV_ZFS_JAIL", .value = 282 },
    .{ .name = "PRIV_NFS_DAEMON", .value = 290 },
    .{ .name = "PRIV_NFS_LOCKD", .value = 291 },
    .{ .name = "PRIV_VFS_READ", .value = 310 },
    .{ .name = "PRIV_VFS_WRITE", .value = 311 },
    .{ .name = "PRIV_VFS_ADMIN", .value = 312 },
    .{ .name = "PRIV_VFS_EXEC", .value = 313 },
    .{ .name = "PRIV_VFS_LOOKUP", .value = 314 },
    .{ .name = "PRIV_VFS_BLOCKRESERVE", .value = 315 },
    .{ .name = "PRIV_VFS_CHFLAGS_DEV", .value = 316 },
    .{ .name = "PRIV_VFS_CHOWN", .value = 317 },
    .{ .name = "PRIV_VFS_CHROOT", .value = 318 },
    .{ .name = "PRIV_VFS_RETAINSUGID", .value = 319 },
    .{ .name = "PRIV_VFS_EXCEEDQUOTA", .value = 320 },
    .{ .name = "PRIV_VFS_EXTATTR_SYSTEM", .value = 321 },
    .{ .name = "PRIV_VFS_FCHROOT", .value = 322 },
    .{ .name = "PRIV_VFS_FHOPEN", .value = 323 },
    .{ .name = "PRIV_VFS_FHSTAT", .value = 324 },
    .{ .name = "PRIV_VFS_FHSTATFS", .value = 325 },
    .{ .name = "PRIV_VFS_GENERATION", .value = 326 },
    .{ .name = "PRIV_VFS_GETFH", .value = 327 },
    .{ .name = "PRIV_VFS_GETQUOTA", .value = 328 },
    .{ .name = "PRIV_VFS_LINK", .value = 329 },
    .{ .name = "PRIV_VFS_MKNOD_BAD", .value = 330 },
    .{ .name = "PRIV_VFS_MKNOD_DEV", .value = 331 },
    .{ .name = "PRIV_VFS_MKNOD_WHT", .value = 332 },
    .{ .name = "PRIV_VFS_MOUNT", .value = 333 },
    .{ .name = "PRIV_VFS_MOUNT_OWNER", .value = 334 },
    .{ .name = "PRIV_VFS_MOUNT_EXPORTED", .value = 335 },
    .{ .name = "PRIV_VFS_MOUNT_PERM", .value = 336 },
    .{ .name = "PRIV_VFS_MOUNT_SUIDDIR", .value = 337 },
    .{ .name = "PRIV_VFS_MOUNT_NONUSER", .value = 338 },
    .{ .name = "PRIV_VFS_SETGID", .value = 339 },
    .{ .name = "PRIV_VFS_SETQUOTA", .value = 340 },
    .{ .name = "PRIV_VFS_STICKYFILE", .value = 341 },
    .{ .name = "PRIV_VFS_SYSFLAGS", .value = 342 },
    .{ .name = "PRIV_VFS_UNMOUNT", .value = 343 },
    .{ .name = "PRIV_VFS_STAT", .value = 344 },
    .{ .name = "PRIV_VFS_READ_DIR", .value = 345 },
    .{ .name = "PRIV_VM_MADV_PROTECT", .value = 360 },
    .{ .name = "PRIV_VM_MLOCK", .value = 361 },
    .{ .name = "PRIV_VM_MUNLOCK", .value = 362 },
    .{ .name = "PRIV_VM_SWAP_NOQUOTA", .value = 363 },
    .{ .name = "PRIV_VM_SWAP_NORLIMIT", .value = 364 },
    .{ .name = "PRIV_DEVFS_RULE", .value = 370 },
    .{ .name = "PRIV_DEVFS_SYMLINK", .value = 371 },
    .{ .name = "PRIV_RANDOM_RESEED", .value = 380 },
    .{ .name = "PRIV_NET_BRIDGE", .value = 390 },
    .{ .name = "PRIV_NET_GRE", .value = 391 },
    .{ .name = "PRIV_NET_BPF", .value = 394 },
    .{ .name = "PRIV_NET_RAW", .value = 395 },
    .{ .name = "PRIV_NET_ROUTE", .value = 396 },
    .{ .name = "PRIV_NET_TAP", .value = 397 },
    .{ .name = "PRIV_NET_SETIFMTU", .value = 398 },
    .{ .name = "PRIV_NET_SETIFFLAGS", .value = 399 },
    .{ .name = "PRIV_NET_SETIFCAP", .value = 400 },
    .{ .name = "PRIV_NET_SETIFNAME", .value = 401 },
    .{ .name = "PRIV_NET_SETIFMETRIC", .value = 402 },
    .{ .name = "PRIV_NET_SETIFPHYS", .value = 403 },
    .{ .name = "PRIV_NET_SETIFMAC", .value = 404 },
    .{ .name = "PRIV_NET_ADDMULTI", .value = 405 },
    .{ .name = "PRIV_NET_DELMULTI", .value = 406 },
    .{ .name = "PRIV_NET_HWIOCTL", .value = 407 },
    .{ .name = "PRIV_NET_SETLLADDR", .value = 408 },
    .{ .name = "PRIV_NET_ADDIFGROUP", .value = 409 },
    .{ .name = "PRIV_NET_DELIFGROUP", .value = 410 },
    .{ .name = "PRIV_NET_IFCREATE", .value = 411 },
    .{ .name = "PRIV_NET_IFDESTROY", .value = 412 },
    .{ .name = "PRIV_NET_ADDIFADDR", .value = 413 },
    .{ .name = "PRIV_NET_DELIFADDR", .value = 414 },
    .{ .name = "PRIV_NET_LAGG", .value = 415 },
    .{ .name = "PRIV_NET_GIF", .value = 416 },
    .{ .name = "PRIV_NET_SETIFVNET", .value = 417 },
    .{ .name = "PRIV_NET_SETIFDESCR", .value = 418 },
    .{ .name = "PRIV_NET_SETIFFIB", .value = 419 },
    .{ .name = "PRIV_NET_VXLAN", .value = 420 },
    .{ .name = "PRIV_NET_SETLANPCP", .value = 421 },
    .{ .name = "PRIV_NET_SETVLANPCP", .value = 421 },
    .{ .name = "PRIV_NET_OVPN", .value = 422 },
    .{ .name = "PRIV_NET_ME", .value = 423 },
    .{ .name = "PRIV_NET_WG", .value = 424 },
    .{ .name = "PRIV_NET80211_VAP_GETKEY", .value = 440 },
    .{ .name = "PRIV_NET80211_VAP_MANAGE", .value = 441 },
    .{ .name = "PRIV_NET80211_VAP_SETMAC", .value = 442 },
    .{ .name = "PRIV_NET80211_CREATE_VAP", .value = 443 },
    .{ .name = "PRIV_NETATM_CFG", .value = 460 },
    .{ .name = "PRIV_NETATM_ADD", .value = 461 },
    .{ .name = "PRIV_NETATM_DEL", .value = 462 },
    .{ .name = "PRIV_NETATM_SET", .value = 463 },
    .{ .name = "PRIV_NETBLUETOOTH_RAW", .value = 470 },
    .{ .name = "PRIV_NETGRAPH_CONTROL", .value = 480 },
    .{ .name = "PRIV_NETGRAPH_TTY", .value = 481 },
    .{ .name = "PRIV_NETINET_RESERVEDPORT", .value = 490 },
    .{ .name = "PRIV_NETINET_IPFW", .value = 491 },
    .{ .name = "PRIV_NETINET_DIVERT", .value = 492 },
    .{ .name = "PRIV_NETINET_PF", .value = 493 },
    .{ .name = "PRIV_NETINET_DUMMYNET", .value = 494 },
    .{ .name = "PRIV_NETINET_CARP", .value = 495 },
    .{ .name = "PRIV_NETINET_MROUTE", .value = 496 },
    .{ .name = "PRIV_NETINET_RAW", .value = 497 },
    .{ .name = "PRIV_NETINET_GETCRED", .value = 498 },
    .{ .name = "PRIV_NETINET_ADDRCTRL6", .value = 499 },
    .{ .name = "PRIV_NETINET_ND6", .value = 500 },
    .{ .name = "PRIV_NETINET_SCOPE6", .value = 501 },
    .{ .name = "PRIV_NETINET_ALIFETIME6", .value = 502 },
    .{ .name = "PRIV_NETINET_IPSEC", .value = 503 },
    .{ .name = "PRIV_NETINET_REUSEPORT", .value = 504 },
    .{ .name = "PRIV_NETINET_SETHDROPTS", .value = 505 },
    .{ .name = "PRIV_NETINET_BINDANY", .value = 506 },
    .{ .name = "PRIV_NETINET_HASHKEY", .value = 507 },
    .{ .name = "PRIV_NETINET_KTLSKEYS", .value = 508 },
    .{ .name = "PRIV_NETNCP", .value = 530 },
    .{ .name = "PRIV_NETSMB", .value = 540 },
    .{ .name = "PRIV_VM86_INTCALL", .value = 550 },
    .{ .name = "PRIV_PIPEBUF", .value = 560 },
    .{ .name = "PRIV_MODULE0", .value = 600 },
    .{ .name = "PRIV_MODULE1", .value = 601 },
    .{ .name = "PRIV_MODULE2", .value = 602 },
    .{ .name = "PRIV_MODULE3", .value = 603 },
    .{ .name = "PRIV_MODULE4", .value = 604 },
    .{ .name = "PRIV_MODULE5", .value = 605 },
    .{ .name = "PRIV_MODULE6", .value = 606 },
    .{ .name = "PRIV_MODULE7", .value = 607 },
    .{ .name = "PRIV_MODULE8", .value = 608 },
    .{ .name = "PRIV_MODULE9", .value = 609 },
    .{ .name = "PRIV_MODULE10", .value = 610 },
    .{ .name = "PRIV_MODULE11", .value = 611 },
    .{ .name = "PRIV_MODULE12", .value = 612 },
    .{ .name = "PRIV_MODULE13", .value = 613 },
    .{ .name = "PRIV_MODULE14", .value = 614 },
    .{ .name = "PRIV_MODULE15", .value = 615 },
    .{ .name = "PRIV_DDB_CAPTURE", .value = 620 },
    .{ .name = "PRIV_NNPFS_DEBUG", .value = 630 },
    .{ .name = "PRIV_CPUCTL_WRMSR", .value = 640 },
    .{ .name = "PRIV_CPUCTL_UPDATE", .value = 641 },
    .{ .name = "PRIV_C4B_RESET_CTLR", .value = 650 },
    .{ .name = "PRIV_C4B_TRACE", .value = 651 },
    .{ .name = "PRIV_AFS_ADMIN", .value = 660 },
    .{ .name = "PRIV_AFS_DAEMON", .value = 661 },
    .{ .name = "PRIV_RCTL_GET_RACCT", .value = 670 },
    .{ .name = "PRIV_RCTL_GET_RULES", .value = 671 },
    .{ .name = "PRIV_RCTL_GET_LIMITS", .value = 672 },
    .{ .name = "PRIV_RCTL_ADD_RULE", .value = 673 },
    .{ .name = "PRIV_RCTL_REMOVE_RULE", .value = 674 },
    .{ .name = "PRIV_KMEM_READ", .value = 680 },
    .{ .name = "PRIV_KMEM_WRITE", .value = 681 },
    .{ .name = "PRIV_PROC_MEM_WRITE", .value = 682 },
    .{ .name = "PRIV_KDB_SET_BACKEND", .value = 690 },
    .{ .name = "PRIV_VERIEXEC_DIRECT", .value = 700 },
    .{ .name = "PRIV_VERIEXEC_NOVERIFY", .value = 701 },
    .{ .name = "PRIV_VERIEXEC_CONTROL", .value = 702 },
    .{ .name = "PRIV_VMM_PPTDEV", .value = 710 },
};

fn lookupPrivByName(name: []const u8) ?u16 {
    for (priv_names) |pm| {
        if (std.mem.eql(u8, name, pm.name)) return pm.value;
    }
    return null;
}

fn buildBitmap(categories: []const []const u8) AutodoScope {
    var scope = AutodoScope{ .as_bitmap = [_]u64{0} ** AUTODO_BITMAP_WORDS };

    for (categories) |cat| {
        if (std.mem.eql(u8, cat, "all")) {
            for (&scope.as_bitmap) |*w| w.* = ~@as(u64, 0);
            return scope;
        }
        for (priv_categories) |pc| {
            if (std.mem.eql(u8, cat, pc.name)) {
                var p: u16 = pc.start;
                while (p <= pc.end) : (p += 1) {
                    const word = @as(usize, p) / 64;
                    const bit: u6 = @intCast(@as(usize, p) % 64);
                    scope.as_bitmap[word] |= @as(u64, 1) << bit;
                }
            }
        }
    }
    return scope;
}

fn clearPrivBit(bitmap: *[AUTODO_BITMAP_WORDS]u64, priv: u16) void {
    const word = @as(usize, priv) / 64;
    const bit: u6 = @intCast(@as(usize, priv) % 64);
    if (word < AUTODO_BITMAP_WORDS) {
        bitmap[word] &= ~(@as(u64, 1) << bit);
    }
}

extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;

fn pushScope(dev_fd: posix.fd_t, scope: *AutodoScope) !void {
    const rc = ioctl(dev_fd, AUTODO_SET_SCOPE, @as(*anyopaque, @ptrCast(scope)));
    if (rc < 0) return error.IoctlFailed;
}

fn pushPolicy(dev_fd: posix.fd_t, policy: *AutodoPolicy) !void {
    const rc = ioctl(dev_fd, AUTODO_SET_POLICY, @as(*anyopaque, @ptrCast(policy)));
    if (rc < 0) return error.IoctlFailed;
}

fn pushPaths(dev_fd: posix.fd_t, paths: *AutodoPathlist) !void {
    const rc = ioctl(dev_fd, AUTODO_SET_PATHS, @as(*anyopaque, @ptrCast(paths)));
    if (rc < 0) return error.IoctlFailed;
}

const c_grp = @cImport({
    @cInclude("grp.h");
});

fn resolveGroupGid(name: [*:0]const u8) ?u32 {
    const gr = c_grp.getgrnam(name);
    if (gr == null) return null;
    return gr.*.gr_gid;
}

const GroupEntry = struct {
    gid: u32,
    bitmap: [AUTODO_BITMAP_WORDS]u64,
};

const Config = struct {
    enabled: bool = true,
    categories: [12][]const u8 = undefined,
    num_categories: usize = 0,
    audit_enabled: bool = true,
    log_file: []const u8 = default_log_path,
    profile_dir: []const u8 = default_profile_dir,
    all: bool = true,
    groups: [AUTODO_MAX_GROUPS]GroupEntry = undefined,
    num_groups: usize = 0,
    has_groups: bool = false,
    // Global path deny list (root-level "deny { paths = [...] }")
    deny_paths: [AUTODO_MAX_PATHS][]const u8 = undefined,
    num_deny_paths: usize = 0,

    fn setAll(self: *Config) void {
        self.all = true;
        self.num_categories = 1;
        self.categories[0] = "all";
    }
};

fn loadProfile(profile_dir: []const u8, name: []const u8) ?AutodoScope {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}.conf", .{ profile_dir, name }) catch return null;
    // Null-terminate for C API
    if (path.len >= path_buf.len) return null;
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = path_buf[0..path.len :0];

    const parser = ucl.Parser.init(0) orelse return null;
    defer parser.deinit();

    if (!parser.addFile(path_z)) return null;

    const root = parser.getObject() orelse return null;
    defer ucl.unref(root);

    var cats: [12][]const u8 = undefined;
    var num_cats: usize = 0;

    if (root.lookup("scope")) |scope_obj| {
        if (scope_obj.lookup("categories")) |cats_arr| {
            var it = cats_arr.iterate();
            while (it.next()) |item| {
                if (num_cats >= 12) break;
                if (item.toString()) |s| {
                    cats[num_cats] = s;
                    num_cats += 1;
                }
            }
        }
    }

    if (num_cats == 0) {
        cats[0] = "all";
        num_cats = 1;
    }

    var scope = buildBitmap(cats[0..num_cats]);

    // Apply deny list
    if (root.lookup("deny")) |deny_obj| {
        if (deny_obj.lookup("privileges")) |privs| {
            var it = privs.iterate();
            while (it.next()) |item| {
                if (item.toString()) |s| {
                    if (lookupPrivByName(s)) |pval| {
                        clearPrivBit(&scope.as_bitmap, pval);
                    } else {
                        log(.warn, "unknown privilege in deny: {s}", .{s});
                    }
                }
            }
        }
    }

    return scope;
}

fn parseScopeAndDeny(obj: ucl.Object) AutodoScope {
    var cats: [12][]const u8 = undefined;
    var num_cats: usize = 0;

    if (obj.lookup("scope")) |scope_obj| {
        if (scope_obj.lookup("categories")) |cats_arr| {
            var it = cats_arr.iterate();
            while (it.next()) |item| {
                if (num_cats >= 12) break;
                if (item.toString()) |s| {
                    cats[num_cats] = s;
                    num_cats += 1;
                }
            }
        }
    }

    if (num_cats == 0) {
        cats[0] = "all";
        num_cats = 1;
    }

    var scope = buildBitmap(cats[0..num_cats]);

    if (obj.lookup("deny")) |deny_obj| {
        if (deny_obj.lookup("privileges")) |privs| {
            var it = privs.iterate();
            while (it.next()) |item| {
                if (item.toString()) |s| {
                    if (lookupPrivByName(s)) |pval| {
                        clearPrivBit(&scope.as_bitmap, pval);
                    } else {
                        log(.warn, "unknown privilege in deny: {s}", .{s});
                    }
                }
            }
        }
    }

    return scope;
}

fn loadConfig(path: [*:0]const u8) ?Config {
    const parser = ucl.Parser.init(0) orelse return null;
    defer parser.deinit();

    if (!parser.addFile(path)) {
        const err = parser.getError();
        if (err) |e| {
            log(.err, "config parse error: {s}", .{e});
        }
        return null;
    }

    const root = parser.getObject() orelse return null;
    defer ucl.unref(root);

    var cfg = Config{};

    if (root.lookup("enabled")) |obj| {
        cfg.enabled = obj.toBool();
    }

    // Template directory override
    if (root.lookup("profile_dir")) |obj| {
        if (obj.toString()) |s| {
            cfg.profile_dir = s;
        }
    }

    // Multi-group policy: groups { wheel { ... }; developers { ... }; }
    if (root.lookup("groups")) |groups_obj| {
        var git = groups_obj.iterate();
        while (git.next()) |group_obj| {
            if (cfg.num_groups >= AUTODO_MAX_GROUPS) break;
            const group_name = group_obj.key() orelse continue;

            // Null-terminate group name for getgrnam
            var name_buf: [64]u8 = undefined;
            if (group_name.len >= name_buf.len) continue;
            @memcpy(name_buf[0..group_name.len], group_name);
            name_buf[group_name.len] = 0;
            const name_z: [*:0]const u8 = name_buf[0..group_name.len :0];

            const gid = resolveGroupGid(name_z) orelse {
                log(.warn, "unknown group: {s}", .{group_name});
                continue;
            };

            // Determine scope: profile reference or inline scope/deny
            var bitmap: [AUTODO_BITMAP_WORDS]u64 = undefined;
            if (group_obj.lookup("profile")) |prof_obj| {
                if (prof_obj.toString()) |prof_name| {
                    if (loadProfile(cfg.profile_dir, prof_name)) |scope| {
                        bitmap = scope.as_bitmap;
                    } else {
                        log(.warn, "profile not found: {s}", .{prof_name});
                        continue;
                    }
                } else continue;
            } else {
                // Inline scope + deny
                const scope = parseScopeAndDeny(group_obj);
                bitmap = scope.as_bitmap;
            }

            cfg.groups[cfg.num_groups] = GroupEntry{
                .gid = gid,
                .bitmap = bitmap,
            };
            cfg.num_groups += 1;
            log(.info, "group {s} (gid={d}): policy loaded", .{ group_name, gid });
        }
        cfg.has_groups = cfg.num_groups > 0;
    }

    // Legacy single-scope (used when no groups block)
    if (!cfg.has_groups) {
        if (root.lookup("scope")) |scope_obj| {
            if (scope_obj.objectType() == .string) {
                const val = scope_obj.toString() orelse "all";
                if (std.mem.eql(u8, val, "all")) {
                    cfg.setAll();
                }
            } else if (scope_obj.objectType() == .object) {
                if (scope_obj.lookup("categories")) |cats| {
                    var it = cats.iterate();
                    cfg.num_categories = 0;
                    cfg.all = false;
                    while (it.next()) |item| {
                        if (cfg.num_categories >= 12) break;
                        if (item.toString()) |s| {
                            cfg.categories[cfg.num_categories] = s;
                            cfg.num_categories += 1;
                        }
                    }
                }
            }
        }
    }

    // Global path deny list: deny { paths = ["/boot/kernel", ...] }
    if (root.lookup("deny")) |deny_obj| {
        if (deny_obj.lookup("paths")) |paths_arr| {
            var it = paths_arr.iterate();
            while (it.next()) |item| {
                if (cfg.num_deny_paths >= AUTODO_MAX_PATHS) {
                    log(.warn, "too many deny paths (max {d}), ignoring rest", .{AUTODO_MAX_PATHS});
                    break;
                }
                if (item.toString()) |s| {
                    if (s.len == 0 or s[0] != '/') {
                        log(.warn, "deny path must be absolute, ignoring: {s}", .{s});
                        continue;
                    }
                    if (s.len >= AUTODO_PATH_LEN) {
                        log(.warn, "deny path too long (max {d}), ignoring: {s}", .{ AUTODO_PATH_LEN - 1, s });
                        continue;
                    }
                    cfg.deny_paths[cfg.num_deny_paths] = s;
                    cfg.num_deny_paths += 1;
                }
            }
        }
    }

    if (root.lookup("audit")) |audit_obj| {
        if (audit_obj.lookup("enabled")) |obj| {
            cfg.audit_enabled = obj.toBool();
        }
        if (audit_obj.lookup("log_file")) |obj| {
            if (obj.toString()) |s| {
                cfg.log_file = s;
            }
        }
    }

    return cfg;
}

fn commSlice(comm: *const [20]u8) []const u8 {
    var len: usize = 0;
    while (len < 20 and comm[len] != 0) : (len += 1) {}
    return comm[0..len];
}

fn log(comptime level: std.log.Level, comptime fmt: []const u8, args: anytype) void {
    const prefix = switch (level) {
        .err => "error",
        .warn => "warn",
        .info => "info",
        .debug => "debug",
    };
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "autodo-eventd: {s}: " ++ fmt ++ "\n", .{prefix} ++ args) catch return;
    _ = posix.write(2, msg) catch {};
}

const c_event = @cImport({
    @cInclude("sys/event.h");
});

const KEvent = c_event.struct_kevent;

extern "c" fn kqueue() c_int;
extern "c" fn kevent(
    kq: c_int,
    changelist: ?[*]const KEvent,
    nchanges: c_int,
    eventlist: ?[*]KEvent,
    nevents: c_int,
    timeout: ?*const std.c.timespec,
) c_int;

fn makeKevent(ident: usize, filter: c_short, flags: c_ushort, fflags: c_uint) KEvent {
    return KEvent{
        .ident = ident,
        .filter = filter,
        .flags = flags,
        .fflags = fflags,
        .data = 0,
        .udata = null,
        .ext = [_]u64{ 0, 0, 0, 0 },
    };
}

fn applyPaths(dev_fd: posix.fd_t, cfg: *const Config) void {
    var paths = std.mem.zeroes(AutodoPathlist);
    paths.apl_count = @intCast(cfg.num_deny_paths);
    for (0..cfg.num_deny_paths) |i| {
        const s = cfg.deny_paths[i];
        @memcpy(paths.apl_paths[i][0..s.len], s);
    }
    pushPaths(dev_fd, &paths) catch {
        log(.err, "ioctl SET_PATHS failed", .{});
        return;
    };
    if (cfg.num_deny_paths > 0) {
        log(.info, "pushed path deny list ({d} paths)", .{cfg.num_deny_paths});
    }
}

fn applyConfig(dev_fd: posix.fd_t, cfg: *const Config) void {
    if (!cfg.enabled) {
        // Disabled: push a policy with one entry (GID 0, empty bitmap).
        // This activates multi-group mode with zero permissions,
        // ensuring no privileges are granted to anyone.
        var policy = std.mem.zeroes(AutodoPolicy);
        policy.ap_count = 1;
        policy.ap_entries[0].ape_gid = 0;
        // bitmap is already all-zero from zeroes()
        pushPolicy(dev_fd, &policy) catch {
            // Fallback to legacy empty scope
            var scope = AutodoScope{ .as_bitmap = [_]u64{0} ** AUTODO_BITMAP_WORDS };
            pushScope(dev_fd, &scope) catch {
                log(.err, "failed to push disabled scope", .{});
            };
        };
        // Clear the path deny list as well: disabled means disabled.
        var paths = std.mem.zeroes(AutodoPathlist);
        pushPaths(dev_fd, &paths) catch {};
        log(.info, "module disabled via config", .{});
        return;
    }

    if (cfg.has_groups) {
        // Multi-group policy path
        var policy = std.mem.zeroes(AutodoPolicy);
        policy.ap_count = @intCast(cfg.num_groups);
        for (0..cfg.num_groups) |i| {
            policy.ap_entries[i].ape_gid = cfg.groups[i].gid;
            policy.ap_entries[i].ape_pad = 0;
            policy.ap_entries[i].ape_bitmap = cfg.groups[i].bitmap;
        }
        pushPolicy(dev_fd, &policy) catch {
            log(.err, "ioctl SET_POLICY failed", .{});
            return;
        };
        log(.info, "pushed multi-group policy ({d} groups)", .{cfg.num_groups});
    } else {
        // Legacy single-scope path
        var scope = buildBitmap(cfg.categories[0..cfg.num_categories]);
        pushScope(dev_fd, &scope) catch {
            log(.err, "ioctl SET_SCOPE failed", .{});
            return;
        };
        log(.info, "pushed legacy scope bitmap", .{});
    }

    applyPaths(dev_fd, cfg);
}

pub fn main() !void {
    var config_path: [*:0]const u8 = default_config_path;
    var log_path: []const u8 = default_log_path;

    var args = std.process.args();
    _ = args.skip(); // program name
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--config=")) {
            config_path = arg[9.. :0];
        } else if (std.mem.startsWith(u8, arg, "--log=")) {
            log_path = arg[6..];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            const help =
                "usage: autodo-eventd [options]\n" ++
                "\n" ++
                "Options:\n" ++
                "  --config=PATH   Config file (default: " ++ default_config_path ++ ")\n" ++
                "  --log=PATH      Audit log file (default: " ++ default_log_path ++ ")\n" ++
                "  --help          Show this help\n";
            _ = posix.write(1, help) catch {};
            return;
        }
    }

    // Open /dev/autodo
    const dev_fd = posix.open(dev_path, .{ .ACCMODE = .RDWR }, 0) catch |err| {
        log(.err, "cannot open {s}: {s}", .{ dev_path, @errorName(err) });
        return err;
    };
    defer posix.close(dev_fd);

    // Load and apply config
    if (loadConfig(config_path)) |cfg| {
        log(.info, "loaded config from {s}", .{config_path});
        applyConfig(dev_fd, &cfg);
        log_path = cfg.log_file;
        if (!cfg.audit_enabled) log_path = "";
    } else {
        log(.warn, "no config at {s}, using defaults (scope=all)", .{config_path});
        var scope = AutodoScope{ .as_bitmap = [_]u64{~@as(u64, 0)} ** AUTODO_BITMAP_WORDS };
        pushScope(dev_fd, &scope) catch |err| {
            log(.err, "ioctl SET_SCOPE failed: {s}", .{@errorName(err)});
            return err;
        };
    }

    // Open config file fd for vnode monitoring
    const config_fd = posix.open(
        std.mem.span(config_path),
        .{ .ACCMODE = .RDONLY },
        0,
    ) catch blk: {
        log(.warn, "cannot open config for monitoring", .{});
        break :blk @as(posix.fd_t, -1);
    };

    // Open audit log
    var log_file: ?std.fs.File = null;
    if (log_path.len > 0) {
        log_file = std.fs.cwd().createFile(log_path, .{ .truncate = false }) catch |err| blk: {
            log(.err, "cannot open log {s}: {s}", .{ log_path, @errorName(err) });
            break :blk null;
        };
        if (log_file) |f| {
            f.seekFromEnd(0) catch {};
        }
    }
    defer if (log_file) |f| f.close();

    // Set up kqueue
    const kq = kqueue();
    if (kq < 0) {
        log(.err, "kqueue() failed", .{});
        return error.KqueueFailed;
    }

    var changes: [4]KEvent = undefined;
    var nchanges: c_int = 0;

    // Watch /dev/autodo for readable events
    changes[@intCast(nchanges)] = makeKevent(
        @intCast(dev_fd),
        c_event.EVFILT_READ,
        c_event.EV_ADD | c_event.EV_ENABLE,
        0,
    );
    nchanges += 1;

    // Watch config file for writes
    if (config_fd >= 0) {
        changes[@intCast(nchanges)] = makeKevent(
            @intCast(config_fd),
            c_event.EVFILT_VNODE,
            c_event.EV_ADD | c_event.EV_ENABLE | c_event.EV_CLEAR,
            c_event.NOTE_WRITE | c_event.NOTE_RENAME,
        );
        nchanges += 1;
    }

    // Catch SIGTERM
    changes[@intCast(nchanges)] = makeKevent(
        15, // SIGTERM
        c_event.EVFILT_SIGNAL,
        c_event.EV_ADD | c_event.EV_ENABLE,
        0,
    );
    nchanges += 1;

    // Catch SIGHUP for config reload
    changes[@intCast(nchanges)] = makeKevent(
        1, // SIGHUP
        c_event.EVFILT_SIGNAL,
        c_event.EV_ADD | c_event.EV_ENABLE,
        0,
    );
    nchanges += 1;

    // Block SIGTERM/SIGHUP from default handling
    var mask = std.posix.sigemptyset();
    const sigaddset = std.c.sigaddset;
    _ = sigaddset(&mask, 15); // SIGTERM
    _ = sigaddset(&mask, 1); // SIGHUP
    _ = std.c.sigprocmask(std.c.SIG.BLOCK, &mask, null);

    log(.info, "event loop started, monitoring {s}", .{dev_path});

    var running = true;
    var events: [16]KEvent = undefined;
    var buf: [4096]u8 align(@alignOf(AutodoEvent)) = undefined;
    var reg_changes: ?[*]const KEvent = &changes;
    var reg_nchanges: c_int = nchanges;

    while (running) {
        const nevents = kevent(kq, reg_changes, reg_nchanges, &events, 16, null);
        // After first call, changelist is consumed — clear for subsequent iterations
        reg_changes = null;
        reg_nchanges = 0;
        if (nevents < 0) {
            const err = std.c._errno().*;
            if (err != 4) // EINTR
                log(.err, "kevent wait failed, errno={d}", .{err});
            continue;
        }

        var i: usize = 0;
        while (i < @as(usize, @intCast(nevents))) : (i += 1) {
            const ev = &events[i];

            if (ev.filter == c_event.EVFILT_SIGNAL) {
                if (ev.ident == 15) {
                    log(.info, "received SIGTERM, shutting down", .{});
                    running = false;
                } else if (ev.ident == 1) {
                    log(.info, "received SIGHUP, reloading config", .{});
                    if (loadConfig(config_path)) |cfg| {
                        applyConfig(dev_fd, &cfg);
                        log(.info, "config reloaded via SIGHUP", .{});
                    } else {
                        log(.err, "config reload failed", .{});
                    }
                }
            } else if (ev.filter == c_event.EVFILT_VNODE) {
                log(.info, "config file changed, reloading", .{});
                if (loadConfig(config_path)) |cfg| {
                    applyConfig(dev_fd, &cfg);
                    log(.info, "config reloaded via file change", .{});
                }
            } else if (ev.filter == c_event.EVFILT_READ) {
                // Read events from /dev/autodo
                const n = posix.read(dev_fd, &buf) catch |err| {
                    log(.err, "read /dev/autodo: {s}", .{@errorName(err)});
                    continue;
                };
                if (n == 0) continue;

                const event_count = n / @sizeOf(AutodoEvent);
                const event_ptr: [*]const AutodoEvent = @ptrCast(@alignCast(&buf));

                if (log_file) |f| {
                    var j: usize = 0;
                    while (j < event_count) : (j += 1) {
                        var line_buf: [512]u8 = undefined;
                        const aev = &event_ptr[j];
                        const comm = commSlice(&aev.ae_comm);
                        const line = std.fmt.bufPrint(
                            &line_buf,
                            "{{\"ts\":{d},\"pid\":{d},\"uid\":{d},\"gid\":{d},\"priv\":{d},\"granted\":{},\"comm\":\"{s}\"}}\n",
                            .{
                                aev.ae_timestamp, aev.ae_pid,  aev.ae_uid,
                                aev.ae_gid,       aev.ae_priv, aev.ae_granted != 0,
                                comm,
                            },
                        ) catch continue;
                        f.writeAll(line) catch |err| {
                            log(.err, "write log: {s}", .{@errorName(err)});
                        };
                    }
                }
            }
        }
    }

    log(.info, "shutdown complete", .{});
}

fn privBitSet(bitmap: [AUTODO_BITMAP_WORDS]u64, priv: u16) bool {
    const bit: u6 = @intCast(priv % 64);
    return (bitmap[priv / 64] >> bit) & 1 == 1;
}

test "ABI mirror matches src/autodo.h" {
    const c = @cImport({
        @cInclude("sys/types.h");
        @cInclude("autodo.h");
    });
    const expectEqual = std.testing.expectEqual;

    try expectEqual(c.AUTODO_BITMAP_WORDS, AUTODO_BITMAP_WORDS);
    try expectEqual(c.AUTODO_BITMAP_BITS, AUTODO_BITMAP_BITS);
    try expectEqual(c.AUTODO_MAX_GROUPS, AUTODO_MAX_GROUPS);
    try expectEqual(c.AUTODO_RING_SIZE, AUTODO_RING_SIZE);
    try expectEqual(c.AUTODO_MAX_PATHS, AUTODO_MAX_PATHS);
    try expectEqual(c.AUTODO_PATH_LEN, AUTODO_PATH_LEN);

    try expectEqual(@sizeOf(c.struct_autodo_event), @sizeOf(AutodoEvent));
    try expectEqual(@offsetOf(c.struct_autodo_event, "ae_comm"), @offsetOf(AutodoEvent, "ae_comm"));
    try expectEqual(@sizeOf(c.struct_autodo_scope), @sizeOf(AutodoScope));
    try expectEqual(@sizeOf(c.struct_autodo_policy_entry), @sizeOf(AutodoPolicyEntry));
    try expectEqual(@offsetOf(c.struct_autodo_policy_entry, "ape_bitmap"), @offsetOf(AutodoPolicyEntry, "ape_bitmap"));
    try expectEqual(@sizeOf(c.struct_autodo_policy), @sizeOf(AutodoPolicy));
    try expectEqual(@offsetOf(c.struct_autodo_policy, "ap_entries"), @offsetOf(AutodoPolicy, "ap_entries"));
    try expectEqual(@sizeOf(c.struct_autodo_pathlist), @sizeOf(AutodoPathlist));
    try expectEqual(@offsetOf(c.struct_autodo_pathlist, "apl_paths"), @offsetOf(AutodoPathlist, "apl_paths"));

    try expectEqual(@as(c_ulong, @intCast(c.AUTODO_SET_SCOPE)), AUTODO_SET_SCOPE);
    try expectEqual(@as(c_ulong, @intCast(c.AUTODO_GET_SCOPE)), AUTODO_GET_SCOPE);
    try expectEqual(@as(c_ulong, @intCast(c.AUTODO_FLUSH)), AUTODO_FLUSH);
    try expectEqual(@as(c_ulong, @intCast(c.AUTODO_SET_POLICY)), AUTODO_SET_POLICY);
    try expectEqual(@as(c_ulong, @intCast(c.AUTODO_GET_POLICY)), AUTODO_GET_POLICY);
    try expectEqual(@as(c_ulong, @intCast(c.AUTODO_SET_PATHS)), AUTODO_SET_PATHS);
    try expectEqual(@as(c_ulong, @intCast(c.AUTODO_GET_PATHS)), AUTODO_GET_PATHS);
}

test "privilege names match <sys/priv.h>" {
    // The comptime walk below visits every declaration the C headers export.
    @setEvalBranchQuota(1_000_000);
    const p = @cImport({
        @cInclude("sys/types.h");
        @cInclude("sys/priv.h");
    });

    // Table entries the build host defines carry the header's value.
    inline for (priv_names) |pm| {
        if (@hasDecl(p, pm.name)) {
            errdefer std.debug.print("{s}: table has {d}\n", .{ pm.name, pm.value });
            try std.testing.expectEqual(@as(u16, @intCast(@field(p, pm.name))), pm.value);
        }
    }

    // Every PRIV_* constant the build host defines is in the table.
    inline for (@typeInfo(p).@"struct".decls) |decl| {
        if (comptime std.mem.startsWith(u8, decl.name, "PRIV_")) {
            const v = @field(p, decl.name);
            const T = @TypeOf(v);
            if (comptime (@typeInfo(T) == .int or @typeInfo(T) == .comptime_int)) {
                errdefer std.debug.print("{s} = {d} missing from priv_names\n", .{ decl.name, v });
                const want: u16 = @intCast(v);
                try std.testing.expectEqual(@as(?u16, want), lookupPrivByName(decl.name));
            }
        }
    }

    try std.testing.expect(p._PRIV_HIGHEST <= AUTODO_BITMAP_BITS);
}

test "categories fit the bitmap and misc covers PRIV_VMM_PPTDEV" {
    for (priv_categories) |pc| {
        try std.testing.expect(pc.start <= pc.end);
        try std.testing.expect(pc.end < AUTODO_BITMAP_BITS);
    }
    for (priv_names) |pm| {
        try std.testing.expect(pm.value < AUTODO_BITMAP_BITS);
    }

    const pptdev = lookupPrivByName("PRIV_VMM_PPTDEV").?;
    try std.testing.expect(privBitSet(buildBitmap(&.{"all"}).as_bitmap, pptdev));
    try std.testing.expect(privBitSet(buildBitmap(&.{"misc"}).as_bitmap, pptdev));
    try std.testing.expect(!privBitSet(buildBitmap(&.{
        "system", "audit", "cred", "debug", "jail", "kld",
        "proc",   "vfs",   "vm",   "dev",   "net",
    }).as_bitmap, pptdev));

    var scope = buildBitmap(&.{"all"});
    clearPrivBit(&scope.as_bitmap, pptdev);
    try std.testing.expect(!privBitSet(scope.as_bitmap, pptdev));
}

test "every privilege belongs to a category" {
    for (priv_names) |pm| {
        var found = false;
        for (priv_categories) |pc| {
            if (pm.value >= pc.start and pm.value <= pc.end) {
                found = true;
                break;
            }
        }
        errdefer std.debug.print("{s} ({d}) is in no category\n", .{ pm.name, pm.value });
        try std.testing.expect(found);
    }

    // Naming every category therefore grants what "all" grants.
    const named = buildBitmap(&.{
        "system", "audit", "cred", "debug", "jail", "kld",
        "proc",   "vfs",   "vm",   "dev",   "net",  "misc",
    });
    for (priv_names) |pm| {
        errdefer std.debug.print("{s} ({d}) is not granted by the named categories\n", .{ pm.name, pm.value });
        try std.testing.expect(privBitSet(named.as_bitmap, pm.value));
    }
}

test "stock profiles deny only known privileges" {
    const profile_dir = "../config/profiles";
    var dir = try std.fs.cwd().openDir(profile_dir, .{ .iterate = true });
    defer dir.close();

    var checked: usize = 0;
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".conf")) continue;

        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrintZ(&path_buf, profile_dir ++ "/{s}", .{entry.name});
        const parser = ucl.Parser.init(0) orelse return error.UclInit;
        defer parser.deinit();
        try std.testing.expect(parser.addFile(path));
        const root = parser.getObject() orelse return error.UclParse;
        defer ucl.unref(root);

        if (root.lookup("deny")) |deny_obj| {
            if (deny_obj.lookup("privileges")) |privs| {
                var pit = privs.iterate();
                while (pit.next()) |item| {
                    const s = item.toString() orelse return error.NotAString;
                    errdefer std.debug.print("{s}: unknown privilege {s}\n", .{ entry.name, s });
                    try std.testing.expect(lookupPrivByName(s) != null);
                }
            }
        }
        checked += 1;
    }
    try std.testing.expect(checked > 0);
}
