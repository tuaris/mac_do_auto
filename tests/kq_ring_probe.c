/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Daniel Morante
 *
 * Test helper for kern_kqueue_test.sh.
 *
 * Attaches an EVFILT_READ knote to /dev/autodo and waits for a ring event.
 * This drives both call sites of the module's f_event handler: the
 * kevent(2) registration, and knote() when the kernel pushes an audit
 * event.  Prints "registered", then "events=<n> data=<bytes>", or
 * "timeout" (exit 1) when no event arrives.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "autodo.h"

static void
usage(void)
{

	errx(1, "usage: kq_ring_probe [-f] <timeout-seconds>");
}

int
main(int argc, char **argv)
{
	struct kevent kev;
	struct timespec ts;
	int ch, fd, kq, n;
	int flush = 0;

	while ((ch = getopt(argc, argv, "f")) != -1) {
		switch (ch) {
		case 'f':
			flush = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();

	fd = open("/dev/autodo", O_RDONLY);
	if (fd < 0)
		err(1, "open /dev/autodo");
	if (flush && ioctl(fd, AUTODO_FLUSH) != 0)
		err(1, "AUTODO_FLUSH");

	kq = kqueue();
	if (kq < 0)
		err(1, "kqueue");

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0)
		err(1, "kevent register");
	printf("registered\n");
	fflush(stdout);

	ts.tv_sec = strtol(argv[0], NULL, 10);
	ts.tv_nsec = 0;
	n = kevent(kq, NULL, 0, &kev, 1, &ts);
	if (n < 0)
		err(1, "kevent wait");
	if (n == 0) {
		printf("timeout\n");
		return (1);
	}
	printf("events=%d data=%lld\n", n, (long long)kev.data);
	return (0);
}
