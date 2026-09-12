/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Daniel Morante
 *
 * Test helper for kern_vmm_test.sh.
 *
 * Issues VM_UNBIND_PPTDEV on /dev/vmm/<name> for a PCI address that is not
 * a passthrough device attached to the VM.  vmm(4) checks PRIV_VMM_PPTDEV
 * before looking the device up, so the ioctl fails with EPERM when the
 * privilege is denied and with ENOENT (no such ppt device) or EBUSY (owned
 * by another VM) when it is granted.  Prints "denied" or "granted".
 */

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/ioctl.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	char path[MAXPATHLEN];
	struct vm_pptdev pptdev;
	int fd;

	if (argc != 2)
		errx(2, "usage: %s vmname", getprogname());

	snprintf(path, sizeof(path), "/dev/vmm/%s", argv[1]);
	fd = open(path, O_RDWR);
	if (fd < 0)
		err(2, "open %s", path);

	/* Highest PCI bus/slot/function. */
	pptdev.bus = 255;
	pptdev.slot = 31;
	pptdev.func = 7;

	if (ioctl(fd, VM_UNBIND_PPTDEV, &pptdev) == 0)
		errx(1, "VM_UNBIND_PPTDEV unexpectedly succeeded");
	switch (errno) {
	case EPERM:
		printf("denied\n");
		break;
	case ENOENT:
	case EBUSY:
		printf("granted\n");
		break;
	default:
		err(1, "VM_UNBIND_PPTDEV");
	}

	close(fd);
	return (0);
}
