// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#define _GNU_SOURCE
#include <linux/fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define OPEN_HOW_SIZE (sizeof(struct open_how))

int main() {
    const char *pathname = "Makefile";
    int dirfd = AT_FDCWD; // Use AT_FDCWD for the current working directory

    struct open_how how = {
        .flags = O_RDWR | O_CREAT,  // Flags for opening (read-write, create if not exists)
        .mode = 0644,               // Permissions for the new file
        .resolve = RESOLVE_NO_XDEV, // Resolve flag (can be modified according to your needs)
    };

    int fd = syscall(SYS_openat2, dirfd, pathname, &how, OPEN_HOW_SIZE);

    if (fd == -1) {
        perror("openat2");
        return 1;
    }

    printf("File opened successfully with file descriptor: %d\n", fd);

    close(fd);

    return 0;
}