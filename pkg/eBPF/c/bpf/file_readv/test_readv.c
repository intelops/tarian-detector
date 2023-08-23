// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>

int main() {
    int fd = STDIN_FILENO; // File descriptor for stdin
    struct iovec iov[2];
    char buffer1[10]; // Buffer for first read
    char buffer2[10]; // Buffer for second read
    ssize_t total_bytes = 0;

    iov[0].iov_base = buffer1;
    iov[0].iov_len = sizeof(buffer1);
    iov[1].iov_base = buffer2;
    iov[1].iov_len = sizeof(buffer2);

    ssize_t bytes_read = readv(fd, iov, 2);

    if (bytes_read == -1) {
        perror("readv");
        return 1;
    }

    printf("Total bytes read: %zd\n", bytes_read);

    // Print the contents of the buffers if needed
    printf("Buffer 1: %s\n", buffer1);
    printf("Buffer 2: %s\n", buffer2);

    return 0;
}
