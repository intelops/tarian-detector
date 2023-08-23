// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h> 

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main() {
    const char *filename = "Makefile"; // Replace with the desired file path
    int flags = O_CREAT | O_WRONLY; // Create if not exist, open for writing
    mode_t mode = S_IRUSR | S_IWUSR; // Read and write permission for user

    int fd = open(filename, flags, mode);

    if (fd == -1) {
        perror("open");
        return 1;
    }

    printf("File opened successfully with file descriptor: %d\n", fd);

    // Close the file descriptor
    close(fd);

    return 0;
}
