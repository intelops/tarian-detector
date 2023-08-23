// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <syscall.h>
#include <linux/fs.h>

int main() {
    const char *program = "/bin/ls"; // Path to the program you want to execute
    const char *dir = "/tmp";       // Directory in which to execute the program

    int dir_fd = open(dir, O_DIRECTORY);
    if (dir_fd == -1) {
        perror("open");
        return 1;
    }

    char *const argv[] = { (char *)program, NULL };
    char *const envp[] = { NULL };

    long ret = syscall(__NR_execveat, dir_fd, program, argv, envp, 0);
    if (ret == -1) {
        perror("syscall");
        return 1;
    }

    close(dir_fd);

    printf("Program executed successfully!\n");

    return 0;
}
