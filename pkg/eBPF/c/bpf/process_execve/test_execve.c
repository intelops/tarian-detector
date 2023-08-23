// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    char *program = "/bin/ls"; // Path to the program to execute
    char *args[] = {program, "-l", NULL}; // Arguments for the program

    // Fork a new process
    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork");
        return 1;
    } else if (child_pid == 0) {
        // Child process: execute the new program
        execve(program, args, NULL);
        perror("execve"); // This will be printed if execve fails
        exit(1);
    } else {
        // Parent process: wait for the child to finish
        int status;
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("Child process exited with status %d\n", WEXITSTATUS(status));
        } else {
            printf("Child process terminated abnormally\n");
        }
    }

    return 0;
}
