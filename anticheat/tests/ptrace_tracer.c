#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Traces the given command (argv[1..]) via PTRACE_TRACEME so the target
 * observes a real debugger via /proc/self/status TracerPid. Used by the
 * module test suite to exercise the debugger-detection path deterministically.
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 2;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            perror("ptrace TRACEME");
            _exit(1);
        }
        execvp(argv[1], &argv[1]);
        perror("execvp");
        _exit(1);
    }

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return 1;
    }
    while (1) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
            perror("ptrace CONT");
            break;
        }
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            break;
        }
    }
    return 0;
}
