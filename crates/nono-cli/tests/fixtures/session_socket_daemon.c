/* Test-only daemon that changes session, reparents, and invokes a tool shim. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int data_file(const char *directory, const char *name, int flags) {
    char path[4096];
    int size = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (size < 0 || (size_t)size >= sizeof(path)) _exit(2);
    return open(path, flags, 0600);
}

int main(int argc, char **argv) {
    if (argc != 2 || chdir(argv[1]) != 0) return 2;
    alarm(30);
    pid_t child = fork();
    if (child < 0) return 3;
    if (child > 0) return 0;
    if (setsid() < 0) _exit(4);
    child = fork();
    if (child < 0) _exit(5);
    if (child > 0) _exit(0);

    /* Leave no inherited stdio pipe keeping the launching command alive. */
    int null = open("/dev/null", O_RDWR);
    if (null < 0) _exit(6);
    for (int fd = 0; fd < 3; fd++) if (dup2(null, fd) < 0) _exit(7);
    if (null > 2) close(null);
    alarm(30);
    while (getppid() != 1) usleep(10000);
    int pid = data_file(argv[1], "pid", O_WRONLY | O_CREAT | O_TRUNC);
    if (pid < 0 || dprintf(pid, "%d\n", getpid()) < 0) _exit(8);
    close(pid);
    int go;
    while ((go = data_file(argv[1], "go", O_RDONLY)) < 0) usleep(10000);
    close(go);

    int output = data_file(argv[1], "output", O_WRONLY | O_CREAT | O_TRUNC);
    int error = data_file(argv[1], "error", O_WRONLY | O_CREAT | O_TRUNC);
    if (output < 0 || error < 0) _exit(9);
    child = fork();
    if (child < 0) _exit(10);
    if (child == 0) {
        if (dup2(output, 1) < 0 || dup2(error, 2) < 0) _exit(11);
        close(output);
        close(error);
        execlp("leaf", "leaf", "verified", (char *)NULL);
        _exit(127);
    }
    close(output);
    close(error);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) _exit(12);
    int result = data_file(argv[1], "result", O_WRONLY | O_CREAT | O_TRUNC);
    if (result < 0 || dprintf(result, "%d\n", WEXITSTATUS(status)) < 0) _exit(13);
    close(result);
    _exit(0);
}
