#include <fcntl.h>
#include <syscall.h>
#include <sys/types.h>
#include <unistd.h>

extern ssize_t sys_open(const void* path, int flags);
extern ssize_t sys_close(int fd);
extern ssize_t sys_write(int fd, const void* buf, size_t size);
extern ssize_t sys_exit(int exit_code);

void _start() {
    int STDIN = 0;
    int STDOUT = 1;
    int STDERR = 2;
    const char string[] = "Hello, World\n\0";

    sys_write(STDOUT, string, sizeof(string));

    sys_close(STDIN);
    sys_close(STDOUT);
    sys_close(STDERR);

    sys_exit(0);
    __builtin_unreachable();
}
