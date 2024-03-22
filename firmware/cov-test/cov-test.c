#include <fcntl.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

extern ssize_t sys_open(const void* path, int flags);
extern ssize_t sys_close(int fd);
extern ssize_t sys_read(int fd, char* buf, size_t size);
extern ssize_t sys_write(int fd, const void* buf, size_t size);
extern ssize_t sys_exit(int exit_code);

void _start() {
    int STDIN = 0;
    char s[16];
    sys_read(STDIN, s, 16);

    if (s[0] == 'f') {
        if (s[1] == 'u') {
            if (s[2] == 'z') {
                if (s[3] == 'z') {
                    *(int*)0x0 = 0x0;
                }
            }
        }
    }

    sys_exit(0);
    __builtin_unreachable();
}
