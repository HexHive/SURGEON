#include <fcntl.h>
#include <syscall.h>
#include <sys/types.h>
#include <unistd.h>

ssize_t sys_open(const void *path, int flags) {
    register int32_t syscallnum_reg asm("r7") = __NR_write;
    register const void *path_reg asm("r0") = path;
    register int flags_reg asm("r1") = flags;
    asm volatile(
        "svc #0"
        : "+r"(path_reg)
        : "r"(syscallnum_reg), "r"(flags_reg)
        : "r2", "r3", "r4", "r5", "r6", "memory");
    return ((ssize_t)path_reg);
}

ssize_t sys_close(int fd) {
    register int32_t syscallnum_reg asm("r7") = __NR_close;
    register int fd_reg asm("r1") = fd;
    asm volatile(
        "svc #0"
        : "+r"(fd_reg)
        : "r"(syscallnum_reg)
        : "r2", "r3", "r4", "r5", "r6", "memory");
    return fd_reg;
}

ssize_t sys_write(int fd, const void *buf, size_t size) {
    register int32_t syscallnum_reg asm("r7") = __NR_write;
    register int fd_reg asm("r0") = fd;
    register const void *buf_reg asm("r1") = buf;
    register size_t size_reg asm("r2") = size;
    asm volatile(
        "svc #0"
        : "+r"(fd_reg)
        : "r"(syscallnum_reg), "r"(buf_reg), "r"(size_reg)
        : "r3", "r4", "r5", "r6", "memory");
    return fd_reg;
}

ssize_t sys_read(int fd, const void *buf, size_t size) {
    register int32_t syscallnum_reg asm("r7") = __NR_read;
    register int fd_reg asm("r0") = fd;
    register const void *buf_reg asm("r1") = buf;
    register size_t size_reg asm("r2") = size;
    asm volatile(
        "svc #0"
        : "+r"(fd_reg)
        : "r"(syscallnum_reg), "r"(buf_reg), "r"(size_reg)
        : "r3", "r4", "r5", "r6", "memory");
    return fd_reg;
}

ssize_t sys_exit(int exit_code) {
    register int32_t syscallnum_reg asm("r7") = __NR_exit;
    register int exitcode_reg asm("r0") = exit_code;
    asm volatile(
        "svc #0"
        : "+r"(exitcode_reg)
        : "r"(syscallnum_reg)
        : "r1", "r2", "r3", "r4", "r5", "r6", "memory");
    return exitcode_reg;
}
