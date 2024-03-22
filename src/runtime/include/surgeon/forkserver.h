#include <stdint.h>
#include <stdio.h>

#ifndef FORKSERVER_H
#define FORKSERVER_H

static const size_t AFL_MAP_SIZE = 1 << 16;
/**
 * @brief Start the forkserver.
 *
 * @param call_target Function pointer that we pass `addr` to.
 * @param addr        Argument for `call_target`.
 * @return int        Termination status. Return 0 on success, -1 on error.
 */
int start_forkserver(
    __attribute__((noreturn)) void (*call_target)(const void *), void *addr);

#endif /*FORKSERVER_H*/
