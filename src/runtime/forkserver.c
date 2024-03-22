#include <surgeon/forkserver.h>
#include <surgeon/instrumentation.h>
#include <surgeon/runtime.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*##############   Globals   ############## */

// env var for afl shared memory (`shmid` for `shmat()`)
static const char SHM_ENV_VAR[] = "__AFL_SHM_ID";
// incoming messages from afl
static const int FORKSRV_FD_IN = 198;
// outgoing messages to afl
static const int FORKSRV_FD_OUT = 199;
/* Memory location for previous_location for coverage calculation */
cov_instr_ctrl_t *instr_ctrl = NULL;

// Global variable used by the signal handler of SIGINT and SIGTERM to instruct
// the main loop in fork_forever() to exit at the next occasion.
static volatile bool FORK_SERVER_ABORTED = false;

static int afl_read(uint32_t *out) {
    ssize_t res;

    res = read(FORKSRV_FD_IN, out, 4);

    if (res == -1) {
        if (errno == EINTR) {
            fprintf(stderr,
                    "Interrupted while waiting for AFL message, aborting.\n");
        } else {
            fprintf(stderr,
                    "Failed to read four bytes from AFL pipe, aborting.\n");
        }
        return -1;
    } else if (res != 4) {
        return -1;
    } else {
        return 0;
    }
}

static int afl_write(uint32_t value) {
    ssize_t res;

    res = write(FORKSRV_FD_OUT, &value, 4);

    if (res == -1) {
        if (errno == EINTR) {
            fprintf(stderr,
                    "Interrupted while sending message to AFL, aborting.\n");
        } else {
            fprintf(stderr,
                    "Failed to write four bytes to AFL pipe, aborting.\n");
        }
        return -1;
    } else if (res != 4) {
        return -1;
    } else {
        return 0;
    }
}

/**
 * @brief Attach to afl shared memory.
 *
 * @return void* Pointer to the shared memory region shared with afl.
 */
static void *attach_afl_shm() {
    const char *shm_id_str;
    int shm_id;
    void *shm_ptr;

    shm_id_str = getenv(SHM_ENV_VAR);
    if (!shm_id_str) {
        fprintf(stderr, "%s missing\n", SHM_ENV_VAR);
        return NULL;
    }

    // get the `shmat()` shared memory identifier
    shm_id = atoi(shm_id_str);

    char *shm_addr_s = getenv(SHM_ADDR_ENV);
    if (!shm_addr_s) {
        fprintf(stderr, "%s missing\n", SHM_ADDR_ENV);
        return NULL;
    }

    char *endptr = NULL;
    long long int shm_addr = strtoll(shm_addr_s, &endptr, 16);
    if (errno == ERANGE || errno == EINVAL || *endptr != '\0' || shm_addr < 0) {
        fprintf(stderr, "Cannot convert address %s\n", shm_addr_s);
        return NULL;
    }

    printf("shm_addr: %#x\n", (uint32_t)shm_addr);
    shm_ptr = shmat(shm_id, (void *)(uint32_t)shm_addr, SHM_RND | SHM_REMAP);

    if (shm_ptr == (void *)-1) {
        perror("shmat");
        fprintf(stderr, "Overlapping mappings?\n");
        return NULL;
    }
    printf("shm attached\n");

    return shm_ptr;
}

static void term_signal_handler(int signo) {
    (void)signo;  // suppress unused parameter warning
    FORK_SERVER_ABORTED = true;
}

// we catch SIGINTs and SIGTERMs to set the global var `FORK_SERVER_ABORTED`.
// this will gracefully terminate the forkserver
static int install_signal_handlers(void) {
    struct sigaction act = {0};

    act.sa_handler = term_signal_handler;
    sigemptyset(&act.sa_mask);
    // act.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &act, NULL) == -1
        || sigaction(SIGTERM, &act, NULL) == -1) {
        perror("sigaction()");
        return -1;
    }

    return 0;
}

static int fork_forever(
    __attribute__((noreturn)) void (*call_target)(const void *), void *addr,
    void *shm) {
    int status = 0;

    if (install_signal_handlers() == -1) {
        fprintf(stderr, "Failed to install signal handlers, aborting.\n");
        return -1;
    }

    // Fork server main loop:
    while (!FORK_SERVER_ABORTED) {
        pid_t child_pid;
        uint32_t afl_msg = 0;
        int status_for_afl = 0;

        // Hey afl, we're ready to take input!
        if (afl_read(&afl_msg) == -1) {
            status = -1;
            break;
        }

        bzero(shm, AFL_MAP_SIZE);
        child_pid = fork();
        if (child_pid < 0) {
            perror("fork");
            status = -1;
            break;
        }

        if (!child_pid) {
            // child
            call_target(addr);
            exit(EXIT_SUCCESS);
        }

        // write child's pid back to afl
        if (afl_write(child_pid) == -1) {
            fprintf(stderr, "afl write failed for child with pid %d\n",
                    child_pid);
            status = -1;
            break;
        }

        if (waitpid(child_pid, &status_for_afl, 0) < 0) {
            fprintf(stderr,
                    "forkserver could not determine child's exit code\n");
        }

        if (afl_write(status_for_afl) == -1) {
            fprintf(stderr, "afl_write failed. status_for_afl %#x\n",
                    status_for_afl);
            break;
        }
    }

    return status;
}

int start_forkserver(
    __attribute__((noreturn)) void (*call_target)(const void *), void *addr) {
    uint8_t zeros[4] = {0, 0, 0, 0};
    void *afl_shm = NULL;
    int status = 0;

    // hey afl, we're alive!
    if (write(FORKSRV_FD_OUT, zeros, 4) != 4) {
        fprintf(stderr, "Failed sending alive msg to afl\n");
        status = -1;
        goto out;
    }

    // attach to afl shm
    afl_shm = attach_afl_shm();
    if (!afl_shm) {
        fprintf(stderr, "Failed to attach to afl shm\n");
        status = -1;
        goto out;
    }

    instr_ctrl =
        (cov_instr_ctrl_t *)map_region_from_env(INSTR_CTRL_ADDR_ENV, PAGESIZE);
    if (!instr_ctrl) {
        fprintf(stderr, "Cannot map instrumentation control region\n");
        return EXIT_FAILURE;
    }

    fork_forever(call_target, addr, afl_shm);

out:
    return status;
}
