/* ##############   Includes   ############## */
#include <assert.h>
#include <surgeon/runtime.h>
#include <surgeon/logging.h>
#include <surgeon/symbols.h>
#include <surgeon/timer.h>
#include <stdbool.h>
#include <stdint.h>

typedef void thread_task_func_t;

typedef struct riot_thread {
    uintptr_t stack;
    int stacksize;
    char priority;
    int flags;
    thread_task_func_t *function;
    void *arg;
    char *name;
    uintptr_t context[16];
} riot_thread_t;

#define MAX_NUM_THREADS 16
riot_thread_t THREADS[MAX_NUM_THREADS] = {0};
ssize_t CURR_THREAD_IDX = -1;
#define RIOT_SCHED_PRIO_LEVEL 16
int CURR_PRIO = 0;
WEAK generic_func_t _sched_task_exit;

/* #########   Function signatures   ######## */
static uintptr_t USED riot_thread_isr_stack_pointer(void);
static void USED riot_cpu_switch_context_exit(void);
static void USED riot_sched_task_exit(void);
static int USED riot_thread_create(uintptr_t stack, size_t stacksize,
                                   char priority, int flags,
                                   thread_task_func_t *function, void *arg,
                                   char *name);

/**
 * @brief Get the current stack pointer.
 *
 * @param uintptr_t The current stack pointer.
 */
static uintptr_t USED riot_thread_isr_stack_pointer(void) {
    LOGD("%s", __func__);

    int stack;
    return (uintptr_t)&stack;
}

/**
 * @brief Restore the context of the `CURR_THREAD_IDX`
 */
static void riot_context_restore(void) {
    ucontext_t uc = {0};
    LOGD("%s", __func__);

    if (getcontext(&uc) == -1) {
        LOGE("getcontext error");
        perror("getcontext");
        abort();
    }

    riot_thread_t *thread = &THREADS[CURR_THREAD_IDX];
    assert(thread->stack != (uintptr_t)NULL);
    uc.uc_mcontext.arm_r0 = thread->context[0];
    uc.uc_mcontext.arm_r1 = thread->context[1];
    uc.uc_mcontext.arm_r2 = thread->context[2];
    uc.uc_mcontext.arm_r3 = thread->context[3];
    uc.uc_mcontext.arm_r4 = thread->context[4];
    uc.uc_mcontext.arm_r5 = thread->context[5];
    uc.uc_mcontext.arm_r6 = thread->context[6];
    uc.uc_mcontext.arm_r7 = thread->context[7];
    uc.uc_mcontext.arm_r8 = thread->context[8];
    uc.uc_mcontext.arm_r9 = thread->context[9];
    uc.uc_mcontext.arm_r10 = thread->context[10];
    uc.uc_mcontext.arm_fp = thread->context[11];
    uc.uc_mcontext.arm_ip = thread->context[12];
    uc.uc_mcontext.arm_sp = thread->context[13];
    uc.uc_mcontext.arm_lr = thread->context[14];
    uc.uc_mcontext.arm_pc = thread->context[15];

    if (setcontext(&uc) == -1) {
        LOGE("setcontext error");
        perror("setcontext");
        abort();
    }
}

/**
 * @brief Store the context of the `CURR_THREAD_IDX`
 */
static void riot_context_save(void) {
    ucontext_t uc = {0};
    LOGD("%s", __func__);

    if (getcontext(&uc) == -1) {
        LOGE("getcontext error");
        perror("getcotnext");
        abort();
    }

    riot_thread_t *thread = &THREADS[CURR_THREAD_IDX];
    thread->context[0] = uc.uc_mcontext.arm_r0;
    thread->context[1] = uc.uc_mcontext.arm_r1;
    thread->context[2] = uc.uc_mcontext.arm_r2;
    thread->context[3] = uc.uc_mcontext.arm_r3;
    thread->context[4] = uc.uc_mcontext.arm_r4;
    thread->context[5] = uc.uc_mcontext.arm_r5;
    thread->context[6] = uc.uc_mcontext.arm_r6;
    thread->context[7] = uc.uc_mcontext.arm_r7;
    thread->context[8] = uc.uc_mcontext.arm_r8;
    thread->context[9] = uc.uc_mcontext.arm_r9;
    thread->context[10] = uc.uc_mcontext.arm_r10;
    thread->context[11] = uc.uc_mcontext.arm_fp;
    thread->context[12] = uc.uc_mcontext.arm_ip;
    thread->context[13] = uc.uc_mcontext.arm_sp;
    thread->context[14] = uc.uc_mcontext.arm_lr;
    thread->context[15] = uc.uc_mcontext.arm_pc;
    return;
}

/**
 * @brief Switch to another task with a higher priority.
 */
static void USED riot_cpu_switch_context_exit(void) {
    LOGD("%s", __func__);
    if (CURR_THREAD_IDX != -1) {
        riot_context_save();
    }

    riot_thread_t *next_thread = NULL;
    for (int i = CURR_PRIO; i < RIOT_SCHED_PRIO_LEVEL; i++) {
        LOGI("Searching prio: %d\n", i);
        for (int j = 0; j < MAX_NUM_THREADS; j++) {
            // if thread slot `j` is empty, skip
            if (THREADS[j].stack == 0) {
                continue;
            }

            // skip the current thread
            if (CURR_THREAD_IDX != -1
                && THREADS[j].stack == THREADS[CURR_THREAD_IDX].stack) {
                continue;
            }

            LOGI("thread[%d] with prio %d\n", j, THREADS[j].priority);
            if (THREADS[j].stack && THREADS[j].priority <= i) {
                next_thread = &THREADS[j];
                CURR_THREAD_IDX = j;
                CURR_PRIO = next_thread->priority;
                LOGI("next thread is %d\n", j);
            }
            if (next_thread) {
                break;
            }
        }
        if (next_thread) {
            break;
        }
    }

    riot_context_restore();
    return;
}

/**
 * @brief Exit.
 */
static void USED riot_sched_task_exit(void) {
    LOGD("%s", __func__);
    exit(0);
    return;
}

/**
 * @brief Create a new riot thread.
 */
static int USED riot_thread_create(uintptr_t stack, size_t stacksize,
                                   char priority, int flags,
                                   thread_task_func_t *function, void *arg,
                                   char *name) {
    // create new thread object
    riot_thread_t thread = {0};
    thread.stack = stack + stacksize;
    thread.stacksize = stacksize;
    thread.priority = priority;
    thread.flags = flags;
    thread.function = function;
    thread.arg = arg;
    thread.name = name;

    // set up stack
    thread.context[13] = thread.stack;
    thread.context[14] = (uintptr_t)_sched_task_exit;  // Address of sched_task_exit
    // set up the entry point
    thread.context[15] = (uintptr_t)thread.function;

    // search for a free slot in the thread list
    int free_idx = -1;
    for (int i = 0; i < MAX_NUM_THREADS; i++) {
        if (THREADS[i].stack == 0) {
            free_idx = i;
            break;
        }
    }

    // check if we found a free slot, abort if not.
    if (free_idx == -1) {
        LOGE(
            "Cannot create thread. Maximum number of threads reached. "
            "Aborting.");
        abort();
    }

    memcpy(&THREADS[free_idx], &thread, sizeof(riot_thread_t));

    LOGI(
        "Creating RIOT OS thread '%s' at idx '%d' with prio '%d' and stack at "
        "%#x",
        thread.name, free_idx, thread.priority, thread.stack);

    return free_idx;
}
