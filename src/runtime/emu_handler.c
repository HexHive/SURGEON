#include <surgeon/context.h>
#include <surgeon/interrupts.h>
#include <surgeon/runtime.h>
#include <surgeon/timer.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

/* Emulation request IDs encoded in the breakpoint instruction's immediate */
typedef enum _emu_id_e {
    SVC = 1,
    UDF,
    INFLOOP,
    PENDSVID,
    MAX_EMU_ID
} emu_id_t;

/* Alternative stack used by the signal handler */
char signal_stack[STACKSIZE] = {0};

/**
 * @brief The signal handler dispatching TRAP-based emulation requests
 *
 * Based on the emulation request ID encoded in the trapping instruction's
 * immediate operand, the signal handler dispatches to the corresponding
 * emulator function.
 *
 * @param info siginfo_t pointer with information about the dispatched signal
 * @param ctx ucontext_t pointer holding the context from the trap location
 */
void emu_handler(int, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t *)ctx;
    /* Skip the bkpt whenever we return to the location that caused the trap */
    const size_t bkpt_length = 2;
    /* uc_mcontext is machine/implementation specific
     * => see include/sys/ucontext.h */
    uc->uc_mcontext.arm_pc += bkpt_length;

    emu_id_t emu_id = ((char *)info->si_addr)[0];

    switch (emu_id) {
        case SVC: {
            /* If we have a firmware that uses SVC and PENDSV for task
             * switching, only enable PENDSV task switching once we have
             * switched a context first via SVC task switching */
            pendsv_enable = true;
            trigger_interrupt_context_switch(SVCALL, &uc->uc_mcontext);
            break;
        }
        case INFLOOP: {
            /* Make the firmware return to where the signal was originally
             * raised after the timer fast forwarding/interrupt triggering (see
             * setting the PC below). This will likely just raise the signal
             * again and trigger the same code again for another round of timer
             * fast forwarding if we're actually in an infinite loop. OR with
             * 0x1 to ensure we're returning into Thumb mode. */
            uc->uc_mcontext.arm_lr = (uc->uc_mcontext.arm_pc - bkpt_length)
                                     | 0x1U;
            /* Continue execution in our timer fast forwarding code.
             * Mask out the low bit from the PC because the context switch
             * already takes care of Thumb mode and having the low bit set
             * causes an exception. */
            uc->uc_mcontext.arm_pc = (uintptr_t)&fast_forward_timers & ~0x1U;
            break;
        }
        case PENDSVID: {
            trigger_interrupt_context_switch(PENDSV, &uc->uc_mcontext);
            break;
        }
        case UDF:
        default: {
            // We should never reach here
            exit(42);
        }
    }
}

enum EXC_RETURN {
    HANDLER_MODE_MAIN_STACK = -15,  // 0xFFFFFFF1,
    THREAD_MODE_MAIN_STACK = -7,    // 0xFFFFFFF9,
    THREAD_MODE_PROCESS_STACK = -3  // 0xFFFFFFFD
};

/**
 * @brief The signal handler dispatching SEGV-based emulation requests
 *
 * Based on the current PC it is determined if this SEGV is an exception return
 * or a real SEGV. In the prior case, the appropriate context-restore logic is
 * emulated. In the latter case, the signal hanlder is reset and the program
 * crashes.
 *
 * @param signo int the singal number
 * @param info siginfo_t pointer with information about the dispatched signal
 * @param ctx ucontext_t pointer holding the context from the trap location
 */
void segv_emu_handler(int signo, siginfo_t *, void *ctx) {
    ucontext_t *uc = (ucontext_t *)ctx;
    /* uc_mcontext is machine/implementation specific
     * => see include/sys/ucontext.h */

    int pc_val = (int)uc->uc_mcontext.arm_pc;
    printf("pc_val is %d\n", pc_val);
    switch (pc_val - 1) {
        case HANDLER_MODE_MAIN_STACK: {
            printf("HANDLER_MODE_MAIN_STACK\n");
            exit(EXIT_SUCCESS);
            break;
        }
        case THREAD_MODE_MAIN_STACK: {
            printf("THREAD_MODE_MAIN_STACK\n");
            exit(EXIT_SUCCESS);
            break;
        }
        case THREAD_MODE_PROCESS_STACK: {
            printf("THREAD_MODE_PROCESS_STACK\n");
            exit(EXIT_SUCCESS);
            break;
        }
        default: {
            // reset default signal handler
            signal(signo, SIG_DFL);
            raise(SIGSEGV);
        }
    }
}

/**
 * @brief Register a signal handler for emulation requests
 *
 * Registers a signal handler (on a signal handler specific stack) for handling
 * SIGTRAP (which we use as an emulation request for certain instructions from
 * the firmware).
 *
 * @return success_t ERROR if registering the handler fails, SUCCESS otherwise
 */
success_t set_emu_handler(void) {
    /* Set alternative stack for signal handlers (to not mess up the firmware
     * stack) */
    stack_t ss = {
        .ss_sp = (void *)signal_stack,
        .ss_size = STACKSIZE,
        .ss_flags = 0,
    };

    if (sigaltstack(&ss, NULL) < 0) {
        return ERROR;
    }

    /* Register the signal handlers */
    struct sigaction sa_trap = {0};
    sa_trap.sa_flags = SA_ONSTACK | SA_RESTART | SA_SIGINFO;
    sa_trap.sa_sigaction = emu_handler;
    if (sigaction(SIGTRAP, &sa_trap, NULL) < 0) {
        return ERROR;
    }

    // struct sigaction sa_segv = {0};
    // sa_segv.sa_flags = SA_ONSTACK | SA_RESTART | SA_SIGINFO;
    // sa_segv.sa_sigaction = segv_emu_handler;
    // if (sigaction(SIGSEGV, &sa_segv, NULL) < 0) {
    //     return ERROR;
    // }

    return SUCCESS;
}
