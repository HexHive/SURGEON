#include <surgeon/context.h>
#include <surgeon/interrupts.h>
#include <surgeon/runtime.h>
#include <surgeon/timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* #########   Function signatures   ######## */
static void USED emulate_timer(uint32_t inc);

/* ###############   Globals   ############## */
eftimer_t timers[MAX_TIMERS] = {0};
size_t timer_count = 0;

/**
 * @brief Add a timer that will be incremented by our timer emulation code.
 *
 * This adds a new timer to the global list of timers, which will be incremented
 * on each basic block.
 *
 * @param reload_val The reload value with which the timer is restarted
 * @param resolution The value by which to decrease the timer on each tick
 *
 * @return size_t    The index of the newly allocated timer
 */
size_t add_timer(uint64_t reload_val, uint32_t resolution) {
    /* Initialize the timer with 0 ticks and disabled */
    if (timer_count >= MAX_TIMERS) {
        fprintf(stderr,
                "Timer registration failed: Maximum number of supported timers "
                "already registerd");
        return (size_t)-1;
    }
    eftimer_t *tim = &timers[timer_count];
    tim->tick_val = 0;
    tim->reload_val = reload_val;
    tim->resolution = resolution;
    tim->irq_num = NOIRQ;
    tim->is_active = false;
    tim->is_pending = false;
    /* Post-increment timer counter */
    return timer_count++;
}

/**
 * @brief Fast-forward time as perceived by the firmware.
 *
 * Fast-forwards time based on which timer would trigger an interrupt next. This
 * serves as a means to quickly get out of infinite/long-running loops in the
 * firmware which wait for an interrupt to be triggered.
 *
 */
void fast_forward_timers(void) {
    static size_t last_ff_timer = 0;
    uint64_t diff = 0;
    /* Figure out by how much to fast-forward time */
    for (size_t i = last_ff_timer; i < timer_count; i++) {
        /* Round-robin timer triggering -- do not always only check timers at
           the start of the list */
        if (timers[i].is_active && timers[i].irq_num != NOIRQ) {
            /* Found an active timer with an interrupt -- fast forward time so
             * that this interrupt is triggered next */
            diff = timers[i].reload_val - timers[i].tick_val;
            last_ff_timer = ++i % timer_count;
            break;
        }
    }
    /* Actually fast-forward time */
    tick_timers(diff);
    /* Trigger possibly pending interrupts */
    fire_pending_interrupts();
}

/**
 * @brief Emulate timers in the firmware.
 *
 * The function takes care of emulating timer behavior in the firmware.
 * Timers are incremented and in case they have an interrupt associated, the
 * corresponding interrupt is triggered whenever the timer reaches the defined
 * limit.
 */
static void USED emulate_timer(uint32_t inc) {
    /* First, tick all the timers. */
    tick_timers(inc);
    /* Second, fire any pending interrupts that may result from the first step.
     */
    fire_pending_interrupts();

    /* Third, fire the PENDSV exception if it is pending */
    if (*ICSR & PENDSV_BITMASK && isr_active == false && pendsv_enable) {
        /* Clear PENDSVSET bit */
        *ICSR &= ~((uint32_t)PENDSV_BITMASK);
        /* Fire interrupt */
        asm volatile("bkpt #4" ::: "memory");
    }
}
