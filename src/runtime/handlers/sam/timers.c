/* ##############   Includes   ############## */
#include <surgeon/runtime.h>
#include <surgeon/timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* #########   Function signatures   ######## */
static void USED sam_timers_initisr(void *, uint32_t, uint32_t, int irqn);

/**
 * @brief Enable an interrupt with the given IRQ number
 *
 * Technically, this is not part of libsam but groups together multiple
 * functions in libsam for setting up a timer and starting it. Because of the
 * inlining of NVIC_EnableIRQ that we've observed, we implement the handler for
 * the _initISR wrapper function instead of the underlying timer functions in
 * libsam.
 *
 * @param void * (unused) Pointer to the timer for the interrupt
 * @param uint32_t (unused) Timer channel
 * @param uint32_t (unused) Peripheral clock id
 * @param int The number of the external interrupt to enable
 */
static void USED sam_timers_initisr(void *, uint32_t, uint32_t, int irqn) {
#ifndef NDEBUG
    printf("[%s] Configuring timer for external IRQn %d\n", __func__, irqn);
#endif /* NDEBUG */

    uint32_t irq_num = EXTI_BASE + irqn;

    for (size_t i = 0; i < timer_count; i++) {
        if (timers[i].irq_num == irq_num) {
            /* Timer for this IRQ already exists => start */
            start_timer(i);
            return;
        }
    }

    /* Timer for this IRQ does not exist yet => create a new one */
    size_t timer_num = add_timer(10000, DYNINC);
    if (unlikely(timer_num == (size_t)-1)) {
        fprintf(stderr, "[%s] Adding timer for external IRQn %d failed\n",
                __func__, irqn);
        return;
    }
    attach_irq(timer_num, irq_num);
    start_timer(timer_num);
}
