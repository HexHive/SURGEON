/* ##############   Includes   ############## */
#include <surgeon/runtime.h>
#include <surgeon/logging.h>
#include <surgeon/timer.h>
#include <stdbool.h>
#include <stdint.h>

/* #########   Function signatures   ######## */
static void USED riot_nvic_enableirq(int irqn);
static void USED riot_nvic_disableirq(int irqn);

/**
 * @brief Enable an IRQ
 *
 * Starts the timer for an IRQ if it is already set up, creates a new timer
 * otherwise.
 * Note that the concept of timers here does not refer to hardware timers but
 * to our basic block based timer emulation.
 *
 * @param int Interrupt number to enable
 */
static void USED riot_nvic_enableirq(int irqn) {
    /* IRQn is given as number of external interrupt => need to add
     * corresponding offset */
    uint32_t irq_num = (uint32_t)(EXTI_BASE + irqn);
    LOGD("Enable IRQ %u", irq_num);

    for (size_t i = 0; i < timer_count; i++) {
        if (timers[i].irq_num == irq_num) {
            /* Timer for this IRQn already exists => start */
            start_timer(i);
            return;
        }
    }

    /* Timer for this IRQn does not exist yet => create a new one */
    size_t timer_num = add_timer(1000, 1);
    if (unlikely(timer_num == (size_t)-1)) {
        LOGE("Adding timer failed");
        abort();
    }
    attach_irq(timer_num, irq_num);
    start_timer(timer_num);
}

/**
 * @brief Disable an IRQ
 *
 * Stops the timer for an IRQ if it is set up, does nothing otherwise.
 * Note that the concept of timers here does not refer to hardware timers but
 * to our basic block based timer emulation.
 *
 * @param int Interrupt number to disable
 */
static void USED riot_nvic_disableirq(int irqn) {
    /* IRQn is given as number of external interrupt => need to add
     * corresponding offset */
    uint32_t irq_num = (uint32_t)(EXTI_BASE + irqn);
#ifndef NDEBUG
    printf("[%s] Disable IRQ %u\n", __func__, irq_num);
#endif /* NDEBUG */

    for (size_t i = 0; i < timer_count; i++) {
        if (timers[i].irq_num == irq_num) {
            /* Stop the timer */
            stop_timer(i);
            return;
        }
    }

#ifndef NDEBUG
    printf("[%s] Tried to disable IRQ %u which has not been enabled before\n",
           __func__, irq_num);
    abort();
#endif /* NDEBUG */
}
