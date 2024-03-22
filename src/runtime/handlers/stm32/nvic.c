/* ##############   Includes   ############## */
#include <surgeon/runtime.h>
#include <surgeon/timer.h>
#include <stdbool.h>
#include <stdint.h>

/* #########   Function signatures   ######## */
static void USED stm32_nvic_enableirq(int irqn);
static void USED stm32_nvic_disableirq(int irqn);
static void USED stm32_nvic_clearpendingirq(int irqn);

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
static void USED stm32_nvic_enableirq(int irqn) {
    /* IRQn is given as number of external interrupt => need to add
     * corresponding offset */
    uint32_t irq_num = (uint32_t)(EXTI_BASE + irqn);
#ifndef NDEBUG
    printf("[%s] Enable IRQ %u\n", __func__, irq_num);
#endif /* NDEBUG */

    for (size_t i = 0; i < timer_count; i++) {
        if (timers[i].irq_num == irq_num) {
            /* Timer for this IRQn already exists => start */
            start_timer(i);
            return;
        }
    }

    /* Timer for this IRQn does not exist yet => create a new one, trigger every
     * ~10000 instructions */
    size_t timer_num = add_timer(10000, DYNINC);
    if (unlikely(timer_num == (size_t)-1)) {
        fprintf(stderr, "[%s] Adding timer failed\n", __func__);
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
static void USED stm32_nvic_disableirq(int irqn) {
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

/**
 * @brief Clear the pending flag for an IRQ
 *
 * Clears the pending flag for an IRQ if the corresponding timer is set up,
 * does nothing otherwise.
 * Note that the concept of timers here does not refer to hardware timers but
 * to our basic block based timer emulation.
 *
 * @param int Interrupt number for which to clear the pending flag
 */
static void USED stm32_nvic_clearpendingirq(int irqn) {
    /* IRQn is given as number of external interrupt => need to add
     * corresponding offset */
    uint32_t irq_num = (uint32_t)(EXTI_BASE + irqn);
#ifndef NDEBUG
    printf("[%s] Clear pending flag for IRQ %u\n", __func__, irq_num);
#endif /* NDEBUG */

    for (size_t i = 0; i < timer_count; i++) {
        if (timers[i].irq_num == irq_num) {
            /* Clear pending flag */
            timers[i].is_pending = false;
            return;
        }
    }

#ifndef NDEBUG
    printf("[%s] Tried to clear pending flag for invalid IRQ %u\n", __func__,
           irq_num);
    abort();
#endif /* NDEBUG */
}
