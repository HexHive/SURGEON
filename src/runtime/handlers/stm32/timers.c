/* ##############   Includes   ############## */
#include <surgeon/context.h>
#include <surgeon/runtime.h>
#include <surgeon/timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* #########   Function signatures   ######## */
static uint32_t USED stm32_timers_systick_config(uint32_t);
static uint32_t USED stm32_timers_base_start_it(void *htim);

/* ###############   Globals   ############## */
static const uint32_t tim2_irqn =
    EXTI_BASE + 28; /* 28 = IRQn, offset 16 for external interrupts */
static const uint32_t systick_freq =
    1000; /* Trigger systick roughly every 1000 instructions */

/**
 * @brief Set up the SysTick timer if it has not been set up yet
 *
 * @param uint32_t (unused) Tick frequency
 *
 * @return uint32_t 0 in case of success, 1 in case of error
 */
static uint32_t USED stm32_timers_systick_config(uint32_t) {
    uint32_t irq_num = (uint32_t)SYSTICK;

#ifndef NDEBUG
    printf("[%s] Configuring SysTick\n", __func__);
#endif /* NDEBUG */

    for (size_t i = 0; i < timer_count; i++) {
        if (timers[i].irq_num == irq_num) {
            /* Timer for SysTick already exists => start */
            start_timer(i);
            /* HAL_OK */
            return 0;
        }
    }

    /* Timer for SysTick does not exist yet => create a new one */
    size_t timer_num = add_timer(systick_freq, DYNINC);
    if (unlikely(timer_num == (size_t)-1)) {
        fprintf(stderr, "[%s] Adding timer for SysTick failed\n", __func__);
        /* HAL_ERROR */
        return 1;
    }
    attach_irq(timer_num, irq_num);
    start_timer(timer_num);
    /* Also set the reload value/current value MMIO registers -- some firmware
     * might access them directly for time calculations */
    *SYST_CVR = timers[timer_num].tick_val;
    *SYST_RVR = timers[timer_num].reload_val;
    /* HAL_OK */
    return 0;
}

/**
 * @brief Set up a timer in base mode and enable the corresponding interrupt
 *
 * Sets up and starts a timer and enables the corresponding interrupt as well
 * where required. Interrupt numbers unfortunately need to be hardcoded because
 * there is no call to NVIC_Enable with an interrupt number or similar, the
 * interrupt number is implicit in the firmware.
 *
 * @param void * Pointer to the timer struct
 *
 * @return uint32_t 0 in case of success, 1 in case of error
 */
static uint32_t USED stm32_timers_base_start_it(void *htim) {
    uint32_t timer = *(uint32_t *)htim;
    uint32_t irq_num = 0;

    switch (timer) {
        case 0x40000000U: {
            /* TIM2 according to all we've encountered so far */
            irq_num = tim2_irqn;
        }
        default: {
            break;
        }
    }

    if (irq_num != 0) {
        for (size_t i = 0; i < timer_count; i++) {
            if (timers[i].irq_num == irq_num) {
                /* Timer for requested IRQ already exists => start */
                start_timer(i);
                /* HAL_OK */
                return 0;
            }
        }

        /* For now, add a timer that fires every ~10000 instructions */
        size_t timer_num = add_timer(10000, DYNINC);
        if (unlikely(timer_num == (size_t)-1)) {
            fprintf(stderr, "[%s] Adding timer failed\n", __func__);
            abort();
        }
        attach_irq(timer_num, irq_num);
        start_timer(timer_num);
    }
    /* HAL_OK */
    return 0;
}
