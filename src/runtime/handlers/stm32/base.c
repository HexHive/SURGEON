/* ##############   Includes   ############## */
#include <surgeon/runtime.h>
#include <surgeon/timer.h>

/* #########   Function signatures   ######## */
static int USED stm32_base_hal_init(void);
static void USED stm32_base_systeminit(void);

/* ##############   Globals   ############### */
static const uint32_t systick_freq =
    1000; /* Trigger systick roughly every 1000 instructions */

/**
 * @brief Initialize the HAL / start the SysTick timer
 *
 * Currently does not do anything apart from kicking off the SysTick (which is
 * the most important part of the function anyway).
 *
 * @return int 0 as success code
 */
static int USED stm32_base_hal_init(void) {
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
 * @brief Initialize the VTOR
 *
 * Set the VTOR to the usual value of the start of the binary.
 * TODO: outsource VTOR value into a configuration file
 */
static void USED stm32_base_systeminit(void) {
    /* Set up the VTOR */
    *(VTOR) = (vect_t *)0x08000000;
#ifndef NDEBUG
    printf("[%s] Set up VTOR\n", __func__);
#endif /* NDEBUG */
}
