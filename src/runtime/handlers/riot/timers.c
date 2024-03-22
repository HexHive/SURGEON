/* ##############   Includes   ############## */
#include <surgeon/runtime.h>
#include <surgeon/logging.h>
#include <surgeon/timer.h>
#include <stdbool.h>
#include <stdint.h>

/* #########   Function signatures   ######## */
static void USED riot_rtt_init();
static uint32_t USED riot_rtt_get_counter();
static void USED riot_rtt_set_counter(uint32_t ctr);

size_t TIMER_IDX;

/**
 * @brief Initialize rtt timer.
 *
 * Initialize and start the rtt timer.
 *
 */
static void USED riot_rtt_init() {
    TIMER_IDX = add_timer(10000, DYNINC);

    if (unlikely(TIMER_IDX == (size_t)-1)) {
        LOGE("Adding timer failed");
        abort();
    }
    start_timer(TIMER_IDX);
}

/**
 * @brief Get rtt counter value.
 *
 * @return uint32_t The rtt counter value.
 */
static uint32_t USED riot_rtt_get_counter() {
    return (uint32_t)get_timer_val(TIMER_IDX);
}

/**
 * @brief Set rtt counter value.
 *
 * @param ctr The new tick value to set the timer to
 */
static void USED riot_rtt_set_counter(uint32_t ctr) {
    set_timer_val(TIMER_IDX, ctr);
}
