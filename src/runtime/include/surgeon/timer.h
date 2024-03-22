#ifndef TIMER_H
#define TIMER_H

#pragma once

/* ##############   Includes   ############## */
#include <surgeon/interrupts.h>
#include <stdbool.h>
#include <stdint.h>

/* ###############   Macros   ############### */
#define MAX_TIMERS \
    32 /* For now maximum of 32 timers (to avoid dynamic allocation) */
#define NOIRQ \
    ((uint32_t)-1) /* No IRQ assigned to a timer => only count ticks */
#define DYNINC                                                                \
    ((uint32_t)0LL) /* Dynamic increment value instead of fixed increment for \
                       a timer, see tick_timers */

/* ##############   Typedefs   ############## */
typedef struct _eftimer_s {
    uint64_t tick_val;
    uint64_t reload_val;
    uint32_t resolution;
    uint32_t irq_num;
    bool is_active;
    bool is_pending;
} eftimer_t;

/* ########   Function signatures   ######### */
size_t add_timer(uint64_t reload_val, uint32_t resolution);
void fast_forward_timers(void);

/* ############   Declarations   ############ */
extern eftimer_t timers[MAX_TIMERS];
extern size_t timer_count;

/* ##########   Inline functions   ########## */

/**
 * @brief Attach an interrupt to the timer for the given index.
 *
 * Sets an IRQ number for the timer identified by the index into the timer list
 * which causes it to trigger when its reload_val is reached.
 *
 * @param index The list index identifying the timer to trigger interrupts for
 * @param irq_num The IRQ number to attach to the timer
 */
static inline void attach_irq(size_t index, uint32_t irq_num) {
    if (index < timer_count) {
        timers[index].irq_num = irq_num;
    }
}

/**
 * @brief Start the timer for the given index into the timer list.
 *
 * Sets the corresponding timer's active flag to true so that it is included in
 * the tick function.
 *
 * @param index The list index identifying the timer to enable
 */
static inline void start_timer(size_t index) {
    if (index < timer_count) {
        timers[index].is_active = true;
    }
}

/**
 * @brief Stops the timer for the given index into the timer list.
 *
 * Sets the corresponding timer's active flag to fals so that it is excluded in
 * the tick function.
 *
 * @param index The list index identifying the timer to disable
 */
static inline void stop_timer(size_t index) {
    if (index < timer_count) {
        timers[index].is_active = false;
    }
}

/**
 * @brief Gets the tick value for the timer for the given index.
 *
 * Return the tick value for the timer passed. The timer is passed as an index
 * into the timer list.
 *
 * @param index The list index identifying the timer to return
 */
static inline uint64_t get_timer_val(size_t index) {
    if (index < timer_count) {
        return timers[index].tick_val;
    } else {
        return 0;
    }
}

/**
 * @brief Sets the tick value for the timer for the given index.
 *
 * Return the tick value for the timer passed. The timer is passed as an index
 * into the timer list.
 *
 * @param index The list index identifying the timer to return
 * @param timer_val The new tick value to set the timer to
 */
static inline void set_timer_val(size_t index, uint64_t timer_val) {
    if (index < timer_count) {
        timers[index].tick_val = timer_val;
    }
}

/**
 * @brief Tick all the active timers.
 *
 * Increases the tick value for each active timer by its resolution.
 * If necessary, sets the corresponding interrupt as pending and resets the
 * timer value.
 * If a non-zero increment is provided as an argument (e.g., to arbitrarily
 * modify time as seen by the firmware), this increment is added to each active
 * timer. If zero is provided as an argument, the timer's resolution value is
 * added instead.
 *
 * @param increment The increment by which to adjust timers
 */
static inline void tick_timers(uint32_t increment) {
    for (size_t i = 0; i < timer_count; i++) {
        if (timers[i].is_active == false) {
            /* Timer not active -- continue */
            continue;
        }
        /* Timer active -- tick: either by its resolution if set, by the given
         * increment otherwise */
        timers[i].tick_val +=
            (timers[i].resolution != DYNINC) ? timers[i].resolution : increment;
        if (timers[i].irq_num != NOIRQ
            && timers[i].tick_val >= timers[i].reload_val) {
            /* Timer fired! */
            timers[i].is_pending = true;
            timers[i].tick_val = 0;
        }
    }
}

/**
 * @brief Fire pending interrupts.
 *
 * Checks for each of the timers whether it has an interrupt attached and the
 * interrupt is set as pending. If yes, triggers the corresponding interrupt.
 */
static inline void fire_pending_interrupts(void) {
    for (size_t i = 0; isr_active == false && i < timer_count; i++) {
        if (timers[i].is_active == false || timers[i].irq_num == NOIRQ) {
            /* Timer not active/no interrupt attached -- continue */
            continue;
        }
        /* Timer active -- check if pending and trigger if necessary */
        if (timers[i].is_pending) {
            trigger_interrupt(timers[i].irq_num);
            timers[i].is_pending = false;
        }
    }
}

#endif /* TIMER_H */
