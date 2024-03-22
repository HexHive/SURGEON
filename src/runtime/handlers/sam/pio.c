/* ##############   Includes   ############## */
#include <assert.h>
#include <surgeon/runtime.h>
#include <surgeon/models/sam/pio.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

/* #########   Function signatures   ######## */
static void USED sam_pio_setinput(void *port, uint32_t pins, uint32_t);
static void USED sam_pio_setoutput(void *port, uint32_t pins, uint32_t state,
                                   uint32_t, uint32_t);
static uint32_t USED sam_pio_getoutputdatastatus(void *port, uint32_t pins);
static void USED sam_pio_pullup(void *port, uint32_t pins, uint32_t enable);

/**
 * @brief Mark a set of pins as inputs
 *
 * @param void * The port the pins belong to
 * @param uint32_t The bitmask encoding the pins
 * @param uint32_t (unused) Bitmask containing pin attributes
 */
static void USED sam_pio_setinput(void *port, uint32_t pins, uint32_t) {
    size_t port_num = GPIO_PORT(port);
    assert(port_num < NUM_GPIO_PORTS);

    sam_gpio_ports[port_num].direction &= ~pins;
}

/**
 * @brief Mark a set of pins as outputs
 *
 * @param void * The port the pins belong to
 * @param uint32_t The bitmask encoding the pins
 * @param uint32_t Default value to set the pins to
 * @param uint32_t (unused) Indicator to set the pins as open-drain
 * @param uint32_t (unused) Indicator to enable the pins' pull-ups
 */
static void USED sam_pio_setoutput(void *port, uint32_t pins, uint32_t state,
                                   uint32_t, uint32_t) {
    size_t port_num = GPIO_PORT(port);
    assert(port_num < NUM_GPIO_PORTS);
#ifndef NDEBUG
    for (size_t i = 0; i < sizeof(pins) * CHAR_BIT; i++) {
        if (((pins >> i) & 1) != 0) {
            printf("[%s] %s pin %d @ port %d\n", __func__,
                   state ? "Set" : "Clear", i, port_num);
        }
    }
#endif /* NDEBUG */

    sam_gpio_port_t *sam_port = &sam_gpio_ports[port_num];
    /* Set pins as outputs */
    sam_port->direction |= pins;
    /* Set value for the pins */
    if (state == 0) {
        /* Reset pins */
        sam_port->data &= ~pins;
    } else {
        /* Set pins */
        sam_port->data |= pins;
    }
}

/**
 * @brief Retrieve whether a pin is configured as output
 *
 * @param void * The port the pins belong to
 * @param uint32_t The bitmask encoding the pins
 *
 * @return uint32_t 1 if at least one of the pins is configured as output, 0
 *                  otherwise
 */
static uint32_t USED sam_pio_getoutputdatastatus(void *port, uint32_t pins) {
    size_t port_num = GPIO_PORT(port);
    assert(port_num < NUM_GPIO_PORTS);

    return !!(sam_gpio_ports[port_num].direction & pins);
}

/**
 * @brief Enables/disables pull-ups for a set of pins
 *
 * Pull-ups are not fully simulated but we mimic a pullup by just setting the
 * default value of the pins accordingly.
 *
 * @param void * The port the pins belong to
 * @param uint32_t The bitmask encoding the pins
 * @param uint32_t Enable or disable pull-ups
 */
static void USED sam_pio_pullup(void *port, uint32_t pins, uint32_t enable) {
    /* Simulate a puillup through setting a default value -- not exactly
     * accurate but sufficient for now */
    sam_pio_setoutput(port, pins, enable, 0, 0);
}
