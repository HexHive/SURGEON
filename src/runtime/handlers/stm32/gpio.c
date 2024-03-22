/* ##############   Includes   ############## */
#include <assert.h>
#include <surgeon/runtime.h>
#include <surgeon/models/stm32/gpio.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* #########   Function signatures   ######## */
static void USED stm32_gpio_writepin(void *port, uint16_t pin, int state);
static void USED stm32_gpio_togglepin(void *port, uint16_t pin);
static int USED stm32_gpio_readpin(void *port, uint16_t pin);

/**
 * @brief Set/clear a GPIO pin
 *
 * Takes the port address and pin number and sets it to the requested state.
 *
 * @param void * Port address of the GPIO peripheral
 * @param uint16_t Pin number (already encoded in the bitfield)
 * @param int State to set the pin to (0 == clear, 1 == set)
 */
static void USED stm32_gpio_writepin(void *port, uint16_t pin, int state) {
    size_t port_num = ((size_t)port & 0xffff) >> 10;
    assert(port_num < NUM_GPIO_PORTS);

#ifndef NDEBUG
    for (size_t i = 0; i < sizeof(pin) * CHAR_BIT; i++) {
        if (((pin >> i) & 1) != 0) {
            printf("[%s] %s pin %d @ port %d\n", __func__,
                   state ? "Set" : "Clear", i, port_num);
        }
    }
#endif /* NDEBUG */

    if (state == 0) {
        /* Reset pin */
        stm32_gpio_ports[port_num] &= ~pin;
    } else {
        /* Set pin */
        stm32_gpio_ports[port_num] |= pin;
    }
}

/**
 * @brief Toggle a GPIO pin
 *
 * @param void * Port address of the GPIO peripheral
 * @param uint16_t Pin number(s) (already encoded in the bitfield)
 */
static void USED stm32_gpio_togglepin(void *port, uint16_t pin) {
    size_t port_num = ((size_t)port & 0xffff) >> 10;
    assert(port_num < NUM_GPIO_PORTS);

#ifndef NDEBUG
    for (size_t i = 0; i < sizeof(pin) * CHAR_BIT; i++) {
        if (((pin >> i) & 1) != 0) {
            uint32_t old_val = (stm32_gpio_ports[port_num] >> i) & 1;
            printf("[%s] Toggle pin %d @ port %d: %d => %d\n", __func__, i,
                   port_num, old_val, !old_val);
        }
    }
#endif /* NDEBUG */

    stm32_gpio_ports[port_num] ^= pin;
}

/**
 * @brief Read a GPIO pin
 *
 * @param void * Port address of the GPIO peripheral
 * @param uint16_t Pin number (already encoded in the bitfield)
 *
 * @return int The state of the pin (0 == clear, 1 == set)
 */
static int USED stm32_gpio_readpin(void *port, uint16_t pin) {
    size_t port_num = ((size_t)port & 0xffff) >> 10;
    assert(port_num < NUM_GPIO_PORTS);
    assert(pin >> (ctz(pin) + 1) == 0); /* Ensure only a single bit is set */

    int val = (int)((stm32_gpio_ports[port_num] >> ctz(pin)) & 1);

#ifndef NDEBUG
    printf("[%s] Read pin %d @ port %d: %d\n", __func__, ctz(pin), port_num,
           val);
#endif /* NDEBUG */

    return val;
}
