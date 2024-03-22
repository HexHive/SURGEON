/* ##############   Includes   ############## */
#include <assert.h>
#include <surgeon/runtime.h>
#include <surgeon/models/stm32/gpio.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* #########   Function signatures   ######## */
static void USED grbl_gpio_clr(int n);
static void USED grbl_gpio_set(int n);
static void USED grbl_gpio_toggle(int n);
static int USED grbl_gpio_rd(int n);
static int USED grbl_gpio_rd_inv(int n);
static void USED grbl_step_wr(uint32_t x);
static void USED grbl_dirn_wr(uint32_t x);

/* ###############   Globals   ############## */
static const uint32_t step_mask = 0x00000550;
static const uint32_t dir_mask = 0x00000aa0;

/**
 * @brief Unset (clear) a GPIO pin
 *
 * @param int GPIO pin identifier
 */
static void USED grbl_gpio_clr(int n) {
    assert(GPIO_PORT(n) < NUM_GPIO_PORTS);

#ifndef NDEBUG
    printf("[%s] Clear pin %d @ port %d\n", __func__, GPIO_PIN(n),
           GPIO_PORT(n));
#endif /* NDEBUG */

    stm32_gpio_ports[GPIO_PORT(n)] &= ~GPIO_BIT(n);
}

/**
 * @brief Set a GPIO pin
 *
 * @param int GPIO pin identifier
 */
static void USED grbl_gpio_set(int n) {
    assert(GPIO_PORT(n) < NUM_GPIO_PORTS);

#ifndef NDEBUG
    printf("[%s] Set pin %d @ port %d\n", __func__, GPIO_PIN(n), GPIO_PORT(n));
#endif /* NDEBUG */

    stm32_gpio_ports[GPIO_PORT(n)] |= GPIO_BIT(n);
}

/**
 * @brief Toggle a GPIO pin
 *
 * @param int GPIO pin identifier
 */
static void USED grbl_gpio_toggle(int n) {
    assert(GPIO_PORT(n) < NUM_GPIO_PORTS);

#ifndef NDEBUG
    printf("[%s] Toggle pin %d @ port %d: %d => %d\n", __func__, GPIO_PIN(n),
           GPIO_PORT(n), grbl_gpio_rd(n), grbl_gpio_rd_inv(n));
#endif /* NDEBUG */

    stm32_gpio_ports[GPIO_PORT(n)] ^= GPIO_BIT(n);
}

/**
 * @brief Read a GPIO pin
 *
 * @param int GPIO pin identifier
 *
 * @return int The current value of the GPIO pin (0 or 1)
 */
static int USED grbl_gpio_rd(int n) {
    assert(GPIO_PORT(n) < NUM_GPIO_PORTS);

    int val = (int)((stm32_gpio_ports[GPIO_PORT(n)] >> GPIO_PIN(n)) & 1);

#ifndef NDEBUG
    printf("[%s] Read pin %d @ port %d: %d\n", __func__, GPIO_PIN(n),
           GPIO_PORT(n), val);
#endif /* NDEBUG */

    return val;
}

/**
 * @brief Read the inverse of a GPIO pin
 *
 * @param int GPIO pin number
 *
 * @return int The inverted current value of the GPIO pin (0 or 1)
 */
static int USED grbl_gpio_rd_inv(int n) {
    assert(GPIO_PORT(n) < NUM_GPIO_PORTS);

    int val = (int)(~(stm32_gpio_ports[GPIO_PORT(n)] >> GPIO_PIN(n)) & 1);

#ifndef NDEBUG
    printf("[%s] Read pin %d @ port %d: %d\n", __func__, GPIO_PIN(n),
           GPIO_PORT(n), val);
#endif /* NDEBUG */

    return val;
}

/**
 * @brief Write the GPIO pins for stepping
 *
 * @param uint32_t GPIO pin values to set
 */
static void USED grbl_step_wr(uint32_t x) {
    uint32_t val = stm32_gpio_ports[PORTE];
    val &= ~step_mask;
    stm32_gpio_ports[PORTE] = (val | x);
}

/**
 * @brief Write the GPIO pins for setting the direction
 *
 * @param uint32_t GPIO pin values to set
 */
static void USED grbl_dirn_wr(uint32_t x) {
    uint32_t val = stm32_gpio_ports[PORTE];
    val &= ~dir_mask;
    stm32_gpio_ports[PORTE] = (val | x);
}
