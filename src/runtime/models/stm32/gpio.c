#include <surgeon/models/stm32/gpio.h>

/* Array to hold the state of the GPIO pins. Each entry corresponds to a port,
 * each port holds a number of pins (represented by the bits).
 * Note: we currently do not use the GPIO pins for fuzzing input but we'll
 * expand the GPIO interface for that use case as well */
uint32_t stm32_gpio_ports[NUM_GPIO_PORTS] = {0};
