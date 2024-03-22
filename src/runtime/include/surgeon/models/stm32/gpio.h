#ifndef STM32_GPIO_H
#define STM32_GPIO_H

#pragma once

/* ##############   Includes   ############## */
#include <stdint.h>

/* ###############   Macros   ############### */
#define GPIO_NUM(port, pin) (((port) << 4) | (pin))
#define GPIO_PORT(n) ((n) >> 4)
#define GPIO_PIN(n) ((n) & 0x0f)
#define GPIO_BIT(n) (1 << GPIO_PIN(n))

/* ##############   Typedefs   ############## */
typedef enum _stm32_gpio_port_e {
    PORTA = 0,
    PORTB,
    PORTC,
    PORTD,
    PORTE,
    PORTF,
    PORTG,
    PORTH,
    PORTI,
    PORTJ,
    PORTK,
    NUM_GPIO_PORTS
} stm32_gpio_port_t;

/* #############   Global vars   ############ */
/* Provided in models/stm32/gpio.c */
extern uint32_t stm32_gpio_ports[NUM_GPIO_PORTS];

#endif /* STM32_GPIO_H */
