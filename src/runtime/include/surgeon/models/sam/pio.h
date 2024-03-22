#ifndef SAM_PIO_H
#define SAM_PIO_H

#pragma once

/* ##############   Includes   ############## */
#include <stdint.h>

/* ###############   Macros   ############### */
#define GPIO_PORT(n) ((((size_t)n & 0xffffUL) >> 9) - 7)

/* ##############   Typedefs   ############## */
typedef enum _sam_gpio_port_id_e {
    PORTA = 0,
    PORTB,
    PORTC,
    PORTD,
    PORTE,
    PORTF,
    NUM_GPIO_PORTS
} sam_gpio_port_id_t;

typedef enum _sam_gpio_dir_e {
    INPUT = 0,
    OUTPUT
} sam_gpio_dir_t;

typedef struct _sam_gpio_port_s {
    uint32_t data;
    uint32_t direction;
} sam_gpio_port_t;

/* #############   Global vars   ############ */
/* Provided in models/sam/pio.c */
extern sam_gpio_port_t sam_gpio_ports[NUM_GPIO_PORTS];

#endif /* SAM_PIO_H */
