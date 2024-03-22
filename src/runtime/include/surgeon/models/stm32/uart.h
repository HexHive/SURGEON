#ifndef STM32_UART_H
#define STM32_UART_H

#pragma once

/* ##############   Includes   ############## */
#include <stdbool.h>
#include <stddef.h>

/* ##############   Typedefs   ############## */
typedef struct _stm32_uart_status_s {
    void *uart_obj;
    bool sent;
    bool received;
} stm32_uart_status_t;

/* #############   Global vars   ############ */
/* Provided in models/stm32/uart.c */
extern stm32_uart_status_t status;

#endif /* STM32_UART_H */
