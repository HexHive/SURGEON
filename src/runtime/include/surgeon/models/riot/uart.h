#ifndef RIOT_UART_H
#define RIOT_UART_H

#pragma once
/* ##############   Includes   ############## */
#include <stdint.h>

/* ##############   Typedefs   ############## */
typedef uint8_t  uart_t;
typedef void(*uart_rx_cb_t) (void *arg, uint8_t data);

#endif /* RIOT_UART_H */
