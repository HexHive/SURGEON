#include <surgeon/models/stm32/uart.h>

/* Struct to record the last UART peripheral that took an action and what
 * action it was so that we can trigger the correct callback in IRQ handlers
 * for that peripheral */
stm32_uart_status_t status = {
    .uart_obj = NULL, .received = false, .sent = false};
