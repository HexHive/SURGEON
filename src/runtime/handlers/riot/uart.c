/* ##############   Includes   ############## */
#include <ctype.h>
#include <surgeon/runtime.h>
#include <surgeon/logging.h>
#include <surgeon/models/riot/uart.h>
#include <surgeon/symbols.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

/* #########   Function signatures   ######## */
static void USED riot_uart_uart_write(uart_t uart, const uint8_t *data,
                                      size_t len);

/* ###############   Globals   ############## */

static void USED riot_uart_uart_write(uart_t uart, const uint8_t *data,
                                      size_t len) {
    LOGD("Writing to UART #%d", uart);
    LOGD("Data buffer at %p (sz=%zd)", data, len);

    (void)uart;
    (void)data;
    (void)len;
#ifndef NDEBUG
    for (size_t i = 0; i < len; i++) {
        if (isprint((int)data[i])) {
            printf("%c", data[i]);
        } else {
            printf("\\x%.2x", data[i]);
        }
    }
    printf("\n");
#endif /* NDEBUG */
}
