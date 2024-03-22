/* ##############   Includes   ############## */
#include <surgeon/runtime.h>
#include <stdint.h>
#include <stdio.h>

/* #########   Function signatures   ######## */
static int USED sam_uart_available(void *);
static int USED sam_uart_read(void *);
static size_t USED sam_uart_write(void *, uint8_t c);

/**
 * @brief Test if data is available for the UART peripheral
 *
 * Returns a non-zero value if EOF hasn't been reached yet on stdin. This
 * function can be used to determine whether a serial interface has data
 * "available" by emulating the interface with stdio.
 *
 * @param void * (unused) Pointer to the UART object
 *
 * @return int Non-zero value if data available, 0 otherwise
 */
static int USED sam_uart_available(void *) {
    int data_available = !(feof(stdin));

#ifndef NDEBUG
    printf("[%s] Data available: %s\n", __func__,
           (data_available != 0) ? "yes" : "no");
#endif /* NDEBUG */

    return data_available;
}

/**
 * @brief Wraps around getc, exiting in case of EOF
 *
 * The function tries to get a character from stdin and exits if EOF has been
 * reached. This can be used to read fuzzing input byte by byte, exiting when
 * the fuzzing input has been exhausted.
 *
 * @param void * (unused) Pointer to the UART object
 *
 * @return int The value read from stdin if available
 */
static int USED sam_uart_read(void *) {
    static int fail = 0;
    if (!(++fail % 10)) {
        /* Every 10th invocation, signal an error to the caller */
        return -1;
    }

    int in = 0;
    if ((in = fgetc(stdin)) == EOF) {
        exit(0);
    }

#ifndef NDEBUG
    printf("[%s] Read: %#.2x\n", __func__, (char)in);
#endif /* NDEBUG */

    return in;
}

/**
 * @brief Wraps around putc
 *
 * @param void * (unused) Pointer to the UART object
 * @param uint8_t Character to print to stdout
 *
 * @return size_t Always returns 1
 */
static size_t USED sam_uart_write(void *, uint8_t c) {
#ifndef NDEBUG
    /* Do not output in release mode -- not of importance for fuzzing */
    putc((int)c, stdout);
#else
    /* Suppress unused variable warning */
    (void)c;
#endif /* NDEBUG */
    return 1;
}
