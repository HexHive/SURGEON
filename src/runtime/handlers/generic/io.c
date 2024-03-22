/* ##############   Includes   ############## */
#include <surgeon/runtime.h>
#include <surgeon/logging.h>
#include <stdint.h>
#include <stdio.h>

/* #########   Function signatures   ######## */
static char USED generic_io_getc(void);
static void USED generic_io_putc(char c);
static int USED generic_io_data_available(void);
static int USED generic_io_readline(char* buf, size_t sz);

/**
 * @brief Wraps around getc, exiting in case of EOF
 *
 * The function tries to get a character from stdin and exits if EOF has been
 * reached. This can be used to read fuzzing input byte by byte, exiting when
 * the fuzzing input has been exhausted.
 *
 * @return char The byte read from stdin if available
 */
static char USED generic_io_getc(void) {
    int in = 0;
    if ((in = fgetc(stdin)) == EOF) {
        exit(0);
    }

#ifndef NDEBUG
    printf("[%s] Read: %#.2x\n", __func__, (char)in);
#endif /* NDEBUG */

    return (char)in;
}

/**
 * @brief Wraps around putc
 *
 * @param char Character to print to stdout
 */
static void USED generic_io_putc(char c) {
#ifndef NDEBUG
    /* Do not output in release mode -- not of importance for fuzzing */
    putc((int)c, stdout);
#else
    /* Suppress unused variable warning */
    (void)c;
#endif /* NDEBUG */
}

/**
 * @brief Test if data is available on stdin
 *
 * Returns a non-zero value if EOF hasn't been reached yet on stdin. This
 * function can be used to determine whether a serial interface has data
 * "available" by emulating the interface with stdio.
 *
 * @return int Non-zero value if data available, 0 otherwise
 */
static int USED generic_io_data_available(void) {
    int data_available = !(feof(stdin));

#ifndef NDEBUG
    printf("[%s] Data available: %s\n", __func__,
           (data_available != 0) ? "yes" : "no");
#endif /* NDEBUG */

    return data_available;
}

/**
 * @brief Wraps around `fgets` to mimic `readline`
 *
 * The function tries to read a line from stdin and exits if EOF or an error
 * occurs.
 *
 * @param buf Buffer to hold the read line.
 * @param sz Size of the buffer to hold the read line.
 * @return int Status code. Return `0` on success.
 */
static int USED generic_io_readline(char* buf, size_t sz) {
    if (!fgets(buf, sz, stdin)) {
        exit(0);
    }

    LOGD("[%s] Read: %s", __func__, buf);

    return 0;
}
