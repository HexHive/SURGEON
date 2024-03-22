/* ##############   Includes   ############## */
#include <surgeon/runtime.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

/* #########   Function signatures   ######## */
static uint32_t USED stm32_adc_getvalue(void *);

/**
 * @brief Read in an "analog" value
 *
 * Reads 4 bytes from stdin and returns them as if the ADC converted an analog
 * measurement to those 4 digital bytes.
 *
 * @param void * (unused) Pointer to the ADC instance
 *
 * @return uint32_t Value read from stdin
 */
static uint32_t USED stm32_adc_getvalue(void *) {
    uint32_t ret = 0;

#ifndef NDEBUG
    printf("[%s] Reading %zu byte(s) from stdin\n", __func__, sizeof(ret));
#endif /* NDEBUG */

    /* Read in data as requested */
    int in = 0;
    for (size_t i = 0; i < sizeof(ret); i++) {
        if ((in = fgetc(stdin)) == EOF) {
            exit(0);
        }
        ret = (ret << (sizeof(uint8_t) * CHAR_BIT)) | (uint8_t)in;
    }
#ifndef NDEBUG
    printf("[%s] Read analog value %#x\n", __func__, ret);
#endif /* NDEBUG */
    return ret;
}
