/* ##############   Includes   ############## */
#include <assert.h>
#include <ctype.h>
#include <surgeon/runtime.h>
#include <stdint.h>
#include <stdio.h>

/* #########   Function signatures   ######## */
static int USED stm32_i2c_master_transmit(void *, uint16_t devaddr,
                                          uint8_t *data, uint16_t size,
                                          uint32_t);
static int USED stm32_i2c_master_transmit_dma(void *, uint16_t devaddr,
                                              uint8_t *data, uint16_t size);
static int USED stm32_i2c_mem_read(void *, uint16_t devaddr, uint16_t memaddr,
                                   uint16_t memaddrsize, uint8_t *data,
                                   uint16_t size, uint32_t);
static int USED stm32_i2c_mem_write(void *, uint16_t devaddr, uint16_t memaddr,
                                    uint16_t memaddrsize, uint8_t *data,
                                    uint16_t size, uint32_t);

/**
 * @brief Transmit data via a virtualized I2C bus
 *
 * This function has no side effects apart from printing the transmitted data in
 * debug mode.
 *
 * @param void * (unused) Pointer to the I2C peripheral structure
 * @param uint16_t Address of the targeted device on the bus
 * @param uint8_t * Pointer to the data buffer
 * @param uint16_t Number of bytes to transmit
 * @param uint32_t (unused) Timeout for blocking
 *
 * @return int 0 in case of success, 1 otherwise
 */
static int USED stm32_i2c_master_transmit(void *, uint16_t devaddr,
                                          uint8_t *data, uint16_t size,
                                          uint32_t) {
#ifndef NDEBUG
    printf("[%s] Transmit to device %#.4x: \n", __func__, devaddr);
    for (size_t i = 0; i < size; i++) {
        if (isprint((int)data[i])) {
            printf("%c", data[i]);
        } else {
            printf("\\x%.2x", data[i]);
        }
    }
    printf("\n");
#else
    /* Prevent unused variable warnings */
    (void)devaddr;
    (void)data;
    (void)size;
#endif /* NDEBUG */

    /* HAL_OK */
    return 0;
}

/**
 * @brief Transmit data via a virtualized I2C bus in DMA mode
 *
 * This function basically just wraps around the default transmission function,
 * accounting for the different number of arguments.
 *
 * @param void * (unused) Pointer to the I2C peripheral structure
 * @param uint16_t Address of the targeted device on the bus
 * @param uint8_t * Pointer to the data buffer
 * @param uint16_t Number of bytes to transmit
 *
 * @return int 0 in case of success, 1 otherwise
 */
static int USED stm32_i2c_master_transmit_dma(void *, uint16_t devaddr,
                                              uint8_t *data, uint16_t size) {
    return stm32_i2c_master_transmit(NULL, devaddr, data, size, 0);
}

/**
 * @brief Read from an I2C device's memory
 *
 * Reads data from an I2C device's memory into a local buffer.
 *
 * @param void * (unused) Pointer to the I2C peripheral structure
 * @param uint16_t Address of the targeted device on the bus
 * @param uint16_t Memory address on the targeted device to read from
 * @param uint16_t Memory address format of the targeted device
 * @param uint8_t * Pointer to the local data buffer
 * @param uint16_t Number of bytes to read
 * @param uint32_t (unused) Timeout for blocking
 *
 * @return int 0 in case of success, 1 otherwise
 */
static int USED stm32_i2c_mem_read(void *, uint16_t devaddr, uint16_t memaddr,
                                   uint16_t memaddrsize, uint8_t *data,
                                   uint16_t size, uint32_t) {
    /* Fixed values for memaddrsize given by the STM32 HAL, defining the
     * addressing modes in I2C */
    assert(memaddrsize == 0x01 || memaddrsize == 0x10);

#ifndef NDEBUG
    printf("[%s] Reading %hu byte(s) from stdin\n", __func__, size);
#endif /* NDEBUG */

    /* Read in data as requested */
    int in = 0;
    for (size_t i = 0; i < size; i++) {
        if ((in = fgetc(stdin)) == EOF) {
            exit(0);
        }
        data[i] = (uint8_t)in;
    }

#ifndef NDEBUG
    printf("[%s] Read %hu byte(s) from device %#.4x @ %#.4x: ", __func__, size,
           devaddr, memaddr);
    for (size_t i = 0; i < size; i++) {
        if (isprint((int)data[i])) {
            printf("%c", data[i]);
        } else {
            printf("\\x%.2x", data[i]);
        }
    }
    printf("\n");
#else
    /* Prevent unused variable warnings */
    (void)devaddr;
    (void)memaddr;
    (void)memaddrsize;
#endif /* NDEBUG */

    /* HAL_OK */
    return 0;
}

/**
 * @brief Write to an I2C device's memory
 *
 * Writes data from a local buffer to an I2C device's memory.
 *
 * @param void * (unused) Pointer to the I2C peripheral structure
 * @param uint16_t Address of the targeted device on the bus
 * @param uint16_t Memory address on the targeted device to write to
 * @param uint16_t Memory address format of the targeted device
 * @param uint8_t * Pointer to the local data buffer
 * @param uint16_t Number of bytes to write
 * @param uint32_t (unused) Timeout for blocking
 *
 * @return int 0 in case of success, 1 otherwise
 */
static int USED stm32_i2c_mem_write(void *, uint16_t devaddr, uint16_t memaddr,
                                    uint16_t memaddrsize, uint8_t *data,
                                    uint16_t size, uint32_t) {
    /* Fixed values for memaddrsize given by the STM32 HAL, defining the
     * addressing modes in I2C */
    assert(memaddrsize == 0x01 || memaddrsize == 0x10);

#ifndef NDEBUG
    printf("[%s] Writing %hu byte(s) to device %#.4x @ %#.4x: ", __func__, size,
           devaddr, memaddr);
    for (size_t i = 0; i < size; i++) {
        if (isprint((int)data[i])) {
            printf("%c", data[i]);
        } else {
            printf("\\x%.2x", data[i]);
        }
    }
    printf("\n");
#else
    /* Prevent unused variable warnings */
    (void)devaddr;
    (void)memaddr;
    (void)memaddrsize;
    (void)data;
    (void)size;
#endif /* NDEBUG */

    /* HAL_OK */
    return 0;
}
