/* ##############   Includes   ############## */
#include <ctype.h>
#include <surgeon/runtime.h>
#include <surgeon/models/stm32/uart.h>
#include <surgeon/symbols.h>
#include <stdint.h>
#include <stdio.h>

/* #########   Function signatures   ######## */
static int USED stm32_uart_receive(void *, uint8_t *data, uint16_t size,
                                   uint32_t);
static int USED stm32_uart_receive_it(void *huart, uint8_t *data,
                                      uint16_t size);
static int USED stm32_uart_transmit(void *, uint8_t *data, uint16_t size,
                                    uint32_t);
static int USED stm32_uart_transmit_it(void *huart, uint8_t *data,
                                       uint16_t size);
static void USED stm32_uart_irqhandler(void *huart);

/* ###############   Globals   ############## */
WEAK generic_func_t _HAL_UART_RxCpltCallback;
WEAK generic_func_t _HAL_UART_TxCpltCallback;

/**
 * @brief Read data in via a UART peripheral
 *
 * Reads the requested amount of data into the provided buffer.
 *
 * @param void * (unused) Pointer to the UART peripheral structure
 * @param uint8_t * Pointer to the data buffer
 * @param uint16_t Number of bytes to read in
 * @param uint32_t (unused) Timeout for blocking
 *
 * @return int 0 in case of success, 1 otherwise
 */
static int USED stm32_uart_receive(void *, uint8_t *data, uint16_t size,
                                   uint32_t) {
    if (unlikely(data == NULL || size == 0)) {
        /* HAL_ERROR */
        return 1;
    }

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
    printf("[%s] Receive: ", __func__);
    for (size_t i = 0; i < size; i++) {
        if (isprint((int)data[i])) {
            printf("%c", data[i]);
        } else {
            printf("\\x%.2x", data[i]);
        }
    }
    printf("\n");
#endif /* NDEBUG */

    /* HAL_OK */
    return 0;
}

/**
 * @brief Read data in via a UART peripheral
 *
 * Reads the requested amount of data into the provided buffer.
 * This function calls the non _IT version of the receive function which takes
 * a parameter more (timeout for blocking, whereas this function is
 * non-blocking in the STM32 HAL) and sets the peripheral status for the IRQ
 * handler.
 *
 * @param void * Pointer to the UART peripheral structure
 * @param uint8_t * Pointer to the data buffer
 * @param uint16_t Number of bytes to read in
 *
 * @return int 0 in case of success, 1 otherwise
 */
static int USED stm32_uart_receive_it(void *huart, uint8_t *data,
                                      uint16_t size) {
    /* Reuse the same code as for the blocking receive handler which has an
     * additional (unused) timeout parameter */
    int ret = stm32_uart_receive(huart, data, size, 0);
    /* Set the status so that the correct callback can be triggered on the next
     * interrupt */
    if (status.uart_obj != huart) {
        status.sent = false;
    }
    status.uart_obj = huart;
    status.received = true;

    return ret;
}

/**
 * @brief Send data out via a UART peripheral
 *
 * Transmits the requested amount of data from the provided buffer.
 *
 * @param void * (unused) Pointer to the UART peripheral structure
 * @param uint8_t * Pointer to the data buffer
 * @param uint16_t Number of bytes to write out
 * @param uint32_t (unused) Timeout for blocking
 *
 * @return int 0 in case of success, 1 otherwise
 */
static int USED stm32_uart_transmit(void *, uint8_t *data, uint16_t size,
                                    uint32_t) {
    if (unlikely(data == NULL || size == 0)) {
        /* HAL_ERROR */
        return 1;
    }

#ifndef NDEBUG
    printf("[%s] Transmit: ", __func__);
    for (size_t i = 0; i < size; i++) {
        if (isprint((int)data[i])) {
            printf("%c", data[i]);
        } else {
            printf("\\x%.2x", data[i]);
        }
    }
    printf("\n");
#endif /* NDEBUG */

    /* HAL_OK */
    return 0;
}

/**
 * @brief Send data out via a UART peripheral
 *
 * Transmits the requested amount of data from the provided buffer.
 * This function calls the non _IT version of the transmit function which takes
 * a parameter more (timeout for blocking, whereas this function is
 * non-blocking in the STM32 HAL) and sets the peripheral status for the IRQ
 * handler.
 *
 * @param void * Pointer to the UART peripheral structure
 * @param uint8_t * Pointer to the data buffer
 * @param uint16_t Number of bytes to write out
 *
 * @return int 0 in case of success, 1 otherwise
 */
static int USED stm32_uart_transmit_it(void *huart, uint8_t *data,
                                       uint16_t size) {
    /* Reuse the same code as for the blocking transmit handler which has an
     * additional (unused) timeout parameter */
    int ret = stm32_uart_transmit(huart, data, size, 0);
    /* Set the status so that the correct callback can be triggered on the next
     * interrupt */
    if (status.uart_obj != huart) {
        status.received = false;
    }
    status.uart_obj = huart;
    status.sent = true;

    return ret;
}

/**
 * @brief Invoke the corresponding callback for RX or TX events
 *
 * Depending on whether the previous action was an interrupt-based RX or TX
 * action, we invoke the corresponding callback.
 *
 * @param void * Pointer to the UART peripheral structure
 */
static void USED stm32_uart_irqhandler(void *huart) {
    if (status.uart_obj == huart) {
        /* Reset status */
        bool received = status.received;
        bool sent = status.sent;
        status = (stm32_uart_status_t){0};

        /* Call callback according to status */
        if (received == true) {
            void (*HAL_UART_RxCpltCallback)(void *) =
                (void (*)(void *))_HAL_UART_RxCpltCallback;
            HAL_UART_RxCpltCallback(huart);
        }
        if (sent == true) {
            void (*HAL_UART_TxCpltCallback)(void *) =
                (void (*)(void *))_HAL_UART_RxCpltCallback;
            HAL_UART_TxCpltCallback(huart);
        }
    }
}
