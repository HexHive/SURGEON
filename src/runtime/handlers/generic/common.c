
/* ##############   Includes   ############## */
#include <assert.h>
#include <surgeon/runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* #########   Function signatures   ######## */
static void USED NORETURN generic_common_exit(void);
static void USED NORETURN generic_common_abort(void);

/**
 * @brief Exit from the firmware indicating successful execution
 */
static void USED NORETURN generic_common_exit(void) {
#ifndef NDEBUG
    uintptr_t ret_addr = 0;
    asm("mov %0, lr" : "=r"(ret_addr));
    printf("[%s] Quitting with caller @ %#.8x\n", __func__, ret_addr);
#endif /* NDEBUG */
    exit(EXIT_SUCCESS);
}

/**
 * @brief Abort firmware execution
 */
static void USED NORETURN generic_common_abort(void) {
#ifndef NDEBUG
    uintptr_t ret_addr = 0;
    asm("mov %0, lr" : "=r"(ret_addr));
    printf("[%s] Aborting with caller @ %#.8x\n", __func__, ret_addr);
#endif /* NDEBUG */
    abort();
}
