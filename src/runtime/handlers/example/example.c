#include <surgeon/runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Print the return address and return 42
 *
 * This function retrieves the return address of the caller and  prints it.
 *
 * @return int Constant value 42
 */
static int USED example_fortytwo(void) {
    register uintptr_t lr asm("lr");
    printf("Return address is %#.8x\n", lr);

    return 42;
}

/**
 * @brief Increment a counter and print it everytime the function is called
 */
static void USED example_ctr(void) {
    static int x = 0;
    x++;
    printf("Called ctr for the %d. time\n", x);
}

/**
 * @brief Exit the process with exit code 0
 */
static void USED NORETURN example_kill(void) {
    exit(0);
}

/**
 * @brief Print a hello world message
 */
static void USED example_hello_world(void) {
    puts("Hello SURGEON!");
}
