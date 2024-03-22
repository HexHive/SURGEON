#include <stdlib.h>

#ifndef RUNTIME_H
#define RUNTIME_H

/* ###############   Macros   ############### */
#define _STR(x) #x
#define STR(x) _STR(x)
#define STACKSIZE (8UL * 1024 * 1024)
#define ARGENVSIZE (2UL * 1024 * 1024)
#define PAGESIZE (sysconf(_SC_PAGESIZE))
#define ROUND_PAGE_DOWN(x) ((uintptr_t)(x) & (~(PAGESIZE - 1)))
#define ROUND_PAGE_UP(x) (((uintptr_t)(x) + PAGESIZE - 1) & (~(PAGESIZE - 1)))
#define ROUND_UP(x, b) (((((x) - 1) >> (b)) + 1) << (b))
#define ROUND_DOWN(x, b) (((x) >> (b)) << (b))
/* Function attributes */
#define NORETURN __attribute__((noreturn))
#define USED __attribute__((used))
#define UNUSED __attribute__((unused))
#define NAKED __attribute__((naked))
#define WEAK __attribute__((weak))
/* Branch optimizations */
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#define likely(expr) __builtin_expect(!!(expr), 1)
/* Bitwise operations */
#define clz(x) __builtin_clz(x)
#define ctz(x) __builtin_ctz(x)
/* Memory layout */
/* TODO: move RAM base/size into config files! Base is given by ARMv7-M
 * architecture reference manual, size depends on MCU */
#define RAM_BASE (0x20000000UL)
/* Actual SRAM address range is bigger, but that's plenty for now */
#define RAM_SIZE (0x10000000UL)
/* PPB base and size taken from the ARMv7-M architecture reference manual,
 * Chapter System Address Map */
#define PPB_BASE (0xE0000000UL)
#define PPB_SIZE (0x00100000UL)
/* MMIO base and size taken from the ARMv7-M architecture reference manual,
 * Chapter System Address Map */
#define MMIO_BASE (0x40000000UL)
#define MMIO_SIZE (0x20000000UL)

/* ##############   Typedefs   ############## */
typedef enum _success_e {
    SUCCESS,
    ERROR,
} success_t;

/* #########   Function signatures   ######## */
/**
 * @brief Map a region of size `size` given by the environment variable
 * `env_var`.
 *
 * @param env_var Identifier of the env var.
 * @param size    The size of the mapping.
 * @return void*  Address of the new mapping.
 */
void *map_region_from_env(const char *env_var, size_t size);
#endif /*RUNTIME_H*/
