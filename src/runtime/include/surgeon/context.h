#ifndef CONTEXT_H
#define CONTEXT_H
/* Combine include guard and pragma once for compatibility reasons */
#pragma once

/* Macros for both assembly and C (assembly- or C-specific macros guarded by
 * #ifdefs further down) */

/* A word is 32bit == 4 bytes => see uint32_t below */
#define WORDSHIFT 2
#define WORDSIZE 4 /* WORDSIZE == 1 << WORDSHIFT */

/* Important MMIO register addresses (addresses taken from the ARMv7-M
 * architecture reference manual) */
#define ICSR_ADDR 0xE000ED04
#define VTOR_ADDR 0xE000ED08
#define SYST_RVR_ADDR 0xE000E014
#define SYST_CVR_ADDR 0xE000E018

/* Mark something as uninitialized. Mostly used for system configuration
 * register values and similar. We cannot simply test against NULL as you mostly
 * would with C pointers because firmware may map the NULL page and pointers to
 * that may actually be valid. */
#define UNINITIALIZED_RAW 0xffffffff

/* Bitmask that only extracts N, Z, C, V, Q, GE bits from CPSR/xPSR -- those
 * are the bits that are common between Cortex-M and Cortex-A */
#define CPSR_BITMASK 0xf80f0000
/* Bitmask that extracts the PENDSVSET bit from the ICSR */
#define PENDSV_BITMASK 0x10000000

/* Registers used for emulating the banked stack pointer on Cortex-M
 * (msp, psp) => SIMD scalars */
#define MSP_EMU_REG d16[0]
#define PSP_EMU_REG d16[1]

#ifdef __ASSEMBLER__
/* Assembler-only */

/* Provided in context.c */
.extern fw_context
.extern runtime_sp

#else
/* C source only */

/* ##############   Includes   ############## */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stddef.h>
#include <stdint.h>
#include <ucontext.h>

/* ###############   Macros   ############### */
#define PACKED __attribute__((packed))
#define UNUSED __attribute__((unused))

#define VTOR ((vect_t **)VTOR_ADDR)
#define ICSR ((uint32_t *)ICSR_ADDR)
#define SYST_RVR ((uint32_t *)SYST_RVR_ADDR)
#define SYST_CVR ((uint32_t *)SYST_CVR_ADDR)
#define UNINITIALIZED ((uint32_t)UNINITIALIZED_RAW)

/* ##############   Typedefs   ############## */
/* Context containing all the general-purpose registers, including SP and LR */
typedef struct PACKED _context_s {
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r4;
    uint32_t r5;
    uint32_t r6;
    uint32_t r7;
    uint32_t r8;
    uint32_t r9;
    uint32_t r10;
    uint32_t r11;
    uint32_t r12;
    uint32_t sp;
    uint32_t lr;
    uint32_t pc;
    uint32_t xpsr; /* program status register */
} context_t;

/* Sructure mimicking the Vector Table layout described in the ARMv7-M
 * architecture reference manual */
typedef struct PACKED _vect_s {
    uint32_t sp_main;
    uint32_t reset;
    uint32_t nmi;
    uint32_t hardfault;
    uint32_t memmanage;
    uint32_t busfault;
    uint32_t usagefault;
    uint32_t reserved_7;
    uint32_t reserved_8;
    uint32_t reserved_9;
    uint32_t reserved_10;
    uint32_t svcall;
    uint32_t debugmonitor;
    uint32_t reserved_13;
    uint32_t pendsv;
    uint32_t systick;
    uint32_t ext_interrupts[1]; /* Variable-length array for external interrupts
                                   (number not known a priori) */
} vect_t;

/* Some common IRQ numbers mirrored in the above vector table structure */
typedef enum _irq_e {
    SVCALL = 11,
    PENDSV = 14,
    SYSTICK = 15,
    EXTI_BASE = 16,
} irq_t;

/* #########   Function signatures   ######## */
PyMODINIT_FUNC PyInit_surgeon(void);

/* #############   Global vars   ############ */
/* Provided in context.c */
extern context_t fw_context;
extern uintptr_t runtime_sp;

#endif /* __ASSEMBLER__ */
#endif /* CONTEXT_H */
