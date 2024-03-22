#include <surgeon/context.h>

/* Auto-generated at build time, provides offsets into C structs */
#include "struct_offsets.h"

.section .text
.thumb
.syntax unified

.thumb_func
dispatch_asm:
    /* Store context => need to store r4 on the stack temporarily for it to
       hold the context pointer */
    push { r4 }
    ldr r4, =fw_context
    str r0, [r4, #OFFSETOF_context_t_r0]
    str r1, [r4, #OFFSETOF_context_t_r1]
    str r2, [r4, #OFFSETOF_context_t_r2]
    str r3, [r4, #OFFSETOF_context_t_r3]
    str r5, [r4, #OFFSETOF_context_t_r5]
    pop { r5 } /* Pop r4 and store it into the context */
    str r5, [r4, #OFFSETOF_context_t_r4]
    pop { r5 } /* Pop the caller PC and store it into the context */
    str r5, [r4, #OFFSETOF_context_t_pc]
    str r6, [r4, #OFFSETOF_context_t_r6]
    str r7, [r4, #OFFSETOF_context_t_r7]
    str r8, [r4, #OFFSETOF_context_t_r8]
    str r9, [r4, #OFFSETOF_context_t_r9]
    str r10, [r4, #OFFSETOF_context_t_r10]
    str r11, [r4, #OFFSETOF_context_t_r11]
    str r12, [r4, #OFFSETOF_context_t_r12]
    str sp, [r4, #OFFSETOF_context_t_sp]
    str lr, [r4, #OFFSETOF_context_t_lr]
    /* Restore runtime stack pointer and jump to C code */
    ldr r4, =runtime_sp
    ldr sp, [r4]
    ldr r4, =dispatch_c
    blx r4
    /* Store runtime stack pointer and restore context */
    ldr r4, =runtime_sp
    str sp, [r4]
    ldr r4, =fw_context
    ldr r0, [r4, #OFFSETOF_context_t_r0]
    ldr r1, [r4, #OFFSETOF_context_t_r1]
    ldr r2, [r4, #OFFSETOF_context_t_r2]
    ldr r3, [r4, #OFFSETOF_context_t_r3]
    ldr r5, [r4, #OFFSETOF_context_t_r5]
    ldr r6, [r4, #OFFSETOF_context_t_r6]
    ldr r7, [r4, #OFFSETOF_context_t_r7]
    ldr r8, [r4, #OFFSETOF_context_t_r8]
    ldr r9, [r4, #OFFSETOF_context_t_r9]
    ldr r10, [r4, #OFFSETOF_context_t_r10]
    ldr r11, [r4, #OFFSETOF_context_t_r11]
    ldr r12, [r4, #OFFSETOF_context_t_r12]
    ldr sp, [r4, #OFFSETOF_context_t_sp]
    ldr lr, [r4, #OFFSETOF_context_t_lr]
    /* Restore r4 last bc it holds the context ptr */
    ldr r4, [r4, #OFFSETOF_context_t_r4]
    /* Return to firmware */
    bx lr
