#include <surgeon/context.h>

/* Auto-generated at build time, provides offsets into C structs */
#include "struct_offsets.h"

.section .text
.thumb
.syntax unified

/* void trigger_interrupt_asm(uint32_t irq_num, mcontext_t *mctx) */
.global trigger_interrupt_asm
.thumb_func
trigger_interrupt_asm:
    /* Check whether VTOR has been initialized */
    ldr r2, =VTOR_ADDR
    ldr r2, [r2]
    cmp r2, #UNINITIALIZED_RAW
    beq Ltrigger_interrupt_asm.return
    /* VTOR has been initialized => set isr_active to true and context switch to
     * firmware context */
Ltrigger_interrupt_asm.context_restore:
    push { r4, r5, r6, r7, r8, r9, r10, r11, lr }
    ldr r3, =isr_active
    mov r4, #1
    strb r4, [r3] /* isr_active = true */
    ldr r4, =handler_stack
    str sp, [r4]
    ldr r4, =mcontext_addr
    str r1, [r4]
    mov r4, r1
    ldr r1, [r4, #OFFSETOF_mcontext_t_arm_r1]
    ldr r3, [r4, #OFFSETOF_mcontext_t_arm_r3]
    ldr r7, [r4, #OFFSETOF_mcontext_t_arm_r7]
    ldr r8, [r4, #OFFSETOF_mcontext_t_arm_r8]
    ldr r9, [r4, #OFFSETOF_mcontext_t_arm_r9]
    ldr r10, [r4, #OFFSETOF_mcontext_t_arm_r10]
    ldr r11, [r4, #OFFSETOF_mcontext_t_arm_fp]
    ldr r12, [r4, #OFFSETOF_mcontext_t_arm_ip]
    ldr sp, [r4, #OFFSETOF_mcontext_t_arm_sp]
    /* Load ISR address from vector table */
    ldr lr, [r2, r0, LSL #WORDSHIFT]
    /* Restore remaining registers so that we can push them onto the stack */
    ldr r0, [r4, #OFFSETOF_mcontext_t_arm_r0]
    ldr r2, [r4, #OFFSETOF_mcontext_t_arm_r2]
Ltrigger_interrupt_asm.exception_entry:
    /* Push context onto the 4-byte aligned stack (see chapter
     * B1.5.6 - Exception Entry Behavior of the Armv7-M ARM */
    sub sp, #8*WORDSIZE
    /* Store caller-saved registers */
    stm sp, { r0, r1, r2, r3, r12, lr }
    /* Store return address */
    ldr r5, [r4, #OFFSETOF_mcontext_t_arm_pc]
    str r5, [sp, #6*WORDSIZE]
    /* Store xPSR (only certain bits extracted because CPSR != xPSR) */
    ldr r5, [r4, #OFFSETOF_mcontext_t_arm_cpsr]
    ldr r6, =#CPSR_BITMASK
    and r5, r6
    str r5, [sp, #7*WORDSIZE]
    /* Restore r4, r5, r6 last because they were used as scratch registers */
    ldr r5, [r4, #OFFSETOF_mcontext_t_arm_r5]
    ldr r6, [r4, #OFFSETOF_mcontext_t_arm_r6]
    ldr r4, [r4, #OFFSETOF_mcontext_t_arm_r4]
Ltrigger_interrupt_asm.isr_call:
    /* Switch stack from PSP to MSP */
    vmov.32 PSP_EMU_REG, sp
    vmov.32 sp, MSP_EMU_REG
    /* Call into ISR */
    blx lr
    /* Switch stack from MSP to PSP */
    vmov.32 MSP_EMU_REG, sp
    vmov.32 sp, PSP_EMU_REG
Ltrigger_interrupt_asm.exception_return:
    /* Copy r4, r5, r6, r7 into the context first because they're used as
     * scratch registers for the context accesses here */
    push { r4 }
    ldr r4, =mcontext_addr
    ldr r4, [r4]
    str r5, [r4, #OFFSETOF_mcontext_t_arm_r5]
    str r6, [r4, #OFFSETOF_mcontext_t_arm_r6]
    str r7, [r4, #OFFSETOF_mcontext_t_arm_r7]
    pop { r5 } /* r5 has already been saved */
    str r5, [r4, #OFFSETOF_mcontext_t_arm_r4]
    /* Load context from the stack (see chapter B1.5.6 - Exception Entry
     * Behavior of the Armv7-M ARM), needs to account for alignment */
    /* Load xPSR (certain bits extracted because CPSR != xPSR), basically
     * arm_cpsr = (arm_cpsr & ~CPSR_BITMASK) | (xPSR & CPSR_BITMASK) */
    ldr r5, [sp, #7*WORDSIZE]
    ldr r6, [r4, #OFFSETOF_mcontext_t_arm_cpsr]
    ldr r7, =#CPSR_BITMASK
    bic r6, r7
    and r7, r5
    orr r7, r6
    str r7, [r4, #OFFSETOF_mcontext_t_arm_cpsr]
    /* Extract bit 9 from xPSR and multiply by four (for stack alignment) */
    ubfx r5, r5, #9, #1
    lsl r5, #2
    /* Calculate realigned stack address (using r0 as a scratch register) */
    add r0, sp, #8*WORDSIZE
    orr r5, r0, r5
    /* Load return address */
    ldr r0, [sp, #6*WORDSIZE]
    str r0, [r4, #OFFSETOF_mcontext_t_arm_pc]
    /* Load caller-saved registers */
    ldm sp, { r0, r1, r2, r3, r12, lr }
    /* Reset realigned stack */
    mov sp, r5
Ltrigger_interrupt_asm.context_save:
    /* Save the firmware's context and return to our emulator stack */
    str r0, [r4, #OFFSETOF_mcontext_t_arm_r0]
    str r1, [r4, #OFFSETOF_mcontext_t_arm_r1]
    str r2, [r4, #OFFSETOF_mcontext_t_arm_r2]
    str r3, [r4, #OFFSETOF_mcontext_t_arm_r3]
    /* r4, r5, r6, r7 have already been stored above */
    str r8, [r4, #OFFSETOF_mcontext_t_arm_r8]
    str r9, [r4, #OFFSETOF_mcontext_t_arm_r9]
    str r10, [r4, #OFFSETOF_mcontext_t_arm_r10]
    str r11, [r4, #OFFSETOF_mcontext_t_arm_fp]
    str r12, [r4, #OFFSETOF_mcontext_t_arm_ip]
    str sp, [r4, #OFFSETOF_mcontext_t_arm_sp]
    str lr, [r4, #OFFSETOF_mcontext_t_arm_lr]
    /* Set isr_active to false */
    ldr r4, =isr_active
    mov r5, #0
    strb r5, [r4] /* isr_active = false */
    /* Restore runtime stack pointer and return to C code */
    ldr r4, =handler_stack
    ldr sp, [r4]
    pop { r4, r5, r6, r7, r8, r9, r10, r11, lr }
Ltrigger_interrupt_asm.return:
    bx lr

.section .data
handler_stack:
    .word 0x00000000
mcontext_addr:
    .word 0x00000000
