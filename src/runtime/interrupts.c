#include <surgeon/instrumentation.h>
#include <surgeon/interrupts.h>
#include <surgeon/runtime.h>
#include <stdbool.h>

bool isr_active = false;
bool pendsv_enable = false;

/**
 * @brief Calls the ISR for a given IRQ.
 *
 * Based on the given IRQ, the function retrieves the corresponding handler
 * from the vector table and branches to the handler.
 *
 * @param irq_num Interrupt number to trigger
 */
void trigger_interrupt(uint32_t irq_num) {
    if ((uintptr_t)(*VTOR) != (uintptr_t)UNINITIALIZED) {
        /* Get the corresponding interrupt service routine from the
         * vector table */
        uint32_t *vt_base = (uint32_t *)(*VTOR);
        uint32_t isr = vt_base[irq_num];

        /* Call into the ISR */
        isr_active = true;
        if (likely(NULL != instr_ctrl)) {
            /* Save, clear and restore the coverage instrumentation data in
             * order to reduce coverage noise. I.e., edges to and from interrupt
             * handlers should not be part of the coverage because new coverage
             * would be communicated to AFL++ just depending on where the
             * interrupt is triggered */
            cov_instr_ctrl_t tmp = *instr_ctrl;
            *instr_ctrl = (const cov_instr_ctrl_t){0};

            asm volatile(
                "/* Switch stack from PSP to MSP */ \n\t"
                "vmov.32 " STR(PSP_EMU_REG) ", sp   \n\t"
                "vmov.32 sp, " STR(MSP_EMU_REG) "   \n\t"
                "/* Call into ISR */                \n\t"
                "blx %[isr_addr]                    \n\t"
                "/* Switch stack from MSP to PSP */ \n\t"
                "vmov.32 " STR(MSP_EMU_REG) ", sp   \n\t"
                "vmov.32 sp, " STR(PSP_EMU_REG) "   \n\t"
                :
                : [isr_addr] "r"(isr)
                : "r0", "r1", "r2", "r3", "ip", "lr", "memory");

            *instr_ctrl = tmp;
        } else {
            /* No coverage (e.g., for single runs of the firmware) */
            asm volatile(
                "/* Switch stack from PSP to MSP */ \n\t"
                "vmov.32 " STR(PSP_EMU_REG) ", sp   \n\t"
                "vmov.32 sp, " STR(MSP_EMU_REG) "   \n\t"
                "/* Call into ISR */                \n\t"
                "blx %[isr_addr]                    \n\t"
                "/* Switch stack from MSP to PSP */ \n\t"
                "vmov.32 " STR(MSP_EMU_REG) ", sp   \n\t"
                "vmov.32 sp, " STR(PSP_EMU_REG) "   \n\t"
                :
                : [isr_addr] "r"(isr)
                : "r0", "r1", "r2", "r3", "ip", "lr", "memory");
        }
        isr_active = false;
    }
}

/**
 * @brief Switches context and calls the ISR for a given IRQ.
 *
 * Based on the given IRQ, the function retrieves the corresponding handler
 * from the vector table and branches to the handler.
 * Before that, the function switches from the handler context back to the
 * firmware context (and vice versa after returning from the ISR).
 *
 * @param irq_num Interrupt number to trigger
 * @param mctx Pointer to the machine context holding the firmware state
 */
void trigger_interrupt_context_switch(uint32_t irq_num, mcontext_t *mctx) {
    if (likely(NULL != instr_ctrl)) {
        /* Save, clear and restore the coverage instrumentation data in
         * order to reduce coverage noise. I.e., edges to and from interrupt
         * handlers should not be part of the coverage because new coverage
         * would be communicated to AFL++ just depending on where the
         * interrupt is triggered */
        cov_instr_ctrl_t tmp = *instr_ctrl;
        *instr_ctrl = (const cov_instr_ctrl_t){0};

        trigger_interrupt_asm(irq_num, mctx);
        *instr_ctrl = tmp;
    } else {
        /* No coverage (e.g., for single runs of the firmware) */
        trigger_interrupt_asm(irq_num, mctx);
    }
}
