#ifndef INTERRUPTS_H
#define INTERRUPTS_H

/* ##############   Includes   ############## */
#include <surgeon/context.h>
#include <stdbool.h>

/* #########   Function signatures   ######## */
void trigger_interrupt(uint32_t irq_num);
void trigger_interrupt_context_switch(uint32_t irq_num, mcontext_t *mctx);
void trigger_interrupt_asm(uint32_t irq_num, mcontext_t *mctx);

/* #############   Global vars   ############ */
/* Provided in interrupts.c */
extern bool isr_active;
extern bool pendsv_enable;

#endif /* INTERRUPTS_H */
