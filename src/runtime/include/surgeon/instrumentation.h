#include <stdint.h>

#ifndef INSTRUMENTATION_H
#define INSTRUMENTATION_H

#define INSTR_CTRL_ADDR_ENV "INSTR_CTRL_ADDR"
#define SHM_ADDR_ENV "SHM_ADDR"

// Data needed by coverage instrumentation.
typedef struct _cov_instr_ctrl_s {
    uintptr_t prev_location;
} cov_instr_ctrl_t;

/* Global pointer to the previous_location for coverage calculation */
extern cov_instr_ctrl_t *instr_ctrl;

#endif /*INSTRUMENTATION_H*/
