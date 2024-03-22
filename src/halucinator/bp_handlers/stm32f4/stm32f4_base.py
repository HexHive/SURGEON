# Copyright 2019 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains
# certain rights in this software.

# Copyright 2022 HexHive, EPFL
# Modifications to this file include:
#  * Removal of bp_handler function decorators
#  * Generalizing the qemu target to a generic target
#  * Making the target compatible with the SURGEONTarget

from halucinator.peripheral_models.timer import TimerModel
import time

import logging

log = logging.getLogger(__name__)


class STM32F4Base(object):
    """
    This represents the "base" stuff in the STM32.
    All the things related to boot, reset, clocks, and the SysTick timer.
    """

    def __init__(self, model=TimerModel):
        self.model = model
        self.org_lr = None
        self.current_channel = 0
        self.addr2isr_lut = {"0x4000200": 0x32}
        self.irq_rates = {}

    # Handler for HAL function 'HAL_Init'
    def init(self, target, addr):
        log.info("### STM32 HAL INIT ###")
        return False, None

    # Handler for HAL function 'SystemInit'
    def systeminit(self, target, addr):
        log.info("### SystemInit ###")
        return False, None

    # Handler for HAL function 'SystemClock_Config'
    def systemclock_config(self, target, addr):
        log.info("SystemClock_Config called")
        # Return value
        target.r0 = 0

    # Handler for HAL function 'HAL_RCC_OscConfig'
    def rcc_osc_config(self, target, addr):
        log.info("HAL_RCC_OscConfig called")
        # Return value
        target.r0 = 0

    # Handler for HAL function 'HAL_RCC_ClockConfig'
    def rcc_clock_config(self, target, addr):
        log.info("HAL_RCC_ClockConfig called")
        # Return value
        target.r0 = 0

    # Handler for HAL function 'HAL_SYSTICK_Config'
    def systick_config(self, target, addr):
        # rate = target.regs.r0
        rate = 5
        systick_irq = 15
        log.info("Setting SysTick rate to %#08x" % rate)
        self.model.start_timer("SysTick", systick_irq, rate)
        # Return value
        target.r0 = 0

    # Handler for HAL function 'HAL_SYSTICK_CLKSourceConfig'
    def systick_clksourceconfig(selfself, target, addr):
        src = target.regs.r0
        log.info("Setting SysTick source to %#08x" % src)
        return False, None

    # Handler for HAL function 'HAL_InitTick'
    def init_tick(self, target, addr):
        systick_rate = 10
        systick_irq = 12
        log.info("Starting SysTick on IRQ %d, rate %d" % (systick_irq, systick_rate))
        # self.model.start_timer("SysTick", systick_irq, systick_rate)
        # import ipdb; ipdb.set_trace()
        # Return value
        target.r0 = 0

    # Handler for HAL function 'Error_Handler'
    def error_handler(self, target, addr):
        self.model.stop_timer("SysTick")
        self.model.stop_timer("0x40000400")
        # import ipdb; ipdb.set_trace()
        # Return value
        target.r0 = 0
