# Copyright 2019 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains
# certain rights in this software.

# Copyright 2022 HexHive, EPFL
# Modifications to this file include:
#  * Removal of bp_handler function decorators
#  * Generalizing the target target to a generic target
#  * Making the target compatible with the SURGEONTarget

from halucinator.peripheral_models.timer import TimerModel
import halucinator.constants as constants
import time
from collections import defaultdict

import logging

log = logging.getLogger(__name__)


class STM32F4TIM(object):
    def __init__(self, model=TimerModel):
        self.model = model
        self.org_lr = None
        self.current_channel = 0
        self.addr2isr_lut = {
            # '0x40000200': 0x32
            0x40000400: 45
        }
        self.irq_rates = {}
        self.name = "STM32F4TIM"

    def tim_init(self, target, addr):
        """
        Handler for HAL function 'HAL_TIM_Base_Init'
        """
        tim_obj = target.r0
        tim_base = target.read_memory(tim_obj, 4, 1)

        log.info("STM32F4TIM init, base: %#08x" % (tim_base))
        # self.model.start_timer(hex(tim_base), self.name2isr_lut[irq_name], irq_rate)
        # TODO: HACK: FIXME: Take this out when we have better NVIC handling.
        # We call into the MSP init function to get it to set up our IRQ prio
        # without knowing what's there, it changes with #defines
        # target.pc = target.avatar.callables['HAL_TIM_Base_MspInit']
        # import ipdb; ipdb.set_trace()
        return False, None

    def deinit(self, target, addr):
        """
        Handler for HAL function 'HAL_TIM_Base_DeInit'
        """
        tim_obj = target.r0
        tim_base = target.read_memory(tim_obj, 4, 1)

        log.info("STM32F4TIM deinit, base: %#08x" % (hex(tim_base)))
        # self.model.start_timer(hex(tim_base), self.name2isr_lut[irq_name], irq_rate)
        return True, 0

    def config(self, target, addr):
        """
        Handler for HAL function 'HAL_TIM_ConfigClockSource'
        """
        tim_obj = target.r0
        tim_base = target.read_memory(tim_obj, 4, 1)

        log.info("STM32F4TIM config, base: %#08x" % (hex(tim_base)))
        # self.model.start_timer(hex(tim_base), self.name2isr_lut[irq_name], irq_rate)
        return True, 0

    def sync(self, target, addr):
        """
        Handler for HAL function 'HAL_TIMEx_MasterConfigSynchronization'
        """
        tim_obj = target.r0
        tim_base = target.read_memory(tim_obj, 4, 1)
        log.info("STM32F4TIM sync, base: %#08x" % (hex(tim_base)))
        # self.model.start_timer(hex(tim_base), self.name2isr_lut[irq_name], irq_rate)
        return True, 0

    def start(self, target, addr):
        """
        Handler for HAL function 'HAL_TIM_Base_Start_IT'
        """
        tim_obj = target.r0
        tim_base = target.read_memory(tim_obj, 4, 1)
        tim_name = hex(tim_base)  # we just use the base addr as an identifier

        log.info(f"STM32F4TIM start, base: {tim_base:#08x}")

        # TODO: figure out proper rate to trigger irq
        self.model.add_timer(target, tim_name, 50)
        # TODO: irq 44 is used for robot, we need to retrieve this info from
        #       the config.
        self.model.attach_irq(target, tim_name, 44)
        self.model.start_timer(target, tim_name)

        target.r0 = constants.STM32F4_HAL_OK

    def isr_handler(self, target, addr):
        """
        Handler for HAL function 'HAL_TIM_IRQHandler'
        """
        """
        How can we determine which callback to call here?
        How to call the callback from here?
        """
        tim_obj = target.r0
        tim_base = target.read_memory(tim_obj, 4, 1)
        log.info("TICK: Timer %#08x" % tim_base)
        # Call HAL_TIM_PeriodElapsedCallback
        # TODO: Tims can do other things besides elapse.
        # When we see a tim doing that, put it here
        # Leave the regs unchanged, as they should be correct.
        target.pc = target.avatar.callables["HAL_TIM_PeriodElapsedCallback"]
        return False, None

    def stop(self, target, addr):
        """
        Handler for HAL function 'HAL_TIM_Base_Stop_IT'
        """
        tim_obj = target.r0
        tim_base = target.read_memory(tim_obj, 4, 1)
        self.model.stop_timer(hex(tim_base))
        return True, 0

    def sleep(self, target, addr):
        """
        Handler for HAL function 'HAL_Delay'
        """
        amt = target.r0 / 1000.0
        log.debug("sleeping for %f" % amt)
        # time.sleep(amt)
        return True, 0

    def systick_config(self, target, addr):
        """
        Handler for HAL function 'HAL_SYSTICK_Config'
        """
        timer_name: str = "SysTick"
        if self.model.add_timer(target, timer_name, 1000):
            # Added timer successfully => also attach the SysTick IRQ and enable it
            self.model.attach_irq(target, timer_name, constants.SYSTICK_IRQ)
            self.model.start_timer(target, timer_name)
            target.r0 = constants.STM32F4_HAL_OK
        else:
            # Adding timer failed
            target.r0 = constants.STM32F4_HAL_ERROR
