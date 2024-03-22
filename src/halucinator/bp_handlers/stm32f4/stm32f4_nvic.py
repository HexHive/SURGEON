# Copyright 2022 HexHive, EPFL

from halucinator.peripheral_models.timer import TimerModel
import halucinator.constants as constants
import time
from collections import defaultdict

import logging

log = logging.getLogger(__name__)


class STM32F4NVIC(object):
    def __init__(self, model=TimerModel):
        self._model = model

    def enable_irq(self, target, addr):
        """
        Handler for HAL function 'HAL_NVIC_EnableIRQ'
        """
        irq = constants.EXTI_IRQ_BASE + target.r0
        if self._model.add_timer(target, irq, 2000):
            # Added timer to emulate interrupts => also start it and attach the IRQ
            self._model.attach_irq(target, irq, irq)
            self._model.start_timer(target, irq)
        # void function, no return value
