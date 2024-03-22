# Copyright 2022 HexHive, EPFL

import logging
from halucinator.peripheral_models.timer import TimerModel

log = logging.getLogger(__name__)


class RIOTTimer(object):
    def __init__(self, model=TimerModel):
        self._model = model
        self._timer_name: str = "rtt"

    def rtt_init(self, target, addr: int) -> None:
        """
        Handler for HAL function 'void rtt_init(void)'
        """
        if self._model.add_timer(target, self._timer_name, 1000):
            # Added timer successfully => start the timer
            self._model.start_timer(target, self._timer_name)

    def rtt_get_counter(self, target, addr: int) -> None:
        """
        Hander for HAL function 'uint32_t rtt_get_counter(void)'
        """
        timer_val: int = self._model.get_timer_val(target, self._timer_name)
        # Return value
        target.r0 = timer_val

    def rtt_set_counter(self, target, addr: int) -> None:
        """
        Hander for HAL function 'void rtt_set_counter(uint32_t counter)'
        """
        timer_val: int = target.r0
        self._model.set_timer_val(target, self._timer_name, timer_val)
