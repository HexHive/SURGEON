# Copyright 2022 HexHive, EPFL

import logging
from halucinator.peripheral_models.timer import TimerModel

log = logging.getLogger(__name__)


class RIOTNVIC(object):
    def __init__(self, model=TimerModel):
        self._model = model
        self._state: Dict[str, bool] = dict()

    def irq_enable(self, target, addr: int) -> None:
        """
        Handler for HAL function 'irq_enable'
        """
        for tim in self._model.timers:
            self._model.start_timer(target, tim)

    def irq_disable(self, target, addr: int) -> None:
        """
        Handler for HAL function 'irq_disable'
        """
        for tim in self._model.timers:
            self._model.stop_timer(target, tim)
