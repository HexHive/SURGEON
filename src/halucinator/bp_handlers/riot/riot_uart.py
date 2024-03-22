# Copyright 2022 HexHive, EPFL

import logging
from halucinator.peripheral_models.serial import SerialModel

log = logging.getLogger(__name__)


class RIOTUART(object):
    def __init__(self, model=SerialModel):
        self._model = model

    def write(self, target, addr: int) -> None:
        """
        Handler for HAL function 'void uart_write(uart_t uart,uint8_t *data,size_t len)'
        """
        uart_id: int = target.r0
        data_ptr: int = target.r1
        data_len: int = target.r2

        data: bytes = target.read_memory(
            address=data_ptr, size=1, num_words=data_len, raw=True
        )
        self._model.write(uart_id, data)
