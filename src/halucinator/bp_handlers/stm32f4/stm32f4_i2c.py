# Copyright 2022 HexHive, EPFL

from halucinator.peripheral_models.serial import SerialModel
from halucinator import constants
import logging

log = logging.getLogger(__name__)


class STM32F4I2C(object):
    def __init__(self, model=SerialModel):
        self._model = model

    def tx(self, target, addr: int) -> None:
        """
        Handler for HAL functions 'HAL_I2C_Master_Transmit{_IT,_DMA}'
        """
        hi2c: int = target.get_arg(0)
        hw_addr: int = target.read_memory(hi2c, 4, 1)
        buf_addr: int = target.get_arg(2)
        buf_len: int = target.get_arg(3)

        data: bytes = target.read_memory(buf_addr, buf_len, raw=True)
        assert len(data) == buf_len
        log.info(f"I2C TX: {data}")
        self._model.write(hw_addr, data)
        # Return value
        target.set_arg(0, constants.STM32F4_HAL_OK)

    def mem_read(self, target, addr: int) -> None:
        """
        Handler for HAL function 'HAL_I2C_Mem_Read'
        """
        hi2c: int = target.get_arg(0)
        hw_addr: int = target.read_memory(hi2c, 4, 1)
        mem_addr: int = target.get_arg(2)
        mem_size: int = target.get_arg(3)
        buf_addr: int = target.get_arg(4)
        buf_len: int = target.get_arg(5)
        log.debug(f"Requesting data from I2C device @ {hex(mem_addr)}")

        data: bytes = self._model.read(hw_addr, buf_len, block=True)
        assert len(data) == buf_len
        log.info(f"I2C RX: {data}")
        target.write_memory(buf_addr, buf_len, data, raw=True)
        # Return value
        target.set_arg(0, constants.STM32F4_HAL_OK)

    def mem_write(self, target, addr: int) -> None:
        """
        Handler for HAL function 'HAL_I2C_Mem_Write'
        """
        hi2c: int = target.get_arg(0)
        hw_addr: int = target.read_memory(hi2c, 4, 1)
        mem_addr: int = target.get_arg(2)
        mem_size: int = target.get_arg(3)
        buf_addr: int = target.get_arg(4)
        buf_len: int = target.get_arg(5)
        log.debug(f"Pushing data to I2C device @ {hex(mem_addr)}")

        data: bytes = target.read_memory(buf_addr, buf_len, raw=True)
        assert len(data) == buf_len
        log.info(f"I2C TX: {data}")
        self._model.write(hw_addr, data)
        # Return value
        target.set_arg(0, constants.STM32F4_HAL_OK)
