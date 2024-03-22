# Copyright 2019 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains
# certain rights in this software.

# Copyright 2022 HexHive, EPFL
# Modifications to this file include:
#  * Removal of bp_handler function decorators
#  * Generalizing the qemu target to a generic target
#  * Making the target compatible with the SURGEONTarget

from os import sys, path
from halucinator.peripheral_models.serial import SerialModel
import logging

log = logging.getLogger(__name__)


class STM32F4UART(object):
    def __init__(self, impl=SerialModel):
        self.model = impl

    def hal_ok(self, target, addr):
        """
        Handler for HAL function 'HAL_UART_Init'
        """
        log.info("Init Called")
        # Return value
        target.r0 = 0

    def get_state(self, target, addr):
        """
        Handler for HAL function 'HAL_UART_GetState'
        """
        log.info("Get State")
        # Return value
        target.r0 = 0x20  # 0x20 READY

    def handle_tx(self, target, addr):
        """
        Handler for HAL functions 'HAL_UART_Transmit', 'HAL_UART_Transmit_IT', 'HAL_UART_Transmit_DMA'

        Reads the frame out of the emulated device, returns it and an
        id for the interface(id used if there are multiple ethernet devices)
        """
        huart = target.r0
        hw_addr = target.read_memory(huart, 4, 1)
        buf_addr = target.r1
        buf_len = target.r2
        data = target.read_memory(buf_addr, 1, buf_len, raw=True)
        log.info(f"UART TX: {data}")
        self.model.write(hw_addr, data)
        # Return value
        target.r0 = 0

    def handle_rx(self, target, addr):
        """
        Handler for HAL functions 'HAL_UART_Receive', 'HAL_UART_Receive_IT', 'HAL_UART_Receive_DMA'
        """
        huart = target.r0
        hw_addr = target.read_memory(huart, 4, 1)
        size = target.r2
        log.info(f"Waiting for data: {size}")
        data = self.model.read(hw_addr, size, block=True)
        log.info(f"UART RX: {data}")
        target.write_memory(target.r1, 1, data, size, raw=True)
        # Return value
        target.r0 = 0


class STM32F4USART(STM32F4UART):
    """
    Class for supporting higher-level USART functions in addition to the
    inherited UART functions
    """

    def getc(self, target, addr):
        """
        Handler for HAL function 'usart_getc'
        """
        # Return value
        target.r0 = self.model.read(
            int.from_bytes(b"generic_usart", byteorder="little"), 1, block=True
        )[0]

    def putc(self, target, addr):
        """
        Handler for HAL function 'usart_putc'
        """
        self.model.write(
            int.from_bytes(b"generic_usart", byteorder="little"),
            target.r0.to_bytes(length=1, byteorder="little"),
        )
