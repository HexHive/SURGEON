# Copyright 2019 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains
# certain rights in this software.

# Copyright 2022 HexHive, EPFL
# Modifications to this file include:
#  * Removal of bp_handler function decorators
#  * Generalizing the qemu target to a generic target
#  * Making the target compatible with the SURGEONTarget
#  * Addition of higher-level function handlers

from halucinator.peripheral_models.gpio import GPIO
from collections import defaultdict, deque
import struct
import binascii
import os
import logging

log = logging.getLogger(__name__)


class STM32F4GPIO(object):
    def __init__(self, model=GPIO):
        self.model = GPIO
        # Default values from recording
        self.phy_registers = {1: 0x786D, 0x10: 0x115, 0x11: 0, 0x12: 0x2C00}

    def get_id(self, port, pin):
        """
        Creates a unique id for the port and pin
        """
        return hex(port) + "_" + str(pin)

    def handle_exti(self, target, addr):
        """
        Handler for HAL function 'HAL_GPIO_EXTI_IRQHandler
        """
        log.debug("HAL_GPIO_EXTI_IRQHandler calling HAL_GPIO_EXTI_Callback")
        log.debug("GPIO=", hex(target.r0))
        callback_addr = target.avatar.callables["HAL_GPIO_EXTI_Callback"]
        # Effectively does tail call so HAL_GPIO_EXTI_Callback will return
        # without executing HAL_GPIO_EXTI_IRQHandler
        target.lr = callback_addr

    def gpio_init(self, target, addr):
        """
        Handler for HAL function 'HAL_GPIO_Init'
        """
        # Return value
        target.r0 = 0

    def gpio_deinit(self, target, addr):
        """
        Handler for HAL function 'HAL_GPIO_DeInit'
        """
        # Return value
        target.r0 = 0

    def write_pin(self, target, addr):
        """
        Handler for HAL function 'HAL_GPIO_WritePin'
        Reads the frame out of the emulated device, returns it and an
        id for the interface (id used if there are multiple gpio devices)
        """
        port = target.r0
        pin = target.r1
        value = target.r2
        gpio_id = self.get_id(port, pin)
        self.model.write_pin(gpio_id, value)
        # Return value
        target.r0 = 0

    def toggle_pin(self, target, addr):
        """
        Handler for HAL function 'HAL_GPIO_TogglePin'
        Toggles the pin
        """
        port = target.r0
        pin = target.r1
        gpio_id = self.get_id(port, pin)
        self.model.toggle_pin(gpio_id)

    def read_pin(self, target, addr):
        """
        Handler for HAL function 'HAL_GPIO_ReadPin'
        """
        port = target.r0
        pin = target.r1
        gpio_id = self.get_id(port, pin)
        # Return value
        target.r0 = self.model.read_pin(gpio_id)


class STM32F4HighlevelGPIO(STM32F4GPIO):
    """
    Class that implements more high-level handlers for GPIO functionality
    """

    def _write_pin(self, target, addr, value: int):
        """
        Transforms the given GPIO id into a port and pin first
        """
        port = target.r0 >> 4
        pin = target.r0 & 0x0F
        gpio_id = self.get_id(port, pin)
        self.model.write_pin(gpio_id, value)

    def set_pin(self, target, addr):
        """
        Handler for high-level function 'gpio_set'
        """
        self._write_pin(target, addr, 1)

    def clear_pin(self, target, addr):
        """
        Handler for high-level function 'gpio_clr'
        """
        self._write_pin(target, addr, 0)

    def toggle_pin(self, target, addr):
        """
        Handler for high-level function 'gpio_toggle'
        Toggles the pin
        """
        port = target.r0 >> 4
        pin = target.r0 & 0x0F
        gpio_id = self.get_id(port, pin)
        self.model.toggle_pin(gpio_id)

    def read_pin(self, target, addr):
        """
        Handler for high-level function 'gpio_rd'
        """
        port = target.r0 >> 4
        pin = target.r0 & 0x0F
        gpio_id = self.get_id(port, pin)
        # Return value
        target.r0 = self.model.read_pin(gpio_id) & 0x01

    def read_pin_inv(self, target, addr):
        """
        Handler for high-level function 'gpio_rd_inv'
        """
        port = target.r0 >> 4
        pin = target.r0 & 0x0F
        gpio_id = self.get_id(port, pin)
        # Return value
        target.r0 = ~(self.model.read_pin(gpio_id)) & 0x01

    """
    The following two functions are specific to the GRBL firmware for a CNC
    mill, see https://github.com/deadsy/grbl_stm32f4
    """

    def step_wr(self, target, addr):
        """
        Handler for high-level function 'step_wr'
        """
        # Port PORTE (= 4), pin 4
        port = 4
        pin = 4
        gpio_id = self.get_id(port, pin)
        # STEP_MASK = 0x00000550
        mask = 0x00000550
        value = self.model.read_pin(gpio_id)
        value &= ~mask & 0xFFFFFFFF
        self.model.write_pin(gpio_id, value | target.r0)

    def dirn_wr(self, target, addr):
        """
        Handler for high-level function 'dirn_wr'
        """
        # Port PORTE (= 4), pin 5
        port = 4
        pin = 5
        gpio_id = self.get_id(port, pin)
        # DIRECTION_MASK = 0x00000aa0
        mask = 0x00000AA0
        value = self.model.read_pin(gpio_id)
        value &= ~mask & 0xFFFFFFFF
        self.model.write_pin(gpio_id, value | target.r0)
