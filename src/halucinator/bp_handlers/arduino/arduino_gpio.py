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


class ArduinoGPIO(object):
    def __init__(self, model=GPIO):
        self._model = GPIO

    @staticmethod
    def _get_id(pin: int):
        """
        Creates a unique id for the pin
        """
        return hex(pin)

    def pin_mode(self, target, addr: int) -> None:
        """
        Handler for HAL function 'void pinMode(pin_size_t pinNumber, PinMode pinMode)'
        """
        pin: int = target.r0
        mode: int = target.r1
        # Actually not a very useful handler -- currently mode is not considered

    def digital_read(self, target, addr: int) -> None:
        """
        Handler for HAL function 'PinStatus digitalRead(pin_size_t pinNumber)'
        """
        pin: int = target.r0
        target.r0 = self._model.read_pin(self._get_id(pin))

    def digital_write(self, target, addr: int) -> None:
        """
        Handler for HAL function 'void digitalWrite(pin_size_t pinNumber, PinStatus status)'
        """
        pin: int = target.r0
        mode: int = target.r1
        self._model.write_pin(self._get_id(pin), mode)
