# Copyright 2022 HexHive, EPFL

from halucinator.peripheral_models.serial import SerialModel
import logging

log = logging.getLogger(__name__)


class ArduinoSerial(object):
    def __init__(self, model=SerialModel):
        self._model = model
        # We keep an internal counter that "fails" a function call with a certain frequency
        self._fail_freq = 20
        self._ctr = 0

    @property
    def is_available(self) -> bool:
        # Update the internal counter
        self._ctr += 1
        self._ctr %= self._fail_freq
        # Depending on the internal counter, return True (counter != 0) or False
        return self._ctr != 0

    def available(self, target, addr: int) -> None:
        """
        Handler for HAL function 'int Stream::available(void)' (inherited by serials)

        This function is supposed to return the number of available bytes which
        we do not know a priori. It's commonly only checked against 0 so
        returning 1 or 0 for now is sufficient.
        """
        # It's CPP, so r0 holds the 'this *' pointer
        serial_id: int = target.r0
        target.r0 = 1 if self.is_available else 0

    def read(self, target, addr: int) -> None:
        """
        Handler for HAL function 'int Stream::read(void)' (inherited by serials)
        """
        # It's CPP, so r0 holds the 'this *' pointer
        serial_id: int = target.r0
        if self.is_available:
            target.r0 = int.from_bytes(
                self._model.read(serial_id, 1, block=True), byteorder="little"
            )
        else:
            target.r0 = -1

    def write(self, target, addr: int) -> None:
        """
        Handler for HAL function 'size_t Stream::read(uint8_t data)' (inherited by serials)
        """
        # It's CPP, so r0 holds the 'this *' pointer
        serial_id: int = target.r0
        data: bytes = int(target.r1).to_bytes(1, byteorder="little")
        self._model.write(serial_id, data)
