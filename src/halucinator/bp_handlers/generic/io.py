# Copyright 2022 HexHive, EPFL

from halucinator.peripheral_models.serial import SerialModel


class IO(object):
    """
    Class for supporting high-level I/O
    """

    def __init__(self, model=SerialModel):
        self._model = model
        self._id: int = int.from_bytes(b"generic_io", byteorder="little")

    def getc(self, target, addr: int) -> None:
        """
        Handler for HAL functions 'usart_getc', 'getchar', etc.
        """
        # Return value
        target.r0 = self._model.read(self._id, 1, block=True)[0]

    def putc(self, target, addr: int) -> None:
        """
        Handler for HAL function 'usart_putc', 'putchar', etc.
        """
        self._model.write(
            self._id,
            target.r0.to_bytes(length=1, byteorder="little"),
        )
