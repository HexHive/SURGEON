# Copyright 2022 HexHive, EPFL

from halucinator.peripheral_models.serial import SerialModel


class RIOTIO(object):
    """
    Class for supporting high-level I/O provided by RIOT OS
    """

    def __init__(self, model=SerialModel):
        self._model = model
        self._id: int = int.from_bytes(b"riot_io", byteorder="little")

    def readline(self, target, addr: int) -> None:
        """
        Handler for HAL function 'readline' and similar
        """
        buf: int = target.r0
        size: int = target.r1

        # Read in a line (and end it with a null byte)
        line: bytes = self._model.read_line(self._id, size, block=True) + b"\0"
        # Now have the line => copy it into the firmware's memory (and end with a null byte)
        success: bool = target.write_memory(
            address=buf, size=len(line), value=line, num_words=1, raw=True
        )

        # Return value
        target.r0 = 0 if success else -1
