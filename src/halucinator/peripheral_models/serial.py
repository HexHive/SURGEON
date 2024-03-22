# Copyright 2019 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains
# certain rights in this software.

# Copyright 2022 HexHive, EPFL
# Modifications to this file include:
#  * Temporarily remove usage of interrupts and the peripheral server (see TODO comments below)
#  * Read from stdin instead of the peripheral server, TODO: maybe make reading and writing
#    a property of the peripheral server like in original HALucinator instead of the peripheral model?
#  * Rename from SerialModel to SerialModel (reuse across different serial peripheral implementations)

# from . import peripheral_server # TODO
from threading import Event, Thread
from collections import deque, defaultdict
import sys
import logging
from itertools import repeat
import time

log = logging.getLogger(__name__)

# Register the pub/sub calls and methods that need mapped
# @peripheral_server.peripheral_model # TODO
class SerialModel(object):
    rx_buffers = defaultdict(deque)

    @classmethod
    # @peripheral_server.tx_msg # TODO
    def write(cls, serial_id, chars):
        """
        Publishes the data to sub/pub server
        """
        log.info(f"Writing: {chars}")
        msg = {"id": serial_id, "chars": chars}
        return msg

    @classmethod
    def read(cls, serial_id, count=1, block=False):
        """
        Gets data from stdin

        Args:
            serial_id: A unique id for the uart
            count: Max number of chars to read
            block (bool): Block if data is not available
        """
        log.debug(
            f"In: {cls.__name__}.read id:{hex(serial_id)} count:{count}, block:{str(block)}"
        )
        while block and (len(cls.rx_buffers[serial_id]) < count):
            # TODO: No hardcoded input lengths, have it more dependend on the input
            # similar to the serial frames in hal-fuzz
            in_bytes = bytes(sys.stdin.buffer.read(10))
            if len(in_bytes) == 0:
                log.debug("Reached EOF of stdin")
                exit(0)
            cls.rx_buffers[serial_id].extend(in_bytes)
        log.debug(f"Done Blocking: {cls.__name__}.read")
        buffer = cls.rx_buffers[serial_id]
        chars_available = len(buffer)
        if chars_available >= count:
            chars = bytes([buffer.popleft() for _ in range(count)])
        else:
            chars = bytes([buffer.popleft() for _ in range(chars_available)])

        log.info(f"Reading: {chars}")
        return chars

    @classmethod
    def read_line(cls, serial_id, count=1, block=False):
        """
        Gets data from stdin

        Args:
            serial_id: A unique id for the uart
            count: Max number of chars to read
            block (bool): Block if data is not available
        """
        log.debug(
            f"In: {cls.__name__}.read id:{hex(serial_id)} count:{count}, block:{str(block)}"
        )
        while block and (len(cls.rx_buffers[serial_id]) < count):
            if ord(b"\n") in cls.rx_buffers[serial_id]:
                # Have a line end
                break
            # No line end so far => read from stdin
            in_bytes = bytes(sys.stdin.buffer.readline(count))
            if len(in_bytes) == 0:
                log.debug("Reached EOF of stdin")
                exit(0)
            cls.rx_buffers[serial_id].extend(in_bytes)

        log.debug(f"Done Blocking: {cls.__name__}.read_line")
        buffer = cls.rx_buffers[serial_id]
        chars_available = len(buffer)
        # If we have a line end in the buffer, decrease the count to read only
        # that line
        if ord(b"\n") in buffer:
            count = min(count, buffer.index(ord(b"\n")) + 1)

        if chars_available >= count:
            chars = bytes([buffer.popleft() for _ in range(count)])
        else:
            chars = bytes([buffer.popleft() for _ in range(chars_available)])

        log.info(f"Reading: {chars}")
        return chars

    @classmethod
    # @peripheral_server.reg_rx_handler # TODO
    def rx_data(cls, msg):
        """
        Handles reception of these messages from the PeripheralServer
        """
        log.debug(f"rx_data got message: {str(msg)}")
        serial_id = msg["id"]
        data = msg["chars"]
        cls.rx_buffers[serial_id].extend(data)
