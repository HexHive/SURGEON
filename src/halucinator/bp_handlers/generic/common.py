# Copyright 2022 HexHive, EPFL

import logging
import os

log = logging.getLogger(__name__)


class ReturnZero(object):
    """
    Handler that just returns zero
    """

    def return_zero(self, target, addr):
        """
        Intercept Execution and return 0
        """
        log.info(f"ReturnZero @ {hex(addr)}")
        # Return value
        target.r0 = 0


class SkipFunc(object):
    """
    Handler that immediately returns from the function
    """

    def skip(self, target, addr):
        """
        Just return
        """
        log.info(f"Skip function @ {hex(addr)}")


class Abort(object):
    """
    Handler that exits with an error message
    """

    def abort(self, target, addr):
        log.info(f"Abort @ {hex(addr)}")
        os.abort()

class Exit(object):
    """
    Handler that just exits
    """
    def exit(self, target, addr: int):
        log.info(f"Exit @ {hex(addr)}")
        exit(0)
