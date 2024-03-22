# Copyright 2019 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains
# certain rights in this software.

# Copyright 2022 HexHive, EPFL
# Modifications to this file include:
#  * Temporarily remove usage of interrupts and the peripheral server (see TODO comments below)
#  * Add usage of our native code timer emulation

# from . import peripheral_server # TODO
# from .interrupts import Interrupts # TODO
import logging

log = logging.getLogger(__name__)


# Register the pub/sub calls and methods that need mapped
# @peripheral_server.peripheral_model # TODO
class TimerModel(object):

    timers = dict()

    @classmethod
    def add_timer(cls, target, name, rate):
        if name not in cls.timers:
            # Add a timer because we cannot randomly schedule interrupt requests
            idx = target.add_timer(rate, 1)
            if idx == -1:
                # Timer creation failed
                return False
            else:
                # Save the timer for later
                cls.timers[name] = idx
                return True
        return True

    @classmethod
    def attach_irq(cls, target, name, irq_num: int):
        log.debug(f"Attaching IRQ {irq_num} to timer {name}")
        if name in cls.timers:
            target.attach_irq(cls.timers[name], irq_num)

    @classmethod
    def start_timer(cls, target, name):
        log.debug("Starting timer: %s" % name)
        if name in cls.timers:
            target.start_timer(cls.timers[name])

    @classmethod
    def stop_timer(cls, target, name):
        log.debug("Stopping timer: %s" % name)
        if name in cls.timers:
            target.stop_timer(cls.timers[name])

    @classmethod
    def get_timer_val(cls, target, name) -> int:
        timer_val: int = 0
        if name in cls.timers:
            timer_val = target.get_timer_val(cls.timers[name])
        log.debug(f"Timer {name} is at tick {timer_val}")
        return timer_val

    @classmethod
    def set_timer_val(cls, target, name, timer_val: int) -> int:
        if name in cls.timers:
            target.set_timer_val(cls.timers[name], timer_val)
        log.debug(f"Timer {name} is at tick {timer_val}")
