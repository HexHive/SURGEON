# Copyright 2022 HexHive, EPFL

import logging
from typing import List
from halucinator import constants

log = logging.getLogger(__name__)


class RIOTThread(object):
    """
    Data wrapper class for RIOT OS threads
    """

    stack_ptr: int = 0
    stack_size: int = 0
    priority: int = 0
    flags: int = 0
    task_func: int = 0
    task_arg: int = 0
    name: str = ""
    context: List[int] = [
        0,  # r0
        0,  # r1
        0,  # r2
        0,  # r3
        0,  # r4
        0,  # r5
        0,  # r6
        0,  # r7
        0,  # r8
        0,  # r9
        0,  # r10
        0,  # r11
        0,  # r12
        0,  # r13
        0,  # r14
        0,  # r15
    ]


class RIOTThreading(object):
    """
    Handler class for RIOT OS threading
    """

    def __init__(self):
        self._threads: List[RIOTThread] = []
        self._cur_thread: RIOTThread = None
        self._cur_prio: int = 0

    @staticmethod
    def _riot_context_save(target, thread: RIOTThread) -> None:
        """
        Save the thread context
        """
        for i in range(16):
            thread.context[i] = target.read_register(f"r{i}")

    @staticmethod
    def _riot_context_restore(target, thread: RIOTThread) -> None:
        """
        Restore a thread context
        """
        for i in range(14):
            target.write_register(f"r{i}", thread.context[i])
        # TODO: set PC instead of overriding LR
        target.r14 = thread.context[15]

    def _riot_sched(self, target) -> None:
        """
        Schedule a new thread
        """
        # First, store the old threads context
        if self._cur_thread is not None:
            self._riot_context_save(target, self._cur_thread)

        # Second, find a new thread with a higher priority (lower number)
        next_thread: RIOTThread = None
        for prio in range(self._cur_prio, constants.RIOT_SCHED_PRIO_LEVELS):
            candidates: List[RIOTThread] = list(
                filter(lambda x: x.priority <= prio, self._threads)
            )
            if len(candidates) > 0:
                # Found a thread with a higher priority
                next_thread = candidates.pop()
        # Make sure we have a next thread, could still be None
        next_thread = next_thread or self._cur_thread
        # Put current thread into the queue again
        if self._cur_thread is not None:
            self._threads.append(self._cur_thread)

        # Third, remove the next thread from the queue and schedule it
        if next_thread is not None:
            self._threads.remove(next_thread)
            self._cur_thread = next_thread
            self._cur_prio = self._cur_thread.priority
            self._riot_context_restore(target, self._cur_thread)

    def thread_create(self, target, addr: int) -> None:
        """
        Handler for RIOT OS API function 'kernel_pid_t thread_create(...)'
        """
        # Get args
        stack_ptr: int = target.get_arg(0)
        stack_size: int = target.get_arg(1)
        priority: int = target.get_arg(2)
        flags: int = target.get_arg(3)
        task_func: int = target.get_arg(4)
        task_arg: int = target.get_arg(5)
        name_ptr: int = target.get_arg(6)

        # Create new thread object
        thread = RIOTThread()
        thread.stack_ptr = stack_ptr + stack_size
        thread.stack_size = stack_size
        thread.priority = priority
        thread.task_func = task_func
        thread.task_arg = task_arg

        name_bytes = b""
        char: bytes = target.read_memory(
            address=name_ptr, size=1, num_words=1, raw=True
        )
        while char != b"\x00":
            name_bytes += char
            name_ptr += 1
            char = target.read_memory(address=name_ptr, size=1, num_words=1, raw=True)
        name_bytes += char
        # Why latin1? If it works, that's fine, but still...
        thread.name = name_bytes.decode("latin1")

        log.info(f"Creating RIOT OS thread '{thread.name}'")
        # Set up stack
        thread.context[13] = thread.stack_ptr
        # TODO: remove that hardcoded value for the return address -- ewww
        thread.context[14] = 0x794  # Address of sched_task_exit
        # Set up the entry point
        thread.context[15] = thread.task_func
        # Add the thread to our list and return its "PID"
        self._threads.append(thread)
        pid: int = self._threads.index(thread)
        target.r0 = pid

    def sched_task_exit(self, target, addr: int) -> None:
        """
        Handler for RIOT OS API function 'void sched_task_exit(void)'
        """
        log.info(f"Task '{self._cur_thread.name}' is exiting")
        self._cur_thread = None
        self._riot_sched(target)

    def cpu_switch_context_exit(self, target, addr: int) -> None:
        """
        Handler for RIOT OS API function 'void cpu_switch_context_exit(void)'

        Basically just schedules the next thread (the current thread yields).
        """
        self._riot_sched(target)

    def thread_isr_stack_pointer(self, target, addr: int) -> None:
        """
        Handler for RIOT OS API function 'void *thread_isr_stack_pointer(void)'
        """
        target.r0 = target.sp
