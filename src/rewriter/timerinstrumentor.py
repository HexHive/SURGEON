import logging
from .baseinstrumentor import BaseInstrumentor

log = logging.getLogger(__name__)


class TimerInstrumentor(BaseInstrumentor):
    def __init__(self, handler_addr: int):
        self._handler_addr = handler_addr

    def get_instrumentation(self, *args, **kwargs) -> str:
        """
        Timer instrumentation payload.
        Jumps to the corresponding function in the runtime.
        """

        handler_addr_lo, handler_addr_hi = self.imm32tohilo(self._handler_addr)
        # Increment timers by number of instructions if provided
        insn_num = kwargs.get("insn_num", 1)

        asm = f"""
        # load handler address
        movw r1, #{handler_addr_lo:#x}
        movt r1, #{handler_addr_hi:#x}

        # load increment argument (should be small enough for a simple mov)
        mov r0, #{insn_num:#x}

        # branch and link to handler
        blx r1
        """

        return asm
