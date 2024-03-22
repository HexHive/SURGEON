import logging
import random
from .baseinstrumentor import BaseInstrumentor

log = logging.getLogger(__name__)


class CovInstrumentor(BaseInstrumentor):

    AFL_MAP_SIZE: int = 1 << 16

    def __init__(
        self,
        instr_ctrl_addr: int,
        shm_addr: int,
    ):
        self._instr_ctrl_addr = instr_ctrl_addr
        self._shm_addr = shm_addr

    def get_instrumentation(self, *args, **kwargs) -> str:
        """Coverage instrumentation payload."""

        instr_ctrl_addr_lo, instr_ctrl_addr_hi = self.imm32tohilo(self._instr_ctrl_addr)

        shm_addr_lo, shm_addr_hi = self.imm32tohilo(self._shm_addr)

        curr_location = random.randint(0, self.AFL_MAP_SIZE - 1)
        curr_location_lo, curr_location_hi = self.imm32tohilo(curr_location)

        asm = f"""
        # obtain prev_location
        movw r0, #{instr_ctrl_addr_lo:#x}
        movt r0, #{instr_ctrl_addr_hi:#x}
        ldr r1, [r0]

        # curr_location XOR prev_locaton
        movw r2, #{curr_location_lo:#x}
        movt r2, #{curr_location_hi:#x}
        eor r1, r1, r2

        # update prev_location
        lsr r2, r2, #1
        str r2, [r0]

        # obtain shm
        movw r3, #{shm_addr_lo:#x}
        movt r3, #{shm_addr_hi:#x}
        ldrb r2, [r3, r1]
        add r2, r2, #1
        strb r2, [r3, r1]
        """

        return asm
