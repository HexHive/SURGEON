import logging
import re
from enum import Enum
from io import BytesIO
from rewriter.efinstruction import EFInstruction

from .efelf import EFElf

import struct

# typing-related types
from typing import List, Callable

# convert bytes to values
u16: Callable[[bytes], int] = lambda x: struct.unpack("<H", x)[0]
u32: Callable[[bytes], int] = lambda x: struct.unpack("<I", x)[0]

# check if bit at `idx` is set int `val`
is_set: Callable[[int, int], bool] = lambda val, idx: (val >> idx) & 0b1


################################################################################
# globals
################################################################################

log = logging.getLogger(__name__)


class TransplantType(Enum):
    REGEX = 1  # For regex-based replacements (on the instruction mnemonic)
    BYTES = 2  # For byte-based replacements (on the raw instruction bytes)


class TransplantFactory:
    """Create the `Transplant` object for a given `EFInstructions`."""

    TRANS = [
        (TransplantType.REGEX, "mrs (r[0-9]), msp", "vmov.32 {}, d16[0]", 1),
        (TransplantType.REGEX, "mrs (r[0-9]), psp", "vmov.32 {}, d16[1]", 1),
        (TransplantType.REGEX, "msr msp, (r[0-9])", "vmov.32 d16[0], {}", 1),
        (TransplantType.REGEX, "msr psp, (r[0-9])", "vmov.32 d16[1], {}", 1),
        (TransplantType.REGEX, "msr primask, r[0-9]", "nop.w", None),
        (TransplantType.REGEX, "msr basepri, r[0-9]", "nop.w", None),
        (TransplantType.REGEX, "msr basepri_max, r[0-9]", "nop.w", None),
        (TransplantType.REGEX, "mrs (r[0-9]), primask", "mov {}, #0x0", 1),
        (TransplantType.REGEX, "mrs (r[0-9]), basepri", "mov {}, #0x0", 1),
        (TransplantType.REGEX, "mrs (r[0-9]), basepri_max", "mov {}, #0x0", 1),
        (TransplantType.REGEX, "mrs (r[0-9]), ipsr", "mov {}, #0x0", 1),
        (TransplantType.REGEX, "bkpt #1", "nop", None),
        (TransplantType.REGEX, "udf #0xff", "bkpt #2", None),
        (TransplantType.REGEX, "cpsie [if]", "nop", None),
        (TransplantType.REGEX, "cpsid [if]", "nop", None),
        (TransplantType.REGEX, "svc #\d", "bkpt #1", None),
        (TransplantType.BYTES, b"\xfe\xe7", "bkpt #3", None),  # Empty while-true
    ]

    @classmethod
    def create_transplant(cls, insn: EFInstruction) -> str:

        transplant = None
        for t in TransplantFactory.TRANS:
            match t[0]:
                case TransplantType.REGEX:
                    pattern = t[1]
                    match = re.search(pattern, insn.asm())
                    if match:
                        if t[3]:
                            reg = match.group(t[3])
                            transplant = t[2].format(reg)
                        else:
                            transplant = t[2]
                        break
                case TransplantType.BYTES:
                    if insn.bytes == t[1]:
                        transplant = t[2]
                        break

        if not transplant:
            log.info(f"No transplant for {insn}")
            import ipdb; ipdb.set_trace()

        return transplant


class TransInstrumentor:
    def __init__(self, ef_elf: EFElf):
        self._ef_elf = ef_elf

    def instrument(self) -> BytesIO:

        for bb in self._ef_elf.bbs:
            for insn in bb.insns:
                if not self._is_transplantable(insn):
                    log.info(f"Transplanting {insn.address:#08x}: {insn.mnemonic} {insn.op_str}")
                    transplant = TransplantFactory.create_transplant(insn)
                    self._ef_elf.apply_transplant(insn, transplant)

        self._ef_elf.raw_elf.seek(0)
        return self._ef_elf.raw_elf

    def _is_transplantable(self, insn: EFInstruction):
        """Return `True` if Cortex-M Thumb-2 instruction `insn` can be executed
        as a Cortex-A aarch32 Thumb-2 instruction adhering to the
        same semantics.
        Insn encodings taken from `http://class.ece.iastate.edu/cpre288/
        resources/docs/Thumb-2SupplementReferenceManual.pdf`
        """

        transplantable = False
        if insn.is_special_reg():
            # if `insn` touches special regs, we need to add emulation
            transplantable = False
        elif len(insn.bytes) == 2:
            # 2-byte insns
            transplantable = self._is_transplantable16(insn)
        elif len(insn.bytes) == 4:
            # 4-byte insns
            transplantable = self._is_transplantable32(insn)
        else:
            log.error("Unexpected insn of length {}".format(len(insn.bytes)))
            import ipdb
            ipdb.set_trace()

        return transplantable

    def _is_transplantable16(self, insn: EFInstruction):

        assert len(insn.bytes) == 2, "expecting 2 bytes instead of {}".format(
            len(insn.bytes)
        )

        transplantable = False
        ienc = u16(insn.bytes)
        if ienc >> 13 == 0 and ienc >> 11 != 0b11:
            # Shift by immediate, move register
            # log.debug(
            #     "sh imm or mov reg: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 10 == 0b000110:
            # Add / subtract register
            # log.debug("add/sub reg: {} {}".format(ins.mnemonic, ins.op_str))
            transplantable = True
        elif ienc >> 10 == 0b000111:
            # Add / subtract immediate
            # log.debug(
            #     "add/sub immediate: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 13 == 0b001:
            # Add / subtract / compare / move immediate
            # log.debug(
            #     "add/sub/cmp/mv immediate: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif ienc >> 10 == 0b010000:
            # Data-processing register
            # log.debug(
            #     "data-processing reg: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 10 == 0b010001 and (ienc >> 8) & 0b11 != 0b11:
            # Special data processing
            # log.debug(
            #     "special data processing: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif ienc >> 8 == 0b01000111:
            # Branch/exchange instruction set
            # log.debug(
            #     "branch/exchange insn set: {} {}".format(
            #         insn.mnemonic, insn.op_str
            #     )
            # )
            # Potential side effects:
            # * On Cortex-A, switch from T32 to A32 depending on bit[0]
            #   of target address. A32 is not present on Cortex-M and a switch
            #   like this will cause an abort.
            # * Wold switch on Cortex-M between secure/non-secure state.
            transplantable = True
        elif ienc >> 11 == 0b01001:
            # Load from literal pool
            # log.debug(
            #     "load from literal pool: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 12 == 0b0101:
            # Load/store register offset
            # log.debug(
            #     "load/store register offset: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif ienc >> 13 == 0b011:
            # Load/store word/byte immediate offset
            # log.debug(
            #     "load/store word/byte immediate offset: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif ienc >> 12 == 0b1000:
            # Load/store halfword immediate offset
            # log.debug(
            #     "load/store halfword immediate offset: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif ienc >> 12 == 0b1001:
            # load/store stack
            # log.debug(
            #     "load/store stack: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 12 == 0b1010:
            # add to sp or pc
            # log.debug("add to sp or pc: {} {}".format(ins.mnemonic, ins.op_str))
            transplantable = True
        elif ienc >> 12 == 0b1011:
            # misc
            # log.debug("misc: {} {}".format(ins.mnemonic, ins.op_str))
            transplantable = self._is_transplantable16_misc(insn)
        elif ienc >> 12 == 0b1100:
            # load/store mutliple
            # log.debug(
            #     "load/store mutliple: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 12 == 0b1101 and ((ienc >> 9) & 0b111) != 0b111:
            # conditional branch
            # log.debug(
            #     "conditional branch: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 8 == 0b11011110:
            # undefined insn
            log.debug(
                "undefined insn: {} {}".format(insn.mnemonic, insn.op_str)
            )
            transplantable = False
        elif ienc >> 8 == 0b11011111:
            # service system call
            log.debug(
                "service system call: {} {}".format(insn.mnemonic, insn.op_str)
            )
            transplantable = False
        elif ienc == 0b1110011111111110:
            # 0b1110011111111110 == 0xe7fe
            # unconditional branch with offset -2 (i.e., empty infinite loop)
            transplantable = False
        elif ienc >> 11 == 0b11100:
            # unconditional branch
            # log.debug(
            #     "unconditional branch: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        else:
            log.debug("unknown16: {} {}".format(insn.mnemonic, insn.op_str))
            log.error("Our insn decoding is incomplete, if we end up here.")
            import ipdb

            ipdb.set_trace()

        return transplantable

    def _is_transplantable16_misc(self, insn: EFInstruction):
        ienc = u16(insn.bytes)
        assert ienc >> 12 == 0b1011, "Not a misc insn"
        transplantable = False

        if ienc >> 8 == 0b10110000:
            # Adjust stack pointer
            # log.debug(
            #     "adjust stack pointer: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 8 == 0b10110010:
            # Sign/zero extend
            # log.debug(
            #     "sign/zero extend: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 12 == 0b1011 and not is_set(ienc, 10) and is_set(ienc, 8):
            # Compare and branch on non-zero
            # log.debug(
            #     "compare and branch on non-zero: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 12 == 0b1011 and is_set(ienc, 10) and not is_set(ienc, 9):
            # Push / pop reg list
            # log.debug(
            #     "push / pop reg list: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> 4 == 0b101101100100:
            # Unpredictable
            log.debug("unpredictable: {} {}".format(insn.mnemonic, insn.op_str))
            transplantable = False
        elif ienc >> 4 == 0b101101100101:
            # Set endianess
            log.debug("set endianess: {} {}".format(insn.mnemonic, insn.op_str))
            transplantable = False
        elif ienc >> 5 == 0b10110110011 and ((ienc >> 3) & 0b1) == 0:
            # Change processor state
            log.debug(
                "change processor state: {} {}".format(
                    insn.mnemonic, insn.op_str
                )
            )
            transplantable = False
        elif ienc >> 5 == 0b10110110011 and is_set(ienc, 3):
            # Unpredictable
            log.debug("unpredictable: {} {}".format(insn.mnemonic, insn.op_str))
            transplantable = False
        elif ienc >> 8 == 0b10111010:
            # Reverse bytes
            log.debug("reverse bytes: {} {}".format(insn.mnemonic, insn.op_str))
            transplantable = True
        elif ienc >> 8 == 0b10111110:
            # Software breakpoint
            log.debug(
                "software breakpoint: {} {}".format(insn.mnemonic, insn.op_str)
            )
            transplantable = False
        elif ienc >> 8 == 0b10111111 and ienc & 0b1111 != 0b0000:
            # If-Then insns
            # log.debug("if-then insns: {} {}".format(insn.mnemonic, insn.op_str))
            transplantable = True
        elif ienc >> 8 == 0b10111111 and ienc & 0b1111 == 0b0000:
            # NOP-compatbile hints
            if ienc & 0b11111111 == 0:
                # just a nop
                transplantable = True
            else:
                # yield, wait for event, wait for interrupt, send event
                log.debug(
                    "nop-compatbile hints: {} {}".format(
                        insn.mnemonic, insn.op_str
                    )
                )
                transplantable = False
        else:
            log.debug("unknown16: {} {}".format(insn.mnemonic, insn.op_str))
            log.error("Our insn decoding is incomplete, if we end up here.")
            import ipdb

            ipdb.set_trace()
        return transplantable

    def _is_transplantable32(self, insn: EFInstruction):

        assert len(insn.bytes) == 4, "expecting 4 bytes instead of {}".format(
            len(insn.bytes)
        )

        transplantable = False
        ienc = u16(insn.bytes[:2]) << 16 | u16(insn.bytes[2:])

        if ienc >> (11 + 16) == 0b11110 and not is_set(ienc, 15):
            # Data processing: immediate, including bitfield, and saturate
            # log.debug(
            #     "data processing imm, bitfield, saturate: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif (
            ienc >> (13 + 16) == 0b111 and ((ienc >> (9 + 16)) & 0b111) == 0b101
        ):
            # Data processing no immediate operand
            # log.debug(
            #     "data processing no imm: {} {}".format(ins.mnemonic, ins.op_str)
            # )
            transplantable = True
        elif ienc >> (9 + 16) == 0b1111100:
            # Load and store single data item
            # log.debug(
            #     "load and store single data item: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif ienc >> (9 + 16) == 0b1110100 and is_set(ienc, 6 + 16):
            # Load and store, double and exclusive, and table branch
            # log.debug(
            #     "load and store, double and exclusive, and table branch: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif ienc >> (9 + 16) == 0b1110100 and not is_set(ienc, 6 + 16):
            # Load and store multiple, RFE and SRS
            if is_set(ienc, 8 + 16) != is_set(ienc, 7 + 16):
                # V != U (see manual)
                transplantable = True
            else:
                log.debug(
                    "load and store multiple, RFE and SRS: {} {}".format(
                        insn.mnemonic, insn.op_str
                    )
                )
                transplantable = False
        elif ienc >> (11 + 16) == 0b11110 and is_set(ienc, 15):
            # Branches, misc control
            transplantable = self._is_transplantable32_misc(insn)
        elif ienc >> (13 + 16) == 0b111 and (ienc >> (10 + 16)) & 0b11 == 0b11:
            # co-processor
            import ipdb

            ipdb.set_trace()
            log.debug("co-processor: {} {}".format(insn.mnemonic, insn.op_str))
            transplantable = False
        else:
            log.debug("unknown32: {} {}".format(insn.mnemonic, insn.op_str))
            log.error("Our insn decoding is incomplete, if we end up here.")
            import ipdb

            ipdb.set_trace()

        return transplantable

    def _is_transplantable32_misc(self, insn: EFInstruction):
        assert len(insn.bytes) == 4, "expecting 4 bytes instead of {}".format(
            len(insn.bytes)
        )
        ienc = u16(insn.bytes[:2]) << 16 | u16(insn.bytes[2:])
        assert ienc >> (11 + 16) == 0b11110, "expecting 0b11110 insn prefix"

        transplantable = False

        if is_set(ienc, 15) and not is_set(ienc, 14) and is_set(ienc, 12):
            # Branch
            # log.debug(
            #     "branch: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif is_set(ienc, 15) and is_set(ienc, 14) and is_set(ienc, 12):
            # Branch with link
            # log.debug(
            #     "branch with link: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif (
            is_set(ienc, 15)
            and is_set(ienc, 14)
            and not is_set(ienc, 12)
            and not is_set(ienc, 0)
        ):
            # Branch with link change to ARM
            # log.debug(
            #     "branch with link change to arm: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        elif (
            is_set(ienc, 15)
            and is_set(ienc, 14)
            and not is_set(ienc, 12)
            and is_set(ienc, 0)
        ):
            # Reserved
            # log.debug(
            #     "reserved: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = False
        elif is_set(ienc, 15) and not is_set(ienc, 14) and not is_set(ienc, 12):
            # Conditional branch
            # log.debug(
            #     "conditional branch: {} {}".format(
            #         ins.mnemonic, ins.op_str
            #     )
            # )
            transplantable = True
        else:
            # Other 32-bit ctrl insns
            log.debug(
                "other 32-bit ctrl insns: {} {}".format(
                    insn.mnemonic, insn.op_str
                )
            )
            transplantable = False
        return transplantable
