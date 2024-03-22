import logging
from typing import List

from capstone import (
    CsInsn,
    CS_GRP_JUMP,
    CS_GRP_CALL,
    CS_GRP_RET,
    CS_AC_WRITE,
    CS_AC_READ,
)

from capstone.arm_const import (
    ARM_OP_REG,
    ARM_REG_PC,
    ARM_OP_SYSREG,
    ARM_OP_MEM,
    ARM_OP_IMM,
)
from keystone import KsError
from .constants import BRANCH_MAXDIST, COND_BRANCH_MAXDIST
from . import EF_ASM


# logging
log = logging.getLogger(__name__)


# set of capstone control flow groups
CS_CF_GRPS = set([CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET])
RELOCATABLE_CF_INSNS_UNCOND = set(
    [
        "bl",
        "b",
        "b.w",
    ]
)
RELOCATABLE_CF_INSNS_COND = set(
    [
        "bne",
        "bne.w",
        "blt",
        "blt.w",
        "ble",
        "ble.w",
        "beq",
        "beq.w",
        "bge",
        "bge.w",
        "bgt",
        "bgt.w",
        "bhi",
        "bhi.w",
        "bls",
        "bls.w",
        "bmi",
        "bmi.w",
        "bpl",
        "bpl.w",
        "blo",
        "blo.w",
        "bhs",
        "bhs.w",
    ]
)
RELOCATABLE_CF_INSNS = RELOCATABLE_CF_INSNS_COND | RELOCATABLE_CF_INSNS_UNCOND
# CB(N)Z is not relocatable because the possible PC offset is too small
NON_RELOCATABLE_CF_INSNS = set(
    [
        "cbz",
        "cbnz",
    ]
)


class EFInstructionException(Exception):
    pass


class EFInstruction(object):
    """A convenience wrapper for capstone instructions (`CsInsn`)."""

    def __init__(self, insn: CsInsn):
        self._insn = insn
        # Relocated bytes may be updated as part of the relocabality check
        self._relocated_bytes = self._insn.bytes

    @property
    def size(self) -> int:
        return self._insn.size

    @property
    def address(self) -> int:
        return self._insn.address

    @property
    def bytes(self) -> bytes:
        return self._insn.bytes

    @property
    def mnemonic(self) -> str:
        return self._insn.mnemonic

    @property
    def operands(self) -> List:
        return self._insn.operands

    @property
    def op_str(self) -> str:
        return self._insn.op_str

    @property
    def relocated_bytes(self) -> bytes:
        return self._relocated_bytes

    def asm(self) -> str:
        return f"{self._insn.mnemonic} {self._insn.op_str}"

    def it_block_len(self) -> int:
        """Returns the number of insns in an if-then block."""
        if not self.is_it():
            return 0
        return len(self._insn.mnemonic) - 1

    def is_it(self) -> bool:
        if "it" in self._insn.mnemonic:
            return True
        return False

    def is_special_reg(self) -> bool:
        """Returns `True` if this insn touches a special register, `False` otherwise."""
        for op in self._insn.operands:
            if op.type == ARM_OP_SYSREG:
                return True
        return False

    def is_relocatable(self, reloc_addr: int = -1) -> bool:
        """is `insn` relocatable, i.e., can be relocated into a trampoline?

        we consider an `insn` not relocatable if it reads/writes the pc or
        triggers certain control flow transfers.
        """

        if self.reads_pc():
            return False

        wpc = self.writes_pc()

        if wpc and self._insn.mnemonic in ["pop", "pop.w"]:
            # Popping an address from the stack into the pc is
            # not position dependent, can be relocated
            return True
        elif wpc:
            # TODO: consider ADR insn as position dependent?
            # this case is often used for jump tables where ADR and LDR insns are
            # combined to index the table correctly and jump accordingly.
            # For example:
            #   ADR     R2, jpt_8003456
            #   LDR.W   PC, [R2,R3,LSL#2]
            # this case is position dependent
            return False

        if set(self._insn.groups) & CS_CF_GRPS:
            if self._insn.mnemonic in NON_RELOCATABLE_CF_INSNS:
                return False

            elif self._insn.mnemonic in RELOCATABLE_CF_INSNS:
                assert (
                    len(self._insn.operands) == 1
                    and self._insn.operands[0].type == ARM_OP_IMM
                )
                target_addr: int = self._insn.operands[0].value.imm

                is_conditional: bool = self._insn.mnemonic in RELOCATABLE_CF_INSNS_COND

                branch_dist: int = (
                    COND_BRANCH_MAXDIST if is_conditional else BRANCH_MAXDIST
                )
                if reloc_addr != -1 and abs(reloc_addr - target_addr) < branch_dist:
                    # Branch reach allows us to move the branch into the trampoline
                    # Keystone adds an offset of 4 to conditional branches... haven't been able to figure out why
                    reloc_asm = (
                        self._insn.mnemonic
                        + " "
                        + f"#{target_addr - reloc_addr - (4 if is_conditional else 0):#x}"
                    )
                    try:
                        encoding, _ = EF_ASM.asm(reloc_asm)
                        if encoding is None:
                            log.error(
                                f"Failed to assemble: {reloc_asm} => not relocating"
                            )
                            return False
                        self._relocated_bytes = bytes(encoding)
                    except KsError as e:
                        log.error(e)
                        import ipdb
                        ipdb.set_trace()
                        raise EFInstructionException(
                            "Relocated instruction could not be assembled"
                        )
                    return True
                else:
                    return False

            if self._insn.mnemonic not in ["bx", "blx"]:
                log.debug(
                    f"{self._insn.address:#x}:\t{self._insn.mnemonic}\t{self._insn.op_str}"
                )
                import ipdb
                ipdb.set_trace()

        return True

    def reads_pc(self) -> bool:
        """does `insn` read pc?"""
        for op in self._insn.operands:
            if (
                op.type == ARM_OP_REG
                and op.value.reg == ARM_REG_PC
                and op.access == CS_AC_READ
            ) or (
                op.type == ARM_OP_MEM
                and (
                    op.value.mem.base == ARM_REG_PC or op.value.mem.index == ARM_REG_PC
                )
                and op.access == CS_AC_READ
            ):
                return True
        return False

    def writes_pc(self) -> bool:
        """does `insn` write pc?"""
        for op in self._insn.operands:
            if (
                op.type == ARM_OP_REG
                and op.value.reg == ARM_REG_PC
                and op.access == CS_AC_WRITE
            ):
                return True
        return False
