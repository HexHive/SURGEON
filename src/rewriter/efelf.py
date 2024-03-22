import logging
from io import BytesIO
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
from keystone.keystone import KsError

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    CS_MODE_MCLASS,
    CsError,
)

from .efbasicblock import EFBasicBlock
from .efinstruction import EFInstruction

# typing-related types
from typing import List, Tuple

################################################################################
# globals
################################################################################

log = logging.getLogger(__name__)


class EFElf:
    def __init__(
        self,
        elf: BytesIO,
        bb_ranges: List[Tuple[int, int]],
    ):
        elf.seek(0)
        self._raw_elf = BytesIO(elf.read())
        elf.seek(0)
        self._elf = ELFFile(elf)
        self._bb_ranges = bb_ranges

        # init capstone
        self._md = Cs(CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_MCLASS)
        self._md.detail = True

        self._section: Section = self._elf.get_section_by_name(".text")
        self._ef_bbs = self._disas()

        # init keystone
        self._ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    @property
    def bbs(self) -> List[EFBasicBlock]:
        return self._ef_bbs

    @property
    def raw_elf(self) -> BytesIO:
        return self._raw_elf

    @property
    def text_bounds(self) -> Tuple[int, int]:
        start: int = self._section["sh_addr"]
        end: int = start + self._section["sh_size"]
        return (start, end)

    def assemble(self, asm: str) -> bytes:

        try:
            encoding: List[int]
            encoding, _ = self._ks.asm(asm.encode())
        except KsError as e:
            log.error(e)
            import ipdb

            ipdb.set_trace()
        return bytes(encoding)

    def apply_transplant(self, insn: EFInstruction, transplant: str):

        instr_point: int = (
            insn.address - self._section["sh_addr"] + self._section["sh_offset"]
        )
        self._raw_elf.seek(instr_point)

        code = self.assemble(transplant)

        if len(code) != len(insn.bytes):
            log.error("Transplant size mismatch.")
            import ipdb; ipdb.set_trace()

        self._raw_elf.write(code)
        return

    def patch_detour(self, va_src: int, va_dst: int):
        instr_point: int = (
            va_src - self._section["sh_addr"] + self._section["sh_offset"]
        )
        self._raw_elf.seek(instr_point)

        call_off = va_dst - va_src
        asm = f"""b.w #{call_off:#x}"""

        try:
            code = self.assemble(asm)
        except Exception as e:
            import ipdb

            ipdb.set_trace()
        self._raw_elf.write(code)
        return

    def _disas(self) -> List[EFBasicBlock]:
        """Disassemble basic blocks in `section` and return a list of
           them.

        Returns:
            List[EFBasicBlock]: list of basic blocks in this section.
        """

        bbs: List[EFBasicBlock] = []

        code: bytes = self._section.data()
        assert self._section.compressed == 0, "We do not expect a compressed section."

        for start, end in self._bb_ranges:
            insns: List[EFInstruction] = []
            try:
                off = start
                code_start: int = start - self._section["sh_addr"]
                code_end: int = end - self._section["sh_addr"] + 1
                for insn in self._md.disasm(code[code_start:code_end], start):
                    insns.append(EFInstruction(insn))
                    off += insn.size
                    # log.debug(
                    #     f"{insn.address:#x}:\t{insn.mnemonic}\t{insn.op_str}"
                    # )
                    if off > end:
                        break
            except CsError as e:
                log.error(f"error: {e}")

            if insns:
                # could happen if capstone cannot disasm
                # example: f3ef 8009       mrs     r0, PSP (Console)
                bbs.append(EFBasicBlock(start, end, insns))
        return bbs
