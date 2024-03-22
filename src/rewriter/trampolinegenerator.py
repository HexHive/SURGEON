import logging
import random
from io import BytesIO
from mmap import PAGESIZE

from .efelf import EFElf
from .efbasicblock import EFBasicBlock
from .efinstruction import EFInstruction
from .eftrampoline import EFTrampoline, EFTrampolineException
from .baseinstrumentor import BaseInstrumentor

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    CsError,
)

from makeelf import elf, elfstruct


# typing-related types
from typing import BinaryIO, List, Tuple

################################################################################
# globals
################################################################################

log = logging.getLogger(__name__)


class TrampolineGenerator(object):
    def __init__(
        self,
        efelf: EFElf,
        trampoline_base_addr: int,
        patch_addr: List,
    ):
        self._efelf = efelf
        self._trampoline_base_addr = trampoline_base_addr
        self._passes: List[BaseInstrumentor] = list()
        self._patch_addrs = patch_addr

    def add_instrumentation_pass(self, instrumentation_pass: BaseInstrumentor) -> None:
        self._passes.append(instrumentation_pass)

    def trampolines2elf(self, trampoline_code: bytes, code_base_addr: int) -> bytes:
        """creates a new ELF file containing a `PT_LOAD` segment named
        `.trampolines` that contains the `trampoline_code`. Saves the ELF
        file to `path`. Returns the serialized ELF.
        """

        # Create new ELF file and set header size and flags
        new_elf = elf.ELF(
            e_class=elfstruct.ELFCLASS.ELFCLASS32,
            e_data=elfstruct.ELFDATA.ELFDATA2LSB,
            e_type=elfstruct.ET.ET_EXEC,
            e_machine=elfstruct.EM.EM_ARM,
        )

        new_elf.Elf.Ehdr.e_shentsize = 0x28
        new_elf.Elf.Ehdr.e_flags = 0x5000000

        sec_id = new_elf.append_section(".trampolines", trampoline_code, code_base_addr)
        trampoline_section = new_elf.get_section_by_name(".trampolines")[0]
        trampoline_section.sh_flags = (
            elfstruct.SHF.SHF_ALLOC | elfstruct.SHF.SHF_EXECINSTR
        )
        trampoline_section.sh_addralign = PAGESIZE

        # good stuff! calling `__bytes__()` will adjust the section offsets
        # this needs to happen before(!) we add the segment to have the correct
        # offsets available
        bytes(new_elf)
        segment_id: int = new_elf.append_segment(sec_id, code_base_addr)

        # adjust offsets yet again
        bytes(new_elf)

        # Make sure that our trampoline section is page aligned by padding the preceding shstrtab section
        trampoline_headers, trampoline_section = new_elf.get_section_by_name(
            ".trampolines"
        )
        strtab_headers, strtab_section = new_elf.get_section_by_name(".shstrtab")
        offset_rounded_up = trampoline_headers.sh_addralign * max(
            1, trampoline_headers.sh_offset / trampoline_headers.sh_addralign
        )
        diff = offset_rounded_up - trampoline_headers.sh_offset
        strtab_section.blob += bytes(diff)
        trampoline_headers.sh_offset = offset_rounded_up

        # Also adjust segment offset and alignment according to the padding
        new_elf.Elf.Phdr_table[segment_id].p_offset = trampoline_headers.sh_offset
        new_elf.Elf.Phdr_table[segment_id].p_align = trampoline_headers.sh_addralign

        return bytes(new_elf)

    @staticmethod
    def _emit_trampoline_section(trampolines: List[EFTrampoline]) -> bytes:
        content = b""
        for t in trampolines:
            content += t.code
        return content

    def _instrument_basic_blocks(
        self, trampolines: List[EFTrampoline], trampoline_text_start: int
    ):
        trampoline_off = trampoline_text_start
        for t in trampolines:
            self._efelf.patch_detour(t.call_off, trampoline_off)
            trampoline_off += t.size

    def instrument(self) -> Tuple[BytesIO, BytesIO]:
        # collect trampolines
        trampolines: List[EFTrampoline] = []
        trampoline_base_addr: int = self._trampoline_base_addr
        for bb in self._efelf.bbs:
            # TODO: refactor this monstrosity
            if (
                len(
                    list(
                        filter(
                            lambda patch_addr: (
                                (
                                    patch_addr[0]
                                    <= bb.bounds[0]
                                    < patch_addr[0] + patch_addr[1]
                                )
                                or (
                                    patch_addr[0]
                                    <= bb.bounds[1]
                                    < patch_addr[0] + patch_addr[1]
                                )
                            ),
                            self._patch_addrs,
                        )
                    )
                )
                != 0
            ):
                log.warning("HAL function overlaps with basic block, skip basic block")
                # Might hit too many bbs but we're rewriting on a best-effort basis anyways...
                continue

            instr: str = ""
            for instrumentation_pass in self._passes:
                instr += instrumentation_pass.get_instrumentation(
                    insn_num=len(bb.insns)
                )
            try:
                t = EFTrampoline(bb, instr, trampoline_base_addr)
                # self._trampoline_section_sz += t.size
                if t.size > 0:
                    # Only append if the trampoline actually contains code
                    trampolines.append(t)
                    trampoline_base_addr += t.size
            except EFTrampolineException as e:
                log.warn(e)

        # generate ELF for trampolines
        trampoline_section_content = self._emit_trampoline_section(trampolines)
        trampoline_raw_elf = self.trampolines2elf(
            trampoline_section_content, self._trampoline_base_addr
        )

        # patch trampoline call into basic blocks
        self._instrument_basic_blocks(trampolines, self._trampoline_base_addr)

        self._efelf.raw_elf.seek(0)
        return self._efelf.raw_elf, BytesIO(trampoline_raw_elf)
