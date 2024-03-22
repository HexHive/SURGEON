import logging
from .efbasicblock import EFBasicBlock
from . import EF_DISASM, EF_ASM
from capstone import CsError
from keystone.keystone import KsError


log = logging.getLogger(__name__)


class EFTrampolineException(Exception):
    pass


class EFTrampoline:
    # sz of the trampoline call at the instrumentation point
    CALL_SZ = 4
    PROLOGUE = """
    # save context
    push {r0, r1, r2, r3, ip, lr}
    # save application program state (e.g., flags used for comparisons)
    mrs r0, apsr
    push {r0}
    """
    EPILOGUE = """
    # restore application program state (e.g., flags used for comparisons)
    pop {r0}
    msr apsr, r0
    # restore context
    pop {r0, r1, r2, r3, ip, lr}
    """

    def __init__(self, bb: EFBasicBlock, instr: str, base_addr: int):
        self._bb = bb
        self._instr = instr
        # call_off is initialized to -1 here but is actually updated once the trampoline is generated
        self._trampoline_call_off = -1
        self._base_addr = base_addr
        # generate the trampoline code for this basic block (`self._bb`)
        self._trampoline_code = self._create_trampoline()

    @property
    def size(self) -> int:
        return len(self._trampoline_code)

    @property
    def code(self) -> bytes:
        return self._trampoline_code

    @property
    def call_off(self) -> int:
        return self._bb._start + self._trampoline_call_off

    def __str__(self) -> str:
        if not self._trampoline_code:
            out = "No trampoline code"
            return out

        out = ""
        try:
            for insn in EF_DISASM.disasm(self._trampoline_code, 0x0):
                out += f"{insn.address:#x}:\t{insn.mnemonic}\t{insn.op_str}\n"
        except CsError as e:
            log.error(f"error: {e}")
        return out

    def _create_trampoline(self) -> bytes:
        # Assembly for the trampoline: prologue, instrumentation, epilogue
        trampoline_asm = self.PROLOGUE + self._instr + self.EPILOGUE
        try:
            # Step 1: Assemble the trampoline code
            encoding, _ = EF_ASM.asm(trampoline_asm.encode())
            trampoline_code = bytes(encoding)
            log.debug(
                f"Base addr: {self._base_addr:#x}, trampoline size: {len(trampoline_code):#x}"
            )

            # Step 2: Identify instructions to relocate into the trampoline and where
            # to insert the branch in the original basic block
            off = 0
            sz = 0
            skip_ninsns = 0
            reloc_code = b""
            for insn in self._bb.insns:
                off += insn.size
                if skip_ninsns > 0:
                    skip_ninsns -= 1
                    continue
                if insn.is_it():
                    # If `insn` is if-then block, we reset `sz`
                    sz = 0
                    reloc_code = b""
                    # `skip_ninsns` will skip the following `n` insns
                    skip_ninsns = insn.it_block_len()
                    # This continue skips the it insn itself
                    continue
                # Check whether the instruction can be relocated into the current code location
                if not insn.is_relocatable(
                    self._base_addr + len(trampoline_code) + len(reloc_code)
                ):
                    # If `insn` is position dependent and cannot be moved into the trampoline, we reset `sz`
                    sz = 0
                    reloc_code = b""
                else:
                    # Otherwise we increase `sz` by the size of `insn`
                    sz += insn.size
                    reloc_code += insn.relocated_bytes
                # If we have enough space to fit the trampoline, we set the offset into
                # the basic block where the branch into the trampoline can be placed
                if sz >= self.CALL_SZ:
                    self._trampoline_call_off = off - sz
                    break

            if self._trampoline_call_off == -1:
                if len(self._bb.insns) < 1:
                    import ipdb
                    ipdb.set_trace()
                raise EFTrampolineException(
                    f"Basic block @{self._bb.insns[0].address:#x} "
                    "cannot fit call to trampoline."
                )

            trampoline_ret = self._bb._start + self._trampoline_call_off + sz

            while len(trampoline_code + reloc_code) % 4 != 0:
                # Not a multiple of 4 bytes => messes up alignment for literal
                # pools in the trampoline
                # TODO: relocate more/less instructions instead of adding nops
                encoding, _ = EF_ASM.asm(b"nop")
                assert len(encoding) == 2
                reloc_code += bytes(encoding)

            # Step 3: Return from trampoline to instrumented basic block
            # TODO: we don't need this if reloc insns contain pc modifying instructions
            log.debug(f"Trampoline should return to {trampoline_ret:#x}")
            # Load the return address from a literal pool -- otherwise we mess up registers
            ret_branch = f"ldr.w pc, ={trampoline_ret | 0b1:#x}"
            encoding, _ = EF_ASM.asm(ret_branch.encode())
            ret_branch_code = bytes(encoding)

            # Finally, return the concatenated instrumentation, relocated instructions, and the return
            return trampoline_code + reloc_code + ret_branch_code
        except KsError as e:
            log.error(e)
            import ipdb
            ipdb.set_trace()
            raise EFTrampolineException("Trampoline could not be assembled")
