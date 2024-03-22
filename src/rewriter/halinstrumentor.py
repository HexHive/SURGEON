import logging
from io import BytesIO
from elftools.elf.elffile import ELFFile

from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
from typing import BinaryIO, List, Dict, Any, Tuple

from .constants import BRANCH_MAXDIST

log = logging.getLogger(__name__)


class HALInstrumentorException(Exception):
    pass


class HALInstrumentor:
    def __init__(
        self,
        elf: BinaryIO,
        hal_funcs: List[Dict[str, Any]],
        branch_targets: Dict[str, int],
    ):
        self._elf = ELFFile(elf)
        elf.seek(0)
        self._rw_elf = BytesIO(elf.read())
        self._hal_funcs = hal_funcs
        self._branch_targets = branch_targets
        self._dispatcher_addr = branch_targets["dispatch_asm"]
        self._native_handlers = {
            "native.return_constant": self._gen_ret_constant,
            "native.skip": self._gen_skip,
            "native.nop": self._gen_nop,
            "native.detour": self._gen_detour,
        }

    def _encode(self, code: str = "", addr: int = 0) -> bytes:
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        encoding, _ = ks.asm(code.encode(), addr=addr)

        # debug generated asm and opcodes
        out = "%s = [ " % code
        for i in encoding:
            out += "%02x " % i
        out += "]"
        log.debug(out)

        return bytes(encoding)

    def _gen_ret_constant(self, addr: int, constant: int = 0, *args) -> bytes:
        """return a patch that returns a constant"""
        code = f"""
        mov r0, #{constant}
        bx lr
        """
        return self._encode(code)

    def _gen_skip(self, addr: int, *args) -> bytes:
        """return a patch that immediately returns"""
        code = f"""
        bx lr
        """
        return self._encode(code)

    def _gen_nop(self, addr: int, wide: bool = False, *args) -> bytes:
        """return a patch that just nops out an instruction"""
        code = f"""
        nop{'.w' if wide else ''}
        """
        return self._encode(code)

    def _gen_detour(self, source_addr: int, symbol: str, *args) -> bytes:
        """
        return a patch that branches to another symbol

        This detour requires the target function to accept the same type of
        parameters in the same order (registers).
        """
        # Find the correct symbol (in case there are multiple definitions, take the first)
        hal_func: Dict[str, Any] = next(
            filter(lambda x: x["name"] == symbol, self._hal_funcs)
        )
        # Get the symbol's address (first occurrence only)
        target_addr = hal_func["addr"][0]

        return self._gen_trampoline(source_addr=source_addr, target_addr=target_addr)

    def _gen_push_pc(self, *args) -> bytes:
        """return a patch that pushes the current PC onto the stack"""
        # move pc into r12 first because Arm Thumb does not permit pushing the pc
        code = f"""
            mov  r12, pc
            push.n {{r12}}
            """
        return self._encode(code)

    def _gen_trampoline(self, source_addr: int, target_addr: int, *args) -> bytes:
        """return a trampoline that jumps to `target_addr`."""

        code = ""
        # Check whether a simple branch works or whether we need to insert a literal pool
        if abs(target_addr - source_addr) < BRANCH_MAXDIST:
            # Target is in reach for a simple branch
            code += f"""
            b #{target_addr:#x}
            """
        else:
            # Target is out of reach for a branch => take address from literal pool
            code += f"""
            ldr.w pc, ={target_addr:#x}
            """
        return self._encode(code, addr=source_addr)

    def gen_patches(
        self, hal_func: Dict[str, Any], text_start: int, text_end: int
    ) -> Tuple[int, bytes]:
        symbol = hal_func["name"]
        addresses = hal_func["addr"]
        handler = hal_func.get("handler", None)
        args = hal_func.get("native_args", list())
        log.debug(f"Rewriting {symbol}@{[hex(addr) for addr in addresses]}")

        for addr in addresses:
            if addr < text_start or addr >= text_end:
                raise HALInstrumentorException("HAL function outside of .text section.")

            if handler is None:
                # A symbol that we only keep around for its address but that we do not actually want to handle
                continue
            elif handler.startswith("native"):
                if handler in self._native_handlers:
                    # Generate native handlers for certain trivial handlers
                    patch_func = self._native_handlers[handler]
                    patch = patch_func(addr, *args)
                else:
                    raise HALInstrumentorException(
                        f"Native handler '{handler}' does not exist"
                    )
            elif handler.startswith("halucinator"):
                # Generate a trampoline for entering our HAL function dispatcher
                patch = self._gen_push_pc()
                patch += self._gen_trampoline(addr + len(patch), self._dispatcher_addr)
            elif handler.startswith("surgeon"):
                func: str = handler.split(".")[-1]
                patch = self._gen_trampoline(addr, self._branch_targets[func])
            else:
                raise HALInstrumentorException(
                    "Unsupported handler type: only supporting 'native', 'surgeon', "
                    "'halucinator' handlers"
                )

            if addr + len(patch) >= text_end:
                raise HALInstrumentorException(
                    "HAL function patch exceeds .text section"
                )
            # Use the function as an iterator
            yield addr, patch

    def instrument(self) -> Tuple[BinaryIO, List]:
        section = self._elf.get_section_by_name(".text")
        start = section["sh_addr"]
        offset = section["sh_offset"]
        end = start + section["sh_size"]
        assert start < end, "sections start after end"

        log.debug(f".text:\t{start:#x} - {end:#x}")

        patch_addrs = list()
        for func in self._hal_funcs or list():
            for addr, patch in self.gen_patches(func, start, end):
                patch_addrs.append((addr, len(patch)))
                self._rw_elf.seek(offset + (addr - start))
                self._rw_elf.write(patch)

        self._rw_elf.seek(0)
        return self._rw_elf, patch_addrs
