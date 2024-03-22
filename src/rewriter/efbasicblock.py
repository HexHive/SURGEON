# typing-related types
from typing import List, Tuple

from rewriter.efinstruction import EFInstruction


class EFBasicBlock:
    def __init__(self, start: int, end: int, insns: List[EFInstruction]):
        self._start = start
        self._end = end
        self._insns = insns

    @property
    def insns(self) -> List[EFInstruction]:
        return self._insns

    @property
    def bounds(self) -> Tuple[int, int]:
        return (self._start, self._end)

    def off2idx(self, off: int) -> int:
        """returns the index into `self._insns` of raw offset `off`"""
        if off == 0:
            return 0

        idx = 0
        tmpoff = 0
        for insn in self._insns:
            tmpoff += insn.size
            idx += 1
            if tmpoff == off:
                return idx

        raise Exception("Offset out of bounds.")

    def __str__(self) -> str:
        out = ""
        for insn in self._insns:
            out += f"{insn.address:#x}:\t{insn.mnemonic}\t{insn.op_str}\n"
        return out
