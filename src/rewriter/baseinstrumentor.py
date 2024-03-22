import abc


class BaseInstrumentor(abc.ABC):
    """Abstract base class that any instrumentation pass should follow"""

    @staticmethod
    def imm32tohilo(val: int):
        """Split up a 32-bit value into its lower and higher 16 bits"""
        assert val >= 0 and val < 2**32, "imm32 out of range"
        lo = val & 0xFFFF
        hi = (val >> 16) & 0xFFFF
        return lo, hi

    @abc.abstractmethod
    def get_instrumentation(self, *args, **kwargs) -> str:
        """
        Method that returns the instrumentation code (as an assembly string) for
        the corresponding instrumentation pass
        """
        return ""
