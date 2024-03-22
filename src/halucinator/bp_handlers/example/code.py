import logging

log = logging.getLogger(__name__)


class Example:
    def __init__(self, *args, **kwargs):
        self._x = 0
        pass

    def wrap(self, target, addr: int) -> bool:
        self._x += 1
        log.info(f"Called wrap on the object the {self._x}. time")
        return self.example(target, addr)

    def example(self, target, addr: int) -> bool:
        # Read and write memory -- here: do not corrupt the stack, write what we've read
        mem = target.read_memory(target.read_register("sp"), 4, 1)
        success = target.write_memory(target.sp, 4, mem)
        log.debug(
            f"Example handler entered successfully at addr {hex(addr)}\n"
            + f"lr = {target.lr}\n"
            + f"Successfully read and wrote {hex(mem)} from/to {target.sp}\n"
            + f"Argument to the function was: {hex(target.get_arg(0))}"
        )
        return True

    def kill(self, target, addr: int) -> None:
        exit(0)

    def hello_world(self, target, addr: int) -> bool:
        log.info("Hello SURGEON!")
        return True
