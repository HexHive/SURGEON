import logging
import yaml
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_ST_INFO_TYPE
from io import BytesIO
from typing import Dict, List, TextIO, BinaryIO

log = logging.getLogger(__name__)


class AutogenException(Exception):
    pass


def emit_hal_symbols(hal_funcs: List, out_file: TextIO) -> None:
    """
    Reads in HAL function locations from `hal_funcs` and generates C code
    in `out_file`. Check runtime/include/symbols.h for the data structure
    that is used for the generated code.
    """

    header: str = (
        "/*\n"
        " * Warning: This is an auto-generated source file.\n"
        " * Do not modify the file, it will be overwritten by the next\n"
        " * invocation of the compiler.\n"
        " */\n"
        "#include <surgeon/symbols.h>\n"
        "\n"
    )
    symbols: str = "const symbol_t symbols[] = {\n"
    func_ptrs: str = (
        "/* Function pointers to firmware functions\n"
        " * The function pointers are generic, cast them to the correct\n"
        " * arguments/return values before using them */\n"
    )

    symbol_num: int = 0
    try:
        for func in hal_funcs:
            handler = func.get("handler", None)
            name = func["name"]
            addrs = func["addr"]
            if handler is None:
                # Create a function pointer for functions that don't have a handler,
                # we might want to jump to them
                if len(addrs) > 1:
                    log.warn(
                        f"Multiple locations for function {name}, only generating a"
                        " function pointer to the first location"
                    )
                func_ptrs += (
                    f"generic_func_t _{name} = (generic_func_t){hex(addrs[0] | 0b1)};\n"
                )
            elif handler.startswith("native.") or handler.startswith("surgeon"):
                # No need to do anything about functions that have been replaced with our native counterparts
                continue
            elif handler.startswith("halucinator."):
                # Generate symbol mapping for dispatching to HALucinator handlers
                for addr in addrs:
                    c_symbol_t = (
                        f"{{.sym_addr = {hex(addr)}, "
                        + f'.sym_name = "{name}", '
                        + f'.handler = "{handler}"}},'
                    )
                    log.debug(c_symbol_t)
                    symbols += " " * 4 + c_symbol_t + "\n"
                    symbol_num += 1

    except KeyError as e:
        raise AutogenException(
            f"Incorrect yaml format: not a valid list of symbol to address mapping, error {e}"
        )

    if symbol_num == 0:
        # Prevent compiler errors for empty initializer
        c_symbol_t = '{.sym_addr = 0x00U, .sym_name = "", .handler = ""},'
        symbols += " " * 4 + c_symbol_t + "\n"
    symbols += "};\n\n" + f"const size_t symbol_num = {symbol_num};\n\n"

    out_file.write(header + symbols + func_ptrs)


def get_funcs(runtime: BinaryIO) -> Dict:
    """
    Creates a function name to function address mapping based on the requested
    functions in the runtime.
    """
    runtime_elf = ELFFile(runtime)

    # Get the symbol table
    symtab = runtime_elf.get_section_by_name(".symtab")
    assert symtab is not None

    # Create a dictionary of symbols
    func_dict = dict()
    for func in symtab.iter_symbols():
        if func.entry["st_info"]["type"] != "STT_FUNC":
            # Only get functions
            continue
        func_dict[func.name] = func.entry["st_value"]

    return func_dict


def emit_func_config(funcs: Dict, out_file: TextIO) -> None:
    """
    Emit a Yaml configuration file based on the function dictionary passed.
    """
    yaml.dump(funcs, out_file)
