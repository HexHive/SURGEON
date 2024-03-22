import subprocess

# typing-related types
from typing import List, Dict


def identify_hal(elf_path: str) -> List[Dict]:

    p = subprocess.run(["arm-none-eabi-nm", elf_path], stdout=subprocess.PIPE)

    hal_funcs: Dict[Dict] = {}
    for line in p.stdout.decode().split("\n"):

        if not line:
            continue

        addr_s: str
        sym_type: str
        sym: str

        addr_s, sym_type, sym = line.split(" ")[:3]

        # We are only interested in symbols in the `.text` section
        if sym_type not in ["T", "t"]:
            continue

        addr: int = int(addr_s, 16)

        # Add heuristics to identify HAL funtions here
        if "HAL" in sym:
            if sym not in hal_funcs:
                # Create new entry
                d = {
                    "name": sym,
                    "addr": [
                        addr,
                    ],
                    "handler": "handler-example.MainWrapper.kill",
                }
                hal_funcs[sym] = d
                continue
            else:
                # Append address to existing entry
                d = hal_funcs[sym]
                d["addr"].append(addr)
                continue

    return list(hal_funcs.values())
