#!/usr/bin/env python3
import ghidra
import sys
import yaml
from typing import Dict, List, Set

def get_bbs_dfs(funcs: List, monitor, block_model, visited: Set[int]) -> Set[int]:
    ret: Set[int] = set()
    for func in funcs:
        # Check whether function has already been visited
        addr: int = func.getEntryPoint().getOffset()
        if addr not in visited:
            visited.add(addr)
            print(f"#visited: {len(visited)}")
            # Add all BBs of the function to the set of BBs below the HAL
            block = block_model.getCodeBlocksContaining(func.getBody(), monitor) 
            while block.hasNext():
                bb = block.next()
                ret.add(bb.getMinAddress().getOffset())
            # Go down the graph
            ret |= get_bbs_dfs(func.getCalledFunctions(monitor), monitor, block_model, visited)
    return ret

if __name__ == "__main__":
    args = getScriptArgs()
    if len(args) != 1:
        # Did not receive symbol list with addresses
        exit(1)

    funcs = currentProgram.getFunctionManager().getFunctions(True)
    monitor = ghidra.util.task.ConsoleTaskMonitor()
    block_model = ghidra.program.model.block.BasicBlockModel(currentProgram)

    with open(args[0], "r") as f:
        hal_funcs: List[Dict[str, any]] = yaml.load(f, yaml.Loader)
        hal_func_addrs: List[int] = [addr for func in hal_funcs for addr in func["addr"]]

    # Filter functions for intercepted HAL functions
    funcs = filter(lambda x: x.getEntryPoint().getOffset() in hal_func_addrs, funcs)
    
    # Do the DFS
    visited: Set[int] = set()
    below_hal_bbs: Set[int] = get_bbs_dfs(funcs, monitor, block_model, visited)

    proj = state.getProject()
    proj_loc = proj.getProjectLocator().getLocation()
    out = f"{proj_loc}/{currentProgram.getName()}-hal-bbs.yaml"
    with open(out, "w") as f:
        yaml.dump({"bbs": sorted(below_hal_bbs)}, f)
