import sys
import ghidra
import yaml


def get_bbs(funcs, blockModel, monitor, deny_list=None):
    """Returns a set of `func`'s bbs."""
    bbs = set()

    func_blocks = [
        (func, blockModel.getCodeBlocksContaining(func.getBody(), monitor))
        for func in funcs
    ]

    for func, block in func_blocks:
        # add the entrypoint
        ep = func.getEntryPoint().getOffset()
        if deny_list and ep in deny_list:
            print(f"Deny func@{ep:#x}")
            continue

        while block.hasNext():
            bb = block.next()
            bbs.add(
                (bb.getMinAddress().getOffset(), bb.getMaxAddress().getOffset())
            )
    return bbs


def main(deny_list_path=None):

    # if deny_list_path:
        # with open(deny_list_path, "r") as f:
        #     deny_list = yaml.load(f, Loader=yaml.Loader)

        # if deny_list:
        #     deny_list = [d["addr"] for d in deny_list]
        # else:
        # deny_list = None

    # currentProgram.setImageBase(toAddr(0), False)
    # ghidra.program.model.data.DataUtilities.isUndefinedData(
    #     currentProgram, currentAddress
    # )
    funcs = currentProgram.getFunctionManager().getFunctions(True)
    monitor = ghidra.util.task.ConsoleTaskMonitor()
    blockModel = ghidra.program.model.block.SimpleBlockModel(currentProgram)

    # bbs = get_bbs(funcs, blockModel, monitor, deny_list)
    bbs = get_bbs(funcs, blockModel, monitor)
    bbs = list(bbs)

    print(f"{currentProgram.getName()} #basic blocks: {len(bbs)}")
    proj = state.getProject()
    proj_loc = proj.getProjectLocator().getLocation()
    fout = f"{proj_loc}/{currentProgram.getName()}-cov-bbs.yaml"
    with open(fout, "w") as f:
        yaml.dump({"bbs": bbs}, f)
    print(f"Output file: {fout}")


if __name__ == "__main__":
    args = getScriptArgs()
    if len(args) > 0:
        deny_list_path = args[0]
        print(deny_list_path)
    else:
        deny_list_path = None

    main(deny_list_path)
