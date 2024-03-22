#@category ARM
#@keybinding
#@menupath
#@toolbar

# for code snippets visit https://github.com/HackOvert/GhidraSnippets
import re
import statistics
import json

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.decompiler import DecompInterface
from java.awt import Color


# helper function to get a Ghidra Address type
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def colorize_blocks(all_bbs):
    # count number of basic blocks hit
    hit_bbs = {}

    import_path = askFile("Import coverage file", "Choose File")
    if not import_path:
        print("No target path specified... quitting")
    else:
        service = state.getTool().getService(ColorizingService)

        start_addrs = set()
        print(f"len(all_bbs): {len(all_bbs)}")
        max_hits = 0

        with open(import_path.getAbsolutePath(), "r") as f:
            cov_counters = json.load(f)

        for addr, count in cov_counters.items():
            # get trace info as array
            try:
                # basic block start address
                start_addr = int(addr, 16)

                # is the address actually the start of a bb?
                if start_addr in all_bbs.keys():
                    bb = all_bbs[start_addr]
                    start = bb.getMinAddress().getOffset()
                    # getMaxAddress() points to the last byte of the last insn of this bb
                    end = bb.getMaxAddress().getOffset() + 1
                    size = end - start

                    hit_bbs[start_addr] = { "hits": count, "size": size }
                    if hit_bbs[start_addr]["hits"] > max_hits:
                        max_hits = hit_bbs[start_addr]["hits"]
            except ValueError:
                # sometimes there might be problems with log buffering
                # then more than one trace info can be in a line
                # should rarely happen just skip
                pass


        hit_counts = []
        for start, hit_bb in hit_bbs.items():
            hit_counts.append(hit_bb["hits"])

        median_hit_counts = statistics.median(hit_counts)

        for start, hit_bb in hit_bbs.items():
            print(hit_bb)

            # bb = hit_bb["bb"]
            start = toAddr(start) #bb.getStart()
            # end = bb.getStop()

            # basic block size
            # size = end.getOffset() - start.getOffset()
            size = hit_bb["size"]

            # get color of basic block
            c = service.getBackgroundColor(start)


            if hit_bb["hits"] > median_hit_counts:
                intensity = 1
            else:
                intensity = (hit_bb["hits"] / max_hits)

            # red gradient
            # 255, 234, 230
            # 255, 64, 25
            r = 255

            g_scale = int((234 - 64) * intensity)
            g = 234 - g_scale

            b_scale = int((234 - 64) * intensity)
            b = 234 - b_scale

            c_new = Color(r, g, b)
            service.setBackgroundColor(start, start.add(size - 1), c_new)

    return


if __name__ == '__main__':
    bbm = BasicBlockModel(currentProgram)
    blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)
    block = blocks.next()

    all_bbs = {}
    while block:
        # print("Label: {}".format(block.getName()))
        # print("Min Address: {}".format(block.getMinAddress()))
        # print("Max address: {}".format(block.getMaxAddress()))
        # print()
        all_bbs[block.getMinAddress().getOffset()] = block
        block = blocks.next()

    # color bbs
    colorize_blocks(all_bbs)
