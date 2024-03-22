import argparse
import logging
import yaml
import os
from io import BytesIO
from collections import defaultdict
from itertools import chain


from .efelf import EFElf
from .halinstrumentor import HALInstrumentor
from .covinstrumentor import CovInstrumentor
from .timerinstrumentor import TimerInstrumentor
from .transplantationinstrumentor import TransInstrumentor
from .trampolinegenerator import TrampolineGenerator

# typing-related types
from typing import List, Tuple, Dict


FORMAT = "%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"
log = logging.getLogger(__name__)


def fail(msg: str) -> None:
    """
    Log a critical error message and quit with error code.
    """
    log.critical(msg)
    exit(1)


def main():

    logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG)

    arg_parser = setup_args()
    args = arg_parser.parse_args()

    elf = BytesIO(args.fw_elf.read())

    # Branch targets used for HAL instrumentation
    branch_targets: Dict = yaml.load(args.branches, Loader=yaml.Loader) or dict()
    # Rewritten HAL funcs
    hal_funcs: Dict = dict()
    # List of patch address-length tuples
    patch_addrs: List = list()

    if args.symbols:
        # Get the patches for the HAL funcs to exclude them from trampoline insertion
        hal_funcs = yaml.load(args.symbols, Loader=yaml.Loader)

        hal_inst = HALInstrumentor(elf, hal_funcs, branch_targets)
        _, patch_addrs = hal_inst.instrument()
        # TODO: refactor passes -- this is done again further down becasue we
        # need patch sizes first and do the actual patching later

    if args.transplant:
        """The format of this file is a dict with the single key `bbs`.
        The value is a `List[Tuple(int, int)]`. The integers are the start and
        end addresses of basic blocks.

        Example:

        bbs:
        - !!python/tuple
            - 424
            - 443
        - ...

        """
        bb_yaml: Dict[List] = yaml.load(
            args.transplant, Loader=yaml.Loader
        ) or defaultdict(list)
        bbs: List[Tuple[int, int]] = bb_yaml["bbs"]

        efelf = EFElf(elf, bbs)
        trans_inst = TransInstrumentor(efelf)
        elf = trans_inst.instrument()

    if args.coverage or args.emultimer:
        if not args.instrument:
            fail(
                "Instrumentation requested but no configuration file for the trampolines provided."
            )

        # Load configuration for trampoline-based instrumentation
        tramp_cfg = yaml.load(args.instrument, Loader=yaml.Loader)
        trampoline_base_addr = tramp_cfg["trampoline_base_addr"]

        # Load basic blocks to instrument
        bbs_path = os.path.join(
            os.path.dirname(args.instrument.name), tramp_cfg["bbs_file"]
        )
        with open(bbs_path, "r") as f:
            bb_yaml: Dict[List] = yaml.load(f, Loader=yaml.Loader) or defaultdict(list)
            bbs: List[Tuple[int, int]] = bb_yaml["bbs"]

        efelf = EFElf(elf, bbs)
        trampoline_gen = TrampolineGenerator(
            efelf,
            trampoline_base_addr,
            patch_addrs,
        )

        if args.coverage:
            instr_ctrl_addr = os.getenv("INSTR_CTRL_ADDR")
            if instr_ctrl_addr is None:
                fail(
                    "Environment variable 'INSTR_CTRL_ADDR' not found, cannot add coverage instrumentation"
                )
            # Convert to integer (base 0 means autodetection)
            instr_ctrl_addr = int(instr_ctrl_addr, base=0)
            shm_addr = os.getenv("SHM_ADDR")
            if shm_addr is None:
                fail(
                    "Environment variable 'SHM_ADDR' not found, cannot add coverage instrumentation"
                )
            # Convert to integer (base 0 means autodetection)
            shm_addr = int(shm_addr, base=0)

            cov_inst = CovInstrumentor(instr_ctrl_addr, shm_addr)
            trampoline_gen.add_instrumentation_pass(cov_inst)

        if args.emultimer:
            timer_handler_addr = branch_targets["emulate_timer"]
            timer_inst = TimerInstrumentor(timer_handler_addr)
            trampoline_gen.add_instrumentation_pass(timer_inst)

        elf, trampoline = trampoline_gen.instrument()
        trampoline_path = f"{args.rewritten_fw_elf.name}-tramp"

        # write trampoline to disk
        with open(trampoline_path, "wb") as f:
            f.write(trampoline.read())

    if args.symbols:
        # Replace HAL functions with their corresponding handlers
        hal_inst = HALInstrumentor(elf, hal_funcs, branch_targets)
        elf, _ = hal_inst.instrument()
        # TODO: refactor -- see first occurence of this snippet

    args.rewritten_fw_elf.write(elf.read())

    return


def setup_args():
    """Returns an initialized argument parser."""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-t",
        "--transplant",
        type=argparse.FileType("r"),
        metavar="transplant-bbs.yaml",
        help="Apply transplantation for basic blocks given (YAML configuration file).",
    )

    parser.add_argument(
        "-i",
        "--instrument",
        type=argparse.FileType("r"),
        metavar="tramp-cfg.yaml",
        help="Configuration file for trampoline-based instrumentation in YAML format"
        " (pre-requisite for coverage instrumentation and timer emulation).",
    )

    parser.add_argument(
        "-c",
        "--coverage",
        action=argparse.BooleanOptionalAction,
        help="Apply coverage instrumentation based on the trampoline configuration.",
    )

    parser.add_argument(
        "-e",
        "--emultimer",
        action=argparse.BooleanOptionalAction,
        help="Apply timer emulation instrumentation based on the trampoline configuration.",
    )

    parser.add_argument(
        "-s",
        "--symbols",
        type=argparse.FileType("r"),
        metavar="hal-syms.yaml",
        help="Configuration file for the HAL instrumentation in YAML"
        " format. Contains list of symbols and their handlers.",
    )

    parser.add_argument(
        "-b",
        "--branches",
        type=argparse.FileType("r"),
        metavar="func-autogen.yaml",
        help="Configuration file with function addresses for instrumentation"
        " branch targets in YAML format (autogenerated at runtime build time).",
    )

    parser.add_argument(
        "fw_elf",
        type=argparse.FileType("rb"),
        help="FW ELF to be instrumented.",
    )

    parser.add_argument(
        "rewritten_fw_elf",
        type=argparse.FileType("wb"),
        help="Rewritten FW ELF. If the instrumentation requires additional"
        " code, an additional ELF file `<rewritten_fw_elf_name>-tramp` will be"
        " generated and stored next to the `rewritten_fw_elf`.",
    )

    return parser


if __name__ == "__main__":
    main()
