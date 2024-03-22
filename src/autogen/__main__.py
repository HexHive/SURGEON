import argparse
import logging
import yaml
from . import autogen


FORMAT = "%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"
log = logging.getLogger(__name__)


def fail(msg: str):
    """Log a fatal error and exit with an error code."""
    log.critical(msg)
    exit(1)


def main():

    logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG)

    arg_parser = setup_args()
    args = arg_parser.parse_args()

    if args.hal_func_config and args.runtime:
        fail(
            "Can only either generate C code from a Yaml configuration file or a "
            "Yaml configuration file from the runtime ELF, not both at the same time."
        )

    if args.hal_func_config:
        hal_funcs = yaml.load(args.hal_func_config, Loader=yaml.Loader) or list()
        autogen.emit_hal_symbols(hal_funcs, args.out_file)
    elif args.runtime:
        funcs = autogen.get_funcs(args.runtime)
        autogen.emit_func_config(funcs, args.out_file)
    else:
        fail("Neither configuration file nor runtime provided, cannot generate code")


def setup_args():
    """Returns an initialized argument parser."""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c",
        "--hal_func_config",
        type=argparse.FileType("r"),
        required=False,
        help="Yaml file with HAL functions.",
    )

    parser.add_argument(
        "-l",
        "--runtime",
        type=argparse.FileType("rb"),
        required=False,
        help="Runtime ELF file with functions for which we want to find the address.",
    )

    parser.add_argument(
        "-o",
        "--out_file",
        type=argparse.FileType("w"),
        required=True,
        help="Output C file with symbol list or Yaml file with the function addresses, depending on input.",
    )

    return parser


if __name__ == "__main__":
    main()
