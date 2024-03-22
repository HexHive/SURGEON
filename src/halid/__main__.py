import logging
import argparse
import yaml
from . import halid

FORMAT = (
    "%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s"
)
log = logging.getLogger(__name__)


def main():

    logging.basicConfig(
        format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG
    )

    arg_parser = setup_args()
    args = arg_parser.parse_args()

    if args.elf:
        print(yaml.dump(halid.identify_hal(args.elf), default_flow_style=False))


def setup_args():
    """Returns an initialized argument parser."""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-e",
        "--elf",
        required=True,
        help="Path to ELF file with HAL function symbols.",
    )
    return parser


if __name__ == "__main__":
    main()
