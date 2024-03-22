import logging
import argparse
import re
import json
from collections import Counter

FORMAT = (
    "%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s"
)
log = logging.getLogger(__name__)


def parse_trace(trace_path: str) -> Counter:
    """Parses a QEMU trace log file and collects program counter (R15) values.

    Args:
        trace_path (str): Path to the log file

    Returns:
        Counter: Counter collection of program counters
    """

    with open(trace_path, "r") as f:
        trace_text = f.read()
    matches = re.findall("R15=([0-9a-f]{8})", trace_text)
    # counter = Counter([int(match, 16) for match in matches])
    counter = Counter(matches)

    return counter


def main():

    logging.basicConfig(
        format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG
    )

    arg_parser = setup_args()
    args = arg_parser.parse_args()

    if args.trace:
        counter = parse_trace(args.trace)
        # convert counter to dict and store in json file
        out_path = f"{args.trace}.cov"
        with open(out_path, "w") as f:
            json.dump(dict(counter), f)
        print(f"Pls find coverage in {out_path}")


def setup_args():
    """Returns an initialized argument parser."""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-t",
        "--trace",
        required=True,
        help="Path to QEMU logfile containing traces.",
    )
    return parser


if __name__ == "__main__":
    main()
