import argparse
import logging
from crytic_compile import cryticparser
from falcon import Falcon

logging.basicConfig()
logging.getLogger("Falcon").setLevel(logging.INFO)

logger = logging.getLogger("Falcon-demo")


def parse_args():
    """
    Parse the underlying arguments for the program.
    :return: Returns the arguments for the program.
    """
    parser = argparse.ArgumentParser(description="Demo", usage="falcon-demo filename")

    parser.add_argument(
        "filename", help="The filename of the contract or truffle directory to analyze."
    )

    # Add default arguments from crytic-compile
    cryticparser.init(parser)

    return parser.parse_args()


def main():
    args = parse_args()

    # Perform falcon analysis on the given filename
    _falcon = Falcon(args.filename, **vars(args))

    logger.info("Analysis done!")


if __name__ == "__main__":
    main()
