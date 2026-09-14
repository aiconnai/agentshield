"""Main entrypoint for python -m agentshield invocation."""

import sys
import subprocess
from . import find_agentshield_bin


def main() -> None:
    bin_path = find_agentshield_bin()
    args = [bin_path] + sys.argv[1:]
    try:
        result = subprocess.run(args)
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
