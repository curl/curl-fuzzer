"""Common logging functionality."""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO


def common_logging(name: str, filename: str, stream: TextIO = sys.stdout) -> None:
    """Set up common logging."""
    if name == "__main__":
        log_filename = Path(filename).with_suffix("").name
    else:
        log_filename = name

    formatter = logging.Formatter("%(asctime)s %(levelname)-5.5s %(message)s")

    log_path = Path(log_filename)

    # Get the current time as a timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    rootdir = Path(__file__).parent.parent.parent
    logsdir = rootdir / "logs"
    logsdir.mkdir(exist_ok=True)

    logspath = logsdir / f"{log_path.name}_{timestamp}.log"
    filehandler = logging.FileHandler(logspath)
    filehandler.setFormatter(formatter)
    filehandler.setLevel(logging.DEBUG)

    errfilehandler = logging.FileHandler(
        logsdir / f"{log_path.name}_{timestamp}_errors.log"
    )
    errfilehandler.setFormatter(formatter)
    errfilehandler.setLevel(logging.ERROR)

    streamhandler = logging.StreamHandler(stream)
    streamhandler.setFormatter(formatter)
    streamhandler.setLevel(logging.INFO)

    root_logger = logging.getLogger()
    root_logger.addHandler(filehandler)
    root_logger.addHandler(errfilehandler)
    root_logger.addHandler(streamhandler)
    root_logger.setLevel(logging.DEBUG)

    root_logger.info("Logging to %s", logspath)
