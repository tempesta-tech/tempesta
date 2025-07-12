import logging

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


logger = logging.getLogger()
logger.propagate = True
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
handler.setFormatter(
    logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s]: %(message)s")
)
logger.addHandler(handler)
