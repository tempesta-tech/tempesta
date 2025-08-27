import logging

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


logger = logging.getLogger("ddos")
logger.propagate = True
handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s]: %(message)s")
)
logger.addHandler(handler)
