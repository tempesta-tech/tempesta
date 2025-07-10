import logging


logger = logging.getLogger()
logger.propagate = True
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s]: %(message)s'))
logger.addHandler(handler)
