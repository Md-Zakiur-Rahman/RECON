import logging


def setup_logger(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO

    logger = logging.getLogger("recon")
    logger.handlers.clear()
    logger.setLevel(level)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)

    return logger
