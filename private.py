import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.getLogger().setLevel(logging.INFO)


def go():
    print(f"In the private module.")
    logger.info("this is an info-level log message from the private module.")
    logger.warning("this is an warning-level log message from the private module.")
    logger.critical("this is an critical-level log message from the private module.")
