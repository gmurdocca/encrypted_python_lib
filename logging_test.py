#!/usr/bin/env python3
import jrjcrypt
import logging


logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

enc_module_name = "private.py.aes256"
password = "qwe123"


if __name__ == "__main__":

    with open(enc_module_name, "r") as enc:
        module_code = jrjcrypt.decrypt(enc.read(), password)
    private = jrjcrypt.import_code(module_code, "private")

    print(f"In the main module.")
    logger.info("this is an info-level log message from the main module.")
    logger.warning("this is an warning-level log message from the main module.")
    logger.critical("this is an critical-level log message from the main module.")
    print('*** calling go() in the private module')
    private.go()
    print('*** returned to the main module. Exiting.')
