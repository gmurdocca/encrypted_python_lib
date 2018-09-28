#!/usr/bin/env python3

# requires: pycrypto (pip install pycrypto)

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


def import_code(code, name, add_to_sys_modules=0):
    """
    Obtained from: https://www.oreilly.com/library/view/python-cookbook/0596001673/ch15s03.html
    """
    import imp
    module = imp.new_module(name)
    if add_to_sys_modules:
        import sys
        sys.modules[name] = module
    exec(code, module.__dict__)
    return module


#########################
###### Secret Area ######

# This password would be chosen by Modelling team, and stored in a place were only the deployed AWS Lambda function can read it
password = "supersecret"

# Modelling team would define this python module.
secret_module = """
def secret_function(data):
    return data.upper()
"""

# Modelling team would execute the below, write the output of the encrypt() function to a file and provide us with the file.
encrypted_secret_module = encrypt(secret_module, password)

###### End Secret Area) ######
##############################


if __name__ == "__main__":

    # We would obtain the below password at run time, when this script is run within AWS Lambda
    password = "supersecret"
    
    # We'd read in the file containing the cyphertext and store in secret_lib_data, but here we just re-use encrypted_secret_function from above
    cyphertext = encrypted_secret_module

    print(f"Cyphertext contents of secret module source code is:\n\n{cyphertext}\n")

    # Decrypt the module source code using our password
    module_source = decrypt(cyphertext, password)

    print(f"Contents of decrypted secret module source code is:\n {bytes.decode(module_source)}")

    print("Importing the module...", end='')
    secret_module = import_code(module_source, "secret_module")
    print("Done")

    print(f"Running function within module, \"secret_module.secret_function('test')\". Output is:")
    result = secret_module.secret_function("test")
    print(result)



