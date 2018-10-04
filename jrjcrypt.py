#!/usr/bin/env python3
# requires: pycryptodome

from Crypto.Cipher import AES
from Crypto import Random
import argparse
import getpass
import hashlib
import base64
import sys
import os


SUFFIX="aes256"
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)      # noqa: E731
unpad = lambda s: s[:-ord(s[len(s) - 1:])]                                                          # noqa: E731


def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw).encode("utf8")
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


def example():
    """
    Example implementation
    """
    ##############################
    #        Secret Area         #

    # This password would be chosen by Modelling team,
    # and stored in a place were only the deployed AWS Lambda function can read it
    password = "supersecret"

    # Modelling team would define this python module.
    secret_module = """
    def secret_function(data):
        return data.upper()
    """

    # Modelling team would execute the below,
    # write the output of the encrypt() function to a file and provide us with the file.
    encrypted_secret_module = encrypt(secret_module, password)

    #      End Secret Area       #
    ##############################


    # We would obtain the below password at run time, when this script is run within AWS Lambda
    password = "supersecret"

    # We'd read in the file containing the cyphertext and store in secret_lib_data,
    # but here we just re-use encrypted_secret_function from above
    cyphertext = encrypted_secret_module
    with open("tests/test_cipher.py.aes256", 'w') as w:
        w.write(cyphertext.decode("utf-8"))

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


def get_password():
    while True:
        pass1 = getpass.getpass("Enter encryption password: ")
        pass2 = getpass.getpass("Verify encryption password: ")
        if pass1 == pass2:
            break
        print("Passwords do not match, please try again.")
    return pass1


def argparser():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
            '--envkey',
            metavar="environment_variable_name",
            type=str,
            help="Name of environment variable containing encryption password. Omitting will invoke password input prompt."
            )
    parser.add_argument(
            'file_to_encrypt',
            help="Python module or any other file to encrypt (aes256-cbc).",
            nargs='+',
            )
    return parser

def bail(parser, msg, rc=1):
    print(msg)
    parser.print_usage()
    sys.exit(rc)




if __name__ == "__main__":
    p = argparser()
    args = p.parse_args()
    files = args.file_to_encrypt
    for f in files:
        if not os.path.isfile(f):
            bail(p, f"Error: file {f} does not exist.")
    print(f"Encrypting files: {','.join(files)}")
    if not args.envkey:
        password = get_password()
    else:
        password = os.environ.get(args.envkey, None)
        if args.envkey not in os.environ:
            bail(p, f"Error: Environment variable {args.envkey} does not exist.")
        elif not password:
            bail(p, f"Error: Environment variable {args.envkey} contains empty value.")
    for f in files:
        with open(f) as src_file:
            encfile = f"{f}.{SUFFIX}"
            with open(encfile, "wb") as ef:
                ef.write(encrypt(src_file.read(), password))
    print(f"Done, wrote files:", ','.join([f"{f}.{SUFFIX}" for f in files]))



