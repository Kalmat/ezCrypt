#!/usr/bin/python3
# -*- coding: utf-8 -*-

__version__ = "1.0.0"

"""
********* CRYPTO TOOL by alef ********* 
This is a very simple tool to cipher/decipher any file or message of your choice, using a password you will provide.
Based on: https://nitratine.net/blog/post/encryption-and-decryption-in-python/ (@brentvollebregt)
     and: https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
     (I replaced salt random number method, which has to be stored, by a fully password-based method, using a hash)

USAGE: 'python3 crypto.py -h'

Basically, it:
- Asks for a password (which will never be stored)
- Obtains a hash from the password (SHA-256)
- Adds a random timestamp number to the data to be encrypted (same data will never produce same result)
- Uses the hash as a key to encrypt/decrypt data (using Fernet)
- Removes random number from decrypted data (original data remains unaltered)
- Returns encrypted/decrypted data on console, file or QR
- Optionally, it may generate a key from a password, but it will not store or manage keys in any safe way 

SUGGESTION: If you intend to compress the file, first compress it, then cipher it (will reduce size and time)
WARNING: Will only work running it from command-line
WARNING: Fernet is ideal for encrypting data that easily fits in memory, so I developed a "chunky" method for files!!!
SUPERWARNING: Do not interchange or store keys. Just interchange passwords, by a secure method (e.g. mouth-to-ear)
SUPERWARNING: Not sure how secure it is!!! Do not use it to cipher, let's say, your more precious secrets...

UPDATE: Recently discovered 'gpg' command (native on Ubuntu) which is able to do a lot more (and better, I guess)
        Encrypt: gpg --symmetric --cipher-algo AES256 input_file
        Decrypt: gpg -d input_file.gpg -o output_file 
... nevertheless, it does not use QRs in any way, and it's a "little bit" more complex to use and adapt to your needs!  
"""

import base64
import os
import sys
from pathlib import Path, PurePath
import datetime as dt
import traceback
import getpass
import cryptography.hazmat.backends as backends
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.fernet as fernet
import cryptography.exceptions as exceptions
import qr
import clparser
from cloptions import *


def raise_error(error, print_error=True):

    if error == 0:
        pass
    elif error == 1:
        print("ERROR: Cannot identify image format in QR input file")
    elif error == 2:
        print("ERROR: Unknown error while reading input file. Possible reasons:")
        print("    - Non-existing or empty file")
        print("    - Wrong file format")
        print("    - Invalid permissions")
    elif error == 3:
        print("ERROR: Unknown error while opening output file. Possible reasons:")
        print("    - Wrong file name format")
        print("    - Read-only file system")
        print("    - Invalid permissions")
    elif error == 4:
        print("ERROR: Unknown error while encrypting file")
    elif error == 5:
        print("ERROR: Error while decrypting file. Possible reasons:")
        print("    - Incorrect Password")
        print("    - The input file is not already encrypted")
    elif error == 6:
        print("ERROR: Input file is a directory. Compress it first, then encrypt the resulting archive file")
    elif error == 7:
        print("ERROR: Given Password or Key is not correct")
    elif error == 8:
        print("ERROR: Ciphered Message is not correct. Check if the message is ciphered and complete")
    elif error == 9:
        print("ERROR: Wrong argument. Check command line definition file")
    elif error == 10:
        print("ERROR: wrong path. Check full path of input file")

    if print_error:
        print()
        print(traceback.format_exc())
    exit()


def check_file(file, extension="", find_alt=False):

    file = file.rstrip("\\").rstrip("/")
    dir_name, file_name = os.path.split(file)
    short_name, file_ext = os.path.splitext(file_name)

    valid_path = True
    if dir_name:
        if Path(dir_name).is_dir():
            dir_name += os.sep
        else:
            dir_name = ""
            valid_path = False

    if (extension and file_ext.lower() != extension.lower()) or not file_ext:
        file_ext += extension

    file_name = "{}{}{}".format(dir_name, short_name, file_ext)

    is_file = Path(file_name).is_file()
    is_dir = Path(file_name).is_dir()

    if find_alt:
        i = 1
        while Path(file_name).is_file() or Path(file_name).is_file():
            file_name = PurePath(file_name).with_name("{}{}_{}{}".format(dir_name, file_name, i, file_ext))
            i += 1

    return file_name, is_dir, is_file, valid_path


def get_params():

    key = None
    password = None
    input_file = None
    output_file = None
    message = None
    qr_input_file = None
    qr_output_file = None
    chunk_size = None
    ignore = []

    args, args_names, args_values, opts, opts_values = clparser.read_command_line(sys.argv, arguments, options, arg_opt)
    argument = args[0]
    arg_name = args_names[0]

    if arg_name == "encrypt":
        chunk_size = 1024 * 1024
    elif arg_name == "decrypt":
        chunk_size = 1024 * 1024 + 349624  # Adding extra bits for version (8), time_stamp (64), iv( 128) and hmac (256)
    elif arg_name == "generate key":
        pass
    else:
        raise_error(9)

    for item in arg_opt.keys():
        if item == argument:
            ignore = arg_opt[item]["Ignored"]

    for i, option in enumerate(opts):
        if option == "-k" and option not in ignore:
            key = opts_values[i]
        elif option == "-p" and option not in ignore:
            password = " ".join(opts_values[i])
        elif option == "-m" and option not in ignore:
            message = " ".join(opts_values[i])
        elif option == "-i" and option not in ignore:
            input_file, isdir, isfile, valid_path = check_file(opts_values[i], extension="", find_alt=False)
            if isdir:
                raise_error(6, print_error=False)
            elif not isfile:
                raise_error(2, print_error=False)
            elif not valid_path:
                raise_error(10, print_error=False)
        elif option == "-o" and option not in ignore:
            output_file, isdir, foo, valid_path = check_file(opts_values[i], extension="", find_alt=True)
            if isdir:
                print("WARNING: output file can not be a directory. Writing data to %s" % output_file)
            elif not valid_path:
                print("WARNING: wrong path. Writing output file %s to current directory" % output_file)
            elif output_file != opts_values[i]:
                print("WARNING: output file already exists. Writing data to %s" % output_file)
        elif option == "-iq" and option not in ignore:
            qr_input_file, isdir, isfile, valid_path = check_file(opts_values[i], extension="", find_alt=False)
            if isdir:
                raise_error(6, print_error=False)
            elif not isfile:
                raise_error(2, print_error=False)
            elif not valid_path:
                raise_error(10, print_error=False)
            if qr_input_file.find(".png") < 0 and qr_input_file.find(".PNG") < 0:
                print("WARNING: QR file must have PNG format. Decoding could fail on this file")
        elif option == "-oq" and option not in ignore:
            qr_output_file, isdir, foo, valid_path = check_file(opts_values[i], extension=".png", find_alt=True)
            if isdir:
                print("WARNING: output file can not be a directory. Writing data to %s" % qr_output_file)
            elif not valid_path:
                print("WARNING: wrong path. Writing output file %s to current directory" % qr_output_file)
            elif qr_output_file != opts_values[i]:
                print("WARNING: QR output must be a non-existing PNG file. Writing data to %s" % qr_output_file)
        else:
            raise_error(9)

    if arg_name in ("encrypt", "decrypt"):
        if "-i" in opts:
            if "-o" not in opts:
                if arg_name == "encrypt":
                    output_file, foo, foo, valid_path = check_file(input_file, extension=".enc", find_alt=True)
                elif arg_name == "decrypt":
                    output_file, foo, foo, valid_path = check_file(input_file.rsplit(".enc", 1)[0], extension=".dec", find_alt=True)

                if "-oq" in opts:
                    print("WARNING: output file (-oq) can not be a QR (won't fit). Writing data to '%s'" % output_file)
                else:
                    print("WARNING: output file (-o) not defined. Writing data to '%s'" % output_file)

        elif "-iq" in opts:
            try:
                message = qr.qr_decode(qr_input_file)
            except OSError:
                raise_error(1, print_error=False)
            except Exception:
                raise_error(2, print_error=False)

        elif "-m" not in opts:
            print(">>> Enter (or paste) your secret message:")
            message = input("")

    if "-p" not in opts and ("-k" not in opts or "-g" in args):
        password = get_password()

    return arg_name, input_file, output_file, qr_input_file, qr_output_file, message, key, password, chunk_size


def get_password():

    while True:
        pass1 = getpass.getpass(">>> Password:")
        pass2 = getpass.getpass(">>> Repeat Password:")
        if pass1 != pass2:
            print("ERROR: passwords do not match. Please enter again")
        else:
            break

    return pass1


def generate_key(password):

    digest = hashes.Hash(hashes.SHA256(), backend=backends.default_backend())
    digest.update(password.encode())
    key = base64.urlsafe_b64encode(digest.finalize())

    return key


def open_input_file(input_file):

    rf = None
    try:
        rf = open(input_file, 'rb')
    except Exception:
        raise_error(2)

    return rf


def open_output_file(output_file):

    wf = None
    try:
        wf = open(output_file, 'ab')
    except Exception:
        raise_error(3)

    return wf


def get_chunk_size(chunk_size=1024):

    chunk = ""
    for i in range(chunk_size):
        chunk += "A"
    key = generate_key('K4l4k0l0nut1@19/11'.encode())
    fnt = fernet.Fernet(key)
    data = fnt.encrypt(chunk.encode())
    print("Plain text length:", chunk_size)
    print("Ciphered text length:", len(data))
    print("Additional chunk length to read when deciphering:", len(data) - chunk_size)

    return len(data) - chunk_size


def read_file_chunk(input_file, chunk_size=1024):

    return iter(lambda: input_file.read(chunk_size), b'')


def encrypt(key, data, fnt=None):

    if not fnt:
        try:
            fnt = fernet.Fernet(key)
        except Exception as e:
            print("ERROR: %s. Key seems not to be correct. Check the key, its length and its padding" % e)
            raise_error(0, print_error=False)

    try:
        ciphered = fnt.encrypt(data)
    except Exception:
        raise_error(4)

    return ciphered, fnt


def decrypt(key, data, fnt=None):

    if not fnt:
        try:
            fnt = fernet.Fernet(key)
        except Exception as e:
            print("ERROR: %s. Key seems not to be correct. Check the key, its length and its padding" % e)
            raise_error(0, print_error=False)

    try:
        deciphered = fnt.decrypt(data)
    except fernet.InvalidToken as e:
        # In this case the previous exception is in __context__, not in __cause__
        if e.__cause__ is None and e.__context__ is not None and type(e.__context__) == exceptions.InvalidSignature:
            raise_error(7, print_error=False)
        else:
            raise_error(8, print_error=False)
    except Exception as e:
        raise_error(5)

    return deciphered, fnt


def crypto_file(argument, input_file, password, key, output_file, chunk_size=1024):

    if not key:
        key = generate_key(password)

    rf = open_input_file(input_file)

    fnt = None
    file_open = False
    for chunk in read_file_chunk(rf, chunk_size=chunk_size):
        if argument == "encrypt":
            data, fnt = encrypt(key, chunk, fnt)
        elif argument == "decrypt":
            data, fnt = decrypt(key, chunk, fnt)
            while True:
                if data[:3] == b'-r.' and data[3:9].isdigit() and data[9:12] == b'.r-':
                    data = data[12:]
                else:
                    break

        if not file_open:
            wf = open_output_file(output_file)
            file_open = True
        wf.write(data)

    rf.close()
    wf.close()

    return


def crypto_message(argument, message, password, key, output_file=None, qr_output_file=None):

    if not key:
        key = generate_key(password)

    if argument == "encrypt":
        message = "-r." + str(dt.datetime.timestamp(dt.datetime.now())).replace(".", "")[-6:] + ".r-" + message
        data, fnt = encrypt(key, message.encode())
        result = "ciphered"
    elif argument == "decrypt":
        data, fnt = decrypt(key, message.encode())
        while True:
            if data[:3] == b'-r.' and data[3:9].isdigit() and data[9:12] == b'.r-':
                data = data[12:]
            else:
                break
        result = "plain"

    if output_file:
        wf = open_output_file(output_file)
        wf.write(data)
        wf.close()
    elif qr_output_file:
        qr.qr_encode(data, qr_output_file)
    else:
        print(">>> Your %s message:" % result)
        print(data.decode())

    return


def provide_key(password, output_file=None, qr_output_file=None):

    key = generate_key(password)

    if output_file:
        wf = open_output_file(output_file)
        wf.write(key)
        wf.close()
    elif qr_output_file:
        qr.qr_encode(key, qr_output_file)
    else:
        print(">>> Here is your Key (do NOT share!!!):")
        print(key.decode())

    return


def main():

    arg, input_file, output_file, qr_input_file, qr_output_file, message, key, password, chunk_size = get_params()

    if arg in ("encrypt", "decrypt"):
        if input_file:
            crypto_file(arg, input_file, password, key, output_file, chunk_size)
        elif message:
            crypto_message(arg, message, password, key, output_file, qr_output_file)
    elif arg == "generate key":
        provide_key(password, output_file, qr_output_file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        exit()
