import argparse
import datetime

import logging
logger = logging.getLogger(__name__)

import os

import numpy as np

def function_logger(func, *args): #
    def wrapper(args):
        try:
            t = datetime.datetime.now()
            logger.info(f"{t}\tExecuting {func.__name__}.") 
            return func(args)
        except Exception as e:
                error_writer(e, description=f"Wrapper error.")
    return wrapper

# tuple unpacking kwargs and all of that didn't work for a two param function... brittle code but I'm rusty
def function_logger_too(func, *args, **kwargs): #
    def wrapper(args, kwargs):
        try:
            t = datetime.datetime.now()
            logger.info(f"{t}\tExecuting {func.__name__}.") 
            return func(args, kwargs)
        except Exception as e:
                error_writer(e, description=f"Wrapper error.")
    return wrapper

def error_writer(e:Exception, description:str):
    t = datetime.datetime.now()
    logger.error(f"{t}\t{description}\t{e}")

@function_logger
def source_dir_walker(cyphertext_filename):
    try:
        #looking for files under the directory
        dir_ = os.path.dirname(os.path.realpath(__file__))
        full_path = os.path.join(dir_, cyphertext_filename)

        if os.path.isfile(full_path):
            return (True, full_path)
        else:
            logger.warning(f"404. File not found under {dir_}")
            return (False, "")
    except Exception as e:
        error_writer(e, description=f"{cyphertext_filename} not found.")

@function_logger
def cyphertext_reader(cyphertext_filename:str):
    try:
        # shutil or something walk to and read from the .txt
        full_path = source_dir_walker(cyphertext_filename)
        if full_path[0]:
            with open(full_path[1], "r") as file:
                cyphertext_blob = file.read()
                cyphertext_blob = [(l - 64) for l in cyphertext_blob.upper().encode() if (64<int(l)<=90)] #utf-8 encoding, and bytes to [1-26]
                return cyphertext_blob
    except Exception as e:
        error_writer(e, description=f"Error while reading {cyphertext_filename}.")

@function_logger_too
def cyphertext_digitizer_and_matrixator(cyphertext_blob:list, key:str):
    try:
        digitized_key = [(k - 64) for k in key.upper().encode() if (64<int(k)<=90)]
        key_length = len(digitized_key)

        index_ = 1
        row_ = 0
        cyphertext_blob_matrix = np.full((int(len(cyphertext_blob) / (key_length) + 1), key_length), 0) # the +1 is not perfect stuff

        # blob populates a matrix, could be while streaming the cyphertext.txt but for now kept separate
        for cl in cyphertext_blob:
            column = ((index_-1) % key_length)
            cyphertext_blob_matrix[row_, column] = cl
            row_shifter = 1 if (int((index_) % key_length) == 0 and index_ != 0) else 0
            row_ = row_ + row_shifter
            index_ = index_ + 1
        return cyphertext_blob_matrix, digitized_key
    except Exception as e:
        error_writer(e, description=f"Error while turning .txt into a digitized matrix.")

@function_logger_too
def matrix_encipherer(cyphertext_blob_matrix:np.ndarray, digitized_key:list): #needs to be numpy array/matrix
    try:
        # column-based matrix sums
        cyphertext_blob_matrix_ciphered = (cyphertext_blob_matrix + digitized_key) % 26 # mod 25 or mod 26... i think mod 26 but will have to see
        return cyphertext_blob_matrix_ciphered
    except Exception as e:
        error_writer(e, description=f"Error while enciphering the matrix.")

@function_logger
def matrix_decryption_bytes(cyphertext_blob_matrix_ciphered:np.ndarray):
    try:
        # numpy to utf-8 format
        plaintext_blob_matrix = cyphertext_blob_matrix_ciphered

        # numpy to list dump

        # list decoding to string
        
        return plaintext_blob_matrix
    except Exception as e:
        error_writer(e)

@function_logger
def matrix_alphabetization_and_dumper(plaintext_blob_matrix):
    try:
        plaintext_blob = plaintext_blob_matrix
        return plaintext_blob
    except Exception as e:
        error_writer(e)

@function_logger
def plaintext_writeout(plaintext_blob:str):
    try:
        #writeout and bool upon success/failure
        writeout_confirmation = plaintext_blob
        return True
    except Exception as e:
        error_writer(e)

def main(argv=None):

    description = "A vigenere decypherer written in Python."

    ap = argparse.ArgumentParser(prog="vigenere_decrypt.py", description=description,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)

    logging.basicConfig(filename='vigenere_decrypt.log', level=logging.INFO)

    ap.add_argument('encrpyted_text_name')           # positional argument
    ap.add_argument('key')           # positional argument
    args = ap.parse_args()

    # eventually check for both text_name and key args to be present or else stdout + error

    t = datetime.datetime.now()
    logger.info(f'\t{t}\tStarting decryption of {args.encrpyted_text_name} using key {args.key}')

    extracted_text_blob = cyphertext_reader(args.encrpyted_text_name)
    blob_matrix, digitized_key = cyphertext_digitizer_and_matrixator(extracted_text_blob, args.key)
    blob_matrix_ciphered = matrix_encipherer(blob_matrix, digitized_key)
    decrypted_blob_matrix = matrix_decryption_bytes(blob_matrix_ciphered)
    decrypted_blob = matrix_alphabetization_and_dumper(decrypted_blob_matrix)
    writeout_confirmation = plaintext_writeout(decrypted_blob)
    print(f"Success status:\t{writeout_confirmation}")

if __name__ == "__main__":
    main()