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
def source_dir_walker(plaintext_filename):
    try:
        #looking for files under the directory
        dir_ = os.path.dirname(os.path.realpath(__file__))
        full_path = os.path.join(dir_, plaintext_filename)

        if os.path.isfile(full_path):
            return (True, full_path)
        else:
            logger.warning(f"404. File not found under {dir_}")
            return (False, "")
    except Exception as e:
        error_writer(e, description=f"{plaintext_filename} not found.")

@function_logger
def plaintext_reader(plaintext_filename:str):
    try:
        # shutil or something walk to and read from the .txt
        full_path = source_dir_walker(plaintext_filename)
        if full_path[0]:
            with open(full_path[1], "r") as file:
                plaintext_blob = file.read()
                plaintext_blob = [(l - 64) for l in plaintext_blob.upper().encode() if (64<int(l)<=90)] #utf-8 encoding, and bytes to [1-26]
                return plaintext_blob, len(plaintext_blob)
    except Exception as e:
        error_writer(e, description=f"Error while reading {plaintext_filename}.")

@function_logger_too
def ciphertext_digitizer_and_matrixator(plaintext_blob:list, key:str):
    try:
        digitized_key = [(k - 64) for k in key.upper().encode() if (64<int(k)<=90)]
        key_length = len(digitized_key)

        index_ = 1
        row_ = 0
        ciphertext_blob_matrix = np.full((int(len(plaintext_blob) / (key_length) + 1), key_length), 0) # the +1 is not perfect stuff

        # blob populates a matrix, could be while streaming the ciphertext.txt but for now kept separate
        for cl in plaintext_blob:
            column = ((index_-1) % key_length)
            ciphertext_blob_matrix[row_, column] = cl
            row_shifter = 1 if (int((index_) % key_length) == 0 and index_ != 0) else 0
            row_ = row_ + row_shifter
            index_ = index_ + 1
        return ciphertext_blob_matrix, digitized_key
    except Exception as e:
        error_writer(e, description=f"Error while turning .txt into a digitized matrix.")

@function_logger_too
def matrix_encipherer(ciphertext_blob_matrix:np.ndarray, digitized_key:list): #needs to be numpy array/matrix
    try:
        # column-based matrix sums
        ciphertext_blob_matrix_ciphered = (ciphertext_blob_matrix + digitized_key) % 26 # mod 25 or mod 26... i think mod 26 but will have to see
        return ciphertext_blob_matrix_ciphered
    except Exception as e:
        error_writer(e, description=f"Error while enciphering the matrix.")

@function_logger_too
def matrix_to_texter(ciphertext_blob_matrix_ciphered:np.ndarray, blob_length:int):
    try:
        # numpy to utf-8 format
        ciphertext_blob_matrix = ciphertext_blob_matrix_ciphered.flatten() #64 does not work as of right now
        ciphertext_blob_matrix = [chr(int(l + 64)) for l in ciphertext_blob_matrix]
        ciphertext_blob_matrix = ''.join(ciphertext_blob_matrix)
        return ciphertext_blob_matrix[:blob_length]
    except Exception as e:
        error_writer(e, description=f"Error going from a matrix to utf-8, to strings.")

@function_logger_too
def ciphertext_writeout(ciphertext_blob:str, plaintext_filename:str):
    try:
        dir_ = os.path.dirname(os.path.realpath(__file__))
        full_path = os.path.join(dir_, str(plaintext_filename[:-4] + "_encrypted.txt"))

        # i'm never checking the full_path... but that's ok I guess
        with open(full_path, "w") as file:
            ciphertext_blob = file.write(ciphertext_blob)
            return True
        #writeout and bool upon success/failure
        writeout_confirmation = ciphertext_blob
    except Exception as e:
        error_writer(e, description="Error on final file writeout.")
        return False

def main(argv=None):

    description = "A vigenere encipherer written in Python."

    ap = argparse.ArgumentParser(prog="vigenere_encrypt.py", description=description,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)

    logging.basicConfig(filename='vigenere_encrypt.log', level=logging.INFO)

    ap.add_argument('encrpyted_text_name')           # positional argument
    ap.add_argument('key')           # positional argument
    args = ap.parse_args()

    # eventually check for both text_name and key args to be present or else stdout + error

    t = datetime.datetime.now()
    logger.info(f'\t{t}\tStarting encryption of {args.encrpyted_text_name} using key {args.key}')

    extracted_text_blob, blob_length = plaintext_reader(args.encrpyted_text_name)
    blob_matrix, digitized_key = ciphertext_digitizer_and_matrixator(extracted_text_blob, args.key)
    blob_matrix_ciphered = matrix_encipherer(blob_matrix, digitized_key)
    final_letter_blob = matrix_to_texter(blob_matrix_ciphered, blob_length)
    writeout_confirmation = ciphertext_writeout(final_letter_blob, args.encrpyted_text_name)
    print(f"Success status:\t{writeout_confirmation}")

if __name__ == "__main__":
    main()