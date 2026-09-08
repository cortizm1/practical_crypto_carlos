import argparse
import datetime

import logging
logger = logging.getLogger(__name__)

import os

def function_logger(func, *args): #
    func_args = args

    def wrapper(func_args):
        t = datetime.datetime.now()
        logger.info(f"{t}\tExecuting {func.__name__}.")
        return func(func_args)

    return wrapper

def error_writer(e:Exception):
    t = datetime.datetime.now()
    logger.error(f"{t}\t{e}")

@function_logger
def source_dir_walker(cyphertext_filename):
    #looking for files under the directory
    dir = os.path.dirname(os.path.realpath(__file__))

    #not walking more than this dir
    for files in os.walk(os.path.dirname(os.path.realpath(__file__))):
        if cyphertext_filename in files:
            print(f"{cyphertext_filename} FOUND!!")  # don't visit __pycache__ directories
        else:
            print(f"{cyphertext_filename} NOTFOUND!!")

@function_logger
def cyphertext_reader(cyphertext_filename:str):
    try:
        # shutil or something walk to and read from the .txt
        source_dir_walker(cyphertext_filename)
        f1 = open("cyphertext_filename", "r") 
        cyphertext_blob = cyphertext_filename
        return cyphertext_blob
    except Exception as e:
        error_writer(e)
        print(f"{cyphertext_filename} not found.")

@function_logger
def cyphertext_digitizer_and_matrixator(cyphertext_blob:str):
    try:
        # blob populates a matrix, could be while streaming the cyphertext.txt but for now kept separate
        cyphertext_blob_matrix = cyphertext_blob
        return cyphertext_blob_matrix
    except Exception as e:
        error_writer(e)

@function_logger
def matrix_validator(cyphertext_blob_matrix): #needs to be numpy array/matrix
    try:
        # quick check of the number of columns just to flex really
        cyphertext_blob_matrix_verified = cyphertext_blob_matrix
        return cyphertext_blob_matrix_verified
    except Exception as e:
        error_writer(e)

@function_logger
def matrix_decryption(cyphertext_blob_matrix_verified):
    try:
        # matrix operations make the shifting needed to decrypt, using mod 26
        plaintext_blob_matrix = cyphertext_blob_matrix_verified
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
    print(f"{extracted_text_blob}")
    blob_matrix = cyphertext_digitizer_and_matrixator(extracted_text_blob)
    blob_matrix_verified = matrix_validator(blob_matrix)
    decrypted_blob_matrix = matrix_decryption(blob_matrix_verified)
    decrypted_blob = matrix_alphabetization_and_dumper(decrypted_blob_matrix)
    writeout_confirmation = plaintext_writeout(decrypted_blob)
    print(f"Success status:\t{writeout_confirmation}")

if __name__ == "__main__":
    main()