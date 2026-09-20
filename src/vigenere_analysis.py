import argparse
import datetime

import logging
logger = logging.getLogger(__name__)

import os

from itertools import permutations, chain

import numpy as np
import random

from vigenere_encrypt import ciphertext_digitizer_and_matrixator, matrix_encipherer, matrix_to_texter
from vigenere_cryptanalyze import ciphertext_digitizer_and_matrixator as cdam, single_matrix_cryptanalyzer

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
def source_dir_walker(ciphertext_filename):
    try:
        #looking for files under the directory
        dir_ = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        full_path = os.path.join(dir_, ciphertext_filename)

        if os.path.isfile(full_path):
            return (True, full_path)
        else:
            logger.warning(f"404. File not found under {dir_}")
            return (False, "")
    except Exception as e:
        error_writer(e, description=f"{ciphertext_filename} not found.")

@function_logger
def ciphertext_reader(ciphertext_filename:str):
    try:
        # shutil or something walk to and read from the .txt
        full_path = source_dir_walker(ciphertext_filename)
        if full_path[0]:
            with open(full_path[1], "r") as file:
                ciphertext_blob = file.read()
                ciphertext_blob = [(l - 64) for l in ciphertext_blob.upper().encode() if (64<int(l)<=90)] #utf-8 encoding, and bytes to [1-26]
                return ciphertext_blob, len(ciphertext_blob)
    except Exception as e:
        error_writer(e, description=f"Error while reading {ciphertext_filename}.")

@function_logger_too
def key_search(extracted_text_blob:list, list_keylength:list): #needs to be numpy array/matrix
    try:
        list_possible_keylengths = list_keylength # keylength as an arg... multiple keylength functionality only on the vigenere_break.py

        extracted_text_blob = [(l - 64) for l in extracted_text_blob.upper().encode() if (64<int(l)<=90)]
        ciphertext_matrices = []
        [ciphertext_matrices.append([i, cdam(extracted_text_blob, i)]) for i in list_possible_keylengths]
        ciphertext_keys = [(l[0], single_matrix_cryptanalyzer(l)) for l in ciphertext_matrices]

        return ciphertext_keys
    except Exception as e:
        error_writer(e, description=f"Error while computing iocs end-to-end.")

@function_logger
def letter_by_letter(letter):
    try:
        if letter is not None:
            letter = chr(int(letter + 65))
    except Exception as e:
        letter = chr(int(6 + 65))
        error_writer(e, description=f"Error while computing iocs end-to-end.")
    return letter

@function_logger
def serialized_key(possible_key:tuple):
    try:
        possible_key_ = list(chain.from_iterable(possible_key[1]))
        #possible_key_ = [(possible_key_[i]+65) for l in range(possible_key_)]
        serialized_possible_key = [letter_by_letter(l) for l in possible_key_]
        serialized_possible_key = "".join(serialized_possible_key)
        return possible_key[0], serialized_possible_key
    except Exception as e:
        error_writer(e, description=f"Error on serialized key.")

@function_logger
def key_serializer(n_key:list):
    try:
        #pk, n_key = n_key[0]
        # in theory after the arbitrage stuff there should only be a single possible key/shift for each of the positions in the key
        possible_key_world = [(keylength, list(chain.from_iterable(possible_key))) for keylength, possible_key in n_key]
        possible_key_world = [serialized_key(n) for n in n_key]
        return possible_key_world
    except Exception as e:
        error_writer(e, description=f"Error on key serializer.")

@function_logger
def key_decoder(n_keys:list):
    keys = [key_serializer(key_universe) for key_universe in n_keys] # for now just returning a possible key... could either return n keys per keylength or 1 key per n keylengths
    return keys

@function_logger_too
def plaintext_writeout(top_n_keys:list, ciphertext_filename:str):
    try:
        dir_ = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        full_path = os.path.join(dir_, str(ciphertext_filename[:-4] + "_candidate_keys.txt"))

        # i'm never checking the full_path... but that's ok I guess
        with open(full_path, "w") as file:
            file.writelines("Possible keys.\n")
            [file.writelines(f"Actual Key: {key}\t|\tContext Window:{context_window}\nCandidate keys: {c}\n") for key, context_window, *candidates in top_n_keys for c in candidates]
            #[file.writelines(f"Actual Key: {key}\t|\tContext Window:{context_window}\nCandidate key: {le}\n") for key, context_window, *candidates in top_n_keys for c in candidates for i in c if i is not None for le in i if le is not None]
            return True
        #writeout and bool upon success/failure
        #writeout_confirmation = plaintext_blob
    except Exception as e:
        error_writer(e, description="Error on final file writeout.")
        return False

@function_logger
def std_writeout(top_n_keys:list):
    try:
        # conditional has to work a little different since we are working with lists of tuples
        if len(top_n_keys) >= 1:
            top_n_keys = [key_decoder(n_keys) for _, *n_keys in top_n_keys]
            top_n_keys = list(chain.from_iterable(top_n_keys))
            #[print(f"{k}") for k in top_n_keys]
        else:
            # default list of possibilities in case somehow all went wrong
            defaults_ = ['between','from','about','leave','think','them','your','some','little','because']
            #[print(f"{i}") for i in defaults_]
    except Exception as e:
        error_writer(e, description="Error on std writeout.")

@function_logger
def random_key(key_length):
    try:
        digitized_key = [random.randint(1,26) for i in range(key_length)]
        digitized_key = [chr(int(d + 64)) for d in digitized_key]
        key_ = ''.join(digitized_key)
        return key_
    except Exception as e:
        error_writer(e, description="Error on std writeout.")

@function_logger_too
def random_ranger(text_length, text_window_):
    try:
        beginning = random.randint(1, abs(text_window_-text_length))
        end = beginning + text_window_
        return beginning, end
    except Exception as e:
        error_writer(e, description="Error on random range.")

def vigenere_encrypt(sample_text, key_, text_window_):
    try:
        beg_, end_ = random_ranger(len(sample_text), text_window_)
        sample_text = sample_text[beg_:end_]
        blob_matrix, digitized_key = ciphertext_digitizer_and_matrixator(sample_text, key_)
        blob_matrix_ciphered = matrix_encipherer(blob_matrix, digitized_key)
        final_letter_blob = matrix_to_texter(blob_matrix_ciphered, len(sample_text))
        return key_, text_window_, final_letter_blob
    except Exception as e:
        error_writer(e, description="Error on encryption.")

def main(argv=None):

    description = "A vigenere decipherer written in Python."

    ap = argparse.ArgumentParser(prog="vigenere_analysis.py", description=description,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)

    logging.basicConfig(filename='vigenere_analysis.log', level=logging.ERROR)

    ap.add_argument('sample_text_name')           # positional argument
    args = ap.parse_args()

    # eventually check for both text_name and key args to be present or else stdout + error
    possible_keylengths = [3, 5, 7, 10, 15, 20]
    random_keys = [random_key(pk) for pk in possible_keylengths]
    possible_text_windows = [100, 200, 500, 1000, 2000, 5000, 20000]

    extracted_text_blob, _ = ciphertext_reader(args.sample_text_name)

    sample_trials = [vigenere_encrypt(extracted_text_blob, rk, ptw) for rk in random_keys for ptw in possible_text_windows]

    t = datetime.datetime.now()
    logger.info(f'\t{t}\tStarting key search on {args.sample_text_name} with keylengths {possible_keylengths}.')
    #possible_keylengths_too = [int(i) for i in range(3-21)]

    possible_keylengths = [3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]

    # algo run of IoC
    top_n_keys = [(key_, text_window_, key_search(final_letter_blob, possible_keylengths)) for key_, text_window_, final_letter_blob in sample_trials]
    top_n_keys = [(key, text_window_, key_decoder(n_keys)) for key, text_window_, *n_keys in top_n_keys]
    #[print(f"{t}\n") for t in top_n_keys]
    #top_n_keys = list(chain.from_iterable(top_n_keys))
    writeout_confirmation = plaintext_writeout(top_n_keys, args.sample_text_name)
    _ = std_writeout(top_n_keys)
    #writeout_confirmation = ioc_writeout((best_ioc, top_7_iocs), args.sample_text_name)
    logger.info(f"Success status:\t{writeout_confirmation}")

if __name__ == "__main__":
    main()