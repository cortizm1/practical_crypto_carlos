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
def key_search(extracted_text_blob:list, list_keylength:int): #needs to be numpy array/matrix
    try:
        list_possible_keylengths = [list_keylength] # keylength as an arg... multiple keylength functionality only on the vigenere_break.py
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
        #else:
        #    letter = 0
    except Exception as e:
        #letter = chr(int(6 + 65))
        error_writer(e, description=f"Error while letter by letter.")
    return letter

@function_logger
def serialized_key(possible_key:list):
    try:
        serialized_possible_key = [letter_by_letter(l) for l in possible_key]
        serialized_possible_key = "".join(serialized_possible_key)
        return serialized_possible_key
    except Exception as e:
        error_writer(e, description=f"Error on serialized key.")

@function_logger
def key_decoder(n_keys:list):
    try:
        possible_key_world = list(chain.from_iterable(n_keys))
        keys = serialized_key(possible_key_world) # for now just returning a possible key... could either return n keys per keylength or 1 key per n keylengths
        return keys
    except Exception as e:
        error_writer(e, description=f"Error on key decoder.")

@function_logger_too
def key_checker(string, key):
    try:
        if string == key:
            value = 1
            partial = 0
        else:
            value = 0

            counter = 0
            string = list(string)
            key = list(key)

            for i in range(len(key)):
                if string[i] == key[i]:
                    counter = counter + 1

            if counter >= (int(len(key)/2)):
                partial = 1
            else:
                partial = 0
        return value, partial
    except Exception as e:
        error_writer(e, description=f"Error on key checker.")

@function_logger
def statistic_computer(list_trials:list):
    try:
        freq_table = [0,0,0,0,0,0,0]
        partial_freq_table = [0,0,0,0,0,0,0]
        freq_dist = [0,0,0,0,0,0,0]
        true_freq_dist = [24,24,24,24,24,24,24]

        # hard-coding this tbh
        for key, context_window, candidates in list_trials:
            if key is not None and candidates is not None:
                freq_, partial_ = key_checker(key, candidates)
                if context_window == 100:
                    freq_table[0] = freq_table[0]+freq_
                    partial_freq_table[0] = partial_freq_table[0]+partial_
                    freq_dist[0] = freq_dist[0]+1
                elif context_window == 200:
                    freq_table[1] = freq_table[1]+freq_
                    partial_freq_table[1] = partial_freq_table[1]+partial_
                    freq_dist[1] = freq_dist[1]+1
                elif context_window == 500:
                    freq_table[2] = freq_table[2]+freq_
                    partial_freq_table[2] = partial_freq_table[2]+partial_
                    freq_dist[2] = freq_dist[2]+1
                elif context_window == 1000:
                    freq_table[3] = freq_table[3]+freq_
                    partial_freq_table[3] = partial_freq_table[3]+partial_
                    freq_dist[3] = freq_dist[3]+1
                elif context_window == 2000:
                    freq_table[4] = freq_table[4]+freq_
                    partial_freq_table[4] = partial_freq_table[4]+partial_
                    freq_dist[4] = freq_dist[4]+1
                elif context_window == 5000:
                    freq_table[5] = freq_table[5]+freq_
                    partial_freq_table[5] = partial_freq_table[5]+partial_
                    freq_dist[5] = freq_dist[5]+1
                elif context_window == 20000:
                    freq_table[6] = freq_table[6]+freq_
                    partial_freq_table[6] = partial_freq_table[6]+partial_
                    freq_dist[6] = freq_dist[6]+1

        return freq_table, partial_freq_table, freq_dist, true_freq_dist, [100, 200, 500, 1000, 2000, 5000, 20000]

    except Exception as e:
        error_writer(e, description=f"Error on key statistic computer.")

@function_logger
def statistic_computer_too(list_trials:list):
    try:
        freq_table = [0,0,0,0,0,0]
        partial_freq_table = [0,0,0,0,0,0]
        freq_dist = [0,0,0,0,0,0]
        true_freq_dist = [28,28,28,28,28,28]

        # hard-coding this tbh
        for key, context_window, candidates in list_trials:
            if key is not None and candidates is not None:
                freq_, partial_ = key_checker(key, candidates)
                if len(key) == 3:
                    freq_table[0] = freq_table[0]+freq_
                    partial_freq_table[0] = partial_freq_table[0]+partial_
                    freq_dist[0] = freq_dist[0]+1
                elif len(key) == 5:
                    freq_table[1] = freq_table[1]+freq_
                    partial_freq_table[1] = partial_freq_table[1]+partial_
                    freq_dist[1] = freq_dist[1]+1
                elif len(key) == 7:
                    freq_table[2] = freq_table[2]+freq_
                    partial_freq_table[2] = partial_freq_table[2]+partial_
                    freq_dist[2] = freq_dist[2]+1
                elif len(key) == 10:
                    freq_table[3] = freq_table[3]+freq_
                    partial_freq_table[3] = partial_freq_table[3]+partial_
                    freq_dist[3] = freq_dist[3]+1
                elif len(key) == 15:
                    freq_table[4] = freq_table[4]+freq_
                    partial_freq_table[4] = partial_freq_table[4]+partial_
                    freq_dist[4] = freq_dist[4]+1
                elif len(key) == 20:
                    freq_table[5] = freq_table[5]+freq_
                    partial_freq_table[5] = partial_freq_table[5]+partial_
                    freq_dist[5] = freq_dist[5]+1
        return freq_table, partial_freq_table, freq_dist, true_freq_dist, [3, 5, 7, 10, 15, 20]
    except Exception as e:
        error_writer(e, description=f"Error on key statistic computer.")

@function_logger_too
def plaintext_writeout(top_n_keys:list, ciphertext_filename:str):
    try:
        dir_ = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        full_path = os.path.join(dir_, str(ciphertext_filename[:-4] + "_candidate_keys.txt"))

        statistics_list_cw = statistic_computer(top_n_keys) # context window
        statistics_list_kl = statistic_computer_too(top_n_keys) # keylength

        # i'm never checking the full_path... but that's ok I guess
        with open(full_path, "w") as file:
            file.writelines("Context_Window\tExact\tPartial\tFunctional\tAttempted\n")
            [file.writelines(f"{statistics_list_cw[4][i]}\t\t\t\t{statistics_list_cw[0][i]}\t\t{statistics_list_cw[1][i]}\t\t{statistics_list_cw[2][i]}\t\t\t{statistics_list_cw[3][i]}\n") for i in range(len(statistics_list_cw[0])) if i < 3]
            [file.writelines(f"{statistics_list_cw[4][i]}\t\t\t{statistics_list_cw[0][i]}\t\t{statistics_list_cw[1][i]}\t\t{statistics_list_cw[2][i]}\t\t\t{statistics_list_cw[3][i]}\n") for i in range(len(statistics_list_cw[0])) if i >= 3]
            
            file.writelines("\nKeylength\tExact\tPartial\tFunctional\tAttempted\n")
            [file.writelines(f"{statistics_list_kl[4][i]}\t\t\t{statistics_list_kl[0][i]}\t\t{statistics_list_kl[1][i]}\t\t{statistics_list_kl[2][i]}\t\t\t{statistics_list_kl[3][i]}\n") for i in range(len(statistics_list_kl[0]))]
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
        else:
            # default list of possibilities in case somehow all went wrong
            defaults_ = ['between','from','about','leave','think','them','your','some','little','because']
    except Exception as e:
        error_writer(e, description="Error on std writeout.")

@function_logger
def random_key(key_length):
    try:
        keys = []
        for i in range(4):
            digitized_key = [random.randint(1,26) for i in range(key_length)]
            digitized_key = [chr(int(d + 64)) for d in digitized_key]
            key_ = ''.join(digitized_key)
            keys.append(key_)
        return keys
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

@function_logger
def keyl_removal(tuple_):
    try:
        _, b = tuple_
        for i, x in enumerate(b):
            if x is None:
                b[i] = 0
        return b # default to a just because tbh
    except Exception as e:
        error_writer(e, description="Error on key removal.")

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
    random_keys = list(chain.from_iterable(random_keys))
    possible_text_windows = [100, 200, 500, 1000, 2000, 5000, 20000]

    extracted_text_blob, _ = ciphertext_reader(args.sample_text_name)

    sample_trials = [vigenere_encrypt(extracted_text_blob, rk, ptw) for rk in random_keys for ptw in possible_text_windows]

    t = datetime.datetime.now()
    logger.info(f'\t{t}\tStarting key search on {args.sample_text_name} with keylengths {possible_keylengths}.')
    #possible_keylengths_too = [int(i) for i in range(3-21)]

    # algo run of IoC
    top_n_keys = [(key_, text_window_, key_search(final_letter_blob, len(key_))) for key_, text_window_, final_letter_blob in sample_trials]
    top_n_keys = [(key, text_window_, key_decoder(keyl_removal(n_key[0]))) for key, text_window_, n_key in top_n_keys]
    writeout_confirmation = plaintext_writeout(top_n_keys, args.sample_text_name)
    _ = std_writeout(top_n_keys)
    #writeout_confirmation = ioc_writeout((best_ioc, top_7_iocs), args.sample_text_name)
    logger.info(f"Success status:\t{writeout_confirmation}")

if __name__ == "__main__":
    main()