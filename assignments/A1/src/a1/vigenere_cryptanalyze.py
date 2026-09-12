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
def source_dir_walker(ciphertext_filename):
    try:
        #looking for files under the directory
        dir_ = os.path.dirname(os.path.realpath(__file__))
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
def ciphertext_digitizer_and_matrixator(ciphertext_blob:list, keylength:int):
    try:
        index_ = 1
        row_ = 0
        ciphertext_blob_matrix = np.full((int(len(ciphertext_blob) / (keylength) + 1), keylength), 0) # the +1 is not perfect stuff

        # blob populates a matrix, could be while streaming the ciphertext.txt but for now kept separate
        for cl in ciphertext_blob:
            column = ((index_-1) % keylength)
            ciphertext_blob_matrix[row_, column] = cl
            row_shifter = 1 if (int((index_) % keylength) == 0 and index_ != 0) else 0
            row_ = row_ + row_shifter
            index_ = index_ + 1
        return ciphertext_blob_matrix
    except Exception as e:
        error_writer(e, description=f"Error while turning .txt into a digitized matrix.")

@function_logger
def ioc_matrix_frequency_computer(column_:np.ndarray):
    try:
        unique_ = list(set(column_))
        column_frequencies_ = []
        [column_frequencies_.append((int(i), list(column_).count(i))) for i in unique_] #using lists instead of the would be numpy equivalents (easier)
        # pseudo recursive frequency of frequencies thingy
        return column_frequencies_, len(column_)
    except Exception as e:
        error_writer(e, description=f"Error while computing per column frequency tables.")

@function_logger_too
def prob_dist(frequency_tuple_:tuple, blob_length:int):
    try:
        letter, ntimes_ = frequency_tuple_
        return (letter, round(ntimes_/blob_length, 8))
    except Exception as e:
        error_writer(e, description=f"Error while computing prob_dist.")

#bubblesort
@function_logger
def sort_algo(list_iocs_:list):
    try:
        tuple_length = len(list_iocs_)

        for i in range(tuple_length):
            final_position = False
            for j in range(0, tuple_length - i - 1):
                if list_iocs_[j][1] > list_iocs_[j + 1][1]:
                    list_iocs_[j], list_iocs_[j + 1] = list_iocs_[j + 1], list_iocs_[j]
                    final_position = True
            if not final_position:
                break

        return list_iocs_[:5]+list_iocs_[-6:]
    except Exception as e:
        error_writer(e, description=f"Error while filtering ioc list.")

@function_logger
def cipher_combinatorics():
    print()


@function_logger_too
def monoal_matrix_distribution_computer(frequency_tuples, blob_length:int):
    try:
        sum_prob_dist = 0.00
        frequency_tuples = sort_algo(frequency_tuples[0]) # top 6 and top6n't
        tops_prob_dist = [prob_dist(tuple_, blob_length) for tuple_ in frequency_tuples]
        validated_combinatronics = cipher_combinatorics() # monoalphabetism makes it easier (linear?) to find pairings... as they are 1-to-1
        return round(sum_prob_dist)
    except Exception as e:
        error_writer(e, description=f"Error while computing per matrix iocs.")

@function_logger
def avg_ioc_per_matrix(matrix):
    try:
        # good ol' for loop
        matrix_ = 0.00
        for x in range(0,len(matrix)):
            matrix_ = matrix_ + matrix[x]

        matrix_ = matrix_/len(matrix)
        return matrix_
    except Exception as e:
        error_writer(e, description=f"Error while computing average matrix ioc.")

@function_logger_too
def ioc_matrix_computer(ciphertext_matrix:np.ndarray, blob_length:int):
    try:
        matrix_frequencies = [ioc_matrix_frequency_computer(ciphertext_matrix[1][:,i]) for i in range(0, ciphertext_matrix[0])]
        # so I have the n number of monoalphabetic ciphers, now its time to figure out the actual key
        ioc_calcs_ = [monoal_matrix_distribution_computer(list_tuple_, column_freqs_) for *list_tuple_, column_freqs_ in matrix_frequencies]
        return avg_ioc_per_matrix(ioc_calcs_) #averaging since the theory is vigenere is acting as collections of monoaplphabetic ciphers sequencing out
    except Exception as e:
        error_writer(e, description=f"Error while computing all matrix iocs.")

@function_logger
def ioc_filterer(list_iocs_:list):
    try:
        # so we are thinking again, multiple monoalphabetic ciphers in a sequence... and text is not random
        # so we expect the p2 to be close to 0.066 with a small delta on either side
        delta = 0.002 #arbitrary
        
        filtering_pass = [(keylength, ioc_) for keylength, ioc_ in list_iocs_ if ((0.066 - delta)< ioc_ < (0.066 + delta))]
        filtering_pass = filtering_pass if len(filtering_pass) >=1 else [(keylength, ioc_) for keylength, ioc_ in list_iocs_ if ((0.066 - (5*delta))< ioc_ < (0.066 + (5*delta)))]
        filtering_pass = filtering_pass if len(filtering_pass) >=1 else [(keylength, ioc_) for keylength, ioc_ in list_iocs_ if ((0.066 - (15*delta))< ioc_ < (0.066 + (15*delta)))]

        return filtering_pass if len(filtering_pass) >=1 else list_iocs_ #guessing at this point (uniform distribution... random text or a polyalphabetic cyper... or larger keylength)
    except Exception as e:
        error_writer(e, description=f"Error while filtering ioc list.")

#modded bubblesort
@function_logger
def factorial_collapser(list_iocs_:list):
    try:
        tuple_length = len(list_iocs_)

        for i in range(tuple_length-1):
            final_position = False
            for j in range(tuple_length-1):
                if (list_iocs_[j + 1][0] % list_iocs_[i][0] == 0) and (list_iocs_[j + 1][0] != 1) and (list_iocs_[i][0] !=1):
                    list_iocs_[j + 1] = (1,1)

        factorial_pass = [(keylength, ioc_) for keylength, ioc_ in list_iocs_ if (keylength>1)]
        return factorial_pass

    
    except Exception as e:
        error_writer(e, description=f"Error while filtering ioc list by factorization.")

@function_logger_too
def ioc_search(extracted_text_blob:list, blob_length:int): #needs to be numpy array/matrix
    try:
        list_keylengths = [6] #hardcoding for now
        ciphertext_matrices = []
        [ciphertext_matrices.append([i, ciphertext_digitizer_and_matrixator(extracted_text_blob, i)]) for i in list_keylengths]
        ciphertext_iocs = [(l[0], ioc_matrix_computer(l, blob_length)) for l in ciphertext_matrices]
        # now ordering, filtering out, and considering the factorial possibility
        filtered_iocs = factorial_collapser(ioc_filterer(sort_algo(ciphertext_iocs)))
        return filtered_iocs
    except Exception as e:
        error_writer(e, description=f"Error while computing iocs end-to-end.")

@function_logger
def ioc_sort(top_n_iocs:list):
    try:
        # there is space here for multi-language support, or other types of arbitrage (more than one key)... for now nothing
        return top_n_iocs
    except Exception as e:
        error_writer(e, description=f"Error going from a matrix to utf-8, to strings.")

@function_logger_too
def plaintext_writeout(top_n_iocs:list, ciphertext_filename:str):
    try:
        dir_ = os.path.dirname(os.path.realpath(__file__))
        full_path = os.path.join(dir_, str(ciphertext_filename[:-4] + "_candidate_keylengths.txt"))

        # i'm never checking the full_path... but that's ok I guess
        with open(full_path, "w") as file:
            file.writelines("Possible keylength candidates.\n")
            [file.writelines(f"Keylength: {keylength_}\tIoc Value: {ioc_value}\n") for keylength_, ioc_value in top_n_iocs]
            return True
        #writeout and bool upon success/failure
        #writeout_confirmation = plaintext_blob
    except Exception as e:
        error_writer(e, description="Error on final file writeout.")
        return False

def main(argv=None):

    description = "A vigenere decipherer written in Python."

    ap = argparse.ArgumentParser(prog="vigenere_cryptanalyze.py", description=description,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)

    logging.basicConfig(filename='vigenere_cryptanalyze.log', level=logging.INFO)

    ap.add_argument('encrpyted_text_name')           # positional argument
    args = ap.parse_args()

    # eventually check for both text_name and key args to be present or else stdout + error

    t = datetime.datetime.now()
    logger.info(f'\t{t}\tStarting index of coincidence calculation on {args.encrpyted_text_name}.')

    extracted_text_blob, blob_length = ciphertext_reader(args.encrpyted_text_name)

    # algo run of IoC
    top_n_iocs = ioc_search(extracted_text_blob, blob_length)
    best_ioc = ioc_sort(top_n_iocs)
    writeout_confirmation = plaintext_writeout(best_ioc, args.encrpyted_text_name)
    #writeout_confirmation = ioc_writeout((best_ioc, top_7_iocs), args.encrpyted_text_name)
    print(f"Success status:\t{writeout_confirmation}")

if __name__ == "__main__":
    main()