import argparse
import datetime

import logging
logger = logging.getLogger(__name__)

import os

from itertools import permutations, chain

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
def matrix_frequency_computer(column_:np.ndarray):
    try:
        unique_ = list(set(column_))
        column_frequencies_ = []
        [column_frequencies_.append((int(i), list(column_).count(i))) for i in unique_ if i !=0] #using lists instead of the would be numpy equivalents (easier)
        # also the !=0 helps a lot, since matrices were coming with those extra 0s I introduced as kind of padding when initializing the matrices
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

        return list_iocs_
    except Exception as e:
        error_writer(e, description=f"Error while filtering ioc list.")

@function_logger
def cipher_combinatorics(tops_prob_dist):

    # hardcoded english language letter frequency distribution
    letters_distribution = [(1, 0.08167), (2, 0.01492), (3, 0.02782), (4, 0.04253), (5, 0.12702), (6, 0.02228), (7, 0.02015), 
    (8, 0.06094), (9, 0.06966), (10, 0.00153), (11, 0.00772), (12, 0.04025), (13, 0.02406), (14, 0.06749), (15, 0.07507), 
    (16, 0.01929), (17, 0.00095), (18, 0.05987), (19, 0.06327), (20, 0.09056), (21, 0.02758), (22, 0.00978), (23, 0.02360), 
    (24, 0.00150), (25, 0.01974), (26, 0.00074)]

    letters_distribution = sort_algo(letters_distribution)

    letters_distribution_lower = letters_distribution[:4]
    tops_prob_dist_lower = tops_prob_dist[:4]

    permutation_lower = []
    for i, args in enumerate(permutations([i for i in range(len(letters_distribution_lower))])):
        unique_ = [((tops_prob_dist_lower[args[l]][0] - letters_distribution_lower[l][0]) % 26) for l in range(len(args))]
        unique_checker = permutation_lower.append(unique_) if (len(set(unique_)) < 3) else False # might need to relax this...

    letters_distribution_upper = letters_distribution[(len(letters_distribution)-6):]
    tops_prob_dist_upper = tops_prob_dist[(len(tops_prob_dist)-6):]

    permutation_upper = []
    for i, args in enumerate(permutations([i for i in range(len(letters_distribution_upper))])):
        unique_ = [((tops_prob_dist_upper[args[l]][0] - letters_distribution_upper[l][0]) % 26) for l in range(len(args))]
        unique_checker = permutation_upper.append(unique_) if (len(set(unique_)) < 3) else False # might need to relax this...

    permutation_lower = [list(set(permutation_lower[0]))] if len(permutation_lower)==1 else [list(set(x)) for x in permutation_lower]
    permutation_upper = [list(set(permutation_upper[0]))] if len(permutation_upper)==1 else [list(set(x)) for x in permutation_upper]

    joined_permutations_ = permutation_lower + permutation_upper
    joined_permutations =  list(set(chain.from_iterable(joined_permutations_))) #there are clearly most likely candidates... in case our postprocessing step doesn't work we come back here
    
    all_inclusive_permutations = []
    
    for x in joined_permutations:
        all_inclusive = True
        for l in joined_permutations_:
            if x not in l:
                all_inclusive = False
                break

        if all_inclusive:
            all_inclusive_permutations.append(x)

    return all_inclusive_permutations if len(all_inclusive_permutations)>0 else joined_permutations

@function_logger
def sort_algo_too(list_iocs_:list):
    try:
        tuple_length = len(list_iocs_)

        for i in range(tuple_length):
            final_position = False
            for j in range(0, tuple_length - i - 1):
                if list_iocs_[j][0] > list_iocs_[j + 1][0]:
                    list_iocs_[j], list_iocs_[j + 1] = list_iocs_[j + 1], list_iocs_[j]
                    final_position = True
            if not final_position:
                break

        return list_iocs_
    except Exception as e:
        error_writer(e, description=f"Error while filtering ioc list.")

@function_logger_too
def k_squared(prob_dist_tuples:tuple, possible_key:int):
    try:

        # hardcoded english language letter frequency distribution
        letters_distribution = [(1, 0.08167), (2, 0.01492), (3, 0.02782), (4, 0.04253), (5, 0.12702), (6, 0.02228), (7, 0.02015), 
        (8, 0.06094), (9, 0.06966), (10, 0.00153), (11, 0.00772), (12, 0.04025), (13, 0.02406), (14, 0.06749), (15, 0.07507), 
        (16, 0.01929), (17, 0.00095), (18, 0.05987), (19, 0.06327), (20, 0.09056), (21, 0.02758), (22, 0.00978), (23, 0.02360), 
        (24, 0.00150), (25, 0.01974), (26, 0.00074)]

        #letters_distribution = sort_algo(letters_distribution)
        plaintexted_prob_dist = [(((l-possible_key)%26)+1, prob) for l, prob in prob_dist_tuples] # the plus one is key here... else we get 0-25 letter indexes
        #print(plaintexted_prob_dist)
        plaintexted_prob_dist = sort_algo_too(plaintexted_prob_dist)

        sum_k_squared = []

        # prob_dist bound to an actual letter now (we have the possible key)
        for l, prob in plaintexted_prob_dist: # it might be the case not all letters are used
            for i in letters_distribution:
                if i[0] == l:
                    k_squared = (prob - i[1])**2
                    sum_k_squared.append(k_squared)
                    break

        return possible_key, sum(sum_k_squared) #ntimes_*(freq_/blob_length)**2
    except Exception as e:
        error_writer(e, description=f"Error while computing p_squared.")

@function_logger_too
def monoal_cryptanalyzer(frequency_tuples, blob_length:int):
    try:
        frequency_tuples_complete = sort_algo(frequency_tuples[0]) # top 6 and top6n't
        prob_dist_complete = [prob_dist(tuple_, blob_length) for tuple_ in frequency_tuples_complete]

        #frequency_tuples_ = frequency_tuples_complete[:4] + frequency_tuples_complete[(len(frequency_tuples_)-6):]
        tops_prob_dist = prob_dist_complete[:4] + prob_dist_complete[(len(prob_dist_complete)-6):] #[prob_dist(tuple_, blob_length) for tuple_ in frequency_tuples_]
        validated_combinatronics = cipher_combinatorics(tops_prob_dist) # monoalphabetism makes it easier (linear?) to find pairings... as they are 1-to-1
                
        candidate_best_possible_keys = [k_squared(prob_dist_complete, pkey) for pkey in validated_combinatronics] if len(validated_combinatronics)>1 else (validated_combinatronics[0], 0)
        # if there is more than 1 candidate we send them all as is... we first want to check if another keylength has a 1-to-1 match
        # we could set breaks for the case 1-to-1 matches are found... but we leaving it as is for now
        return candidate_best_possible_keys
    except Exception as e:
        error_writer(e, description=f"Error while computing per matrix iocs.")

@function_logger
def candidate_keys_keylengths_arbitrage(list_lists_candidates:list):
    try:
        # for now there is no arbitrage... if we relax the candidate space choosing then we might need to implement some logic here
        return list_lists_candidates
    except Exception as e:
        error_writer(e, description=f"Error while computing average matrix ioc.")

@function_logger
def single_matrix_cryptanalizer(ciphertext_matrix:np.ndarray):
    try:
        matrix_frequencies = [matrix_frequency_computer(ciphertext_matrix[1][:,i]) for i in range(0, ciphertext_matrix[0])]
        # so I have the n number of monoalphabetic ciphers, now its time to figure out the actual key
        candidate_best_possible_keys_keylengths = [monoal_cryptanalyzer(list_tuple_, column_freqs_) for *list_tuple_, column_freqs_ in matrix_frequencies]
        # candidate arbitrage... if there is a 1-to-1 match we use it... else we do something else
        candidate_best_possible_keys = candidate_keys_keylengths_arbitrage(candidate_best_possible_keys_keylengths) # doing a top 7 if not 1-to-1 type of thing
        return candidate_best_possible_keys #averaging since the theory is vigenere is acting as collections of monoaplphabetic ciphers sequencing out
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
def ioc_search(extracted_text_blob:list, keylength:int): #needs to be numpy array/matrix
    try:
        list_possible_keylengths = [keylength] # keylength as an arg... multiple keylength functionality only on the vigenere_break.py

        ciphertext_matrices = []
        [ciphertext_matrices.append([i, ciphertext_digitizer_and_matrixator(extracted_text_blob, i)]) for i in list_possible_keylengths]
        ciphertext_key = [(l[0], single_matrix_cryptanalizer(l)) for l in ciphertext_matrices]
        print(ciphertext_key)

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