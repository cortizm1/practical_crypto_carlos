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

@function_logger_too
def permutation_generator(generic_letters_distribution:list, actual_letters_distribution:list):
    try:
        worst_case = len(generic_letters_distribution)
        permutation_space = []

        for i, args in enumerate(permutations([i for i in range(len(generic_letters_distribution))])):
            unique_ = [((actual_letters_distribution[args[l]][0] - generic_letters_distribution[l][0]) % 26) for l in range(len(args))]
            _ = permutation_space.append(unique_) if (len(set(unique_)) <= worst_case) else False#
            worst_case = len(set(unique_)) if (len(set(unique_)) <= worst_case) else worst_case

        permutation_space = [perm for perm in permutation_space if (len(set(perm))) <= worst_case]
        return permutation_space
    except Exception as e:
        error_writer(e, description=f"Error while generating a possible small permutation subspace.")

@function_logger
def all_inclusive_permutation_checker(lists_permutations:list):
    try:
        permutation_candidates_joined =  list(set(chain.from_iterable(lists_permutations))) #there are clearly most likely candidates... in case our postprocessing step doesn't work we come back here

        all_inclusive_permutations = []
        
        for x in permutation_candidates_joined:

            all_inclusive = True
            for l in lists_permutations:
                if x not in l:
                    all_inclusive = False
                    break

            if all_inclusive:
                all_inclusive_permutations.append(x)

        if len(all_inclusive_permutations)<1:
            all_inclusive_permutations = permutation_candidates_joined

        return all_inclusive_permutations
    except Exception as e:
        error_writer(e, description=f"Error while filtering by all inclusive permutations.")

@function_logger
def mode_of_modes_and_perm_space_mode(lists_permutations:list):
    try:
        permutation_candidates_joined =  list(set(chain.from_iterable(lists_permutations)))
        perm_space_mode = max(set(permutation_candidates_joined), key=permutation_candidates_joined.count)

        mode_of_modes = [max(set(l), key=l.count) for l in lists_permutations]
        mode_of_modes = max(set(mode_of_modes), key=mode_of_modes.count)

        return [perm_space_mode, mode_of_modes]
    except Exception as e:
        error_writer(e, description=f"Error while computating permutation related modes.")

@function_logger
def cipher_combinatorics(tops_prob_dist):
    try:
        # hardcoded english language letter frequency distribution
        letters_distribution = [(1, 0.08167), (2, 0.01492), (3, 0.02782), (4, 0.04253), (5, 0.12702), (6, 0.02228), (7, 0.02015), 
        (8, 0.06094), (9, 0.06966), (10, 0.00153), (11, 0.00772), (12, 0.04025), (13, 0.02406), (14, 0.06749), (15, 0.07507), 
        (16, 0.01929), (17, 0.00095), (18, 0.05987), (19, 0.06327), (20, 0.09056), (21, 0.02758), (22, 0.00978), (23, 0.02360), 
        (24, 0.00150), (25, 0.01974), (26, 0.00074)]

        letters_distribution = sort_algo(letters_distribution)

        letters_distribution_lower = letters_distribution[:4]
        tops_prob_dist_lower = tops_prob_dist[:4]

        permutation_lower = permutation_generator(letters_distribution_lower, tops_prob_dist_lower)
        all_inclusive_lower = all_inclusive_permutation_checker(permutation_lower)
        modes_lower = mode_of_modes_and_perm_space_mode(permutation_lower)

        letters_distribution_upper = letters_distribution[(len(letters_distribution)-6):]
        tops_prob_dist_upper = tops_prob_dist[(len(tops_prob_dist)-6):]

        permutation_upper = permutation_generator(letters_distribution_upper, tops_prob_dist_upper)
        all_inclusive_upper = all_inclusive_permutation_checker(permutation_upper)
        modes_upper = mode_of_modes_and_perm_space_mode(permutation_upper)

        modes_set = list(set(modes_lower + modes_upper))

        # three tiered system... 80% show up or all inclusive mode (both all inclusives) | or set of modes plus smaller all inclusive set | or all else left in filtered down sets
        shared_list = modes_set+all_inclusive_lower+all_inclusive_upper

        first_tier_candidates = list(set([i for i in shared_list if i in modes_set and i in all_inclusive_lower and i in all_inclusive_upper]))

        second_tier_candidates = list(set(all_inclusive_upper + modes_set)) if len(all_inclusive_upper) <= len(all_inclusive_lower) else list(set(all_inclusive_lower + modes_set))
        second_tier_candidates = [i for i in second_tier_candidates if i not in first_tier_candidates]

        third_tier_candidates = list(set([i for i in shared_list if i not in first_tier_candidates and i not in second_tier_candidates]))

        return first_tier_candidates, second_tier_candidates, third_tier_candidates
    except Exception as e:
        error_writer(e, description=f"Error while doing the permutation combinatronics.")

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
        plaintexted_prob_dist = [(((l-possible_key)%26), prob) for l, prob in prob_dist_tuples] # the plus one is key here... else we get 0-25 letter indexes
        
        for i, k in enumerate(plaintexted_prob_dist):
            if k[0]==0:
                plaintexted_prob_dist[i] = (k[0] + 26, k[1])
            else: 
                pass # the plus one is key here... else we get 0-25 letter indexes

        plaintexted_prob_dist = sort_algo_too(plaintexted_prob_dist)

        sum_k_squared = []

        # prob_dist bound to an actual letter now (we have the possible key)
        for l, prob in plaintexted_prob_dist: # it might be the case not all letters are used
            for i in letters_distribution:
                if i[0] == l:
                    k_squared = (prob - i[1])**2/prob
                    sum_k_squared.append(k_squared)
                    break

        return possible_key, sum(sum_k_squared) #ntimes_*(freq_/blob_length)**2... k squared is actually shifted one to the left
    except Exception as e:
        error_writer(e, description=f"Error while computing k_squared.")

@function_logger_too
def layered_possible_letter_handler(prob_dist_tuples:tuple, possible_keys:list):
    try:
        candidate_keys = [k_squared(prob_dist_tuples, pkey) for pkey in possible_keys]
        return candidate_keys
    except Exception as e:
        error_writer(e, description=f"Error while handling k-score computations.")

@function_logger_too
def possible_key_pruning(possible_keys:list, std_n:int):
    try:
        if len(possible_keys) > 1:
            # standard deviation pruning (definitely far far away)
            std_delta = (2*np.std([k_squared for key, k_squared in possible_keys]))
            _, smallest_ksquared_in_tier = possible_keys[0] #they are sorted
            reduced_keys = [(key, k_squared) for key, k_squared in possible_keys if abs(k_squared-smallest_ksquared_in_tier) < std_delta]

        else:
            reduced_keys = possible_keys

        return reduced_keys
    except Exception as e:
        error_writer(e, description=f"Error while std pruning possible candidates.")

@function_logger_too
def xor_pruning_lists(covet_groups: list, possible_keys:list):
    try:
        structured_possible_keys = [(n+1, i) for n, p in enumerate(possible_keys) for i in p if i in covet_groups]
        return structured_possible_keys
    except Exception as e:
        error_writer(e, description=f"Error while xor pruning possible candidates.")

@function_logger_too
def monoal_cryptanalyzer(frequency_tuples, blob_length:int):
    try:
        frequency_tuples_complete = sort_algo(frequency_tuples[0]) # top 6 and top6n't
        prob_dist_complete = [prob_dist(tuple_, blob_length) for tuple_ in frequency_tuples_complete]

        #frequency_tuples_ = frequency_tuples_complete[:4] + frequency_tuples_complete[(len(frequency_tuples_)-6):]
        tops_prob_dist = prob_dist_complete[:4] + prob_dist_complete[(len(prob_dist_complete)-6):] #[prob_dist(tuple_, blob_length) for tuple_ in frequency_tuples_]
        validated_combinatronics = cipher_combinatorics(tops_prob_dist) # monoalphabetism makes it easier (linear?) to find pairings... as they are 1-to-1
        # if tier 1 is composed of 1 and only 1 we choose it
        if len(validated_combinatronics[0]) == 1:
            validated_combinatronics = validated_combinatronics[0]
            candidate_best_possible_keys = validated_combinatronics
        else:
            candidate_best_possible_keys = [layered_possible_letter_handler(prob_dist_complete, layered_pkey) for layered_pkey in validated_combinatronics if len(validated_combinatronics)>1]
        
        # tier pruning
        candidate_best_possible_keys = [possible_key_pruning(sort_algo(t), 2) for t in candidate_best_possible_keys] if len(candidate_best_possible_keys)>1 else candidate_best_possible_keys
        # outlier pruning (tier independent)
        tier_independent_best_keys = possible_key_pruning(sort_algo(list(set(chain.from_iterable(candidate_best_possible_keys)))), 2) if len(candidate_best_possible_keys)>1 else candidate_best_possible_keys
        # the 10x ratio seems to be working surprisingly well
        tier_independent_best_keys = [(key, ksquared) for key, ksquared in tier_independent_best_keys if (float(tier_independent_best_keys[0][1])*10 >= float(ksquared)) or ((tier_independent_best_keys[0][0]) == key)] if len(tier_independent_best_keys)>1 else tier_independent_best_keys
        # setting up an additional arbitrage (just go for min if more than two still exist)
        tier_independent_best_keys = [tier_independent_best_keys[0]] if len(tier_independent_best_keys)>1 else tier_independent_best_keys

        if len(candidate_best_possible_keys)>1 and len(tier_independent_best_keys)==1:
            candidate_best_possible_keys = [tier_independent_best_keys[0][0]]
        elif len(candidate_best_possible_keys)==1:
            candidate_best_possible_keys = candidate_best_possible_keys
        else:
            logger.error("COULDN'T FIGURE OUT THE LETTER... DEFAULTING LOL")
            candidate_best_possible_keys = [0]
            #candidate_best_possible_keys = [candidate_best_possible_keys, tier_independent_best_keys] # need to handle this special case scenarios
            #candidate_best_possible_keys_tuple = xor_pruning_lists(list(set(chain.from_iterable(covet_group))), candidate_best_possible_keys)
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
def single_matrix_cryptanalyzer(ciphertext_matrix:np.ndarray):
    try:
        matrix_frequencies = [matrix_frequency_computer(ciphertext_matrix[1][:,i]) for i in range(0, ciphertext_matrix[0])]
        # so I have the n number of monoalphabetic ciphers, now its time to figure out the actual key
        candidate_best_possible_keys_keylengths = [monoal_cryptanalyzer(list_tuple_, column_freqs_) for *list_tuple_, column_freqs_ in matrix_frequencies]
        # candidate arbitrage... if there is a 1-to-1 match we use it... else we do something else
        candidate_best_possible_keys = candidate_keys_keylengths_arbitrage(candidate_best_possible_keys_keylengths) # doing a full candidate return... filtering on vigenere_break.py
        return candidate_best_possible_keys 
    except Exception as e:
        error_writer(e, description=f"Error while computing all matrix iocs.")

@function_logger_too
def key_search(extracted_text_blob:list, keylength:int): #needs to be numpy array/matrix
    try:
        list_possible_keylengths = [keylength] # keylength as an arg... multiple keylength functionality only on the vigenere_break.py

        ciphertext_matrices = []
        [ciphertext_matrices.append([i, ciphertext_digitizer_and_matrixator(extracted_text_blob, i)]) for i in list_possible_keylengths]
        ciphertext_keys = [(l[0], single_matrix_cryptanalyzer(l)) for l in ciphertext_matrices]

        return ciphertext_keys
    except Exception as e:
        error_writer(e, description=f"Error while computing iocs end-to-end.")

@function_logger
def key_serializer(n_key:list):
    return [chr(int(l + 65)) for l, score in n_key] #65 NOT 64... 

@function_logger
def key_decoder(n_keys:list):
    keys = [key_serializer(n_key) for n_key in n_keys]
    return ["".join(key) for key in keys]

@function_logger_too
def plaintext_writeout(top_n_keys:list, ciphertext_filename:str):
    try:
        dir_ = os.path.dirname(os.path.realpath(__file__))
        full_path = os.path.join(dir_, str(ciphertext_filename[:-4] + "_candidate_keys.txt"))
        top_n_keys = [key_decoder(n_keys) for _, *n_keys in top_n_keys]
        top_n_keys = list(chain.from_iterable(top_n_keys))

        # i'm never checking the full_path... but that's ok I guess
        with open(full_path, "w") as file:
            file.writelines("Possible keys.\n")
            [file.writelines(f"Key: {key}\n") for key in top_n_keys]
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
    ap.add_argument('keylength')           # positional argument
    args = ap.parse_args()

    # eventually check for both text_name and key args to be present or else stdout + error

    t = datetime.datetime.now()
    logger.info(f'\t{t}\tStarting key search on {args.encrpyted_text_name} with keylength {args.keylength}.')

    extracted_text_blob, _ = ciphertext_reader(args.encrpyted_text_name)

    # algo run of IoC
    top_n_keys = key_search(extracted_text_blob, int(args.keylength))
    writeout_confirmation = plaintext_writeout(top_n_keys, args.encrpyted_text_name)
    #writeout_confirmation = ioc_writeout((best_ioc, top_7_iocs), args.encrpyted_text_name)
    print(f"Success status:\t{writeout_confirmation}")

if __name__ == "__main__":
    main()