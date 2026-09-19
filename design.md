# Design note (≤ 1 page)

## Key-length decision rule (Part 2)
Yeah for the key length I am using the IoCs. Compute the IoC on each digit in the key and sum them all together. 
I do this for all key lengths from 2-32. I then have sums of IoCs (e.g. 0.04,0.05, 0.06). I go ahead and try to filter out:
First the ones the furthest away, by setting up deltas (kind of like the sigmas in a distribution) from the expected IoC for non-uniform distributions (0.0656). So if it is not inside a given range delta+-(0.656*delta) it's thrown out. Note the Ioc (p squared values are normalized by
the # times they show up, giving greater importance to those letters that show up more frequently).

I then sort out the remaining candidates and filter out once again any factorial combinations (e.g if there exists 7, and 14 I just keep the 7...
but if there is 6, and 9 I keep both becaue 3 was not present here.)

## Column-shift scoring (Part 3)
I am computing permutations where there exists at least one letter from the top 6 or from the bottom 4 from the english frequency distribution in the cipher text's top 6 or bottom 4 ciphered distribution.

For this I use sets (keeping only unique values in the possible universe of permutations) and replace the top 6 and top 4 with their "would be"
counterparts. This replacement gives me the possible key/shift (i.e 23 -> 24 -> 1) and I get permutation sets (1,4,3,1,1) <- this would translate
to a english freq. actual freq. distribution plausible assumption match.

Given the large number of possible keys (not so large though) I then compress this by either placing it on T1, or T2 or set(set(), set()) for T3
where a T3 simplification looks like set(set(1,2,3,1), set(2,3,4,3)) -> (1,2,3,4) i then go ahead and try all shifts (it is a monoalphabetic shift cipher after all so trying 4 different shifts is not expensive at all).

So I've got 3 tiers.

Tier 1 
If it smells like lemons and tastes like lemons...
I use an 80% AND Mode of modes filter.
If >80% of the shifts in a set are a single shift (1,1,1,2,1) AND the mode of all set's modes is the same then it is T1.

Tier 2
Decent but might be a bit unorthodox.
If was the mode of only one of the sets T2. 

Tier 3
All possible permutations computed. NOTE: I am not computing all possible permutations but actually just those where there exists at least one letter from the top 6 or from the bottom 4 from the english frequency distribution in the cipher text's top 6 or bottom 4 ciphered distribution.
And crunching recursive sets of sets (just keeping the unique values).

If it is an extremely unorthdodox text that does not follow the english frequency distribution in this way it won't work. Also it heavily depends on
a correct choice of keylength. Else I'm trying to find zebras in a fish pond.

After the tier pruning I do additional steps to filter out the possible value.
If T1 then I most likely keep it.

I do however compute the "error" (english frequency distribution - distribution here) *normalized* and if no clear t1 then use this sum(error)
heuristic to determine the new best possible candidate.

Additional pruning based on standard deviation in terms of the error... but the truth is this is not needed as I am still picking the best possible
candidate anyways unless there exists a very strong case for T1.

## Known failure cases
If keylength wrong it brakes.
Different language would need to change distribution and psquared (IoC) as this are hard-coded assumptions here.
Sometimes it might brake because of mod/shifts... on index 26 + 0 decrypt/encrypt scenarios (this was very tricky lol).
Trying different keylengths would need the additional vigenere-break script (i.e. TODO), and right now I'm actually doing very heavy filtering (Top 10 is actually a Top 1).
Unorthodox texts that don't follow the english frequency distribution brake it (I have a reduced permutation space).
Some extremely primitive fallback mechanisms (hardcoded arbitrary default value).