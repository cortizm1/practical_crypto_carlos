# Part 4 — Empirical analysis

## Procedure

Context_Window	Exact	Partial	Functional	Attempted
100				1		11		14			24
200				1		15		22			24
500				4		18		24			24
1000			8		15		24			24
2000			9		15		24			24
5000			14		10		24			24
20000			24		0		24			24

Keylength	Exact	Partial	Functional	Attempted
3			20		8		28			28
5			17		10		28			28
7			10		18		28			28
10			5		20		26			28
15			5		13		24			28
20			4		15		22			28

Made a new .py to handle this. So we generated 6 random keys per keylength (3,5...) and we are trying to 
find the keys on all available context windows. Given the actual behavior of my tool (heavy filtering) and
a lazy fallback mechanism that isn't always enforced (default to x value) the tool works best when we do know
the actual keylength, and we have sufficient vocabulary to enforce the english frequency distribution implicitly.

On smaller sets of context we see a very flaky tool, that grows more robust in both terms of functionality and
preciseness as we expand the context windows.

We also see that as that as the key grows bigger we find less exact results and more partial results.

The reason some iterations completely "fail" is that a given digit on the key is None (fallback not enforcing?),
and I just discard that attempt.

## Where and why it breaks (≤ 300 words, your own reasoning)

It breaks because of:

The preliminary reduction of the permutation space to what we found to be the top 6 and bottom 4 letters from the ciphertext.
If there is not enough context then it might pick up certain letters to be the most frequent (that simply do not show up on the
standard english frequency distribution).

It also breaks because of the tier selection logic, it is flaky for some edge cases, and I tried to enforce the default fallback
but I still get some Nones here and there.

It might also break because of the many lists, sets, and tuples I am using... a wrong index, parameter somewhere might be unpacking
an extra value somewhere it doesn't belong or cutting a list short when it should keep going, etc.

It also naturally breaks because the IoC + Frequency Distribution assumptions in my code seem to be directly correlated with each other.
If I am trying to find meaningful patterns and distributions with a keylength 7, and the keylength was actually 19 because of the way
the shifts work distributions simply won't show up under a ciphered text with a wrong keylength.

## Does Part 3 fail at the same boundary as Part 2? (one sentence)

Failure seems to behave similarily (inversely) for the 2 biggest context windows and for the 2 smallest keylengths we expect exact matches,
but as we move away towards smaller context windows and bigger keylengths we start to see more partial results.

Overall I think it is a good tool for long vigenere ciphered texts under a congruent english letter frequency distribution.