FUZZER

--------------------------------------------------------
Directions for Executing Fuzz Program
--------------------------------------------------------
The fuzzer takes arguments in the form 'relative path to seed file' 'number of iterations to run'. The fuzzer outputs a mutated seed formatted as a string of hexidecimal values to stdout. Test the fuzzer on programs by piping the fuzzer's stdout into each programs executable in the linux command terminal as shown in the example below:
	$./FuzzProgram prog0/seed 10000 | ./prog0/prog_0

Test the fuzzer on all three programs with one command line by saving and navigating to the 'fuzztesting' folder and then execute the 'testfuzzer.sh' file.

--------------------------------------------------------
Fuzzer Output / Program Input Generation Strategy
--------------------------------------------------------
The fuzzer enacts a psuedo-random number generator by utilizing C's srand(unsigned int seed) function. The seed in this case is derived from each programs 'seed' file. srand()'s int argument is the multiplication of each byte in the seed file (seed = seed * c; where c is a byte in the seed file). In this way the program is deterministic because: each program is tested using the same seed file -> this produces the same seed int for the PRNG -> this produces the same results when rand() is called -> which finally results in the same fuzzer output for each execution and given the same # of iterations.

The fuzzer mutates the input seed according to the project directions by 1) changing each byte to a random in the seed file with a 13% probability; and 2) adding 10 random bytes to end of seed file every 500 iterations. The fuzzer uses the rand() function to mutate the seed file resulting in the output being deterministic. The final tactic employed was hexadecimally formatting the final mutated seed that is outputted as inputs to the programs.
