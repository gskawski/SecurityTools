#!/bin/sh
# Program 0
./FuzzProgram prog0/seed 10000 | ./prog0/prog_0
# Program 1
./FuzzProgram prog1/seed 100000 | ./prog1/prog_1
# Program 2
./FuzzProgram prog2/seed 100000 | ./prog2/prog_2
