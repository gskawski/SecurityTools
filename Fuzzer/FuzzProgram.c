#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

int fuzzer(char *prng_seed_filepath, int num_of_iterations) {

    FILE *seedfiletoread = NULL;
    FILE *fuzzeroutput = NULL;
    int c,d;
    int seed = 1;

    seedfiletoread = fopen(prng_seed_filepath, "rb"); // has to be present
    fuzzeroutput = fopen("fuzzeroutput","wb"); // fuzzeroutpt file created if does not exist, otherwise truncated to 0 size

    // copy seed file to fuzzeroutput file
    while((c = fgetc(seedfiletoread)) != EOF) {
        fputc(c,fuzzeroutput);
        seed = seed * c;
    }
    fclose(seedfiletoread);
    fclose(fuzzeroutput);

    // seed psuedo random number generator so fuzzeroutput is deterministic
    srand(seed);

    // iterate on fuzzeroutput for `num_iterations` times
    for(int i = 1; i <= num_of_iterations; i++) {
        if(rand() % 100 < 13) { // change each byte in fuzzeroutput to a random byte with a 13% probability
            fuzzeroutput = fopen("fuzzeroutput","rb+");
            int c;
            while((c = fgetc(fuzzeroutput)) != EOF) 
                fputc(rand() % 255, fuzzeroutput);
            fclose(fuzzeroutput);
        }

        if (i % 500 == 0) { // extend fuzzeroutput by adding 10 random characters to end every 500 iterations
            fuzzeroutput = fopen("fuzzeroutput","ab");
            for(int j = 10; j > 0; j--)  // generate random 10 characters
                fputc(rand() % 255, fuzzeroutput); // append a random character to fuzzeroutput
            fclose(fuzzeroutput);
        }
    }
    // after completing num_iterations, print unsigned hexadecimal formatted fuzzeroutput contents to stdout
    fuzzeroutput = fopen("fuzzeroutput","rb");
    while((d = fgetc(fuzzeroutput)) != EOF) 
        printf("%x",d);
    fclose(fuzzeroutput);

    return(1);
}

int main(int argc, char* argv[]) { // program arguments need to follow "relative path to seed file" "number of iterations" order
    int num_of_iterations;

    sscanf(argv[2], "%u", &num_of_iterations); // convert char input to int

    fuzzer(argv[1], num_of_iterations); // argv[1] = relative path to seed file for each program (prog0/seed)

    return(1);
}