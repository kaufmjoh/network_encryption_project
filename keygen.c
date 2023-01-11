/***********************************************
 * John Kaufman: kaufmjoh@oregonstate.edu
 *
 * Assignment 4 : OTP (keygen.c)
 *
 * This function takes a command line agrument,
 * 	and makes a c-string of capital letters
 * 	and spaces, and writes to stdout
 * *********************************************/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[])
{
	srand(time(NULL));
	//List of acceptable key chars
	char* source = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "; 
	
	char* key; //c string of random chars
	int length = atoi(argv[1]); //length of key
	
	int i = 0; //index of key

	key = malloc(sizeof(char) * (length)); //make an array of chars

	while(i < length) //for each char
	{
		key[i] = source[(rand () % 27)]; //generate a random number and take from source
		i++;
	}
	printf("%s\n", key);

	free(key);
}
