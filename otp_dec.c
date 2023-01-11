/**********************************************************
 * John Kaufman: kaufmjoh@oregonstate.edu
 *
 * CS344 Assignment 4: OTP (otp_dec.c)
 *
 * read in cipher and a key given from the command line
 *
 * make a socket connection to
 * 	otp_dec_d.c, via a port given from the command line
 * 	the connection will return plaintext
 * ********************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

#define ROW_LENGTH 10 //THE LENGTH OF A ROW OF THE BUFFER / LETTERS READ AT A TIME

int commence_communication_with_server(int size, int socketFD, char** buffer[2], char* port);
void client_to_server(int size, int socketFD, char** buffer);

void error(const char* msg) {perror(msg); exit(0);}
int max(int num1, int num2);

int get_size_of_file(char* file);

void fill_buffer(char** buffer[2], char* ciphertext_file, char* key_file);
void read_from_file(char** buffer, char* file);
int valid_char(char c);


int int_to_str(char* buffer, int num);
char i_to_c(int num);

int main(int argc, char* argv[])
{
	int socketFD; //a file descriptor for the client process socket
	int portNumber; //the port number of the socket

	struct sockaddr_in serverAddress; 
	struct hostent* serverHostInfo;

	char** buffer[2]; //Store the plaintext and the key

	int i = 0; //general index

	//Read in the size of the plaintext and the key
	int size = max(get_size_of_file(argv[1]), get_size_of_file(argv[2]));
	if(size == -1) 
	{
		fprintf(stderr, "otp_dec error: %s contains bad characters\n", argv[1]);
		return(1);
	}
	if(size == -2)
	{
		fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
		return (1);		
	}

	//ALLOCATE BUFFER SPACE BACED ON THE SIZE OF THE FILES AND THE ROW_LENGTH
	buffer[0] = malloc(sizeof(char*) * ((size / ROW_LENGTH) + 1));
	while(i < ((size / ROW_LENGTH) + 1))
	{
		buffer[0][i] = malloc(sizeof(char) * ROW_LENGTH);
		memset(buffer[0][i], '\0', ROW_LENGTH);
		i++;
	}
	i = 0;
	buffer[1] = malloc(sizeof(char*) * ((size / ROW_LENGTH) + 1));
	while(i < ((size / ROW_LENGTH) + 1))
	{
		buffer[1][i] = malloc(sizeof(char) * ROW_LENGTH);
		memset(buffer[1][i], '\0', ROW_LENGTH);
		i++;
	}
	//BUFFER SPACE HAS BEEN ALLOCATED

	//Fill the buffer with info from the plaintext and key files
	fill_buffer(buffer, argv[1], argv[2]);

	//Set up the serverAddress struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));
	portNumber = atoi(argv[3]);
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(portNumber);
	serverHostInfo = gethostbyname("localhost");
	if(serverHostInfo == NULL) {printf("Error\n");}
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length);
	//The ServerAddress struct is complete

	//Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0);
	if(socketFD < 0) error("CLIENT: ERROR opening socket\n");

	//Connect to the server
	if(connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) 
		fprintf(stderr, "Error: could not contact otp_dec_d on port %s\n", argv[3]);


	//BEGIN the back-and-forth communication with the server	
	if(commence_communication_with_server(size, socketFD, buffer, argv[3]) == 2)
	{
		close(socketFD);
		return 2;
	}

	close(socketFD);

	return 0;

}

/***********************************************************************************
 * void commence_communication_with_server(int size, int socketFD, char** buffer[2])
 *
 * The main calls this function once the socket has been connected to the server.
 *
 * This function sends to the server a message affirming the correct connection,
 * the size of the message, the plaintext, and a key.
 *
 * This function receives from the server the ciphertext.
 *
 * int size: the size of the message
 * int socketFD: File descriptor for socket
 * char** buffer[2]: 3d array containing the plaintext and the key
 * *********************************************************************************/
int commence_communication_with_server(int size, int socketFD, char** buffer[2], char* port)
{	
	int charsWritten;
	int charsRead;
	int i = 0;
	char misc_buffer[256];
	
	//Verify the correct connection
	charsWritten = send(socketFD, "D", 1, 0);
	if(charsWritten < 0) error("CLIENT: ERROR writing to socket\n");
	charsRead = recv(socketFD, misc_buffer, 1, 0);
	if(charsRead < 0) error("CLIENT: Error reading from server\n");
	if(misc_buffer[0] == 'N')
	{
		printf("Error: otp_dec could not contact otp_dec_d on port %s\n", port);
		return 2;
	}

	//Send the size of the message
	memset(misc_buffer, '\0', 256);
	int_to_str(misc_buffer, size);
	charsWritten = send(socketFD, misc_buffer, 255, 0);
	if(charsWritten < 0) error("CLIENT: ERROR writing to socket\n");

	//Read information from the server
	memset(misc_buffer, '\0', 256);
	charsRead = recv(socketFD, misc_buffer, 255, 0);
	if(charsRead < 0) error("CLIENT: Error reading from server\n");

	//Send CIPHERTEXT to the server
	client_to_server(size, socketFD, buffer[0]);
	//Send KEY to the server
	client_to_server(size, socketFD, buffer[1]);

	//Read information from the server
	i = 0;
	while(i < (size / ROW_LENGTH) + 1)
	{
		charsRead = recv(socketFD, buffer[0][i], ROW_LENGTH, 0);
		if(charsRead < 0) error("CLIENT: Error reading from server\n");
		printf("%s", buffer[0][i]);
		i++;
	}
	printf("\n");
	
	//printf("CLIENT: Finished receiving all data\n");
	return 0;

}

/***********************************************************
 * void client_to_server(int size, int socketFD, char ** buffer)
 *
 * Write information of size length stored in buffer
 * to the server connected to socketFD *
 * *******************************************************/
void client_to_server(int size, int socketFD, char** buffer)
{
	int charsWritten;
	int charsRead;
	char misc_buffer[256];

	int i = 0;
	while(i < (size / ROW_LENGTH) + 1) //information is stored in a 2d array, write one row at a time
	{
		//Write information to the server
		charsWritten = send(socketFD, buffer[i], ROW_LENGTH, 0); //write the row
		if(charsWritten < 0) error("CLIENT: ERROR writing to socket\n");
		else if(charsWritten < strlen(buffer[i])) error("CLIENT: Not all data written to socket!\n");
		//printf("CLIENT: Chars written: %d, size of message is: %d\n", charsWritten, strlen(buffer[0]));	
		
		//Read confirmation message from the server
		memset(misc_buffer, '\0', 256);
		charsRead = recv(socketFD, misc_buffer, 255, 0);
		if(charsRead < 0) error("CLIENT: Error reading from server\n");
		//printf("CLIENT: I received: %s from the server!\n", misc_buffer);
		i++;
	}

}

/**********************************************************
 * void fill_buffer(char ** buffer[2], char* ciphertext_file, char* key_file)
 *
 *	fill the 2 2d components of a 3d array with info
 *		from ciphertext_file and key_file
 *
 * ********************************************************/
void fill_buffer(char ** buffer[2], char* ciphertext_file, char* key_file)
{

	read_from_file(buffer[0], ciphertext_file);
	read_from_file(buffer[1], key_file);

}

/*************************************************
 * void read_from_file(char ** buffer, char* file)
 *
 *	open char* file, and put its contents
 *	into the 2d array buffer
 *
 * ********************************************/
void read_from_file(char** buffer, char* file)
{
	char c = '1';
	int i = 0;
	int j = 0;
	int FD = open(file, O_RDONLY);
	while(c != '\n') //for each char
	{
		j = 0;
		while(j < ROW_LENGTH && c!= '\n') //for the length of the row
		{
			read(FD, &c, 1);
			buffer[i][j] = c;
			j++; 
		}
		i++; //go to the next column
	}
	buffer[i-1][j-1] = '\0';
	close(FD);

}

/************************************************
 * int get_size_of_file(char* file)
 *
 * return the number of chars in a the given file
 * 	Char* file
 * ***********************************************/
int get_size_of_file(char* file)
{
	char c = '1';
	int i = 0;
	int FD = open(file, O_RDONLY);
	read(FD, &c, 1);
	while(c != '\n') //count until the end of the file
	{
		i++;
		if(valid_char(c) == 0) //die if a char is invalid
			return -1;
		read(FD, &c, 1);
	}
	close(FD);

	//printf("The length of %s is %d\n", file, i);
	return i;
}

/*******************************************************
 * int max(int num1, int num2)
 *
 * 	compare the size of two arguments
 * 	if either is -1, one is invalid, so return -1
 * 	if num2(key) is less than the text, return -2
 *
 * 	otherwise, return the size of the key 
 * ***************************************************/
int max(int num1, int num2)
{
	if(num1 == -1 || num2 == -1)
		return -1;

	if(num2 < num1)
		return -2;

	return num2;
}

/*******************************************************
 * int valid_char(char c)
 *
 * 	test is a given char is a capital letter, or 
 * 	whitespace
 *
 * 	return 1 if its valid
 * 	return 0 if not 
 * ***************************************************/
int valid_char(char c)
{
	//	printf("Testing if %c is a valid char\n", c);
	char* acceptable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "; //all valid chars
	int i = 0;
	while(i < 27) //test against each valid char
	{
		if(c == acceptable[i])
			return 1;
		i++;
	}
	return 0;
}

/*********************************************************
 * int int_to_str(char * buffer, int num)

 *  Convert the parameter num, to a c-string, stored in
 *      buffer
 *
 * First, count the places in num, and the calculate
 *      the value of each place. Convert the int to a char
 *
 * return the number of places
 ******************************************************/
int int_to_str(char* buffer, int num)
{
	int i = 0; //index for places
	int places = 1; //default number of places
	int count = 1; //count the value of each place
	int memoized[100]; //an array of integers, one index represents a 'place'

	while(num >= (count*10)) //find the power of 10 not exceeding the number
	{
		places++; //for each power of ten, increase the places
		count = count*10;
	}

	while(i < places) //in each place
	{
		memoized[i] = 0; //start at 0
		while(num >= count) //while the number is greater than the power of 10
		{
			num = num - count; //subtract powers of 10 from num
			memoized[i]++; //incrementing the memoized number
		}
		buffer[i] = i_to_c(memoized[i]); //convert the memoized int to a char in buffer
		count = count/10; //reduce the power of 10
		i++;
	}
	buffer[i] = '\0';

	return i+1; //return the number of places
}

/******************************************************
 * char i_to_c(int num)
 *
 *      Based on an integer parameter (should be 0-9),
 *      return a single corresponding character. *
 * *************************************************/
char i_to_c(int num)
{
	if(num == 0)
		return '0';
	else if(num == 1)
		return '1';
	else if(num == 2)
		return '2';
	else if(num == 3)
		return '3';
	else if(num == 4)
		return '4';
	else if(num == 5)
		return '5';
	else if(num == 6)
		return '6';
	else if(num == 7)
		return '7';
	else if(num == 8)
		return '8';
	else if(num == 9)
		return '9';
	else
		printf("Catastrophe\n");


}
