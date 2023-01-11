/**********************************************************************
 * John Kaufman: kaufmjoh@oregonstate.edu
 *
 * CS344 Assignment 4: OTP (otp_enc_d)
 *
 * This program is a daemon, which will run in the background.
 *
 * It listens for connections from clients, hosting up to 5 connections at a time
 *
 * When a connection is made, this daemon will read from the client plaintext
 * and a key, encrypt it, and write back to the client cipher_text
 ******************************* ***************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#define ROW_LENGTH 10 //THE LENGTH OF A ROW OF THE BUFFER / THE NUMBER OF LETTERS SENT A TIME IN recv() and send()

int children = 0; //The number of children processes currently running
 
void commence_communications(int establishedConnectionFD, char ** buffer[3]);
void server_from_client(int size, int establishedConnectionFD, char** buffer);

void enc_message(char* plaintext, char* key, char* encrypted, int size);

void error(const char* msg) {perror(msg); exit(1); }

void catchSIGCHLD(int signo, siginfo_t* data, void* blank);

int main(int argc, char* argv[])
{
	//Trap SIGCHLD(sent when a child terminates)
	struct sigaction SIGCHLD_action = {0};
	SIGCHLD_action.sa_sigaction = catchSIGCHLD;
	sigfillset(&SIGCHLD_action.sa_mask);
	SIGCHLD_action.sa_flags = SA_SIGINFO;
	sigaction(SIGCHLD, &SIGCHLD_action, NULL);

	int listenSocketFD; //socket for listening
	int establishedConnectionFD; //store the accepted socket here
	int portNumber; //port to connect to
	int charsRead; //catch the number of bytes read

	struct sockaddr_in serverAddress, clientAddress;
	socklen_t sizeOfClientInfo;
	
	char** buffer [3]; //store the information here
	int size; //the size of the message
	int i = 0; //general index
	char misc_buffer[256]; //general buffer

	pid_t spawn_PID; //PID of child
	pid_t actual_PID; //PID of paren
	int child_exit_method;

	int waiting = 0; //holds whether or not a process is waiting
	int mostRecentConnection = -1; //the FD for the most recent connection

	//Set up the Server Address
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));
	portNumber = atoi(argv[1]);
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(portNumber);
	serverAddress.sin_addr.s_addr = INADDR_ANY;

	//Set up the listening socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
	if(listenSocketFD < 0) error("Error: could not open socket for listening\n");

	//Bind the socket and start listening
	if(bind(listenSocketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) 
		fprintf(stderr, "Error: could not bind on port: %s\n", argv[1]);

	listen(listenSocketFD, 10); //start listening for up to ten connections at a time

	while(1) //Always be listening for another connection
	{
		//Accept A connection
		do
		{
			//Accept a new connection if none are waiting, blocking if one is not available until one connects
			if(waiting == 0)
			{
				sizeOfClientInfo = sizeof(clientAddress);
				establishedConnectionFD = accept(listenSocketFD, (struct sockaddr*) & clientAddress, &sizeOfClientInfo);
			}
			//IF THERE ARE ALREADY 5 Connections
			if(children > 4)
			{
				if(waiting == 0)
					fprintf(stderr, "Error: no more processes may be created at this time\n");
				waiting = 1; //Wait
				sleep(2);
			}
			
		}
		while(mostRecentConnection == establishedConnectionFD || establishedConnectionFD == -1 || children > 4);
		//do not move on if a new connection is not made, or an error has occured, or there are already 5 children

		waiting = 0;
		mostRecentConnection = establishedConnectionFD;

		if(children <= 5)
		{
			children++; //increment the number of children
			spawn_PID = fork(); //FORK A NEW PROCESS
			if(spawn_PID == 0)
			{

				//CONNECT TO THE CLIENT
				if(establishedConnectionFD < 0) 
				{
					error("SERVER: Error on accepting socket\n");
					exit(1);
					kill(getpid(), 0);
				}
				
				//AFFIRM THE CONNECTION HAS ARRIVED FROM otp_enc.c
				memset(misc_buffer, '\0', 256);
				charsRead = recv(establishedConnectionFD, misc_buffer, 1, 0);
				if(misc_buffer[0] == 'E')
				{
					//if the connection has been affirmed, give the "Go" to client
					charsRead = send(establishedConnectionFD, "G", 1, 0);
					if(charsRead < 0) error("SERVER: Error writing to socket\n");
				}
				else
				{
					//if the connection is not correct, tell the client "No go"
					charsRead = send(establishedConnectionFD, "N", 1, 0);
					if(charsRead < 0) error("SERVER: Error writing to socket\n");
//					fprintf(stderr, "Invalid Client Connection. \n");
					execlp("sleep", "sleep", "0", NULL);
					kill(getpid(), 3);
				}

//				printf("SERVER: Connected Client with PID: %d at port: %d\n",getpid(),ntohs(clientAddress.sin_port));

				//BEGIN THE COMMUNICATION PROCESS
				commence_communications(establishedConnectionFD, buffer);
			
				//printf("SERVER: Finished sending all data.\n");

				execlp("sleep","sleep" ,"0", NULL);
				close(establishedConnectionFD);

			}
			else
			{
				sleep(1);
				//actual_PID = waitpid(spawn_PID, &child_exit_method, 0);
				//This is the parent process, it currently doesn't do anything
			}
		}
	}

	close(listenSocketFD);
	

	return 0;

}

/****************************************************************************
 * void commence_communications(int establishedConnectionFD, char** buffer[3])
 *
 * Once a process has been forked in the main, and a connection to a client
 * established, this fucntion is called to handle the communication with the
 * client
 *
 * This function reads from the client a confirmation char, the size of the
 * message, plaintext, and a key. This function writes ciphertext back
 * to the client
 * ************************************************************************/
void commence_communications(int establishedConnectionFD, char** buffer[3])
{
	char misc_buffer[256];
	int charsRead;
	int size;
	int i = 0;

//	sleep(5);
	memset(misc_buffer, '\0', 256);
	
	//Read the size of the message from the client
	charsRead = recv(establishedConnectionFD, misc_buffer, 255, 0);
	if (charsRead < 0) error("SERVER: Error reading from the socket\n");
	//printf("Server: the size is: %s, numerized: %d\n", misc_buffer, atoi(misc_buffer));
	size = atoi(misc_buffer);
	
	//Send a success message back to the client
	charsRead = send(establishedConnectionFD, "I am the server, and I got your 0th message", 43, 0);
	if(charsRead < 0) error("SERVER: Error writing to socket\n");

	//ALLOCATE MEMORY FOR THE BUFFER
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
	i = 0;
	buffer[2] = malloc(sizeof(char*) * ((size / ROW_LENGTH) + 1));
	while(i < ((size / ROW_LENGTH) + 1))
	{
		buffer[2][i] = malloc(sizeof(char) * ROW_LENGTH);
		memset(buffer[2][i], '\0', ROW_LENGTH);
		i++;
	}
	//MEMORY HAS BEEN ALLOCATED TO THE BUFFER

	//Get data from the client
	//Receive the PLAINTEXT from the client
	server_from_client(size, establishedConnectionFD, buffer[0]);

	//Receive the KEY from the client
	server_from_client(size, establishedConnectionFD, buffer[1]);


	//ENCRYPT PLAINTEXT
	//printf("SERVER: Preparing to encrypt message\n");
	i = 0;
	while(i < (size / ROW_LENGTH)+1)
	{
		enc_message(buffer[0][i], buffer[1][i], buffer[2][i], size);
//		printf("SERVER: created an encrypted line: %s\n", buffer[2][i]);
		i++;
	}

	//SEND the CIPHERTEXT to the Client
	i = 0;
	while(i < (size / ROW_LENGTH) + 1)
	{
		charsRead = send(establishedConnectionFD, buffer[2][i], ROW_LENGTH, 0);
		if(charsRead < 0) error("SERVER: Error writing to socket\n");
		i++;
	}
}

/******************************************************************************
 * void server_from_client(int size, int establishedConnectionFD, char** buffer)
 *
 *  Read information from the client, and write back a message of affirmation.
 *
 *  The message is size letters long, stored in buffer, and should be written
 *  to establishedConnectionFD
 * ****************************************************************************/
void server_from_client(int size, int establishedConnectionFD, char** buffer)
{
	int charsRead;
	int i = 0;
	while(i < (size / ROW_LENGTH) + 1)//information is stored in a 2d array of chars, sent ROW_LENGTH letters at a time
	{
		//GET Information FROM THE CLIENT	
		charsRead = recv(establishedConnectionFD, buffer[i], ROW_LENGTH, 0);
		if (charsRead < 0) error("SERVER: Error reading from the socket\n");
		//printf("SERVER: Bytes read: %d; Client Message: %s\n",charsRead, buffer[i]);

		//Send a success message back to the client
		charsRead = send(establishedConnectionFD, "I am the server, and I got your 1st message", 43, 0);
		if(charsRead < 0) error("SERVER: Error writing to socket\n");
		i++;
	}
}

/**********************************************************************
 * void enc_message(char* plaintext, char* key, char* encrypted, int size)
 *
 *	Encrypt the line of plaintext with the key, storig results in
 *	encrypted.
 *
 *	use ascii values to calculate the value of the encrypted char
 * ********************************************************************/
void enc_message(char* plaintext, char* key, char* encrypted, int size)
{
	int text_nums[ROW_LENGTH+1]; //an array of integers to represent a char
	int key_nums[ROW_LENGTH+1]; //an array of integers to represent a char
	int combined;

	char* source = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

	int i = 0;
	while(i < ROW_LENGTH) //for char in the row
	{
		//printf("Encrypting: %c at [%d]\n", plaintext[i], i);

		//Check to make sure the char is valid
		if((plaintext[i] < 65 || plaintext[i] > 90) && plaintext[i] != ' ' &&plaintext[i] != '\0')
		{
			fprintf(stderr, "SERVER Error: Bad Input Found\n");
			encrypted[0] = '\0';

		}
		else if(plaintext[i] == '\0')
		{
			int k = 1;
		}
		else
		{
			//Assign an integer 0-26 to the corresponding index char
			if(plaintext[i] == ' ')
				text_nums[i] = 26;
			else
				text_nums[i] = plaintext[i] - 65;

			if(key[i] == ' ')
				key_nums[i] = 26;
			else
				key_nums[i] = key[i] - 65;

			//Combine the two integers to find the encrypted value
			combined = (text_nums[i] + key_nums[i])% 27;
			//printf("Text Value (%d) + Key value (%d) %27 =: %d\n", text_nums[i], key_nums[i], combined);
			//Assign encrypted[i] the corresponding char
			if(combined == 26)
				encrypted [i] = ' ';
			else
				encrypted [i] = combined + 65;

		}
		i++;
	}
	
	encrypted[i] = '\0';

}

/***********************************************************
 * void catchSIGCHLD(int signo, siginfo_t* data, void* blank)
 *
 *  When a child dies, catch the SIGCHLD sent to the parent.
 *
 *  Reap the child, and decrease the global counter for the
 *  number of running children *
 * *********************************************************/
void catchSIGCHLD(int signo, siginfo_t* data, void* blank)
{
	int stat;
	waitpid((*data).si_pid, &stat, 0);

//	write(STDOUT_FILENO, "A child has terminated\n", 23);
	children--;
}



