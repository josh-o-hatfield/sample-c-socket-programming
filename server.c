// CSCI-C 291 (Section 7784)
// Final Project Option 2: Network Programming
// Project Group 5: Josh Hatfield and Nick Mathein
// 12/8/2022

// server.c - UDP server that receives message from client and decrypts encrypted message

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Header files for socket programming
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8000
#define MESS_LEN 500

// function prototypes
char *decrypt(char *cipher_text, int key);
int toInt(char *key);
char *split(char *text, int n);

// decrypts the ciphertext message given the key split from the message and converted to an integer
char *decrypt(char *cipher_text, int key){
	// 1. Decrypt the text using key and return the plain text
	
	// temporary char array that allows us to make conversions for ciphertext to plaintext given key
	char plain_text[MESS_LEN] = "";
	
	// algorithm that converts the ciphertext to plaintext; 
	// needs to account for:
		// lowercase characters decremented by the key at the beginning of the alphabet (Ex. b with key 3 = y)
		// uppercase characters decremented by the key at the end of the alphabet (Ex. B with key 3 = Y)
		// numbers decremented by the key at the end of single-digit numbers (Ex. 0 with key 3 = 7; 1 with key 3 = 8)
	for (int i = 0; i < strlen(cipher_text); i++) {
		// spaces are not affected by key incrementation
		if (cipher_text[i] == ' ') {
			plain_text[i] = cipher_text[i];
		}
		// accounts for lowercase characters; if character - key is less than 'a', go forward to 'z' or equivalent and decrement
		else if ((cipher_text[i] - key < 97) && (cipher_text[i] >= 97 && cipher_text[i] <= 122)) {
			plain_text[i] = cipher_text[i] + 26 - key;
		}
		// accounts for uppercase characters; if character - key is less than 'A', go forward to 'Z' or equivalent and decrement
		else if ((cipher_text[i] - key < 65) && (cipher_text[i] >= 65 && cipher_text[i] <= 90)) {
			plain_text[i] = cipher_text[i] + 26 - key;
		}
		// accounts for integers; if integer - key is less than '0', go back to '9' or equivalent and decrement
		else if ((cipher_text[i] - key < 48) && (cipher_text[i] >= 48 && cipher_text[i] <= 57)) {
			plain_text[i] = cipher_text[i] + 10 - key;
		}
		// subtract key normally to any remaining characters not affected by letter or number sequencing
		else {
			plain_text[i] = cipher_text[i] - key;
		}
	}
	
	// stores temporary char array as a pointer that we can use as arguments for other functions
	char * plain_text_pointer = plain_text;
	
	// returns plaintext pointer to split() function
	return plain_text_pointer;
}

// takes the key pointer as an argument and converts key to integer using strtol() function
int toInt(char *key){
	// 1. Convert the key of character array to int and return it
	
	// variable for storing key as an integer
	int key_int = 0;
	// need a pointer for converting key as char to int
	char * key_pointer;
	
	// strtol converts char to integer
	key_int = strtol(key, &key_pointer, 10);
	
	// returns key as an integer later for the decrypt() function
	return key_int;
}

// splits message using : delimiter, where the key and ciphertext are tokenized and stored
char *split(char *text, int n){
	// 1. Split the key and encrypted text
	
	// variable indicating : delimiter for splitting the message into the key and ciphertext
	char * delimiter = ":";
	
	// token variable for tokenizing the message with every delimiter occurrence indicated
	char * token = strtok(text, delimiter);
	
	// after initial tokenization, key can be pointed to and stored
	char * key = token;
	
	// ciphertext variable for pointing and storing latter part of message
	char * split_text = token;
	
	// ends tokenization where \n exists, assuming fgets is used on client side
	while (token != NULL) {
		split_text = token;
		token = strtok(NULL, "\n");
	}
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 2. Convert the key to int
	
	// call to toInt() function, where the key pointer is converted to an integer
	int key_int = toInt(key);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 3. Call the decrypt function with encrypted text and key as an argument
	
	// call to decrypt() function, where the ciphertext is converted to plaintext using the key_int argument
	char * plain_text = decrypt(split_text, key_int);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 4. Return the plain text to main
	return plain_text;
}

void main() {
	// 1. Create Socket
	
	// socket points to the include statement above, where:
		// the AF_INET argument specifies IPv4 for the communication domain
		// the SOCK_DGRAM argument specifies UDP traffic transmission
		// the 0 argument specifies using the default protocol for the address family
	int socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 2. Initialize the struct variables
	
	// creates a struct utilizing sockaddr_in as specified by the netinet/in.h include statement; essentially acts as the INPUT chain
	struct sockaddr_in server_addr;
	
	// adds a new variable to the struct, where sin_family represents the address family matching AF_INET for IPv4
	server_addr.sin_family = AF_INET;
	
	// adds a new variable to the struct, where sin_port represents the port to listen on (previously specified as 8000);
	// htons takes the port as a 16-bit number in host byte order and converts/returns as aa 16-bit number network byte order
	server_addr.sin_port = htons(PORT);
	
	// adds a new variable to the struct, where sin_addr.s_addr binds to local addresses
	server_addr.sin_addr.s_addr = INADDR_ANY;
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 3. Bind
	
	// bind associates the socket with the local address, where:
		// the socket_desc argument references the file descriptor of the socket
		// the (struct sockaddr*)&server_addr argument points to the struct and supplementarily describes the local interface
		// ... to which the socket is to be bound
		// the sizeof(server_addr) argument references the byte size of the struct
	bind(socket_desc, (struct sockaddr*)&server_addr, sizeof(server_addr));
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 4. Create client_addr struct and get the length of struct client_addr
	
	// creates a struct utilizing sockaddr_in as specified by the netinet/in.h include statement; will act to specify the client
	struct sockaddr_in client_addr;
	
	// determines and stores byte size of the client_addr struct
	int client_struct_length = sizeof(client_addr);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 5. Wait for the Client to send the message and receive it using recfrom() method, and return type is int (Length of the message)
	
	// variable for storing the encrypted_text retrieved from the server during the recvfrom() function
	char encrypted_text[MESS_LEN] = "";
	
	// the server must receive the client's address and other information only after recvfrom() is initialized
	// calls the recvfrom function, where:
		// the socket_desc argument references the file descriptor of the socket
		// the buffer (encrypted_text) argument is the application buffer for receiving data
		// the sizeof(encrypted_text) argument includes the size of buffer application buffer
		// the flag (0) argument allows bitwise OR functionality to modify socket behavior
		// the (struct sockaddr*) &client_addr argument references to the struct containing the client address
		// the &client_struct_length references the previous variable of the size of the client_addr structure
	// int n returns the length of the message
	int n = recvfrom(socket_desc, encrypted_text, sizeof(encrypted_text), 0, (struct sockaddr*) &client_addr, &client_struct_length);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 6. Call the split() function and inside a split function, call the decrypt function to get plain text
	
	char * text = split(encrypted_text, n);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 7. Print the plain text returned and stored from the split() function above
	printf("Data Received: %s", text);
}