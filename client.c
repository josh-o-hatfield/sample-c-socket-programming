// CSCI-C 291 (Section 7784)
// Final Project Option 2: Network Programming
// Project Group 5: Josh Hatfield and Nick Mathein
// 12/8/2022

// client.c - Client-side input that encrypts and sends message to a specified server

#include <stdio.h>
#include <string.h>

// Header files for socket programming
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8000

// Max Length of the plaintext
#define MESS_LEN 500

// arbitrary character array size for key storage as character
#define SIZE 80

// max length of the ciphertext combined with arbitrary key length
#define TOTAL_MESS_LEN 580

// function prototypes
int get_len_key(int key);
char *toString(int key);
char *encrypt(char *plain_text, int key);

// determines the number of digits of the key that will be used within the toString() function
int get_len_key(int key){
	// variable for calculating number of digits
	int digits_calc = 0;
	// variable for storing number of key digits
	int key_digits = 0;
	// temporary variable referencing key so as to not change original key
	int temp_key = key;
	
	// if key is only one digit, set number of key digits to 1 and return
	if (temp_key / 10 == 0) {
		key_digits = 1;
	
		return key_digits;
	}
	// else, decrement by factor of 10 and add number of key digits until division equals 0
	else {
		// Return the number of digits of the key
		while (temp_key != 0) {
			digits_calc = temp_key / 10;
			key_digits++;
		}
	}
}

// converts the integer key to a character pointer for concatenation
char *toString(int key) {
	// 1. Get the number of digits of the key
	
	// variable for storing return value of the number of digits of the key
	int key_digits = 0;
	
	// call to get_len_key() function and utilize key as parameter passed
	get_len_key(key);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 2. Convert into a character pointer and return it.
	
	// variable for initially converting integer key to string
	char key_char[SIZE] = "";
	
	// function for converting integer to string and storing in key_char
	sprintf(key_char, "%d", key);
	
	// variable acting as character pointer
	char * key_char_pointer = key_char;
	
	// return key pointer back to the encrypt() function
	return key_char_pointer;
}

// encrypts the plaintext message and concatenates with the key for future decryption by the server
char *encrypt(char *plain_text, int key) {
	// 1. Convert the plain_text to encrypt_text using key
	
	// temporary char array that allows us to make conversions for plaintext to ciphertext given key
	char cipher_text[MESS_LEN] = "";
	
	// algorithm that converts the plaintext to ciphertext; 
	// needs to account for:
		// lowercase characters incremented by the key at the end of the alphabet (Ex. y with key 3 = b)
		// uppercase characters incremented by the key at the end of the alphabet (Ex. Y with key 3 = B)
		// numbers incremented by the key at the end of single-digit numbers (Ex. 7 with key 3 = 0; 8 with key 3 = 1)
	for (int i = 0; i < strlen(plain_text); i++) {
		// spaces are not affected by key incrementation
		if (plain_text[i] == ' ') {
			cipher_text[i] = plain_text[i];
		}
		// accounts for lowercase characters; if character + key is greater than 'z', go back to 'a' or equivalent and increment
		else if ((plain_text[i] + key > 122) && (plain_text[i] >= 97 && plain_text[i] <= 122)) {
			cipher_text[i] = plain_text[i] - 26 + key;
		}
		// accounts for uppercase characters; if character + key is greater than 'Z', go back to 'A' or equivalent and increment
		else if ((plain_text[i] + key > 90) && (plain_text[i] >= 65 && plain_text[i] <= 90)) {
			cipher_text[i] = plain_text[i] - 26 + key;
		}
		// accounts for integer; if integer + key is greater than '9', go back to '0' or equivalent and increment
		else if ((plain_text[i] + key > 57) && (plain_text[i] >= 48 && plain_text[i] <= 57)) {
			cipher_text[i] = plain_text[i] - 10 + key;
		}
		// add key normally to any remaining characters not affected by letter or number sequencing
		else {
			cipher_text[i] = plain_text[i] + key;
		}
	}
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 2. Convert the key (int) to a Character pointer using the toString() method.
	
	// call to toString() function, utilizing key as parameter passed
	char * key_char_pointer = toString(key);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 3. Concat key:encrypt_text
	
	// pointer that combines key pointer with : delimiter with ciphertext
	char * encrypted_message = strcat(strcat(key_char_pointer, ":"), cipher_text);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 4. Return the key:encrypt_text to main() method
	return encrypted_message;
}
void main(){
	// 1. Create socket
	
	// socket points to the include statement above, where:
		// the AF_INET argument specifies the protocol family
		// the SOCK_DGRAM argument specifies UDP traffic transmission
		// the 0 argument specifies using the default protocol for the address family
	int socket_desc = socket(PF_INET, SOCK_DGRAM, 0); 
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 2. Initialize the struct variables
	
	// creates a struct utilizing sockaddr_in as specified by the netinet/in.h include statement; essentially acts as the OUTPUT chain 
	struct sockaddr_in server_addr;
	
	// adds a new variable to the struct, where sin_family represents the address family matching AF_INET for IPv4
	server_addr.sin_family = AF_INET;
	
	// adds a new variable to the struct, where sin_port represents the port to listen on (previously specified as 8000);
	// htons takes the port as a 16-bit number in host byte order and converts/returns as aa 16-bit number network byte order
	server_addr.sin_port = htons(PORT);
	
	// adds a new variable to the struct, where sin_addr.s_addr binds to local addresses
	server_addr.sin_addr.s_addr = INADDR_ANY;
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 3. Take a key and plain plain_text as an input (Key: Int, Plain plain_text: Pointer Array of character)
	
	// int variable that will be utilized to increment characters based on a simple Caesar cipher shift
	int encrypt_key = 0;
	
	// pointer array of characters with max array size defined as 500 characters
	char client_plain_text[MESS_LEN] = "";

	// plaintext prompt
	printf("Enter a message to encrypt: ");
	// user input with max size 500
	fgets(client_plain_text, MESS_LEN, stdin);
	
	// key prompt
	printf("Enter key: ");
	// scanf key size
	scanf("%d", &encrypt_key);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 4. Encrypt the plain text using key
	
	// call to encrypt() function, where the plaintext array and integer key act as the parameters
	char * encrypted_text = encrypt(client_plain_text, encrypt_key);
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 5. Send the encrypt_text to Server using the sendto() method.
	
	// calls the sendto function, where:
		// the socket_desc argument references the file descriptor of the socket
		// the buffer (encrypted_text) argument is the application buffer for receiving data
		// the strlen(encrypted_text) argument includes the size of buffer application buffer
		// the flag (0) argument allows bitwise OR functionality to modify socket behavior
		// the (struct sockaddr*) &server_addr argument references to the struct containing the server address
		// the &client_struct_length references the previous variable of the size of the client_addr structure
	sendto(socket_desc, encrypted_text, strlen(encrypted_text), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
	
	// -----------------------------------------------------------------------------------------------------------------------------
	
	// 6. Print the encrypt_text
	printf("Data Sent: %s\n", encrypted_text);
}