/*
    AES Encryption Program (AES-128)
    
    - Encrypts a user-input message using AES-128 encryption.
    - Reads a 128-bit key from "keyfile".
    - Pads the input message to a multiple of 16 bytes.
    - Performs 10 rounds of AES encryption.
    - Writes the encrypted message to "message.aes".
*/

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <ctime>

#include "structures.h"



using namespace std;


/*
    XORs each byte of the state with the corresponding round key byte.
    serves as the initial round during encryption
    AddRoundKey is simplye an XOR of a 128-bit block with the 128-bit key.
    the AddRoundKey step is one of the four main transformations in each AES round. it ensures that the encryption is securely linked to the secret key, making brute-force attacks difficult.
*/
void AddRoundKey(unsigned char* state, unsigned char* roundKey)
{
    for(int i = 0; i < 16; i++)
    {
        state[i] ^= roundKey[i];
    }
}


/*
    Perform substitution to each of the 16 bytes 
    uses S-box as lookup table

*/

void subBytes(unsigned char * state){
    for(int i = 0 ; i < 16 ; i++){
        state[i] = s[state[i]];
    }
}


// Shifts rows to the left for diffusion.
void ShiftRows(unsigned char * state){
    unsigned char temp[16];

    // first column
    temp[0] = state[0];
    temp[1] = state[5];
    temp[2] = state[10];
    temp[3] = state[15];

    // second column
    temp[4] = state[4];
    temp[5] = state[9];
    temp[6] = state[14];
    temp[7] = state[3];
    // third column
    temp[8] = state[8];
    temp[9] = state[13];
    temp[10] = state[2];
    temp[11] = state[7];
    // fourth column
    temp[12] = state[12];   
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];

    for(int i = 0 ; i < 16 ; i++){
        state[i] = temp[i];
    }
}


/* MixColumns uses mul2, mul3 look-up tables
  * Source of diffusion
  */
 void MixColumns(unsigned char * state) {
	unsigned char tmp[16];

	tmp[0] = (unsigned char) mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
	tmp[1] = (unsigned char) state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
	tmp[2] = (unsigned char) state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
	tmp[3] = (unsigned char) mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

	tmp[4] = (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
	tmp[5] = (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
	tmp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
	tmp[7] = (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

	tmp[8] = (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
	tmp[9] = (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
	tmp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
	tmp[11] = (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

	tmp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
	tmp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
	tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
	tmp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}


/* Each round operates on 128 bits at a time 
    the number of rounds is defined in AESEncrypt()
*/

void Round(unsigned char * state, unsigned char * key){
    subBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state,key);
}


// same as Round() except it doesn't mix columns
void FinalRound(unsigned char * state, unsigned char * key){
    subBytes(state);
    ShiftRows(state);
    AddRoundKey(state,key);
}


// The AES ecryption function organizes the confusion and diffusion steps into one function
void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * enctypedMessage){

    unsigned char state[16]; // stores the first 16 bytes of orginal message

    for(int i =0 ; i< 16 ; i++){
        state[i] = message[i];
    }

    int numberOfRounds = 9;

    AddRoundKey(state, expandedKey); // initial round

    for(int i = 0 ; i< numberOfRounds; i++){
        Round(state, expandedKey + (16 * (i+1)));
    }

    FinalRound(state , expandedKey + 160);

    // Copy encrypted state to buffer
    for(int i = 0 ; i< 16 ; i++){
        enctypedMessage[i] = state[i];
    }

}

int main() {
    cout << "=============================" << endl;
	cout << " 128-bit AES Encryption Tool   " << endl;
	cout << "=============================" << endl;


    char message[1024];

    cout << "Enter the message to encrpyt: " ;
    cin.getline(message, sizeof(message));
    cout << message << endl;


    // Padding message to 16 bytes
    int originalLen = strlen((const char *) message);

    int paddedMessageLen = originalLen;
    
    if((paddedMessageLen % 16) !=0){
        paddedMessageLen = (paddedMessageLen / 16 + 1) * 16;
    }

    unsigned char * paddedMessage = new unsigned char[paddedMessageLen];  // dynamically alocates memory for padded message
	for (int i = 0; i < paddedMessageLen; i++) {
		if (i >= originalLen) {
			paddedMessage[i] = 0; // pads remaining bytes with 0x00(zero padding).
		}
		else {
			paddedMessage[i] = message[i]; // copies the original message to padded message
		}
	}

    // make the encrypted message the same size as output
    unsigned char * encryptedMessage = new unsigned char[paddedMessageLen];

    // getting key from keyfile
    string str;
    ifstream infile;
    infile.open("keyfile", ios::in | ios::binary); // open file in binary mode

    if(infile.is_open()){
        getline(infile,str);  // reads the key from file as hexadecimal string
        infile.close();
    } else {
        cout << "Unable to open file";
    }

    // convert the hex key to bytes
    istringstream hex_chars_stream(str);
    unsigned char key[16];
    int i = 0 ;
    unsigned int c;
    while(hex_chars_stream >> hex >> c){
        key[i] = c;
        i++;
    }

    // expand the key (AES-128 requires 176 bytes(44 words) of expanded key)
    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    // Encrypt the message : each 16-byte block 
    // paddedMessage + i : pointer to current 16-byte block
    // encryptedMessage + i : stores to current 16-byte block
    for(int i = 0 ; i < paddedMessageLen; i +=16){
        AESEncrypt(paddedMessage+i, expandedKey, encryptedMessage + i);
    }

    cout << "Encrypted message in hex:" << endl;
	for (int i = 0; i < paddedMessageLen; i++) {
		cout << hex << (int) encryptedMessage[i];
		cout << " ";
	}

    cout << endl;


    // Write encrypted message to file "message.aes"
    ofstream outfile;
    outfile.open("message.aes", ios::out | ios::binary);
    if(outfile.is_open()){
        outfile << encryptedMessage;
        outfile.close();
        cout << "Wrote encrypted message to file message.aes" << endl;
    } else {
        cout << "Unable to open file";
    }


    // Free Memory dynamically allocated memory to prevent memory leaks
    delete[] paddedMessage;
    delete[] encryptedMessage;

    

    return 0;

}
