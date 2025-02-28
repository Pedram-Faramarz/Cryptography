/*
decrypt.cpp file for decrypting the data using the AES algorithm

Performs decryption using AES 128 bit

*/

#include <iostream>
#include <cstring>  
#include <fstream>
#include <sstream>
#include "structures.h" // Contains necessary AES lookup tables and key expansioin function

using namespace std;


/*
    XORs the current state with the round key.
    This is the only operation used in the final round and the first step of AES decryption.
    Since XOR is reversible, it allows us to retrieve the original message.
*/
void AddRoundKey(unsigned char* state, unsigned char* roundKey)
{
    for(int i = 0; i < 16; i++)
    {
        state[i] ^= roundKey[i];
    }
}


/*
    InverseMixColumns - Reverses the MixColumns step of AES encryption.
    Uses precomputed multiplication lookup tables (mul9, mul11, mul13, mul14).
    This function ensures that the diffusion effect introduced during encryption is reversed.
*/

void InverseMixColumns(unsigned char * state){
    unsigned char tmp[16];
    
    // Perform matrix multiplication in GF(2^8)
    tmp[0] = (unsigned char) mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
    tmp[1] = (unsigned char) mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
    tmp[2] = (unsigned char) mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
    tmp[3] = (unsigned char) mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

    tmp[4] = (unsigned char) mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
    tmp[5] = (unsigned char) mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
    tmp[6] = (unsigned char) mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
    tmp[7] = (unsigned char) mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

    tmp[8] = (unsigned char) mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
    tmp[9] = (unsigned char) mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
    tmp[10] = (unsigned char) mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
    tmp[11] = (unsigned char) mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

    tmp[12] = (unsigned char) mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
    tmp[13] = (unsigned char) mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
    tmp[14] = (unsigned char) mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
    tmp[15] = (unsigned char) mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];


    // Copy results back to state
    for(int i = 0 ; i< 16 ; i++){
        state[i] = tmp[i];
    }
    
}

/*
    ShiftRows - Performs the inverse of the ShiftRows transformation.
    This undoes the shifting performed during encryption.
*/
void ShiftRows(unsigned char * state){
    unsigned char tmp[16];

    // First row remains unchanged
    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];

    // second column
    tmp[4] = state[4];
    tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	// third column
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	// fourth column
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];


    // Copy results back to state
    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
    
}


/*
    SubBytes - Applies the inverse S-Box to each byte of the state.
    This reverses the byte substitution step in encryption.
*/
void SubBytes(unsigned char * state){
    for(int i = 0 ;  i < 16 ; i++){ 
        state[i] = inv_s[state[i]]; // inv_s is the inverse S-Box lookup table
    }
}


/*
    Round - Performs one full round of AES decryption.
    Each round includes AddRoundKey, InverseMixColumns, ShiftRows, and SubBytes.
*/

void Round(unsigned char * state, unsigned char * key) {
	AddRoundKey(state, key);
	InverseMixColumns(state);
	ShiftRows(state);
	SubBytes(state);
}

/*
    InitialRound - The first round of AES decryption (excludes InverseMixColumns).
*/
void InitialRound(unsigned char * state , unsigned char * key){
    AddRoundKey(state, key);
    ShiftRows(state);
	SubBytes(state);
}

/*
    AESDecrypt - Main decryption function.
    Decrypts a 16-byte block of encrypted data using AES-128.
*/
void AESDecrypt( unsigned char * encryptedMessage, unsigned char * expandedKey, unsigned char * decryptedMessage){
    unsigned char state[16];  // stores the first 16 bytes of encrypted message

    // Copy encrypted message into state
    for(int i = 0 ; i< 16 ; i++){
        state[i] = encryptedMessage[i];
    }


    // Perform Initial Round with the last round key
    InitialRound(state, expandedKey+160); // Last round key is used first

   // Perform 9 main rounds (AES-128 has 10 rounds total)
    for(int i = 8 ; i >=0 ; i--){
        Round(state, expandedKey + (16 * (i + 1)));
    }

    // Final round (only AddRoundKey step)
    AddRoundKey(state, expandedKey); 

    // Copy decrypted state to output buffer
    for(int i= 0; i< 16 ;i ++){
        decryptedMessage[i] = state[i];
    }
}


int main(){
    cout << "=============================" << endl;
	cout << " 128-bit AES Decryption Tool " << endl;
	cout << "=============================" << endl;


    // Read encrypted message from file
    string messageString;
    ifstream infile;
    infile.open("message.aes", ios::in | ios::binary);
    
    if(infile.is_open()){
        getline(infile,messageString);
        cout << "Read in encrypted message from message.aes " << endl;
        infile.close();
    } else {
        cout << "Unable to open file";
    }

    // Convert message to unsigned char array
    char * message = new char [messageString.size()+1];
    strcpy(message, messageString.c_str());
    int n = strlen((const char*) message);

    unsigned char * encryptedMessage = new unsigned char[n];
    for(int i = 0 ; i < n ; i++){
        encryptedMessage[i] = (unsigned char ) message[i];
    }



    // Read encryption key from file
    string keyString;
    ifstream keyfile;
    keyfile.open("keyfile", ios::in | ios::binary);
    
    if(keyfile.is_open()){
        getline(keyfile, keyString); // read the first line

        cout << "Read in the 128-bit key from keyfile" << endl;     
        keyfile.close();
    } else {
        cout << "Unable to open file";
    }

    // Convert hex key string to byte array

    istringstream hex_chars_stream(keyString);
	unsigned char key[16];
	int i = 0;
	unsigned int c;
	while (hex_chars_stream >> hex >> c)
	{
		key[i] = c;
		i++;
	}

    // Generate expanded key
    unsigned char expandedKey[176];
    KeyExpansion(key, expandedKey);

    // Allocate memory for decrypted message
    int messageLen = strlen((const char * ) encryptedMessage);
    unsigned char * decryptedMessage = new unsigned char[messageLen];

    // Decrypt message in 16-byte blocks
    for(int i = 0 ; i < messageLen; i+=16){
        AESDecrypt(encryptedMessage + i , expandedKey, decryptedMessage + i);
    }

    // Output decrypted message in hex format
    cout << "Decrypted message in hex:" << endl;
	for (int i = 0; i < messageLen; i++) {
		cout << hex << (int)decryptedMessage[i];
		cout << " ";
	}
	cout << endl;

    // Output decrypted message as text
	cout << "Decrypted message: ";
	for (int i = 0; i < messageLen; i++) {
		cout << decryptedMessage[i];
	}

	cout << endl;

    // Free allocated memory
    delete[] encryptedMessage;
    delete[] decryptedMessage;

    return 0;
}