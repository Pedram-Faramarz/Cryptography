/*
    AES Encryption Program with Avalanche Effect Analysis
    
    - Encrypts a user-input message using AES-128 encryption.
    - Reads a 128-bit key from "keyfile".
    - Allows modifying a specific bit in the plaintext or key.
    - Tracks bit changes in the ciphertext after each encryption round.
    - Exports bit change data to "avalanche_data.csv" for visualization.
*/


#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
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

// Function to count differing bits between two blocks
int countChangedBits(unsigned char *original, unsigned char *modified, int length) {
    int count = 0;
    for (int i = 0; i < length; i++) {
        unsigned char diff = original[i] ^ modified[i];
        while (diff) {
            count += diff & 1;
            diff >>= 1;
        }
    }
    return count;
}

// Function to flip a specific bit in a byte array
void flipBit(unsigned char *data, int bitPos) {
    int byteIndex = bitPos / 8;
    int bitIndex = bitPos % 8;
    data[byteIndex] ^= (1 << bitIndex);
}

// Modified AES Encryption function to track avalanche effect
void AESEncryptWithAvalanche(unsigned char *message, unsigned char *expandedKey, unsigned char *encryptedMessage, ofstream &dataFile) {
    unsigned char state[16];
    unsigned char originalState[16];

    for (int i = 0; i < 16; i++) {
        state[i] = message[i];
        originalState[i] = message[i];
    }

    int numberOfRounds = 9;
    AddRoundKey(state, expandedKey);
    dataFile << "0," << countChangedBits(originalState, state, 16) << "\n";

    for (int i = 0; i < numberOfRounds; i++) {
        Round(state, expandedKey + (16 * (i + 1)));
        dataFile << (i + 1) << "," << countChangedBits(originalState, state, 16) << "\n";
    }

    FinalRound(state, expandedKey + 160);
    dataFile << "10," << countChangedBits(originalState, state, 16) << "\n";

    for (int i = 0; i < 16; i++) {
        encryptedMessage[i] = state[i];
    }
}


int main() {
    cout << "=============================" << endl;
    cout << " 128-bit AES Encryption Tool with Avalanche Effect Analysis " << endl;
    cout << "=============================" << endl;

    char message[1024];
    cout << "Enter the message to encrypt: ";
    cin.getline(message, sizeof(message));
    
    int bitToFlip;
    char choice;
    cout << "Modify bit in (p)laintext or (k)ey? ";
    cin >> choice;
    cout << "Enter bit position to flip (0-127): ";
    cin >> bitToFlip;

    int originalLen = strlen(message);
    int paddedMessageLen = (originalLen % 16 == 0) ? originalLen : (originalLen / 16 + 1) * 16;
    unsigned char *paddedMessage = new unsigned char[paddedMessageLen]();
    memcpy(paddedMessage, message, originalLen);
    unsigned char *encryptedMessage = new unsigned char[paddedMessageLen];

    string str;
    ifstream infile("keyfile", ios::in | ios::binary);
    if (!infile) {
        cout << "Unable to open keyfile" << endl;
        return 1;
    }
    getline(infile, str);
    infile.close();

    istringstream hex_chars_stream(str);
    unsigned char key[16];
    int i = 0;
    unsigned int c;
    while (hex_chars_stream >> hex >> c) {
        key[i++] = c;
    }

    unsigned char expandedKey[176];
    KeyExpansion(key, expandedKey);

    if (choice == 'p') {
        flipBit(paddedMessage, bitToFlip);
        ofstream dataFile("avalanche_data_plaintext.csv");
        dataFile << "Round,Changed Bits\n";

        for (int i = 0; i < paddedMessageLen; i += 16) {
                AESEncryptWithAvalanche(paddedMessage + i, expandedKey, encryptedMessage + i, dataFile);
         }
        dataFile.close();

    } else if (choice == 'k') {
        flipBit(key, bitToFlip);
        KeyExpansion(key, expandedKey);
        ofstream dataFile("avalanche_data_key.csv");
        dataFile << "Round,Changed Bits\n";

        for (int i = 0; i < paddedMessageLen; i += 16) {
                AESEncryptWithAvalanche(paddedMessage + i, expandedKey, encryptedMessage + i, dataFile);
         }
     
         dataFile.close();
    }

    // ofstream dataFile("avalanche_data.csv");
    // dataFile << "Round,Changed Bits\n";

    // for (int i = 0; i < paddedMessageLen; i += 16) {
    //     AESEncryptWithAvalanche(paddedMessage + i, expandedKey, encryptedMessage + i, dataFile);
    // }
    // dataFile.close();

    cout << "Encrypted message in hex: ";
    for (int i = 0; i < paddedMessageLen; i++) {
        cout << hex << (int)encryptedMessage[i] << " ";
    }
    cout << endl;

    ofstream outfile("message.aes", ios::out | ios::binary);
    outfile.write(reinterpret_cast<char*>(encryptedMessage), paddedMessageLen);
    outfile.close();
    cout << "Wrote encrypted message to file message.aes" << endl;

    delete[] paddedMessage;
    delete[] encryptedMessage;
    return 0;
}