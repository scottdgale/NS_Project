#include "IoTSec.h"

/*
 * Initializes the IoTSec class with the needed keys and initial state.
 * @param radio A pointer to the radio object used to transfer data.
 */
IoTSec::IoTSec(RF24* radio) {
    randomSeed(analogRead(A0));

    //Generate the secret key and initialize other keys.
    this->secretKey = new byte[KEY_DATA_LEN] {36, 152, 131, 242, 98, 145, 27, 252, 14, 79, 42, 22, 126, 158, 25, 156};
    this->masterKey = NULL;
    this->hashKey = NULL;

    //Save an instance of the radio for the library to be able to use.
    this->radio = radio;

    this->handshakeComplete = false;
}

/*
 * Cleans up the pointers that were created in this class.
 */
IoTSec::~IoTSec() {
    if (this->secretKey != NULL) {
        delete[] this->secretKey;
        this->secretKey = NULL;
    }
    if (this->masterKey != NULL) {
        delete[] this->masterKey;
        this->masterKey = NULL;
    }
    if (this->hashKey != NULL) {
        delete[] this->hashKey;
        this->hashKey = NULL;
    }
}

/*
 * Performs the handshake between the client and the server.
 * This will generate the masterKey and hashKey after the handshake
 * is finished. The handshakeComplete property will be set to true
 * when the handshake has finished.
 */
void IoTSec::handshake() {
    Serial.println("Testing handshake method");
    this->handshakeComplete = true;
}

/*
 * Returns true if the handshake is complete, false otherwise.
 */
bool IoTSec::isHandshakeComplete() {
    return this->handshakeComplete;
}

int IoTSec::numberDoubler(int v) {
	return v * 2;
}

byte* IoTSec::encrypt(byte plainText[], int len){
    static byte cipherText[16];
    for (int i=0; i<len; i++){
        cipherText[i] = plainText[i] + 10 % 256;	
    }
    
    return cipherText;
}

// Function hash: computes a 8 byte MAC on a 16 byte message, uses 
// @param: message - This is the message that we want to hash (expecting 16 bytes but will work for any length message)
// @param: messageLength - length of message in bytes
// @param: storeHash - Memory allocated by the caller to store the hash (8 bytes)
// @return: none - function stores the hash using the pointer storeHash
void IoTSec::hash(byte message[], int messageLength, byte storeHash[]){
    Serial.println("IoTSec::hash - Hashing message of length: " + (String)messageLength);
    // Use practiceKey for now but will eventually replace with key generated from handshake iot.hashKey
    byte practiceKey[] = {15, 31, 130, 120, 100, 99, 98, 11, 222, 111, 3, 245, 255, 123, 211, 23};
    for(int i=0; i<messageLength/2; i++){
        storeHash[i%HASH_LEN] = message[2*i] ^ message[2*i+1] ^ practiceKey[(2*i)%HASH_KEY_LEN] ^ practiceKey[(2*i+1)%HASH_KEY_LEN];
    }
    /* Print the values of the hash for debugging
    for(int i=0; i<messageLength/2; i++){
        Serial.print((int)storeHash[i]);
        Serial.print(" ");
    }  */
}
