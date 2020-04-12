#include "IoTSec.h"

IoTSec::IoTSec() {
    handshakeComplete = false;
    byte masterKey[16];                     // Generated during the handshake
    byte hashKey[16];                       // Generated during the handshake
    
    
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

unsigned long IoTSec::getSecret(){
    return secret;
}

void IoTSec::setSecret(unsigned long s){
    secret = s;
}
