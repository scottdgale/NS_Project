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
    Serial.println(len);
    for (int i=0; i<len; i++){
        cipherText[i] = plainText[i] + 10 % 256;	
    }
    
    return cipherText;
}
