#include "IoTSec.h"

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

IoTSec::~IoTSec() {
    if (this->secretKey != NULL) {
        delete[] this->secretKey;
    }
    if (this->masterKey != NULL) {
        delete[] this->masterKey;
    }
    if (this->hashKey != NULL) {
        delete[] this->hashKey;
    }
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

//unsigned long IoTSec::getSecret(){
//    return secret;
//}
//
//void IoTSec::setSecret(unsigned long s){
//    secret = s;
//}
