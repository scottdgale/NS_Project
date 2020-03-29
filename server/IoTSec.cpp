#include "IoTSec.h"

// Constructor
IoTSec::IoTSec() {
    handshakeComplete = false;
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

unsigned long IoTSec::getSecret(){
    return secret;
}

void IoTSec::setSecret(unsigned long s){
    secret = s;
}
