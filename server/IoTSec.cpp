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
    Serial.println("INFO: Handshake initialized.");

    Serial.println("INFO: Handshake finished.");
    this->handshakeComplete = true;
}

/*
 * Returns true if the handshake is complete, false otherwise.
 */
bool IoTSec::isHandshakeComplete() {
    return this->handshakeComplete;
}

/*
 * Sends an un-encrypted no integrity string to the client.
 * @param str - The string to send.
 */
void IoTSec::send(String str) {
    byte bytes[str.length()];

    for (int i = 0; i < str.length(); ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, str.length());
}

/*
 * Sends a non-encrypted no integrity array of bytes to the client.
 * @param bytes - The bytes to send.
 * @param size - the size of the byte arr.
 */
void IoTSec::send(byte bytes[], int size) {
    Serial.print("INFO: Sending to server: ");
    this->printByteArr(bytes, size);
    this->radio->write(&bytes, sizeof(bytes));
}

/*
 * Sends an encrypted no integrity string to the client.
 * @param str - The str to encrypt and send.
 * @param encKey - The encryption key byte array to use for encryption.
 */
void IoTSec::send(String str, byte* encKey) {
    byte bytes[str.length()];

    for (int i = 0; i < str.length(); ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, str.length(), encKey);
}

/*
 * Sends an encrypted no integrity array of bytes to the client.
 * @param bytes - The bytes to encrypt and send.
 * @param size - the size of the byte arr.
 * @param encKey - The encryption key byte array to use for encryption.
 */
void IoTSec::send(byte bytes[], int size, byte* encKey) {

    //TODO: Encrypt the bytes here.
    Serial.print("INFO: Sending to server: ");
    this->printByteArr(bytes, size);
    this->radio->write(&bytes, sizeof(bytes));
}

/*
 * Sends an encrypted string with its integrity to the client.
 * @param str - The string to encrypt, generate integrity and send.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param intKey - The integrity key byte array to use for integrity.
 */
void IoTSec::send(String str, byte* encKey, byte* intKey) {
    byte bytes[str.length()];

    for (int i = 0; i < str.length(); ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, str.length(), encKey, intKey);
}

/*
 * Sends an encrypted array of bytes with its integrity to the client.
 * @param bytes - The bytes to encrypt and send.
 * @param size - the size of the byte arr.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param intKey - The integrity key byte array to use for integrity.
 */
void IoTSec::send(byte bytes[], int size, byte* encKey, byte* intKey) {

    //TODO: Generate integrity here.
    //TODO: Encrypt bytes and integrity here.
    Serial.print("INFO: Sending to server: ");
    this->printByteArr(bytes, size);
    this->radio->write(&bytes, sizeof(bytes));
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

/*
 * Prints a formatted array of bytes to the serial monitor.
 * @param arr - The array of bytes to print.
 * @param size - The size of the array.
 */
void IoTSec::printByteArr(byte arr[], int size) {
    Serial.print("[ ");
    for (int i = 0; i < size; ++i) {
        Serial.print((String)arr[i] + " ");
    }
    Serial.println("]");
}

/*
 * Creates a random nonce that is KEY_DATA_LEN bytes long.
 * @param nonce - the array to store the random bytes.
 */
void IoTSec::createNonce(byte nonce[]) {
    for (int i = 0; i < KEY_DATA_LEN; ++i) {
        nonce[i] = random(255);
    }
}
