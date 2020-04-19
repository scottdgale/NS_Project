#include "IoTSec.h"

/*
 * Initializes the IoTSec class with the needed keys and initial state.
 * @param radio - A pointer to the radio object used to transfer data.
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
void IoTSec::authenticate() {
    Serial.println("INFO: Handshake initialized.");

    this->send("hello");
    
    String msg = this->receiveStr(this->secretKey);
    Serial.println(msg);

    Serial.println("INFO: Handshake finished.");
//    this->handshakeComplete = true;
}

/*
 * Returns true if the key has expired, false otherwise.
 */
bool IoTSec::keyExpired() {
    return !this->handshakeComplete;
}

/*
 * Sends an un-encrypted no integrity string to the server.
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
 * Sends a non-encrypted no integrity array of bytes to the server.
 * @param bytes - The bytes to send.
 * @param size - the size of the byte arr.
 */
void IoTSec::send(char* arr, int size) {
    this->radio->stopListening();
    
    Serial.print("INFO: Sending to server: ");
    this->printByteArr(arr, size);
    this->radio->write(arr, size);
}

/*
 * Sends an encrypted no integrity string to the server.
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
 * Sends an encrypted no integrity array of bytes to the server.
 * @param bytes - The bytes to encrypt and send.
 * @param size - the size of the byte arr.
 * @param encKey - The encryption key byte array to use for encryption.
 */
void IoTSec::send(char* arr, int size, byte* encKey) {
    this->radio->stopListening();
    
    //TODO: Encrypt the bytes here.
    Serial.print("INFO: Sending to server: ");
    this->printByteArr(arr, size);
    this->radio->write(arr, size);
}

/*
 * Sends an encrypted string with its integrity to the server.
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
 * Sends an encrypted array of bytes with its integrity to the server.
 * @param bytes - The bytes to encrypt and send.
 * @param size - the size of the byte arr.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param intKey - The integrity key byte array to use for integrity.
 */
void IoTSec::send(char* arr, int size, byte* encKey, byte* intKey) {
    this->radio->stopListening();
    
    //TODO: Generate integrity here.
    //TODO: Encrypt bytes and integrity here.
    Serial.print("INFO: Sending to server: ");
    this->printByteArr(arr, size);
    this->radio->write(arr, size);
}

/*
 * Receives a non-encrypted no integrity string from the server.
 */
String IoTSec::receiveStr() {
    byte bytes[MAX_PACKET_SIZE];
    this->receive(bytes, MAX_PACKET_SIZE);
    return (char*) bytes;
}

/*
 * Receives non-encrypted no integrity data from the server.
 * @param bytes - The byte array to store the data.
 * @param size - The size of the bytes array.
 */
void IoTSec::receive(byte* bytes, int size) {
    this->receiveHelper(bytes, size);
    Serial.print("INFO: Received from server: ");
    this->printByteArr(bytes, size);
}

/*
 * Receives an encrypted string no integrity from the server.
 * @param encKey - The encryption key used to decrypt the data.
 */
String IoTSec::receiveStr(byte* encKey) {
    byte bytes[MAX_PACKET_SIZE];
    this->receive(bytes, MAX_PACKET_SIZE, encKey);
    return (char*) bytes;
}

/*
 * Receives encrypted data no integrity from the server.
 * @param bytes - The array to store the data in.
 * @param size - The size of the bytes array.
 * @param encKey - The Encryption key used to decrypt the data.
 */
void IoTSec::receive(byte* bytes, int size, byte* encKey) {
    this->receiveHelper(bytes, size);
    Serial.print("INFO: Received from server: ");
    this->printByteArr(bytes, size);
    //TODO: Decrypt the bytes here.
}

/*
 * Receives an encrypted string with its integrity from the server.
 * @param encKey - The encryption key used to decrypt.
 * @param intKey - The integrity key used to verify the integrity.
 */
String IoTSec::receiveStr(byte* encKey, byte* intKey) {
    byte bytes[MAX_PACKET_SIZE];
    this->receive(bytes, MAX_PACKET_SIZE, encKey, intKey);
    return (char*) bytes;
}

/*
 * Receives encrypted data and integrity from server.
 * @param bytes - The bytes to store the data in.
 * @param size - The size of the bytes array.
 * @param encKey - The encryption key used to decrypt the data
 * @param intKey - The integrity key used to verify the integrity.
 */
void IoTSec::receive(byte* bytes, int size, byte* encKey, byte* intKey) {
    this->receiveHelper(bytes, size);
    Serial.print("INFO: Received from server: ");
    this->printByteArr(bytes, size);
    //TODO: Decrypt the bytes and integrity here.
    //TODO: Verify integrity.
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

/*
 * The helper function for receiving data. This function
 * waits for a bit until the data has become available.
 * @param bytes - The bytes to start the data.
 * @param size - The size of the bytes array.
 */
void IoTSec::receiveHelper(byte* bytes, int size) {
    this->radio->startListening();
    memset(bytes, 0, size);

    unsigned long started_waiting = micros();
    boolean timeout = false;

    while (!this->radio->available()){
        if (micros() - started_waiting > 1000000 ){
            timeout = true;
            break;
        }
    }

    if (!timeout) {
        this->radio->read(bytes, size);
    }
}
