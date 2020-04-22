#include "IoTSec.h"

/*
 * Initializes the IoTSec class with the needed keys and initial state.
 * @param radio - A pointer to the radio object used to transfer data.
 */
IoTSec::IoTSec(RF24* radio, AES128* encCipher) {
    randomSeed(analogRead(A0));

    //Generate the secret key and initialize other keys.
    this->secretKey = new byte[KEY_DATA_LEN] {36, 152, 131, 242, 98, 145, 27, 252, 14, 79, 42, 22, 126, 158, 25, 156};
    this->masterKey = NULL;
    this->hashKey = NULL;

    //Save an instance of the radio for the library to be able to use.
    this->radio = radio;

    //Save an instance of the cipher to be used for encryption/decryption
    this->encCipher = encCipher;

    this->handshakeComplete = false;
    this->numMsgs = 0;
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
 * Returns true if the key has expired, false otherwise.
 */
bool IoTSec::keyExpired() {
    return !this->handshakeComplete;
}

/*
 * Sends an un-encrypted no integrity string to the server.
 * @param str - The string to send.
 * @param state - The state header.
 */
void IoTSec::send(String str, String state) {
    byte bytes[str.length()];

    for (int i = 0; i < str.length(); ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, str.length(), state);
}

/*
 * Sends a non-encrypted no integrity array of bytes to the server.
 * @param bytes - The bytes to send.
 * @param size - the size of the byte arr.
 * @param state - The state header.
 */
void IoTSec::send(char* arr, int size, String state) {
    this->radio->stopListening();
    byte bytes[MAX_PACKET_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE);
    createHeader(state, bytes);

    for (int i = 0; i < size; ++i) {
        bytes[i + state.length() + 2] = arr[i];
    }
    
    Serial.print("INFO: Sending to server: ");
    this->printByteArr(bytes, size + state.length() + 2);
    this->radio->write(bytes, size + state.length() + 2);

    this->incrMsgCount();
    this->radio->startListening();
}

/*
 * Sends an encrypted no integrity string to the server.
 * @param str - The str to encrypt and send.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param state - The state header.
 */
void IoTSec::send(String str, byte* encKey, String state) {
    byte bytes[str.length()];

    for (int i = 0; i < str.length(); ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, str.length(), encKey, state);
}

/*
 * Sends an encrypted no integrity array of bytes to the server.
 * @param bytes - The bytes to encrypt and send.
 * @param size - the size of the byte arr.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param state - The state header.
 */
void IoTSec::send(char* arr, int size, byte* encKey, String state) {
    this->radio->stopListening();
    byte bytes[MAX_PACKET_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE);
    createHeader(state, bytes);
    
    // Encrypt the char array here.
    byte encBytes[size];
    int numPacketSegments = size/16;
    for (int i = 0; i < numPacketSegments; i++){
      this ->encCipher->encryptBlock(encBytes + i*16,arr + i*16);
    }
    
    for (int i = 0; i < size; ++i) {
        bytes[i + state.length() + 2] = arr[i];
    }

    Serial.print("INFO: Sending to server: ");
    this->printByteArr(bytes, size + state.length() + 2);
    this->radio->write(bytes, size + state.length() + 2);

    this->incrMsgCount();
    this->radio->startListening();
}

/*
 * Sends an encrypted string with its integrity to the server.
 * @param str - The string to encrypt, generate integrity and send.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param intKey - The integrity key byte array to use for integrity.
 * @param state - The state header.
 */
void IoTSec::send(String str, byte* encKey, byte* intKey, String state) {
    byte bytes[str.length()];

    for (int i = 0; i < str.length(); ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, str.length(), encKey, intKey, state);
}

/*
 * Sends an encrypted array of bytes with its integrity to the server.
 * @param bytes - The bytes to encrypt and send.
 * @param size - the size of the byte arr.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param intKey - The integrity key byte array to use for integrity.
 * @param state - The state header.
 */
void IoTSec::send(char* arr, int size, byte* encKey, byte* intKey, String state) {
    this->radio->stopListening();
    byte bytes[MAX_PACKET_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE);
    createHeader(state, bytes);
    
    //TODO: Generate integrity here.
    //TODO: Encrypt bytes and integrity here.

    for (int i = 0; i < size; ++i) {
        bytes[i + state.length() + 2] = arr[i];
    }

    Serial.print("INFO: Sending to server: ");
    this->printByteArr(bytes, size + state.length() + 2);
    this->radio->write(bytes, size + state.length() + 2);

    this->incrMsgCount();
    this->radio->startListening();
}

/*
 * Receives a non-encrypted no integrity string from the server.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
String IoTSec::receiveStr(char* state, bool block) {
    byte bytes[MAX_PACKET_SIZE];
    this->receive(bytes, MAX_PACKET_SIZE, state, block);
    return (char*) bytes;
}

/*
 * Receives non-encrypted no integrity data from the server.
 * @param bytes - The byte array to store the data.
 * @param size - The size of the bytes array.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
void IoTSec::receive(byte* bytes, int size, char* state, bool block) {
    this->receiveHelper(bytes, size, state, block);
    Serial.print("INFO: Received from server: ");
    this->printByteArr(bytes, size);
}

/*
 * Receives an encrypted string no integrity from the server.
 * @param encKey - The encryption key used to decrypt the data.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
String IoTSec::receiveStr(byte* encKey, char* state, bool block) {
    byte bytes[MAX_PACKET_SIZE];
    this->receive(bytes, MAX_PACKET_SIZE, encKey, state, block);
    return (char*) bytes;
}

/*
 * Receives encrypted data no integrity from the server.
 * @param bytes - The array to store the data in.
 * @param size - The size of the bytes array.
 * @param encKey - The Encryption key used to decrypt the data.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
void IoTSec::receive(byte* bytes, int size, byte* encKey, char* state, bool block) {
    this->receiveHelper(bytes, size, state, block);
    Serial.print("INFO: Received from server: ");
    this->printByteArr(bytes, size);
    
    // Decrypt the bytes here.
    byte decBytes[size];
    int numPacketSegments = size/16;
    for (int i = 0; i < numPacketSegments; i++){
      this->encCipher->decryptBlock(decBytes + i*16,bytes + i*16);
    }
    this->printByteArr(decBytes, size);
}

/*
 * Receives an encrypted string with its integrity from the server.
 * @param encKey - The encryption key used to decrypt.
 * @param intKey - The integrity key used to verify the integrity.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
String IoTSec::receiveStr(byte* encKey, byte* intKey, char* state, bool block) {
    byte bytes[MAX_PACKET_SIZE];
    this->receive(bytes, MAX_PACKET_SIZE, encKey, intKey, state, block);
    return (char*) bytes;
}

/*
 * Receives encrypted data and integrity from server.
 * @param bytes - The bytes to store the data in.
 * @param size - The size of the bytes array.
 * @param encKey - The encryption key used to decrypt the data
 * @param intKey - The integrity key used to verify the integrity.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
void IoTSec::receive(byte* bytes, int size, byte* encKey, byte* intKey, char* state, bool block) {
    this->receiveHelper(bytes, size, state, block);
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
 * Gets the master key used for encryption.
 */
byte* IoTSec::getMasterKey() {
    return this->masterKey;
}

/*
 * Gets the hash key used for integrity.
 */
byte* IoTSec::getHashKey() {
    return this->hashKey;
}

/*
 * Gets the secret key used for the handshake.
 */
byte* IoTSec::getSecretKey() {
    return this->secretKey;
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
 * Generates the master and hash keys from the two nonces that were passed to each other.
 * @param nonce1 - The clients nonce
 * @param nonce2 - The servers nonce
 */
void IoTSec::generateKeys(byte nonce1[], byte nonce2[]) {
    this->masterKey = new byte[KEY_DATA_LEN];
    this->hashKey = new byte[HASH_KEY_LEN];

    for (int i = 0; i < KEY_DATA_LEN; ++i) {
        masterKey[i] = ((nonce1[i] * 13) % 256) ^ ((nonce2[i] * 17) % 256);
        hashKey[i] = ((nonce1[i] * 19) % 256) ^ ((nonce2[i] * 23) % 256);
    }
    this->encCipher->setKey(this->masterKey,sizeof(this->masterKey));
}

/*
 * Sets the handshake complete to the flag passed in.
 * @param complete - The flag to govern whether the handshake is complete or not.
 */
void IoTSec::setHandshakeComplete(bool complete) {
    if ((!this->handshakeComplete && complete) || (!complete)) {
        this->numMsgs = 0;
    }
  
    this->handshakeComplete = complete;
}

/*
 * Increments the msg count and checks if a key refresh is needed.
 */
void IoTSec::incrMsgCount() {
    this->numMsgs++;

    if (this->numMsgs > MAX_MESSAGE_COUNT) {
        this->setHandshakeComplete(false);
    }
}

/*
 * The helper function for receiving data. This function
 * waits for a bit until the data has become available.
 * @param bytes - The bytes to start the data.
 * @param size - The size of the bytes array.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
void IoTSec::receiveHelper(byte* bytes, int size, char* state, bool block) {
    this->radio->startListening();
    memset(bytes, 0, size);
    byte packet[MAX_PACKET_SIZE];

    unsigned long started_waiting = micros();
    boolean timeout = false;

    while (!this->radio->available()){
        if (!block && micros() - started_waiting > 1000000 ){
            timeout = true;
            break;
        }
    }

    if (!timeout) {
        this->radio->read(&packet, MAX_PACKET_SIZE);

        int i = 0;

        if ((char)packet[0] == '<') {
            while ((char)packet[i + 1] != '>' && i + 1 < MAX_PACKET_SIZE) {
                ++i;
            }
        }

        memmove(state, packet + 1, i);
        memmove(bytes, packet + i + 2, MAX_PACKET_SIZE - i - 2);
    }
    else {
        Serial.println("\nFailed, response timed out.");
    }
}

/*
 * Creates the header fields given the state. This function will wrap
 * The state in <> tags.
 * @param state - The state for the header.
 * @param bytes - The bytes to store the header in.
 */
void IoTSec::createHeader(String state, byte bytes[]) {
    bytes[0] = '<';

    for (int i = 0; i < state.length(); ++i) {
        bytes[i + 1] = state[i];
    }

    bytes[state.length() + 1] = '>';
}
