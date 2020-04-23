#include "IoTSec.h"

/*
 * Initializes the IoTSec class with the needed keys and initial state.
 * @param radio A pointer to the radio object used to transfer data.
 */
IoTSec::IoTSec(RF24* radio, AES128* encCipher, SHA256* hash256) {
    randomSeed(analogRead(A1));

    //Generate the secret key and initialize other keys.
    this->secretKey = new byte[KEY_DATA_LEN] {36, 152, 131, 242, 98, 145, 27, 252, 14, 79, 42, 22, 126, 158, 25, 156};
    this->masterKey = NULL;
    this->hashKey = NULL;

    this->radio = radio;                //Save an instance of the radio for the library to be able to use.
    this->encCipher = encCipher;        //Save an instance of the cipher to be used for encryption/decryption
    this->hash256 = hash256;            //Save an instance of the HMAC function used for integrity

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
 * Sends an un-encrypted no integrity string to the client.
 * @param str - The string to send.
 * @param state - The state to send in the header.
 */
void IoTSec::send(String str, String state) {
    byte bytes[MAX_PAYLOAD_SIZE];
    memset(bytes, 0, MAX_PAYLOAD_SIZE);

    for (int i = 0; i < str.length() && i < MAX_PAYLOAD_SIZE; ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, state);
}

/*
 * Sends a non-encrypted no integrity array of bytes to the client.
 * @param arr - The bytes to send.
 * @param state - The state to send in the header.
 */
void IoTSec::send(char* arr, String state) {
    this->radio->stopListening();
    byte bytes[MAX_PACKET_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE);
    createHeader(state, bytes);

    for (int i = 0; i < MAX_PAYLOAD_SIZE; ++i) {
        bytes[i + MAX_HEADER_SIZE] = arr[i];
    }

    Serial.print("INFO: Sending to client: ");
    this->printByteArr(bytes, MAX_PACKET_SIZE);
    this->radio->write(bytes, MAX_PACKET_SIZE);

    this->incrMsgCount();
    this->radio->startListening();
}

/*
 * Sends an encrypted no integrity string to the client.
 * @param str - The str to encrypt and send.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param state - The state to send in the header.
 */
void IoTSec::send(String str, byte* encKey, String state) {
    byte bytes[MAX_PAYLOAD_SIZE];
    memset(bytes, 0, MAX_PAYLOAD_SIZE);

    for (int i = 0; i < str.length() && i < MAX_PAYLOAD_SIZE; ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, encKey, state);
}

/*
 * Sends an encrypted no integrity array of bytes to the client.
 * @param arr - The bytes to encrypt and send.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param state - The state to send in the header.
 */
void IoTSec::send(char* arr, byte* encKey, String state) {
    this->radio->stopListening();
    byte bytes[MAX_PACKET_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE);
    byte msg[MAX_PACKET_SIZE - MAX_HEADER_SIZE];
    memset(msg, 0, MAX_PACKET_SIZE - MAX_HEADER_SIZE);
    createHeader(state, bytes);
    
    memmove(msg, arr, MAX_PAYLOAD_SIZE);
    byte encBytes[MAX_PACKET_SIZE - MAX_HEADER_SIZE];       // Encrypt the char array here.
    this ->encCipher->encryptBlock(encBytes, msg);

    memmove(bytes + 2, encBytes, MAX_PACKET_SIZE - MAX_HEADER_SIZE);

    Serial.print("INFO: Sending to client: ");
    this->printByteArr(bytes, MAX_PACKET_SIZE);
    this->radio->write(bytes, MAX_PACKET_SIZE);

    this->incrMsgCount();
    this->radio->startListening();
}

/*
 * Sends an encrypted string with its integrity to the client.
 * @param str - The string to encrypt, generate integrity and send.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param intKey - The integrity key byte array to use for integrity.
 * @param state - The state to send in the header.
 */
void IoTSec::send(String str, byte* encKey, byte* intKey, String state) {
    byte bytes[MAX_PAYLOAD_SIZE];
    memset(bytes, 0, MAX_PAYLOAD_SIZE);

    for (int i = 0; i < str.length() && i < MAX_PAYLOAD_SIZE; ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, encKey, intKey, state);
}

/*
 * Sends an encrypted array of bytes with its integrity to the server.
 * @param bytes - The bytes to encrypt and send.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param intKey - The integrity key byte array to use for integrity.
 * @param state - The state header.
 */
void IoTSec::send(char* arr, byte* encKey, byte* intKey, String state) {
    this->radio->stopListening();
    byte bytes[MAX_PACKET_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE);
    byte toEncrypt[MAX_PAYLOAD_SIZE + HASH_LEN];
    memset(toEncrypt, 0, MAX_PACKET_SIZE - MAX_HEADER_SIZE);
    createHeader(state, bytes);
    
    this->appendHMAC(arr, toEncrypt);                        //store payload (arr) in toEncrypt and append HMAC
    byte encBytes[MAX_PACKET_SIZE - MAX_HEADER_SIZE];
    this ->encCipher->encryptBlock(encBytes, toEncrypt);

    memmove(bytes + 2, encBytes, MAX_PACKET_SIZE - MAX_HEADER_SIZE);

    Serial.print("INFO: Sending to client: ");
    this->printByteArr(bytes, MAX_PACKET_SIZE);
    this->radio->write(bytes, MAX_PACKET_SIZE);

    this->incrMsgCount();
    this->radio->startListening();
}

/*
 * Receives a non-encrypted no integrity string from the client.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
String IoTSec::receiveStr(char* state, bool block) {
    //Null terminate.
    byte bytes[MAX_PAYLOAD_SIZE + 1];
    memset(bytes, 0, MAX_PAYLOAD_SIZE + 1);

    this->receive(bytes, state, block);
    return (char*) bytes;
}

/*
 * Receives non-encrypted no integrity data from the client.
 * @param payload - The byte array to store the data.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
void IoTSec::receive(byte payload[], char* state, bool block) {
    byte bytes[MAX_PACKET_SIZE - MAX_HEADER_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE - MAX_HEADER_SIZE);

    this->receiveHelper(bytes, state, block);

    Serial.print("INFO: Received from client: ");
    this->printByteArr(bytes, MAX_PACKET_SIZE - MAX_HEADER_SIZE);

    memmove(payload, bytes, MAX_PAYLOAD_SIZE);
}

/*
 * Receives an encrypted string no integrity from the client.
 * @param encKey - The encryption key used to decrypt the data.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
String IoTSec::receiveStr(byte* encKey, char* state, bool block) {
    //Null terminate.
    byte bytes[MAX_PAYLOAD_SIZE + 1];
    memset(bytes, 0, MAX_PAYLOAD_SIZE + 1);

    this->receive(bytes, encKey, state, block);
    return (char*) bytes;
}

/*
 * Receives encrypted data no integrity from the client.
 * @param payload - The array to store the data in.
 * @param encKey - The Encryption key used to decrypt the data.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
void IoTSec::receive(byte payload[], byte* encKey, char* state, bool block) {
    byte bytes[MAX_PACKET_SIZE - MAX_HEADER_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE - MAX_HEADER_SIZE);

    this->receiveHelper(bytes, state, block);
    
    // Decrypt the bytes here.
    byte decBytes[MAX_PACKET_SIZE - MAX_HEADER_SIZE];    
    this->encCipher->decryptBlock(decBytes, bytes );
   
    this->printByteArr(decBytes, MAX_PACKET_SIZE - MAX_HEADER_SIZE);

    Serial.print("INFO: Received from client: ");
    this->printByteArr(bytes, MAX_PACKET_SIZE - MAX_HEADER_SIZE);

    memmove(payload, decBytes, MAX_PAYLOAD_SIZE);
}

/*
 * Receives an encrypted string with its integrity from the client.
 * @param encKey - The encryption key used to decrypt.
 * @param intKey - The integrity key used to verify the integrity.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
String IoTSec::receiveStr(byte* encKey, byte* intKey, char* state, bool block) {
    //Null terminate.
    byte bytes[MAX_PAYLOAD_SIZE + 1];
    memset(bytes, 0, MAX_PAYLOAD_SIZE + 1);

    this->receive(bytes, encKey, intKey, state, block);
    return (char*) bytes;
}

/*
 * Receives encrypted data and integrity from client.
 * @param payload - The bytes to store the data in.
 * @param encKey - The encryption key used to decrypt the data
 * @param intKey - The integrity key used to verify the integrity.
 * @param state - The state from the header received.
 * @param block - flag to block receive until message has been received, (No timeout).
 */
void IoTSec::receive(byte* payload, byte* encKey, byte* intKey, char* state, bool block) {
    this->integrityPassed = false;
    byte bytes[MAX_PACKET_SIZE - MAX_HEADER_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE - MAX_HEADER_SIZE);
    byte msgToVerify[MAX_PAYLOAD_SIZE];
    byte hashToVerify[HASH_LEN];
    
    this->receiveHelper(bytes, state, block);

    byte decBytes[MAX_PACKET_SIZE - MAX_HEADER_SIZE];    
    this->encCipher->decryptBlock(decBytes, bytes);        // Decrypt 16 byte message
    
    if (this->verifyHMAC(decBytes)){
        Serial.println("Integrity Passed");
        this->integrityPassed = true;
    }

    Serial.print("INFO: Received from client: ");
    this->printByteArr(decBytes, MAX_PACKET_SIZE - MAX_HEADER_SIZE);

    memmove(payload, decBytes, MAX_PAYLOAD_SIZE);
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
    for (int i = 0; i < NONCE_LEN; ++i) {
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

    for (int i = 0; i < NONCE_LEN; ++i) {
        masterKey[i] = ((nonce1[i] * 13) % 256) ^ ((nonce2[i] * 17) % 256);
        masterKey[i + NONCE_LEN] = ((nonce1[i] * 29) % 256) ^ ((nonce2[i] * 31) % 256);
        hashKey[i] = ((nonce1[i] * 19) % 256) ^ ((nonce2[i] * 23) % 256);
        hashKey[i + NONCE_LEN] = ((nonce1[i] * 37) % 256) ^ ((nonce2[i] * 41) % 256);
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
 * @param state - The state from the header received.
 * @param block - The flag used to block until a message is received (No Timeouts).
 */
void IoTSec::receiveHelper(byte* bytes, char* state, bool block) {
    this->radio->startListening();
    memset(bytes, 0, MAX_PACKET_SIZE - MAX_HEADER_SIZE);
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

//        int i = 0;
//
//        if ((char)packet[0] == '<') {
//            while ((char)packet[i + 1] != '>' && i + 1 < MAX_PACKET_SIZE) {
//                ++i;
//            }
//        }

        memmove(state, packet, MAX_HEADER_SIZE);
        memmove(bytes, packet + MAX_HEADER_SIZE, MAX_PACKET_SIZE - MAX_HEADER_SIZE);
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
    for (int i = 0; i < state.length() && i < MAX_HEADER_SIZE; ++i) {
        bytes[i] = state[i];
    }
}

/*
 * Save the message (char arr) to the toEncrypt buffer, compute and append the HMAC
 * @param arr - The message or payload.
 * @param toEncrypt - Working buffer to store the payload and the computed HMAC.
 */
void IoTSec::appendHMAC(char* arr, byte* toEncrypt) {
    byte hash[HASH_LEN];     // used to store the computed HMAC
    // Store the payload to the working buffer toEncrypt
    for (int i = 0; i < MAX_PAYLOAD_SIZE; i++) {
        toEncrypt[i] = (byte)arr[i];
    }
    this->hash256->resetHMAC(this->hashKey, HASH_KEY_LEN);
    this->hash256->update(arr, MAX_PAYLOAD_SIZE);
    this->hash256->finalizeHMAC(this->hashKey, HASH_KEY_LEN, hash, HASH_LEN);
    // append the HMAC 
    for (int i = 0; i< HASH_LEN; i++) {
        toEncrypt[MAX_PAYLOAD_SIZE + i] = hash[i];
    }
    //Serial.print("Working buffer: ");
    //this->printByteArr(toEncrypt, MAX_PAYLOAD_SIZE + HASH_LEN);
}

/*
 * Save the message (char arr) to the toEncrypt buffer, compute and append the HMAC
 * @param msg - The message or payload.
 * @param toHash - Working buffer to store the computed HMAC.
 */
bool IoTSec::verifyHMAC(byte* bytes) {
    byte msgToVerify[MAX_PAYLOAD_SIZE];
    byte receivedHash[HASH_LEN];
    byte computedHash[HASH_LEN];
    for (int i = 0; i < MAX_PAYLOAD_SIZE; i++) {            // copy the payload
        msgToVerify[i] = bytes[i];
    }
    for (int i = 0; i < HASH_LEN; i++) {                    // copy the HMAC
        receivedHash[i] = bytes[i + MAX_PAYLOAD_SIZE];
    }
    
    this->hash256->resetHMAC(this->hashKey, HASH_KEY_LEN);
    this->hash256->update(msgToVerify, MAX_PAYLOAD_SIZE);
    this->hash256->finalizeHMAC(this->hashKey, HASH_KEY_LEN, computedHash, HASH_LEN);
    
    /*
    Serial.print("Verify HMAC: ");
    this->printByteArr(receivedHash, HASH_LEN);
    Serial.print(" ");
    this->printByteArr(computedHash, HASH_LEN);
    */

    for (int i = 0; i < HASH_LEN; i++) {
        if (!(receivedHash[i] == computedHash[i])) {
            return false;
        }
    }
    return true;
}
    
