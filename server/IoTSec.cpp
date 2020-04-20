#include "IoTSec.h"

/*
 * Initializes the IoTSec class with the needed keys and initial state.
 * @param radio A pointer to the radio object used to transfer data.
 */
IoTSec::IoTSec(RF24* radio) {
    randomSeed(analogRead(A1));

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
void IoTSec::authenticate(bool keyExpired) {
    //Initializations.
    this->handshakeComplete = false;
    char* state = new char[MAX_PACKET_SIZE];
    String msg;
    byte receivedBytes[MAX_PACKET_SIZE];
    byte nonce1[KEY_DATA_LEN];
    byte nonce2[KEY_DATA_LEN];

    //Check for key expiring.
    if (keyExpired) {
        msg = "KEY EXPIRED";
        Serial.println(msg);
        this->send(msg, this->secretKey, "0");
        msg = this->receiveStr(this->secretKey, state, true);
        Serial.println(msg);
    }

    Serial.println("INFO: Handshake initialized.");

    msg = "hello back";
    Serial.println(msg);
    this->send(msg, this->secretKey, "0");

    //Receive nonce from client.
    this->receive(nonce1, KEY_DATA_LEN, this->secretKey, state, false);

    //Send nonce to client.
    this->createNonce(nonce2);
    this->send(nonce2, KEY_DATA_LEN, this->secretKey, "0");

    //Generate keys.
    this->generateKeys(nonce1, nonce2);

    Serial.print("Master key: ");
    this->printByteArr(this->masterKey, KEY_DATA_LEN);
    Serial.print("Hash key: ");
    this->printByteArr(this->hashKey, HASH_KEY_LEN);

    this->handshakeComplete = true;
    Serial.println("INFO: Handshake finished.");

    delete[] state;
    state = NULL;
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
 */
void IoTSec::send(String str, String state) {
    byte bytes[str.length()];

    for (int i = 0; i < str.length(); ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, str.length(), state);
}

/*
 * Sends a non-encrypted no integrity array of bytes to the client.
 * @param arr - The bytes to send.
 * @param size - the size of the byte arr.
 */
void IoTSec::send(char* arr, int size, String state) {
    this->radio->stopListening();
    byte bytes[MAX_PACKET_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE);
        createHeader(state, bytes);

        for (int i = 0; i < size; ++i) {
            bytes[i + state.length() + 2] = arr[i];
        }

        Serial.print("INFO: Sending to client: ");
        this->printByteArr(bytes, MAX_PACKET_SIZE);
        this->radio->write(bytes, MAX_PACKET_SIZE);

    this->radio->startListening();
}

/*
 * Sends an encrypted no integrity string to the client.
 * @param str - The str to encrypt and send.
 * @param encKey - The encryption key byte array to use for encryption.
 */
void IoTSec::send(String str, byte* encKey, String state) {
    byte bytes[str.length()];

    for (int i = 0; i < str.length(); ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, str.length(), encKey, state);
}

/*
 * Sends an encrypted no integrity array of bytes to the client.
 * @param arr - The bytes to encrypt and send.
 * @param size - the size of the byte arr.
 * @param encKey - The encryption key byte array to use for encryption.
 */
void IoTSec::send(char* arr, int size, byte* encKey, String state) {
    this->radio->stopListening();
    byte bytes[MAX_PACKET_SIZE];
    memset(bytes, 0, MAX_PACKET_SIZE);
    createHeader(state, bytes);

    //TODO: Encrypt the char array here.

    for (int i = 0; i < size; ++i) {
        bytes[i + state.length() + 2] = arr[i];
    }

    Serial.print("INFO: Sending to client: ");
    this->printByteArr(bytes, MAX_PACKET_SIZE);
    this->radio->write(bytes, MAX_PACKET_SIZE);

    this->radio->startListening();
}

/*
 * Sends an encrypted string with its integrity to the client.
 * @param str - The string to encrypt, generate integrity and send.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param intKey - The integrity key byte array to use for integrity.
 */
void IoTSec::send(String str, byte* encKey, byte* intKey, String state) {
    byte bytes[str.length()];

    for (int i = 0; i < str.length(); ++i) {
        bytes[i] = str[i];
    }

    this->send(bytes, str.length(), encKey, intKey, state);
}

/*
 * Sends an encrypted array of bytes with its integrity to the client.
 * @param arr - The bytes to encrypt and send.
 * @param size - the size of the byte arr.
 * @param encKey - The encryption key byte array to use for encryption.
 * @param intKey - The integrity key byte array to use for integrity.
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

    Serial.print("INFO: Sending to client: ");
    this->printByteArr(bytes, MAX_PACKET_SIZE);
    this->radio->write(bytes, MAX_PACKET_SIZE);

    this->radio->startListening();
}

/*
 * Receives a non-encrypted no integrity string from the client.
 * @param state - The state from the header received.
 */
String IoTSec::receiveStr(char* state, bool block) {
    byte bytes[MAX_PACKET_SIZE];
    this->receive(bytes, MAX_PACKET_SIZE, state, block);
    return (char*) bytes;
}

/*
 * Receives non-encrypted no integrity data from the client.
 * @param bytes - The byte array to store the data.
 * @param size - The size of the bytes array.
 * @param state - The state from the header received.
 */
void IoTSec::receive(byte bytes[], int size, char* state, bool block) {
    this->receiveHelper(bytes, size, state, block);
    Serial.print("INFO: Received from client: ");
    this->printByteArr(bytes, size);
}

/*
 * Receives an encrypted string no integrity from the client.
 * @param encKey - The encryption key used to decrypt the data.
 * @param state - The state from the header received.
 */
String IoTSec::receiveStr(byte* encKey, char* state, bool block) {
    byte bytes[MAX_PACKET_SIZE];
    this->receive(bytes, MAX_PACKET_SIZE, encKey, state, block);
    return (char*) bytes;
}

/*
 * Receives encrypted data no integrity from the client.
 * @param bytes - The array to store the data in.
 * @param size - The size of the bytes array.
 * @param encKey - The Encryption key used to decrypt the data.
 * @param state - The state from the header received.
 */
void IoTSec::receive(byte bytes[], int size, byte* encKey, char* state, bool block) {
    this->receiveHelper(bytes, size, state, block);
    Serial.print("INFO: Received from client: ");
    this->printByteArr(bytes, size);
    //TODO: Decrypt the bytes here.
}

/*
 * Receives an encrypted string with its integrity from the client.
 * @param encKey - The encryption key used to decrypt.
 * @param intKey - The integrity key used to verify the integrity.
 * @param state - The state from the header received.
 */
String IoTSec::receiveStr(byte* encKey, byte* intKey, char* state, bool block) {
    byte bytes[MAX_PACKET_SIZE];
    this->receive(bytes, MAX_PACKET_SIZE, encKey, intKey, state, block);
    return (char*) bytes;
}

/*
 * Receives encrypted data and integrity from client.
 * @param bytes - The bytes to store the data in.
 * @param size - The size of the bytes array.
 * @param encKey - The encryption key used to decrypt the data
 * @param intKey - The integrity key used to verify the integrity.
 * @param state - The state from the header received.
 */
void IoTSec::receive(byte bytes[], int size, byte* encKey, byte* intKey, char* state, bool block) {
    this->receiveHelper(bytes, size, state, block);
    Serial.print("INFO: Received from client: ");
    this->printByteArr(bytes, size);
    //TODO: Decrypt the bytes and integrity here.
    //TODO: Verify integrity.
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

byte* IoTSec::getMasterKey() {
    return this->masterKey;
}

byte* IoTSec::getHashKey() {
    return this->hashKey;
}

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

void IoTSec::generateKeys(byte nonce1[], byte nonce2[]) {
    this->masterKey = new byte[KEY_DATA_LEN];
    this->hashKey = new byte[HASH_KEY_LEN];

    for (int i = 0; i < KEY_DATA_LEN; ++i) {
        masterKey[i] = ((nonce1[i] * 13) % 256) ^ ((nonce2[i] * 17) % 256);
        hashKey[i] = ((nonce1[i] * 19) % 256) ^ ((nonce2[i] * 23) % 256);
    }
}

void IoTSec::setHandshakeComplete(bool complete) {
    this->handshakeComplete = complete;
}

/*
 * The helper function for receiving data. This function
 * waits for a bit until the data has become available.
 * @param bytes - The bytes to start the data.
 * @param size - The size of the bytes array.
 * @param state - The state from the header received.
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
