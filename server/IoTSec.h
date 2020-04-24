#include"Arduino.h"
#include <RF24.h>
#include <Crypto.h>
#include <AES.h>
#include <SHA256.h>

#define MAX_PACKET_SIZE 18
#define MAX_HEADER_SIZE 2
#define MAX_PAYLOAD_SIZE 8
#define KEY_DATA_LEN 16
#define HASH_KEY_LEN 16
#define HASH_LEN 8
#define MAX_MESSAGE_COUNT 10
#define NONCE_LEN 8

class IoTSec {
	public:
		//Constructors
        IoTSec(RF24* radio, AES128* encCipher, SHA256* hash256);
        ~IoTSec();

        //Functions
        bool keyExpired();
        void send(String str, String state);
        void send(char* arr, String state);
        void send(String str, byte* encKey, String state);
        void send(char* arr, byte* encKey, String state);
        void send(String str, byte* encKey, byte* intKey, String state);
        void send(char* arr, byte* encKey, byte* intKey, String state);
        String receiveStr(char* state, bool block);
        void receive(byte payload[], char* state, bool block);
        String receiveStr(byte* encKey, char* state, bool block);
        void receive(byte payload[], byte* encKey, char* state, bool block);
        String receiveStr(byte* encKey, byte* intKey, char* state, bool block);
        void receive(byte payload[], byte* encKey, byte* intKey, char* state, bool block);
		void printByteArr(byte arr[], int size);
        byte* getMasterKey();
        byte* getHashKey();
        byte* getSecretKey();
        byte* getSecretHashKey();
        void createNonce(byte nonce[]);
        int createRandom();
        void generateKeys(byte nonce1[], byte nonce2[]);
        void setHandshakeComplete(bool complete);
        void incrMsgCount();
        bool getIntegrityPassed();

    private:
        //Keys
        byte* secretKey; //The secret key known to both the client and the server.
        byte* secretHashKey; //The secret hash key computed from secret key.
        byte* masterKey; //The master key generated through the handshake.
        byte* hashKey; //The hash key generated from the master key.

        //State
        bool handshakeComplete; //Flag for whether the handshake has been completed.
        int numMsgs; // The number of messages sent.
        bool integrityPassed;  //Flag set in the receive function validating message integrity

        //Utilities
        RF24* radio;
        AES128* encCipher;
        SHA256* hash256;

        //Functions
        void receiveHelper(byte* bytes, char* state, bool block);
        void createHeader(String state, byte bytes[]);
        void appendHMAC(char* arr, byte* HMAC, byte* hashKey);
        bool verifyHMAC(byte* bytes, byte* hashKey);
};
