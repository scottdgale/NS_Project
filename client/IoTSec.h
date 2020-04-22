#include"Arduino.h"
#include <RF24.h>
#include <Crypto.h>
#include <AES.h>

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
		IoTSec(RF24* radio, AES128* encCipher);
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
        int numberDoubler(int x);
        byte* encrypt(byte plainText[], int len);
        void hash(byte message[], int len, byte hash[]);
        void printByteArr(byte arr[], int size);
        byte* getMasterKey();
        byte* getHashKey();
        byte* getSecretKey();
        void createNonce(byte nonce[]);
        void generateKeys(byte nonce1[], byte nonce2[]);
        void setHandshakeComplete(bool complete);
        void incrMsgCount();

	private:
	    //Keys
		byte* secretKey; //The secret key known to both the client and the server.
        byte* masterKey; //The master key generated through the handshake.
        byte* hashKey; //The hash key generated from the master key.

        //State
        bool handshakeComplete; //Flag for whether the handshake has been completed.
        int numMsgs; //The number of messages sent.

        //Utilities
        RF24* radio;
        AES128* encCipher;

        //Functions
        void receiveHelper(byte* bytes, char* state, bool block);
        void createHeader(String state, byte bytes[]);
};
