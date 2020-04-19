#include"Arduino.h"
#include <RF24.h>

#define MAX_PACKET_SIZE 32
#define KEY_DATA_LEN 16
#define HASH_KEY_LEN 16
#define HASH_LEN 8

class IoTSec {
	public:
	    //Constructors
		IoTSec(RF24* radio);
		~IoTSec();

		//Functions
		void authenticate();
		bool keyExpired();
		void send(String str, String state);
		void send(char* arr, int size, String state);
        void send(String str, byte* encKey, String state);
		void send(char* arr, int size, byte* encKey, String state);
        void send(String str, byte* encKey, byte* intKey, String state);
		void send(char* arr, int size, byte* encKey, byte* intKey, String state);
		String receiveStr();
        void receive(byte bytes[], int size);
        String receiveStr(byte* encKey);
        void receive(byte bytes[], int size, byte* encKey);
        String receiveStr(byte* encKey, byte* intKey);
        void receive(byte bytes[], int size, byte* encKey, byte* intKey);
        int numberDoubler(int x);
        byte* encrypt(byte plainText[], int len);
        void hash(byte message[], int len, byte hash[]);
        void printByteArr(byte arr[], int size);

	private:
	    //Keys
		byte* secretKey; //The secret key known to both the client and the server.
        byte* masterKey; //The master key generated through the handshake.
        byte* hashKey; //The hash key generated from the master key.

        //State
        bool handshakeComplete; //Flag for whether the handshake has been completed.

        //Utilities
        RF24* radio;

        //Functions
        void createNonce(byte nonce[]);
        void receiveHelper(byte* bytes, int size);
        void createHeader(String state, byte bytes[]);
};
