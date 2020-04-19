#include"Arduino.h"
#include <RF24.h>

#define KEY_DATA_LEN 16
#define HASH_KEY_LEN 16
#define HASH_LEN 8

class IoTSec {
	public:
	    //Constructors
		IoTSec(RF24* radio);
		~IoTSec();

		//Functions
		void handshake();
		bool isHandshakeComplete();
        int numberDoubler(int x);
        byte* encrypt(byte plainText[], int len);
        void hash(byte message[], int len, byte hash[]);

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
};
