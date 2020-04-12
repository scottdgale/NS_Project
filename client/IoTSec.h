#include"Arduino.h"

#define KEY_DATA_LEN 16
#define HASH_KEY_LEN 16
#define HASH_LEN 8

class IoTSec {
	public:
		IoTSec();
        int numberDoubler(int x);
        byte* encrypt(byte plainText[], int len);
        void hash(byte message[], int len, byte hash[]);
        unsigned long getSecret();
        void setSecret(unsigned long s);

	private:
		unsigned long secret;
        byte masterKey[KEY_DATA_LEN];
        bool handshakeComplete;
};
