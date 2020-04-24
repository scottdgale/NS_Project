#include <SPI.h>
#include <RF24.h>
#include <Crypto.h>
#include <AES.h>
#include <SHA256.h>
#include "IoTSec.h"


// GLOBAL VARIABLES SECTION ############################################################################################
RF24 radio(9, 10);                            // CE, CSN - PINOUT FOR SPI and NRF24L01      
AES128 cipher;                                // object used to encrypt data  
SHA256 hash256;   
byte addresses[][6] = {"NODE1", "NODE2"};     // Addresses used to SEND and RECEIVE data - ENSURE they are opposite on the sender/receiver               
byte receiveBuffer[MAX_PAYLOAD_SIZE + 1];     // Null terminate.
byte sendBuffer[32];
int state;
int tempVariable; 

// Create IoTSec Object
IoTSec iot(&radio, &cipher, &hash256);

// ####################################################################################################################
void setup() {
    // RADIO SETUP
    radio.begin();                           // Starting the radio communication
    radio.setPALevel(RF24_PA_MIN);           // Transmit power
    radio.setDataRate(RF24_250KBPS);         // Transmit data rate
    radio.setChannel(10);                    // Channel = frequency
    radio.openWritingPipe(addresses[1]);     // Setting the address RECEIVING
    radio.openReadingPipe(1, addresses[0]);  // Setting the address SENDING
    radio.startListening();                  // Setting for server
    Serial.begin(9600);
    //Null terminate.
    memset(receiveBuffer, 0, MAX_PAYLOAD_SIZE + 1);
    randomSeed(analogRead(A1));
}

void loop(){
    radio.startListening();
    if (radio.available())                     //Looking for incoming data
    {
        char* newState = new char[MAX_HEADER_SIZE];
        String msg;

        //If the key has expired the only thing we care about is the header.
        if (iot.keyExpired()) {
          iot.receive(receiveBuffer, iot.getSecretKey(), iot.getSecretHashKey(), newState, false);
        }
        else {
          iot.receive(receiveBuffer, iot.getMasterKey(), iot.getHashKey(), newState, false);
        }

        state = atoi(newState);

        if (!iot.getIntegrityPassed()) {
            Serial.println("\nX INT FAIL X");
            msg = "Int Fail";
            Serial.println("[I] S: " + msg);
            iot.send(msg, iot.getSecretKey(), iot.getSecretHashKey(), "0");
            Serial.println("\n# [H/D]P END #");
            iot.setHandshakeComplete(false);
        }
        /***********************[HANDSHAKE] - Server Authentication.*******************/
        else if (state == 0) {
            Serial.println("\n# HP BEGIN #");
            Serial.println("\n- H INIT -");
            Serial.println("\n- MA INIT -");

            //Receive the random number from the client.
            Serial.print("[I] R: ");
            Serial.println((char*)receiveBuffer);
            iot.setHandshakeComplete(false);

            char* randStr = new char[3];
            memset(randStr, 0, 3);

            int i = 0;
            while (i < 3 && receiveBuffer[i] != '-') {
                randStr[i] = receiveBuffer[i];
                ++i;
            }
            int randNum = atoi(randStr);
            delete[] randStr;

            //Send the client's random number decremented along with the server's random number.
            tempVariable = iot.createRandom();
            msg = ((String) (randNum - 1)) + "-" + ((String) tempVariable);
            Serial.println("[I] S: " + msg);
            iot.send(msg, iot.getSecretKey(), iot.getSecretHashKey(), (String)state);
        }
        /***********************[HANDSHAKE] - Client Authentication.*******************/
        else if (state == 1) {
            //Receives the server's decremented random number from the client.
            Serial.print("[I] R: ");
            Serial.println((char*)receiveBuffer);

            char* randStr = new char[3];
            memset(randStr, 0, 3);

            int i = 0;
            while (i < 3 && receiveBuffer[i] != '-') {
                randStr[i] = receiveBuffer[i];
                ++i;
            }
            int randNum = atoi(randStr);
            delete[] randStr;

            if (randNum == (tempVariable - 1)) {
                Serial.println("\n- C AUTH SUCCESS -");
                Serial.println("\n- MA SUCCESS -");

                //Send a successful message back to client.
                msg = "suc-auth";
                Serial.println("[I] S: " + msg);
                iot.send(msg, iot.getSecretKey(), iot.getSecretHashKey(), (String)state);
            }
            else {
                Serial.println("\nX C AUTH FAIL X");
                Serial.println("\nX MA FAIL X");
                msg = "fail-aut";
                Serial.println("[I] S: " + msg);
                iot.send(msg, iot.getSecretKey(), iot.getSecretHashKey(), "0");
                Serial.println("\n# HP END #");
                iot.setHandshakeComplete(false);
            }
        }
        /***********************[HANDSHAKE] - Share Nonces.*******************/
        else if (state == 2) {
            Serial.println("\n- KEYS GEN INIT -");
            byte nonce1[MAX_PAYLOAD_SIZE];
            byte nonce2[MAX_PAYLOAD_SIZE];
    
            //Retrieve the clients nonce.
            memmove(nonce1, receiveBuffer, MAX_PAYLOAD_SIZE);
            Serial.print("[I] R: ");
            iot.printByteArr(nonce1, MAX_PAYLOAD_SIZE);

            if (atoi(newState) != 0) {
                //Generate and Send the nonce.
                iot.createNonce(nonce2);
                Serial.print("[I] S: ");
                iot.printByteArr(nonce2, MAX_PAYLOAD_SIZE);
                iot.send(nonce2, iot.getSecretKey(), iot.getSecretHashKey(), (String)state);
    
            
                //Generate keys;
                iot.generateKeys(nonce1, nonce2);
                Serial.print("[I] MK: ");
                iot.printByteArr(iot.getMasterKey(), KEY_DATA_LEN);
                Serial.print("[I]  HK: ");
                iot.printByteArr(iot.getHashKey(), KEY_DATA_LEN);
    
                iot.setHandshakeComplete(true);
                Serial.println("\n-----   KEYS GEN SUCCESS   -----");
                Serial.println("\n-----   H SUCCESS   -----");
                Serial.println("\n# HP END #");
    
                Serial.println("\n# DP BEGIN #");
            }
            else {
                state = 0;
                Serial.println("\nX H FAIL X");
                Serial.println("\n# HP END #");
                iot.setHandshakeComplete(false);
            }
        }
        /***********************[VERIFY KEY EXPIRATION] - Send request to renew key.*******************/
        else if (iot.keyExpired()) {
            msg = "Expired";
            Serial.println("\n- EXPIRED -");
            Serial.println("[I] S: " + msg);
            iot.send(msg, iot.getSecretKey(), iot.getSecretHashKey(), "0");
            Serial.println("\n# DP END #");
            iot.setHandshakeComplete(false);
        }
        /***********************[DATA] - Starting The Data Phase.*******************/
        else if (state == 3) {
            Serial.println("\n- P RECEIVED-");
            Serial.print("[I] R: ");
            Serial.println((char*)receiveBuffer);

            msg = "Top Sect";
            Serial.println("\n- P SENT -");
            Serial.println("[I] S: " + msg);
            iot.send(msg, iot.getMasterKey(), iot.getHashKey(), (String)state);
        }

        delete[] newState;
        newState = NULL;
    }
}
