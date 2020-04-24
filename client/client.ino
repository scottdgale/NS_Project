#include <SPI.h>
#include <RF24.h>
#include <Crypto.h>
#include <AES.h>
#include <SHA256.h>
#include "IoTSec.h"

// GLOBAL VARIABLES SECTION ############################################################################################
RF24 radio(9, 10);                            // CE, CSN - PINOUT FOR SPI and NRF24L01      
AES128 cipher;                                // object used to encrypt data   
SHA256 hash256;                               // object used to compute HMAC  
byte addresses[][6] = {"NODE1", "NODE2"};     // Addresses used to SEND and RECEIVE data - ENSURE they are opposite on the sender/receiver               
byte receiveBuffer[MAX_PAYLOAD_SIZE + 1];     // Null terminate.
byte sendBuffer[32];
int tempVariable; 
int state;
IoTSec iot(&radio, &cipher, &hash256);

// ####################################################################################################################
void setup() {
    // RADIO SETUP
    radio.begin();                           // Starting the radio communication
    radio.setPALevel(RF24_PA_MIN);           // Transmit power
    radio.setDataRate(RF24_250KBPS);         // Transmit data rate
    radio.setChannel(10);                    // Channel = frequency
    radio.openWritingPipe(addresses[0]);     // Setting the address SENDING
    radio.openReadingPipe(1, addresses[1]);  // Setting the address RECEIVING
    radio.stopListening();                   // Setting for client
    Serial.begin(9600);
    state = 0;
    //Null terminate.
    memset(receiveBuffer, 0, MAX_PAYLOAD_SIZE + 1);
    randomSeed(analogRead(A0));
}

// ####################################################################################################################
void loop(){
    char* newState = new char[MAX_HEADER_SIZE];
    String msg;

    /***********************[HANDSHAKE] - Server Authentication.*******************/
    if (state == 0) {
//        Serial.println("\n##################     Begin Handshake Phase     ##################");
//        Serial.println("\n-----   Handshake Initialized   -----");
//        Serial.println("\n-----   Mutual Authentication Initialized   -----");
        iot.setHandshakeComplete(false);

        //Send initial conversation.
        int myRandNum = iot.createRandom();
        msg = ((String)myRandNum) + "-cli";
        Serial.println("[INFO] sent: " + msg);
        iot.send(msg, iot.getSecretKey(), iot.getSecretHashKey(), (String)state);

        //Receive initial conversation.
        msg = iot.receiveStr(iot.getSecretKey(), iot.getSecretHashKey(), newState, false);

        char* randStr = new char[3];
        memset(randStr, 0, 3);

        int i = 0;
        while (i < 3 && msg[i] != '-') {
            randStr[i] = msg[i];
            ++i;
        }
        int randNum = atoi(randStr);

        if (iot.getIntegrityPassed() && atoi(newState) == 0 && randNum == (myRandNum - 1)) {
            Serial.println("[INFO] received: " + msg);
//            Serial.println("\n-----   Server authenticated   -----");
            
            memset(randStr, 0, 3);
            for (int j = i + 1; j < msg.length(); ++j) {
                randStr[j - i - 1] = msg[j];
            }

            tempVariable = atoi(randStr);
            
            state = 1;
            delete[] randStr;
        }
        else {
//            Serial.println("\nXXXXX   Server Authentication Failed   XXXXX");
//            Serial.println("\nXXXXX   Mutual Authentication Failded   XXXXX");
//            Serial.println("\n##################     End Handshake Phase     ##################");
            delete[] randStr;
            iot.setHandshakeComplete(false);
        }
    }
    /***********************[HANDSHAKE] - Client Authentication.*******************/
    else if (state == 1) {
        msg = ((String)(tempVariable - 1)) + "-serv";
        Serial.println("[INFO] sent: " + msg);
        iot.send(msg, iot.getSecretKey(), iot.getSecretHashKey(), (String)state);

        msg = iot.receiveStr(iot.getSecretKey(), iot.getSecretHashKey(), newState, false);

        if (iot.getIntegrityPassed() && atoi(newState) != 0 && msg == "suc-auth") {
            Serial.println("[INFO] received: " + msg);
//            Serial.println("\n-----   Mutual Authentication Success   -----");
            state = 2;
        }
        else {
//            Serial.println("\nXXXXX   Mutual Authentication Failded   XXXXX");
//            Serial.println("\n##################     End Handshake Phase     ##################");
            state = 0;
            iot.setHandshakeComplete(false);
        }
    }
    /***********************[HANDSHAKE] - Share Nonces.*******************/
    else if (state == 2) {
//        Serial.println("\n-----   Session Keys Generating   -----");
        byte nonce1[MAX_PAYLOAD_SIZE];
        byte nonce2[MAX_PAYLOAD_SIZE];

        //Generate and Send the nonce.
        iot.createNonce(nonce1);
        Serial.print("[INFO] sent: ");
        iot.printByteArr(nonce1, MAX_PAYLOAD_SIZE);
        iot.send(nonce1, iot.getSecretKey(), iot.getSecretHashKey(), (String)state);

        //Retrieve the servers nonce.
        iot.receive(nonce2, iot.getSecretKey(), iot.getSecretHashKey(), newState, false);

        if (iot.getIntegrityPassed() && atoi(newState) != 0) {
            Serial.print("[INFO] received: ");
            iot.printByteArr(nonce2, MAX_PAYLOAD_SIZE);
            
            //Generate keys;
            iot.generateKeys(nonce1, nonce2);
            Serial.print("[INFO] Master Key: ");
            iot.printByteArr(iot.getMasterKey(), KEY_DATA_LEN);
            Serial.print("[INFO] Hash Key: ");
            iot.printByteArr(iot.getHashKey(), KEY_DATA_LEN);

            iot.setHandshakeComplete(true);
            state = 3;
            
//            Serial.println("\n-----   Session Keys Generating   -----");
//            Serial.println("\n-----   Handshake Finished   -----");
//            Serial.println("\n##################     End Handshake Phase     ##################");

//            Serial.println("\n##################     Begin Data Phase     ##################");
        }
        else {
          state = 0;
//          Serial.println("\nXXXXX   Handshake Failed   XXXXX");
//          Serial.println("\n##################     End Handshake Phase     ##################");
          iot.setHandshakeComplete(false);
        }
    }
    /***********************[VERIFY KEY EXPIRATION] - Set state to renew key.*******************/
    else if (iot.keyExpired()) {
        msg = "Expired";
        Serial.println(msg);
//        Serial.println("\n-----   Key Expired   -----");
//        Serial.println("\n##################     End Data Phase     ##################");
        state = 0;
        iot.setHandshakeComplete(false);
    }
    /***********************[DATA] - Starting The Data Phase.*******************/
    else if (state == 3) {
        msg = "Sh Secrt";
//        Serial.println("\n-----   Payload Sent   -----");
        Serial.println("[INFO] sent: " + msg);
        iot.send(msg, iot.getMasterKey(), iot.getHashKey(), (String)state);
        
        msg = iot.receiveStr(iot.getMasterKey(), iot.getHashKey(), newState, false);
        
        if (iot.getIntegrityPassed() && atoi(newState) != 0) {
//            Serial.println("\n-----   Payload Received   -----");
            Serial.println("[INFO] received: " + msg);
        }
        else {
//            Serial.println("\nXXXXX   Data Integrity Failed   XXXXX");
//            Serial.println("\n##################     End Data Phase     ##################");
            state = 0;
            iot.setHandshakeComplete(false);
        }
    }

    delete[] newState;
    newState = NULL;

    radio.stopListening();                        // Setup to tranmit
    delay(5000);
}

// HELPER FUNCTIONS ###########################################################################################################
bool getResponse(void){
    radio.startListening();                                    // SETUP for receiving data
    memset(receiveBuffer, 0, sizeof(receiveBuffer));           // Clear the reveiveBuffer
                                       
    unsigned long started_waiting = micros();                  // Set up a timeout period, get the current microseconds
    boolean timeout = false;                                   // Set up a variable to indicate if a response was received or not
 
    while (!radio.available()){                                // While nothing is received
        if (micros() - started_waiting > 10000000 ){           // If waited longer than 10ms, indicate timeout and exit while loop
            timeout = true;
            break;
        }     
    }
    if (timeout){                                             
        Serial.println("\nFailed, response timed out.");
        return false;                                           // Nothing received from server
    }
    else{
        radio.read(&receiveBuffer, sizeof(receiveBuffer));
        return true;
    }
}
