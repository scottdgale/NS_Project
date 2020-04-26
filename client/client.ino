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
unsigned long handshakeTime; 

// ####################################################################################################################
void setup() {
    // RADIO SETUP
    radio.begin();                           // Starting the radio communication
    radio.setPALevel(RF24_PA_MAX);           // Transmit power
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
        handshakeTime = micros();
        Serial.println("\n# HP BEGIN #");
        Serial.println("\n- H INIT -");
        Serial.println("\n- MA INIT -");
        iot.setHandshakeComplete(false);

        //Send random number to server.
        int myRandNum = iot.createRandom();
        msg = ((String)myRandNum) + "-cli";
        Serial.println("[I] S: " + msg);
        iot.send(msg, iot.getSecretKey(), iot.getSecretHashKey(), (String)state);

        //Receive decremented random number and rand number from server.
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
            Serial.println("[I] R: " + msg);
            Serial.println("\n- S AUTH SUCCESS -");
            
            memset(randStr, 0, 3);
            for (int j = i + 1; j < msg.length(); ++j) {
                randStr[j - i - 1] = msg[j];
            }

            //Store the server's random number in global memory so that we still remember it in the next loop iteration.
            tempVariable = atoi(randStr);
            
            state = 1;
            delete[] randStr;
        }
        else {
            Serial.println("\nX S AUTH FAIL X");
            Serial.println("\nX MA FAIL X");
            Serial.println("\n# HP END #");
            delete[] randStr;
            iot.setHandshakeComplete(false);
        }
    }
    /***********************[HANDSHAKE] - Client Authentication.*******************/
    else if (state == 1) {
        //Send the servers decremented random number.
        msg = ((String)(tempVariable - 1)) + "-serv";
        Serial.println("[I] S: " + msg);
        iot.send(msg, iot.getSecretKey(), iot.getSecretHashKey(), (String)state);

        //Receive either a success or failure from server.
        msg = iot.receiveStr(iot.getSecretKey(), iot.getSecretHashKey(), newState, false);

        if (iot.getIntegrityPassed() && atoi(newState) != 0 && msg == "suc-auth") {
            Serial.println("[I] R: " + msg);
            Serial.println("\n- MA SUCCESS -");
            state = 2;
        }
        else {
            Serial.println("\nX MA FAIL X");
            Serial.println("\n# HP END #");
            state = 0;
            iot.setHandshakeComplete(false);
        }
    }
    /***********************[HANDSHAKE] - Share Nonces.*******************/
    else if (state == 2) {
        Serial.println("\n- KEYS GEN INIT -");
        byte nonce1[MAX_PAYLOAD_SIZE];
        byte nonce2[MAX_PAYLOAD_SIZE];

        //Generate and Send the nonce.
        iot.createNonce(nonce1);
        Serial.print("[I] S: ");
        iot.printByteArr(nonce1, MAX_PAYLOAD_SIZE);
        iot.send(nonce1, iot.getSecretKey(), iot.getSecretHashKey(), (String)state);

        //Retrieve the servers nonce.
        iot.receive(nonce2, iot.getSecretKey(), iot.getSecretHashKey(), newState, false);

        if (iot.getIntegrityPassed() && atoi(newState) != 0) {
            Serial.print("[I] R: ");
            iot.printByteArr(nonce2, MAX_PAYLOAD_SIZE);
            
            //Generate keys;
            iot.generateKeys(nonce1, nonce2);
            Serial.print("[I] MK: ");
            iot.printByteArr(iot.getMasterKey(), KEY_DATA_LEN);
            Serial.print("[I] HK: ");
            iot.printByteArr(iot.getHashKey(), KEY_DATA_LEN);

            iot.setHandshakeComplete(true);
            state = 3;
            
            Serial.println("\n- KEYS GEN SUCCESS -");
            Serial.println("\n- H SUCCESS -");
            Serial.println("\n# HP END #");

            Serial.println("\n# DP BEGIN #");
        }
        else {
          state = 0;
          Serial.println("\nX H FAIL X");
          Serial.println("\n# HP END #");
          iot.setHandshakeComplete(false);
        }
        handshakeTime = micros() - handshakeTime;
        Serial.print("Handshake timing: " + (String)handshakeTime);
    }
    /***********************[VERIFY KEY EXPIRATION] - Set state to renew key.*******************/
    else if (iot.keyExpired()) {
        Serial.println("\n- K EXPIRED -");
        Serial.println("\n# DP END #");
        state = 0;
        iot.setHandshakeComplete(false);
    }
    /***********************[DATA] - Starting The Data Phase.*******************/
    else if (state == 3) {
        // Generate a simulated sensor reading and message payload
        int reading = analogRead(A0) * millis() % 1024;
        int sensorNumber = random(0, 10);
        msg = (String)sensorNumber + ":" + (String)reading;
      
        Serial.println("\n- P SENT -");
        Serial.println("[I] S: " + msg);
        iot.send(msg, iot.getMasterKey(), iot.getHashKey(), (String)state);
        handshakeTime = micros();
        msg = iot.receiveStr(iot.getMasterKey(), iot.getHashKey(), newState, false);
        
        if (iot.getIntegrityPassed() && atoi(newState) != 0) {
            Serial.println("\n- P RECEIVED -");
            Serial.println("[I] R: " + msg);
            Serial.println("Time: " + (String)(micros()-handshakeTime));
        }
        else {
            Serial.println("\nX INT FAIL X");
            Serial.println("\n# DP END #");
            state = 0;
            iot.setHandshakeComplete(false);
        }
    }

    delete[] newState;
    newState = NULL;

    radio.stopListening();                        // Setup to tranmit
    if (state == 3) {
        delay(5000);
    }
    
}

// HELPER FUNCTIONS ###########################################################################################################
bool getResponse(void){
    radio.startListening();                                    // SETUP for receiving data
    memset(receiveBuffer, 0, sizeof(receiveBuffer));           // Clear the reveiveBuffer
                                       
    unsigned long started_waiting = micros();                  // Set up a timeout period, get the current microseconds
    boolean timeout = false;                                   // Set up a variable to indicate if a response was received or not
 
    while (!radio.available()){                                // While nothing is received
        if (micros() - started_waiting > 50000000 ){           // If waited longer than 10ms, indicate timeout and exit while loop
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
