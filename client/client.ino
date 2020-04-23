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
}

// ####################################################################################################################
void loop(){
    char* newState = new char[MAX_HEADER_SIZE];
    String msg;

    Serial.println("State: " + (String)state);

    /***********************[HANDSHAKE] - Initialize Handshake.*******************/
    if (state == 0) {
        Serial.println("Handshake Initialized");
        iot.setHandshakeComplete(false);

        //Send initial conversation.
        msg = "hello";
        Serial.println(msg);
        iot.send(msg, iot.getSecretKey(), (String)state);

        //Receive initial conversation.
        msg = iot.receiveStr(iot.getSecretKey(), newState, false);
        Serial.println(msg);

        if (atoi(newState) == 0 && msg == "hello") {
            state = 1;
        }
        else {
            Serial.println("Handshake Failed");
        }
    }
    /***********************[HANDSHAKE] - Share Nonces.*******************/
    else if (state == 1) {
        byte nonce1[MAX_PAYLOAD_SIZE];
        byte nonce2[MAX_PAYLOAD_SIZE];

        //Generate and Send the nonce.
        iot.createNonce(nonce1);
        iot.send(nonce1, iot.getSecretKey(), (String)state);

        //Retrieve the servers nonce.
        iot.receive(nonce2, iot.getSecretKey(), newState, false);

        if (atoi(newState) != 0) {
            //Generate keys;
            iot.generateKeys(nonce1, nonce2);
            Serial.print("Master Key: ");
            iot.printByteArr(iot.getMasterKey(), KEY_DATA_LEN);
            Serial.print("Hash Key: ");
            iot.printByteArr(iot.getHashKey(), KEY_DATA_LEN);

            iot.setHandshakeComplete(true);
            state = 2;
            Serial.println("Handshake Completed");
        }
        else {
          state = 0;
          Serial.println("Handshake Failed");
        }
    }
    /***********************[VERIFY KEY EXPIRATION] - Set state to renew key.*******************/
    else if (iot.keyExpired()) {
        msg = "Key Expired";
        Serial.println(msg);
        state = 0;
    }
    /***********************[DATA] - Starting The Data Phase.*******************/
    else if (state == 2) {
        msg = "Sh Secrt";
        Serial.println(msg);
        iot.send(msg, iot.getMasterKey(), iot.getHashKey(), (String)state);

        msg = iot.receiveStr(iot.getMasterKey(), iot.getHashKey(), newState, false);
        
        if (atoi(newState) != 0) {
            Serial.println(msg);
        }
        else {
            state = 0;
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
