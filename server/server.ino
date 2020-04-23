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
}

void loop(){
    radio.startListening();
    if (radio.available())                     //Looking for incoming data
    {
        char* newState = new char[MAX_HEADER_SIZE];
        String msg;

        //If the key has expired the only thing we care about is the header.
        if (iot.keyExpired()) {
          iot.receive(receiveBuffer, iot.getSecretKey(), newState, false);
        }
        else {
          iot.receive(receiveBuffer, iot.getMasterKey(), iot.getHashKey(), newState, false);
        }

        Serial.println("State: " + (String)newState);
        state = atoi(newState);

        /***********************[HANDSHAKE] - Initialize Handshake.*******************/
        if (state == 0) {
            Serial.println("Handshake Initialized");
            iot.setHandshakeComplete(false);
            
            Serial.println((char*)receiveBuffer);

            msg = "hello";
            Serial.println(msg);
            iot.send(msg, iot.getSecretKey(), (String)state);
        }
        /***********************[HANDSHAKE] - Share Nonces.*******************/
        else if (state == 1) {
            byte nonce1[MAX_PAYLOAD_SIZE];
            byte nonce2[MAX_PAYLOAD_SIZE];
    
            //Retrieve the servers nonce.
            memmove(nonce1, receiveBuffer, MAX_PAYLOAD_SIZE);

            if (atoi(newState) != 0) {
                //Generate and Send the nonce.
                iot.createNonce(nonce2);
                iot.send(nonce2, iot.getSecretKey(), (String)state);
    
            
                //Generate keys;
                iot.generateKeys(nonce1, nonce2);
                Serial.print("Master Key: ");
                iot.printByteArr(iot.getMasterKey(), KEY_DATA_LEN);
                Serial.print("Hash Key: ");
                iot.printByteArr(iot.getHashKey(), KEY_DATA_LEN);
    
                iot.setHandshakeComplete(true);
                Serial.println("Handshake Completed");
            }
            else {
                state = 0;
                Serial.println("Handshake Failed");
            }
        }
        /***********************[VERIFY KEY EXPIRATION] - Send request to renew key.*******************/
        else if (iot.keyExpired()) {
            msg = "Expired";
            Serial.println(msg);
            iot.send(msg, iot.getSecretKey(), "0");
        }
        /***********************[DATA] - Starting The Data Phase.*******************/
        else if (state == 2) {
            Serial.println((char*)receiveBuffer);

            msg = "Top Sect";
            Serial.println(msg);
            iot.send(msg, iot.getMasterKey(), iot.getHashKey(), (String)state);
        }

        delete[] newState;
        newState = NULL;
    }
}
