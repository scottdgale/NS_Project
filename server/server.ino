#include <SPI.h>
#include <RF24.h>
#include "IoTSec.h"


// FUNCTION PROTOTYPES ################################################################################################
void get_response(void);                      // Checks for a response from the server - save results in receiveBuffer

// GLOBAL VARIABLES SECTION ############################################################################################
RF24 radio(9, 10);                            // CE, CSN - PINOUT FOR SPI and NRF24L01      
byte addresses[][6] = {"NODE1", "NODE2"};     // Addresses used to SEND and RECEIVE data - ENSURE they are opposite on the sender/receiver               
byte receiveBuffer[32]; 
byte sendBuffer[32];
int state;
int tempVariable; 

// Create IoTSec Object
IoTSec iot(&radio);

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
    
//    randomSeed(analogRead(A0));
//    iot.setSecret(random(2000000));
//    Serial.println("Secret: " + String(iot.getSecret()));
}

void loop(){
    radio.startListening();
    if (radio.available())                     //Looking for incoming data
    {
        char* newState = new char[MAX_PACKET_SIZE];
        String msg;

        //If the key has expired the only thing we care about is the header.
        if (iot.keyExpired()) {
          iot.receive(receiveBuffer, MAX_PACKET_SIZE, iot.getSecretKey(), newState, false);
        }
        else {
          iot.receive(receiveBuffer, MAX_PACKET_SIZE, iot.getMasterKey(), iot.getHashKey(), newState, false);
        }

        Serial.println("State: " + (String)newState);
        state = atoi(newState);

        /***********************[HANDSHAKE] - Initialize Handshake.*******************/
        if (state == 0) {
            Serial.println("Handshake Initialized");
            iot.setHandshakeComplete(false);
            
            Serial.println((char*)receiveBuffer);

            msg = "hello back";
            Serial.println(msg);
            iot.send(msg, iot.getSecretKey(), (String)state);
        }
        /***********************[HANDSHAKE] - Share Nonces.*******************/
        else if (state == 1) {
            byte nonce1[KEY_DATA_LEN];
            byte nonce2[KEY_DATA_LEN];
    
            //Retrieve the servers nonce.
            memmove(nonce1, receiveBuffer, KEY_DATA_LEN);

            if (newState[0] != '0') {
                //Generate and Send the nonce.
                iot.createNonce(nonce2);
                iot.send(nonce2, KEY_DATA_LEN, iot.getSecretKey(), (String)state);
    
            
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
            msg = "Key Expired";
            Serial.println(msg);
            iot.send(msg, iot.getSecretKey(), "0");
        }
        /***********************[DATA] - Starting The Data Phase.*******************/
        else if (state == 2) {
            Serial.println((char*)receiveBuffer);

            msg = "Top Secret Data";
            Serial.println(msg);
            iot.send(msg, iot.getMasterKey(), iot.getHashKey(), (String)state);
        }



        

        
//        radio.read(&receiveBuffer, sizeof(receiveBuffer));
//        Serial.println((char*)receiveBuffer);
        // Process packet header (first 3 bytes)
//        state = (char)receiveBuffer[1] - '0';
//        if (state == 1){
//            Serial.println("State1");
//            // RESPOND TO CLIENT ###########################################################
//            radio.stopListening();
//            byte sendData[] = "<1>ACK1";
//            radio.write(&sendData, sizeof(sendData));
//
//            }
//
//        else if (state == 2){
//            Serial.println("State2");
//            //byte data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
//            //iot.encrypt(data);
//            //Serial.println((char*)data);
//
//            // RESPOND TO CLIENT ###########################################################
//            radio.stopListening();
//            byte sendData[] = "<2>ACK2";
//            radio.write(&sendData, sizeof(sendData));
//        }
//
//        else if (state == 3){
//            Serial.println("State3");
//            // RESPOND TO CLIENT ###########################################################
//            radio.stopListening();
//            byte sendData[] = "<3>ACK3";
//            radio.write(&sendData, sizeof(sendData));
//        }

        delete[] newState;
        newState = NULL;
    }
}

// HELPER FUNCTIONS ###########################################################################################################
