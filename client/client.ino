#include <SPI.h>
#include <RF24.h>
#include <Crypto.h>
#include <AES.h>
#include "IoTSec.h"


// FUNCTION PROTOTYPES ################################################################################################
void get_response(void);                      // Checks for a response from the server - save results in receiveBuffer
bool getResponses(void);

// GLOBAL VARIABLES SECTION ############################################################################################
RF24 radio(9, 10);                            // CE, CSN - PINOUT FOR SPI and NRF24L01      
AES128 cipher;                                // object used to encrypt data     
byte addresses[][6] = {"NODE1", "NODE2"};     // Addresses used to SEND and RECEIVE data - ENSURE they are opposite on the sender/receiver               
byte receiveBuffer[32]; 
byte sendBuffer[32];
int tempVariable; 
int state;
IoTSec iot(&radio, &cipher);

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

//    randomSeed(analogRead(A0));
//    iot.setSecret(random(2000000));
//    Serial.println("Secret: " + String(iot.getSecret()));
}

// ####################################################################################################################
void loop(){
    char* newState = new char[MAX_PACKET_SIZE];
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

        if (atoi(newState) == 0 && msg == "hello back") {
            state = 1;
        }
        else {
            Serial.println("Handshake Failed");
        }
    }
    /***********************[HANDSHAKE] - Share Nonces.*******************/
    else if (state == 1) {
        byte nonce1[KEY_DATA_LEN];
        byte nonce2[KEY_DATA_LEN];

        //Generate and Send the nonce.
        iot.createNonce(nonce1);
        iot.send(nonce1, KEY_DATA_LEN, iot.getSecretKey(), (String)state);

        //Retrieve the servers nonce.
        iot.receive(nonce2, KEY_DATA_LEN, iot.getSecretKey(), newState, false);

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
        msg = "Shhhh Dont Tell";
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








    
//    if (state == 1){
//        // SEND DATA ************************************************************************
//        tempVariable = iot.numberDoubler(10);
//        byte pt[] = {255,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
//        byte testMessage[] = {0, 2, 4, 8, 16, 32, 64, 128, 0, 2, 4, 8, 16, 32, 64, 128, 1, 2, 3, 4, 5, 6, 7};
//        byte* ct = iot.encrypt(pt, sizeof(pt));
//
//        // Test hash function - takes a 16 byte array as argument and stores the hash in the passed in hash array
//        byte hash[8];
//        iot.hash(testMessage, sizeof(testMessage), hash);
//
//        Serial.println("\nLength hash: " + (String)sizeof(hash));
//        for (int i=0; i<sizeof(hash); i++){
//            Serial.print((int)hash[i]);
//            Serial.print(" ");
//        }
//
//        byte sendData[] = "<1>Test";
//        radio.write(&sendData, sizeof(sendData));                  //Sending the message to receiver
//        state = 2;
//
//        // RECEIVE DATA *********************************************************************
//        if (getResponse()){
//            // Check receiveBuffer for data
//            Serial.println((char*)receiveBuffer);
//            if ((char)receiveBuffer[1] == '0') {
//                state = 0;
//            }
//            else {
//                state = 2;
//            }
//        }
//        else{
//            state = 0;
//        }
//    }
//
//    else if (state == 2){
//        // SEND DATA ************************************************************************
//        tempVariable = iot.numberDoubler(20);
//        byte sendData[] = "<2>Test";
//        radio.write(&sendData, sizeof(sendData));                  //Sending the message to receiver
//        // RECEIVE DATA *********************************************************************
//            if (getResponse()){
//                // Check receiveBuffer for data
//                Serial.println((char*)receiveBuffer);
//                if ((char)receiveBuffer[1] == '0') {
//                    state = 0;
//                }
//                else {
//                    state = 3;
//                }
//            }
//            else{
//                state = 0;
//            }
//    }
//
//    else if (state == 3){
//        // SEND DATA ************************************************************************
//        byte sendData[] = "<3>Test";
//        radio.write(&sendData, sizeof(sendData));                  //Sending the message to receiver
//        // RECEIVE DATA *********************************************************************
//        if (getResponse()){
//            // Check receiveBuffer for data
//            Serial.println((char*)receiveBuffer);
//            state = 0;
//        }
//        else{
//            state = 0;
//        }
//    }

    delete[] newState;
    newState = NULL;

    radio.stopListening();                        // Setup to tranmit
    delay(3000);
}

// HELPER FUNCTIONS ###########################################################################################################

bool getResponse(void){
    radio.startListening();                                    // SETUP for receiving data
    memset(receiveBuffer, 0, sizeof(receiveBuffer));           // Clear the reveiveBuffer
                                       
    unsigned long started_waiting = micros();                  // Set up a timeout period, get the current microseconds
    boolean timeout = false;                                   // Set up a variable to indicate if a response was received or not
 
    while (!radio.available()){                                // While nothing is received
        if (micros() - started_waiting > 1000000 ){            // If waited longer than 10ms, indicate timeout and exit while loop
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
