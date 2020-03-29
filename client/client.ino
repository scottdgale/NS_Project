#include <SPI.h>
#include <RF24.h>
#include "IoTSec.h"


// FUNCTION PROTOTYPES ################################################################################################
void get_response(void);                      // Checks for a response from the server - save results in receiveBuffer
bool getResponses(void);

// GLOBAL VARIABLES SECTION ############################################################################################
RF24 radio(9, 10);                            // CE, CSN - PINOUT FOR SPI and NRF24L01      
byte addresses[][6] = {"NODE1", "NODE2"};     // Addresses used to SEND and RECEIVE data - ENSURE they are opposite on the sender/receiver               
byte receiveBuffer[32]; 
byte sendBuffer[32];
int tempVariable; 
int state;
IoTSec iot;

// ####################################################################################################################
void setup() {
    // RADIO SETUP
    radio.begin();                           // Starting the radio communication
    radio.setPALevel(RF24_PA_LOW);           // Transmit power
    radio.setDataRate(RF24_250KBPS);         // Transmit data rate
    radio.setChannel(10);                   // Channel = frequency
    radio.openWritingPipe(addresses[0]);     // Setting the address SENDING
    radio.openReadingPipe(1, addresses[1]);  // Setting the address RECEIVING
    radio.stopListening();                   // Setting for client
    Serial.begin(9600);
    state = 0;

    randomSeed(analogRead(A0));
    iot.setSecret(random(2000000));
    Serial.println("Secret: " + String(iot.getSecret()));
}

// ####################################################################################################################
void loop(){
    if (state == 0){
        // SEND DATA ************************************************************************
        tempVariable = iot.numberDoubler(10);
        byte pt[] = {255,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        byte* ct = iot.encrypt(pt, sizeof(pt));
        Serial.println("Cipher byte 0: " + String(ct[0]));
        
        byte sendData[] = "<0>Test";
        radio.write(&sendData, sizeof(sendData));                  //Sending the message to receiver

        // RECEIVE DATA *********************************************************************
        if (getResponse()){
            // Check receiveBuffer for data
            Serial.println((char*)receiveBuffer);
            state = 1;
        }
        else{
            state = 0;
        }
    }
    
    else if (state == 1){  
        // SEND DATA ************************************************************************
        tempVariable = iot.numberDoubler(20);
        byte sendData[] = "<1>Test";
        radio.write(&sendData, sizeof(sendData));                  //Sending the message to receiver
        // RECEIVE DATA *********************************************************************
            if (getResponse()){
                // Check receiveBuffer for data
                Serial.println((char*)receiveBuffer);
                state = 2;
            }
            else{
                state = 0;
            }
    }

    else if (state == 2){
        // SEND DATA ************************************************************************
        byte sendData[] = "<2>Test";
        radio.write(&sendData, sizeof(sendData));                  //Sending the message to receiver
        // RECEIVE DATA *********************************************************************
        if (getResponse()){
            // Check receiveBuffer for data
            Serial.println((char*)receiveBuffer);
            state = 0;
        }
        else{
            state = 0;
        }
    }
    radio.stopListening();                        // Setup to tranmit
    delay(2000);
}

// HELPER FUNCTIONS ###########################################################################################################

bool getResponse(void){
    
    memset(receiveBuffer, 0, sizeof(receiveBuffer));           // Clear the reveiveBuffer
    radio.startListening();                                    // SETUP for receiving data
    unsigned long started_waiting_at = micros();               // Set up a timeout period, get the current microseconds
    boolean timeout = false;                                   // Set up a variable to indicate if a response was received or not
 
    while (!radio.available()){                                 // While nothing is received
        if (micros() - started_waiting_at > 5000000 ){           // If waited longer than 500ms, indicate timeout and exit while loop
            timeout = true;
            break;
        }     
    }
    if (timeout){                                             
        Serial.println("Failed, response timed out.");
        return false;                                           // Nothing received from server
    }
    else{
        radio.read(&receiveBuffer, sizeof(receiveBuffer));
        return true;
    }
}
