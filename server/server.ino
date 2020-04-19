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
char state;
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
        if (iot.keyExpired()) {
            iot.authenticate();
        }
        else {
            radio.read(&receiveBuffer, sizeof(receiveBuffer));
            Serial.println((char*)receiveBuffer);
            // Process packet header (first 3 bytes)
            state = (char)receiveBuffer[1];

            if (state == '0'){
                Serial.println("State0");
                // RESPOND TO CLIENT ###########################################################
                radio.stopListening();
                byte sendData[] = "ACK0";
                radio.write(&sendData, sizeof(sendData));

                }

            else if (state == '1'){
                Serial.println("State1");
                //byte data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
                //iot.encrypt(data);
                //Serial.println((char*)data);

                // RESPOND TO CLIENT ###########################################################
                radio.stopListening();
                byte sendData[] = "ACK1";
                radio.write(&sendData, sizeof(sendData));
            }

            else if (state == '2'){
                Serial.println("State2");
                // RESPOND TO CLIENT ###########################################################
                radio.stopListening();
                byte sendData[] = "ACK2";
                radio.write(&sendData, sizeof(sendData));
            }
        }
    }
}

// HELPER FUNCTIONS ###########################################################################################################
