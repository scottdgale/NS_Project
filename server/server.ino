#include <SPI.h>
#include <nRF24L01.h>
#include <RF24.h>

RF24 radio(9, 10); // CE, CSN         
uint64_t address = 1;
int count = 0;
char input_buffer[15]; 

void setup() {
  radio.begin();                            //Starting the Wireless communication
  radio.setPALevel(RF24_PA_LOW);
  radio.setDataRate(RF24_250KBPS);
  radio.setChannel(110);
  
  radio.openReadingPipe(1, address);   //Setting the address where we will send the data
  radio.startListening();                    //This sets the module as receiver
  
  Serial.begin(9600);
}

void loop(){
  
  if (radio.available())                     //Looking for incoming data
  {
    radio.read(&input_buffer, sizeof(input_buffer));
    Serial.println(input_buffer);
    delay(1000);
  }
}
