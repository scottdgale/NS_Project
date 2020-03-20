#include <SPI.h>
#include <nRF24L01.h>
#include <RF24.h>

RF24 radio(9, 10); // CE, CSN         
uint64_t address = 1; 
int count = 0;


void setup() {
  radio.begin();                  //Starting the Wireless communication
  radio.setPALevel(RF24_PA_LOW);
  radio.setDataRate(RF24_250KBPS);
  radio.setChannel(110);
  
  radio.openWritingPipe(address); //Setting the address where we will send the data
  radio.stopListening();          //This sets the module as transmitter
  
  Serial.begin(9600);
}

void loop(){
  
  const char text[5] = "Test";
  
  radio.write(&text, sizeof(text));                  //Sending the message to receiver
  Serial.print(text);
  Serial.println(count);
  count++;
  delay(2000);
}
