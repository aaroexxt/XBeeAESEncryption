#include <XBee.h>
#include "libs/states.h"
#include "libs/AES/AES.cpp"

/*
Test sending encrypted packets using XBee API mode and an AES library
Should be uploaded to board with MY address of 0 and DL set to 0x0
*/


/*
TELEMETRY STRUCTS

How does telemetry sending work?

3 different packet types (to conform to XBee packet size limitations in API mode)
"State": holds vehicle state information vehicle -> ground
"Sensor": holds sensor information vehicle -> ground
"Control": holds some command packet ground -> vehicle

Packet structure:
1st byte: packet type@TELEM_PACKET_TYPE
2nd-n(closest multiple that aligns with AES block size) bytes: AES-128 encrypted data
*/
typedef enum {
	TELEM_PACKET_TYPE_STATE = 0x00,
	TELEM_PACKET_TYPE_SENSOR = 0x01,
	TELEM_PACKET_TYPE_CONTROL = 0x02
} TELEM_PACKET_TYPE;

struct S_TELEMETRY_STATE {
	//Raw vehicle information
	unsigned long timeSinceStartup;
	unsigned long missionElapsedTime;

	//State stuff
	FlightMode fMode;
	PyroStates pState;
	ChuteStates cState;
	DataLoggingStates dState;
	TelemSendStates tSState;
	TelemConnStates tCState;

	//Basic sensor data
	float battV;
	float servoV;
	float rollMotorV;
	float boardTemp;

	//Vehicle estimation
	float twr;
	float mass;

	//GNSS locking data
	byte GNSSFix;
	int GNSSpDOP;
	byte GNSSSats;
	int GNSSAccHoriz; //mm
	int GNSSAccVert; //mm
	int GNSSAccVel; //mm

	//Pyro channel data
	byte pyroCont;
	byte pyroFire;
};

struct S_TELEMETRY_SENSOR {
	//Raw sensor data
	float gyroX;
	float gyroY;
	float gyroZ;
	float accX;
	float accY;
	float accZ;
	long GNSSLat;
	long GNSSLon;

	//Calculated state vector data
	float oriX;
	float oriY;
	float oriZ;
	float posX;
	float posY;
	float posZ;
	float velX;
	float velY;
	float velZ;

	//TVC Data
	float tvcY;
	float tvcZ;
	bool tvcActive;

	//Roll wheel data
	float rollPercent;
	float rollSetpoint;
};

struct S_TELEMETRY_CONTROL {
	byte commandID;
	byte data1;
	byte data2;
	byte data3;
};

//Define structs used to hold data
struct S_TELEMETRY_STATE telem_state;
struct S_TELEMETRY_SENSOR telem_sensor;
struct S_TELEMETRY_CONTROL telem_control;

//Define AES stuff (at 128 bit encryption, this is a 16 byte key)
#define KEYBITS 128
//Get buffer size padded out to the next largest correct block size (16 bytes)
#define getAESBufferSize(unpadded_size) unpadded_size - (unpadded_size % 16) + 16
//Includes an extra byte for packet type at beginning
#define getPacketBufferSize(unpadded_size) getAESBufferSize(unpadded_size) + 1

const uint8_t aes_key[KEYLENGTH(KEYBITS)] = {0x80, 0x08, 0x13, 0x58, 0x00, 0x81, 0x35, 0x80, 0x08, 0x13, 0x58, 0x00, 0x81, 0x35, 0x00, 0x01};
uint32_t rk[RKLENGTH(KEYBITS)];

//Buffer sizes for different packet types
#define state_packet_buffer_size getPacketBufferSize(sizeof(S_TELEMETRY_STATE))
#define sensor_packet_buffer_size getPacketBufferSize(sizeof(S_TELEMETRY_SENSOR))
#define control_packet_buffer_size getPacketBufferSize(sizeof(S_TELEMETRY_CONTROL))

//Create buffers to hold aes-encrypted data
uint8_t state_aes_buffer[state_packet_buffer_size];
uint8_t sensor_aes_buffer[sensor_packet_buffer_size];
uint8_t control_aes_buffer[control_packet_buffer_size];

// create the XBee object
XBee xbee = XBee();

Tx16Request txStateEncrypted = Tx16Request(0x0000, state_aes_buffer, state_packet_buffer_size);
Tx16Request txSensorEncrypted = Tx16Request(0x0000, sensor_aes_buffer, sensor_packet_buffer_size);
Tx16Request txControlEncrypted = Tx16Request(0x0000, control_aes_buffer, control_packet_buffer_size); 
TxStatusResponse txStatus = TxStatusResponse();

void setup() {
	Serial.begin(115200);
	Serial1.begin(115200);
	xbee.setSerial(Serial1);
	delay(1000);

	//Setup initial values
	telem_state.timeSinceStartup = millis();
	telem_state.pyroFire = 0b00000011;

	//DEMO STUFF
	
	/*Serial.println("AES-128 KEY:");
	for (int i=0; i<KEYLENGTH(KEYBITS); i++) {
		Serial.print("0x");
		Serial.print(aes_key[i], HEX);
		Serial.print(" ");
	}
	Serial.println("\n");

	uint8_t state_aes_buffer[getPacketBufferSize(sizeof(S_TELEMETRY_STATE))];
	encryptPacket(TELEM_PACKET_TYPE_STATE, state_aes_buffer, &telem_state, sizeof(S_TELEMETRY_STATE));

	S_TELEMETRY_STATE out;
	TELEM_PACKET_TYPE type;
	decryptPacket(&type, &out, state_aes_buffer, sizeof(S_TELEMETRY_STATE));

	Serial.println("TSS, PF1");
	Serial.println(telem_state.timeSinceStartup);
	Serial.println(telem_state.pyroFire);
	Serial.println("TSS, PF2");
	Serial.println(out.timeSinceStartup);
	Serial.println(out.pyroFire);
	Serial.print("Expected vs parsed packet type: 0x"); Serial.print(TELEM_PACKET_TYPE_STATE, HEX); Serial.print(" | 0x"); Serial.println(type, HEX);
	
	Serial.println("\nOriginal telem_state in plaintext");
	printBuffer((uint8_t*)&telem_state, sizeof(S_TELEMETRY_STATE));
	Serial.println("Decrypted buffer");
	printBuffer((uint8_t*)&out, sizeof(S_TELEMETRY_STATE));
	
	while(true){}*/
}

unsigned long lastControl = 0;
unsigned long lastSend = 0;
int targetPPS = 50;
float dtPacket = 1.0/targetPPS;
int packetCount = 0;
int fails = 0;
int successes = 0;
unsigned long lastPrint = 0;

void loop() {
	if ((millis()-lastSend)/1000.0 > dtPacket) {
		unsigned long start = micros();
		encryptPacket(TELEM_PACKET_TYPE_STATE, state_aes_buffer, &telem_state, sizeof(S_TELEMETRY_STATE));
		unsigned long enc = micros();
		xbee.send(txStateEncrypted);
		unsigned long send = micros();

		// Serial.print("AESEncryptTime: ");
		// Serial.print((enc-start)/1000.0f, 3);
		// Serial.print("ms, XBeeSendTime: ");
		// Serial.print((send-enc)/1000.0f, 3);
		// Serial.println("ms");
		// Serial.print("FULLS_STATE: ");
		// Serial.print((send-start)/1000.0f, 3);
		// Serial.println("ms");

		start = micros();
		encryptPacket(TELEM_PACKET_TYPE_SENSOR, sensor_aes_buffer, &telem_sensor, sizeof(S_TELEMETRY_SENSOR));
		enc = micros();
		xbee.send(txSensorEncrypted);
		send = micros();

		// Serial.print("AESEncryptTime: ");
		// Serial.print((enc-start)/1000.0f, 3);
		// Serial.print("ms, XBeeSendTime: ");
		// Serial.print((send-enc)/1000.0f, 3);
		// Serial.println("ms");
		// Serial.print("FULLS_SENSOR: ");
		// Serial.print((send-start)/1000.0f, 3);
		// Serial.println("ms");

		if (millis() - lastControl > 1000) {
			telem_control.commandID++;
			telem_control.data1 = random(0, 255);
			encryptPacket(TELEM_PACKET_TYPE_CONTROL, control_aes_buffer, &telem_control, sizeof(S_TELEMETRY_CONTROL));
			xbee.send(txControlEncrypted);
			lastControl = millis();
		}

		lastSend = millis();
		packetCount++;
	}

	if (millis()-lastPrint > 1000) {

		Serial.print("PacketRate: targ="); Serial.print(targetPPS); Serial.print(" | actual="); Serial.println(packetCount);
		Serial.print("PacketOK: fail%="); Serial.print(fails/float(fails+successes)); Serial.print(" | success%="); Serial.println(successes/float(fails+successes));
		packetCount = 0;
		fails = 0;
		successes = 0;
		lastPrint = millis();
	}

	telem_state.timeSinceStartup = millis();
	telem_sensor.GNSSLat = millis()+100;

	xbee.readPacket();
	if (xbee.getResponse().isAvailable()) {
		if (xbee.getResponse().getApiId() == TX_STATUS_RESPONSE) {
			xbee.getResponse().getTxStatusResponse(txStatus);

			// get the delivery status, the fifth byte
			if (txStatus.getStatus() == SUCCESS) {
				// success.  time to celebrate
				//Serial.println("Send ok; receiver ok");
				successes++;
			} else {
				// the remote XBee did not receive our packet. is it powered on?
				//Serial.println("Send ok; no receiver?");
				fails++;
			}
		} else if (xbee.getResponse().isError()) {
			Serial.println("Send ok; recv corrupt packet");
			Serial.print("Error code: ");
			Serial.println(xbee.getResponse().getErrorCode(), HEX); 
		} else {
			Serial.println("Send fail; radio ok?");
			Serial.print("Weird API ID in response: ");
			Serial.println(xbee.getResponse().getApiId(), HEX);
		}
	}
}


void encryptPacket(TELEM_PACKET_TYPE type, uint8_t *aes_buffer, void *unpaddedData, const int data_size) {
	encryptAESBuffer(aes_buffer, unpaddedData, data_size);

	memmove(aes_buffer+1, aes_buffer, getAESBufferSize(data_size)); //shift buffer over by 1 to make room for packet type as first byte
	memset(aes_buffer, (uint8_t)type, 1); //copy packet type to first byte
}

void encryptAESBuffer(uint8_t *aes_buffer, void *unpaddedData, const int data_size) {
	//Get nRounds, or number of rounds of encryption to do
	int nroundsEnc = aesSetupEncrypt(rk, aes_key, KEYBITS);

	//Find closest buffer size to packet sizes that are divisible by 16
	const uint8_t aes_buffer_size = getAESBufferSize(data_size);

	//Reset aes_buffer
	memset(aes_buffer, 0, aes_buffer_size);
	//Copy plaintext data into buffer
	memcpy(aes_buffer, unpaddedData, data_size);

	//Proceed block by block and encrypt the data
	for (int i=0; i<aes_buffer_size/16; i++) {
		//Declare single block arrays
		uint8_t toEncrypt[16];
		uint8_t encrypted[16];
		memcpy(toEncrypt, aes_buffer+(i*16), 16); //copy single block to be encrypted
		aesEncrypt(rk, nroundsEnc, toEncrypt, encrypted); //Do the encryption
		memcpy(aes_buffer+(i*16), encrypted, 16); //copy data back into buffer
	}
}

//Decrypt to seperate packet type variable
void decryptPacket(TELEM_PACKET_TYPE *type, void *out, uint8_t *aes_buffer, const int data_size) {
	memset(type, aes_buffer[0], 1); //copy packet type into enum
	memmove(aes_buffer, aes_buffer+1, getAESBufferSize(data_size)); //shift memory over correct amount
	decryptAESBuffer(out, aes_buffer, data_size);
}

//Decrypt if you already know the packet type
void decryptPacket(void *out, uint8_t *aes_buffer, const int data_size) {
	memmove(aes_buffer, aes_buffer+1, getAESBufferSize(data_size)); //shift memory over correct amount
	decryptAESBuffer(out, aes_buffer, data_size);
}

void decryptAESBuffer(void *out, uint8_t *aes_buffer, const int data_size) {
	//Get nRounds, or number of rounds of decryption
	int nroundsDec = aesSetupDecrypt(rk, aes_key, KEYBITS);

	const int buffer_size = getAESBufferSize(data_size);

	//Ensure the buffer has a correct block size
	if (buffer_size % 16 != 0) {
		return;
	} else {	
		//Proceed block by block and decrypt the data
		for (int i=0; i<buffer_size/16; i++) {
			uint8_t toDecrypt[16];
			uint8_t decrypted[16];
			memcpy(toDecrypt, aes_buffer+(i*16), 16); //copy single block to be decrypted
			aesDecrypt(rk, nroundsDec, toDecrypt, decrypted);
			memcpy(aes_buffer+(i*16), decrypted, 16); //copy data back into buffer
		}
	}

	//Copy data into final array, without copying decrypted padding
	memcpy(out, aes_buffer, data_size);
}

void printBuffer(uint8_t *buffer, const int buffer_size) {
	Serial.print("BUFFER SIZE=");
	Serial.print(buffer_size);
	Serial.println(" ------");
	for (int i=0; i<buffer_size; i++) {
		Serial.print("0x");
		Serial.print(buffer[i], HEX);
		Serial.print("\t");
		if ((i+1)%6 == 0 && i != 0) Serial.println();
	}
	Serial.println("\n----------\n");
}