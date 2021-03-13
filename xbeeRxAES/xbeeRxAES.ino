#include <XBee.h>
#include "libs/states.h"
#include "libs/AES/AES.cpp"

/*
Test receiving encrypted packets using XBee API mode and an AES library
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

// create the XBee object
XBee xbee = XBee();
XBeeResponse response = XBeeResponse();
Rx16Response rx16 = Rx16Response();

void setup() {
	Serial.begin(115200);
	Serial1.begin(115200);
	xbee.setSerial(Serial1);
	delay(1000);
}

void loop() {
	xbee.readPacket();
	if (xbee.getResponse().isAvailable()) {
		if (xbee.getResponse().getApiId() == RX_16_RESPONSE) { //expect rx_16 only
			xbee.getResponse().getRx16Response(rx16);
			
			uint8_t dataLength = rx16.getDataLength();
			uint8_t rx[dataLength];
			memcpy(rx, rx16.getData(), dataLength);

			switch(rx[0]) { //First byte is packet type
				default:
					Serial.print("Got packet of unknown type? Type=0x");
					Serial.println(rx[0], HEX);
					break;
				case TELEM_PACKET_TYPE_STATE:
					Serial.println("PTypeRX=State");
					decryptPacket(&telem_state, rx, sizeof(S_TELEMETRY_STATE));
					break;
				case TELEM_PACKET_TYPE_SENSOR:
					Serial.println("PTypeRX=Sensor");
					decryptPacket(&telem_sensor, rx, sizeof(S_TELEMETRY_SENSOR));
					break;
				case TELEM_PACKET_TYPE_CONTROL:
					Serial.println("PTypeRX=Control");
					decryptPacket(&telem_control, rx, sizeof(S_TELEMETRY_CONTROL));
					Serial.print("ControlPacket ID="); Serial.print(telem_control.commandID); Serial.print(", data1: "); Serial.println(telem_control.data1);
					break;
			}

			uint8_t rssi = rx16.getRssi();
			Serial.print(" RSSI: "); Serial.println(rssi);

			Serial.print("Times: STATE="); Serial.print(telem_state.timeSinceStartup); Serial.print(", SENSOR(+100ms)="); Serial.println(telem_sensor.GNSSLat);

			// Serial.print("PL");
			// Serial.println(packetLength);
			// switch (packetLength) {
			// 	default:
			// 		Serial.println("Got packet of unknown size");
			// 		break;
			// 	case sizeof(S_TELEMETRY_STATE):
			// 		Serial.println("Got state packet");
			// 		S_TELEMETRY_STATE recv = (S_TELEMETRY_STATE &);
			// 		telem_state.timeSinceStartup = recv.timeSinceStartup;
			// 		break;
			// 	case sizeof(S_TELEMETRY_SENSOR):
			// 		Serial.println("Got sensor packet");
			// 		break;
			// }
		}

		if (xbee.getResponse().isError()) {
		  Serial.print("Error code: ");
		  Serial.println(xbee.getResponse().getErrorCode());
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