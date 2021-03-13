# XBeeAESEncryption
 AES-128 encryption on dynamic telemetry packets sent through XBee in API mode

## XBee Configuration
Wondering how to configure your XBee to be compatible with this code?

| XBee Parameter | Value |
| -------------- | ----- |
| NI | Depends on module; I used RECV_A and RECV_B |
| CH | C |
| PAN ID | 6942 |
| Baud rate | Depends on module; I used 115200 |
| AP | Mode 2 (escaped) |
| MY | 0 |
| DH | 0 |
| DL | 0 |

#### Firmware Version
I used ```XB3-24, 802.15.4, Rev 200C```