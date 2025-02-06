#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include "ping.h"
#include "socket.h"
#include "w5500.h"

// Maximum number of hops for the traceroute
#define MAX_HOPS 30

// The UDP port for sending traceroute packets (typically 33434 for traceroute)
#define PORT 33434

// Buffer length for the ping message
#define BUF_LEN 32

// Function to perform a traceroute
uint8_t traceroute(uint8_t s, uint8_t* dest_addr);

// Function to send a traceroute request with a specific TTL value
void send_traceroute_request(uint8_t s, uint8_t* dest_addr, uint8_t ttl);

// Function to receive and process a traceroute reply
void receive_traceroute_reply(uint8_t s, uint8_t* addr, uint16_t len);

// Function to set the TTL value for outgoing packets
void set_ttl(uint8_t s, uint8_t ttl);

// Function to compute the checksum of a given data buffer
uint16_t checksum(uint8_t* data_buf, uint16_t len);

#endif // TRACEROUTE_H
