#include "socket.h"
#include "w5500.h"
#include "ping.h"

#define MAX_HOPS 30
#define PORT 33434
#define BUF_LEN 32

extern void ping_wait_ms(int ms);

uint8_t traceroute(uint8_t s, uint8_t* dest_addr) {
    uint8_t ttl = 1;
    uint8_t hops = 0;
    int ret;
    uint8_t curr_addr[4];
    uint8_t curr_name[64];
    
    while (ttl <= MAX_HOPS) {
        uint8_t sr = getSn_SR(s);
        eth_printf("SR: %02X", sr);
        
        switch (sr) {
            case SOCK_CLOSED:
                close(s);
                IINCHIP_WRITE(Sn_PROTO(s), IPPROTO_ICMP); // set ICMP Protocol
                if ((ret = socket(s, Sn_MR_IPRAW, 3000, 0)) != s) {
                    eth_printf("socket %d fail %d", s, ret);
                    return SOCKET_ERROR;
                }
                while (getSn_SR(s) != SOCK_IPRAW);
                ping_wait_ms(1000); // Wait for a bit
                break;

            case SOCK_IPRAW:
                send_traceroute_request(s, dest_addr, ttl);
                while (1) {
                    uint16_t len = getSn_RX_RSR(s);
                    if (len > 0) {
                        uint8_t recv_addr[4];
                        receive_traceroute_reply(s, recv_addr, len);
                        eth_printf("Hop %d: %d.%d.%d.%d\n", ttl, recv_addr[0], recv_addr[1], recv_addr[2], recv_addr[3]);
                        if (memcmp(recv_addr, dest_addr, 4) == 0) {
                            eth_printf("Destination reached: %d.%d.%d.%d\n", recv_addr[0], recv_addr[1], recv_addr[2], recv_addr[3]);
                            return 0; // Destination reached
                        }
                        break;
                    }
                    ping_wait_ms(50); // Wait a bit before retrying
                }
                break;

            default:
                break;
        }
        
        ttl++;
        if (ttl > MAX_HOPS) {
            eth_printf("Max hops reached.\n");
            break;
        }
    }
    return FUNCTION_ERROR;
}

void send_traceroute_request(uint8_t s, uint8_t* dest_addr, uint8_t ttl) {
    PINGMSGR PingRequest;
    uint16_t i;
    
    PingRequest.Type = PING_REQUEST;
    PingRequest.Code = CODE_ZERO;
    PingRequest.ID = htons(RandomID++);
    PingRequest.SeqNum = htons(RandomSeqNum++);
    
    for (i = 0; i < BUF_LEN; i++) {
        PingRequest.Data[i] = (i) % 8;
    }
    
    PingRequest.CheckSum = 0;
    PingRequest.CheckSum = htons(checksum((uint8_t*)&PingRequest, sizeof(PingRequest)));
    
    set_ttl(s, ttl); // Set TTL value for each packet sent
    sendto(s, (uint8_t*)&PingRequest, sizeof(PingRequest), dest_addr, PORT);
    eth_printf("Send traceroute request (TTL: %d) to %d.%d.%d.%d\n", ttl, dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
}

void receive_traceroute_reply(uint8_t s, uint8_t* addr, uint16_t len) {
    uint16_t tmp_checksum;
    uint8_t data_buf[128];
    
    uint16_t rlen = recvfrom(s, data_buf, len, addr, &PORT);
    if (data_buf[0] == PING_REPLY) {
        PINGMSGR PingReply;
        PingReply.Type = data_buf[0];
        PingReply.Code = data_buf[1];
        PingReply.CheckSum = (data_buf[3] << 8) + data_buf[2];
        PingReply.ID = (data_buf[5] << 8) + data_buf[4];
        PingReply.SeqNum = (data_buf[7] << 8) + data_buf[6];
        
        tmp_checksum = ~checksum(data_buf, rlen);
        if (tmp_checksum != 0xffff) {
            eth_printf("Checksum failed\n");
        } else {
            eth_printf("Received reply from %d.%d.%d.%d: ID=%x SeqNum=%x\n", addr[0], addr[1], addr[2], addr[3], PingReply.ID, PingReply.SeqNum);
        }
    }
}

void set_ttl(uint8_t s, uint8_t ttl) {
    IINCHIP_WRITE(Sn_TTL(s), ttl);
}

uint16_t checksum(uint8_t* data_buf, uint16_t len) {
    uint16_t sum, tsum, i, j;
    uint32_t lsum;
    
    j = len >> 1;
    lsum = 0;
    tsum = 0;
    for (i = 0; i < j; ++i) {
        tsum = data_buf[i * 2];
        tsum = tsum << 8;
        tsum += data_buf[i * 2 + 1];
        lsum += tsum;
    }
    if (len % 2) {
        tsum = data_buf[i * 2];
        lsum += (tsum << 8);
    }
    sum = (uint16_t)lsum;
    sum = ~(sum + (lsum >> 16));
    return sum;
}
