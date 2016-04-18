#ifndef LITEUDP28J60
#define LITEUDP28J60

#include "Platform.h"

typedef void (*UdpServerCallback) (char *data,  uint16_t len);

typedef struct {
    UdpServerCallback callback;
    uint16_t port;
} UdpServerListener;

// library interface description
class LiteUDP28j60
{
  // user-accessible "public" interface
  public:
     LiteUDP28j60(void);
     void Init(uint8_t* mac, uint8_t* ip);
     void Loop(void);
     void Send(uint8_t* ip, uint16_t port, uint8_t* buffer, uint16_t len);

    void Listen(UdpServerCallback callback, uint16_t port);

  // library-accessible "private" interface
  private:
    uint16_t listening;

    uint8_t  my_ip4[4];
    uint8_t  my_mac[6];
    uint8_t  packet_from_mac[6];
    uint8_t  packet_to_mac[6];
    uint8_t  packet_to_ip4[4];
    uint8_t  packet_from_ip4[4];
    uint8_t  packet_proto[2];
    uint16_t packet_len;
    uint16_t packet_port;
    uint8_t  data[128];

    uint8_t  arp_cache[10 * 24];  //save 24 addresses
    uint8_t  arp_cache_wptr;
    uint8_t  arp_cache_len;

    UdpServerListener Listener;

    uint16_t len_eth;
     uint8_t arp_request(uint8_t* ip, uint8_t* mac);
    void eth_read(void);
   // void eth_send(uint16_t bytes);
    void ip_read(void);
    void udp_read(void);
    void arp_processing(void);
    void icmp_processing(void);
    uint8_t arp_cache_search(uint8_t* ip);
    void arp_cache_add(uint8_t* ip, uint8_t* mac);
    void udp_send(uint8_t* to_ip, uint16_t to_port, uint8_t *data, uint16_t len);
    uint16_t checksum(uint8_t *buf2, uint16_t le,  uint8_t type);
    void ip_send(uint16_t len);
    // void PrintBytes(uint8_t *bytes, uint16_t count);


};

#endif

