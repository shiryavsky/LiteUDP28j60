#include "LiteUDP28j60.h"
#include "HardwareSerial.h"

extern "C" {
    #include "enc28j60.h"
}

#define IP_PROTO_UDP_V 17
#define IP_PROTO_TCP_V 6
#define IP_PROTO_ICMP_V 1
#define ICMP_TYPE_ECHOREPLY_V 0
#define ICMP_TYPE_ECHOREQUEST_V 8
#define UDP_FROM_PORT 5000

LiteUDP28j60::LiteUDP28j60(void) {
    LiteUDP28j60::arp_cache_wptr = 0;
    LiteUDP28j60::arp_cache_len = 0;
}



void LiteUDP28j60::Listen(UdpServerCallback callback, uint16_t port) {
    LiteUDP28j60::Listener = (UdpServerListener) {
        callback, port
    };
    LiteUDP28j60::listening = true;
}


void LiteUDP28j60::eth_read() {
    uint8_t i = 0;
    for (i = 0; i < 6; i++) {
        LiteUDP28j60::packet_to_mac[i] = LiteUDP28j60::data[i];
    }
    for (i = 0; i < 6; i++) {
        LiteUDP28j60::packet_from_mac[i] = LiteUDP28j60::data[i + 6];
    }
    for (i = 0; i < 2; i++) {
        LiteUDP28j60::packet_proto[i] = LiteUDP28j60::data[i + 12];
    }
    if (LiteUDP28j60::packet_proto[0]==0x08 && LiteUDP28j60::packet_proto[1]==0x00)
        LiteUDP28j60::ip_read();
    if (LiteUDP28j60::packet_proto[0]==0x08 && LiteUDP28j60::packet_proto[1]==0x06)
        LiteUDP28j60::arp_processing();
}

uint8_t LiteUDP28j60::arp_cache_search(uint8_t* ip) {
    uint8_t i = 0;
    uint8_t j = 0;
    uint8_t result = 255;
    for (i=0; i<LiteUDP28j60::arp_cache_len; i++) {
        result = i;
        for (j=0; j<4; j++) {
            if (LiteUDP28j60::arp_cache[i*10+j] != ip[j]) result = 255;
        }
        if (result!=255) return result;
    }
    return result;
}

void LiteUDP28j60::arp_cache_add(uint8_t* ip, uint8_t* mac) {
    uint8_t i = 0;
    uint8_t j = 0;
    for (i = 0; i < 6; i++) {
        LiteUDP28j60::arp_cache[LiteUDP28j60::arp_cache_wptr*10 + 4 + i] = mac[i]; //write mac to cahce
        if (i<4) {
            LiteUDP28j60::arp_cache[LiteUDP28j60::arp_cache_wptr*10 + i] = ip[i]; //write ip to cache
        }
    }
    LiteUDP28j60::arp_cache_wptr++;
    if (LiteUDP28j60::arp_cache_wptr == 24) LiteUDP28j60::arp_cache_wptr = 0;
    if (LiteUDP28j60::arp_cache_len < 24) LiteUDP28j60::arp_cache_len++;
}

uint8_t LiteUDP28j60::arp_request(uint8_t* ip, uint8_t* mac) {
    uint8_t result = 0;
    uint8_t i = 0;
    uint8_t j = 0;
    uint8_t arpdata[42];
    uint8_t packetdata[42];
    uint16_t plen = 0;
    //simly check for bcast .255 or .255.255
    if ((ip[3]==0xFF) || ((ip[3]==0xFF) && (ip[2]==0xFF))) {
        for (j=0; j<6; j++) {
            mac[j] = 0xFF;
        }
        return 1;
    }
    //search cache first
    uint8_t from_cache = LiteUDP28j60::arp_cache_search(ip);
    if (from_cache!=255) {
        for (j=0; j<6; j++) {
            mac[j] = LiteUDP28j60::arp_cache[from_cache*10 + 4 +j];
        }
        return 1;
    }
    //make arp packet
    for (i = 0; i < 6; i++) {
        mac[i] = 0xFF; //empty resolved mac
        arpdata[i] = 0xFF; //broadcast request
        arpdata[i+6] = LiteUDP28j60::my_mac[i]; //from mac
        arpdata[i+22] = LiteUDP28j60::my_mac[i]; //from mac
        arpdata[i+32] = 0xFF; //
    }
    for (i = 0; i < 4; i++) {
        arpdata[i+28] = LiteUDP28j60::my_ip4[i];
        arpdata[i+38] = ip[i];
    }
    arpdata[12] = 0x08;
    arpdata[13] = 0x06;  //this is arp
    arpdata[14] = 0x00;
    arpdata[15] = 0x01;
    arpdata[16] = 0x08;
    arpdata[17] = 0x00;
    arpdata[18] = 0x06;
    arpdata[19] = 0x04;
    arpdata[20] = 0x00;
    arpdata[21] = 0x01; //req
    enc28j60PacketSend(42, arpdata);
    i=0;
    while (i<20 && result == 0) {
        plen = enc28j60PacketReceive(42, packetdata);
        i++;
        if (plen) {
            if (packetdata[20]==0x00 && packetdata[21]==0x02) { //this is answer
                result = 1;
                for ( j = 0; j < 4; j++) {
                    if (ip[j]!=packetdata[28+j]) result = 0;
                }
            }
        }
        delay(10);
    }
    if (result) {
        for (i = 0; i < 6; i++) {
            mac[i] =packetdata[22+i];
        }
        LiteUDP28j60::arp_cache_add(ip, mac);
    }
    return result;
}

void LiteUDP28j60::ip_read() {
    uint8_t i = 0;
    i=0; while(i<4) { LiteUDP28j60::packet_from_ip4[i] = LiteUDP28j60::data[26+i]; i++; }//Чтение поля  IP адреса источника
    i=0; while(i<4) { LiteUDP28j60::packet_to_ip4[i] = LiteUDP28j60::data[30+i]; i++; }//Чтение поля  IP адреса назначения
    if  (LiteUDP28j60::data[23] == IP_PROTO_UDP_V)
        LiteUDP28j60::udp_read();
    if (LiteUDP28j60::data[23] == IP_PROTO_ICMP_V)
        LiteUDP28j60::icmp_processing();
}

void LiteUDP28j60::udp_read(void) {
    LiteUDP28j60::packet_port = ((uint16_t)LiteUDP28j60::data[36] << 8) + LiteUDP28j60::data[37];
    LiteUDP28j60::packet_len = ((uint16_t)LiteUDP28j60::data[38] << 8) + LiteUDP28j60::data[39];
    if (LiteUDP28j60::listening && (LiteUDP28j60::packet_port == LiteUDP28j60::Listener.port)) {
        LiteUDP28j60::Listener.callback((char*)&LiteUDP28j60::data[42], LiteUDP28j60::packet_len - 8);
    }
}

void LiteUDP28j60::icmp_processing() {
    uint8_t i = 0;
    if (LiteUDP28j60::data[34]!= ICMP_TYPE_ECHOREQUEST_V) return;
    LiteUDP28j60::data[34] = ICMP_TYPE_ECHOREPLY_V;
    if (LiteUDP28j60::data[0x24] > (0xff-0x08)){
        LiteUDP28j60::data[0x24+1]++;
    }
    LiteUDP28j60::data[0x24]+=0x08;
    for (i=0; i<6; i++) { //swap macs
        LiteUDP28j60::data[i] = LiteUDP28j60::data[i+6];
        LiteUDP28j60::data[i+6] = LiteUDP28j60::my_mac[i];
    }
    for (i=0; i<4; i++) { //swap ips
        LiteUDP28j60::data[i+30] = LiteUDP28j60::data[i+26];
        LiteUDP28j60::data[i+26] = LiteUDP28j60::my_ip4[i];
    }
    enc28j60PacketSend(LiteUDP28j60::len_eth, LiteUDP28j60::data); //send it back
}

void LiteUDP28j60::arp_processing() {
    uint8_t i = 0;
    if((LiteUDP28j60::data[20]==0x00 && LiteUDP28j60::data[21]==0x01) && (LiteUDP28j60::data[38]==LiteUDP28j60::my_ip4[0] &&
        LiteUDP28j60::data[39]==LiteUDP28j60::my_ip4[1] && LiteUDP28j60::LiteUDP28j60::data[40]==my_ip4[2] && LiteUDP28j60::data[41]==LiteUDP28j60::my_ip4[3] )) {
        LiteUDP28j60::data[20] = 0x00;
        LiteUDP28j60::data[21] = 0x02;
        for (i = 0; i < 6; i++)  {
            LiteUDP28j60::data[32 + i] = LiteUDP28j60::data[22 + i];
            LiteUDP28j60::data[22 + i] = LiteUDP28j60::my_mac[i];
        }
        for (i = 0; i < 4; i++)  {
            LiteUDP28j60::data[38 + i] = LiteUDP28j60::data[28 + i];
            LiteUDP28j60::data[28 + i] = LiteUDP28j60::my_ip4[i];
        }
        memcpy(LiteUDP28j60::packet_to_mac,LiteUDP28j60::packet_from_mac,6);
        memcpy(LiteUDP28j60::packet_from_mac,LiteUDP28j60::my_mac,6);
        // LiteUDP28j60::eth_send(28);
        i=0;
        while(i<6) {  LiteUDP28j60::data[i]=LiteUDP28j60::packet_to_mac[i];i++;}
        while(i<12) {  LiteUDP28j60::data[i]=LiteUDP28j60::packet_from_mac[i-6];i++;}
        while(i<14){  LiteUDP28j60::data[i]=LiteUDP28j60::packet_proto[i-12];i++;}
        enc28j60PacketSend(28 + 14, LiteUDP28j60::data);
        if (LiteUDP28j60::arp_cache_search(&LiteUDP28j60::data[38])==255) {
            LiteUDP28j60::arp_cache_add(&LiteUDP28j60::data[38], &LiteUDP28j60::data[32]);
        }
    }
}

uint16_t LiteUDP28j60::checksum(uint8_t *buf2, uint16_t le,  uint8_t type) {
        uint32_t sum = 0;
        if (type==1) {
                sum+=IP_PROTO_UDP_V;
                sum+=le-8;
        }
        if (type==2) {
                sum+=IP_PROTO_TCP_V;
                sum+=le-8;
        }
        while (le >1) {
                sum += 0xFFFF & (*buf2<<8 | *(buf2+1));
                buf2+=2;
                le-=2;
        }
        if (le){
                sum += (0xFF & *buf2)<<8;
        }
        while (sum>>16){
                sum = (sum & 0xFFFF)+(sum >> 16);
        }
        return( (uint16_t) sum ^ 0xFFFF);
}

void LiteUDP28j60::udp_send(uint8_t* to_ip, uint16_t to_port, uint8_t* data, uint16_t len)  {
    uint8_t max_arps = 5;
    uint8_t i = 0;
    uint16_t cks;
    uint8_t *buf1;
    len = len + 8;
    LiteUDP28j60::data[23] = IP_PROTO_UDP_V;
    i=0; while(i<4) { LiteUDP28j60::data[26+i]=LiteUDP28j60::my_ip4[i];i++; }
    i=0; while(i<4) { LiteUDP28j60::data[30+i]=to_ip[i];i++; }
    LiteUDP28j60::data[34] = UDP_FROM_PORT >> 8;
    LiteUDP28j60::data[35] = UDP_FROM_PORT & 0xFF;
    LiteUDP28j60::data[36] = to_port >> 8;
    LiteUDP28j60::data[37] = to_port & 0xFF;
    LiteUDP28j60::data[38] = len >> 8;
    LiteUDP28j60::data[39] = len & 0xFF;
    LiteUDP28j60::data[40] = 0;
    LiteUDP28j60::data[41] = 0;
    i=0; while(i<len-8) { LiteUDP28j60::data[42+i]=data[i];i++;}
    buf1 = &LiteUDP28j60::data[26];
    cks = LiteUDP28j60::checksum(buf1, len + 8, 1);
    LiteUDP28j60::data[40] =  cks>>8; //cks/0xFF - 1;
    LiteUDP28j60::data[41] = cks & 0xff;
    while (LiteUDP28j60::arp_request(to_ip, &LiteUDP28j60::data[0])==255 && max_arps) {
        max_arps--;
    }
    memcpy(&LiteUDP28j60::data[6], LiteUDP28j60::my_mac, 6);
    LiteUDP28j60::ip_send(len);
}

void LiteUDP28j60::ip_send(uint16_t len) {
    uint16_t cks;
    uint8_t *buf1;
    len=len+20;
    LiteUDP28j60::data[12]=0x08; //IP packet
    LiteUDP28j60::data[13]=0x00; //TOS
    LiteUDP28j60::data[14] = 0x45;
    LiteUDP28j60::data[15] = 0x00;
    LiteUDP28j60::data[16] = len >> 8;
    LiteUDP28j60::data[17] = len & 0xFF;
    LiteUDP28j60::data[18] = 0x00;
    LiteUDP28j60::data[19] = 0x00;
    LiteUDP28j60::data[20] = 0x40;
    LiteUDP28j60::data[21] = 0x00;
    LiteUDP28j60::data[22] = 0x40; //64 ttl
   // data[23] must be filled
    LiteUDP28j60::data[24] = 0x00;
    LiteUDP28j60::data[25] = 0x00;
    //data 26, 30 must be filled already
    buf1=&data[14];
    cks = checksum(buf1, 20, 0);
    LiteUDP28j60::data[24] = cks>>8;
    LiteUDP28j60::data[25] = cks & 0xff;
    enc28j60PacketSend(len + 14, LiteUDP28j60::data);
}


void LiteUDP28j60::Send(uint8_t* ip, uint16_t port,  uint8_t* buffer, uint16_t len) {
    LiteUDP28j60::udp_send(ip, port, buffer, len);
}

void LiteUDP28j60::Init(uint8_t* mac, uint8_t* ip) {
    for (uint8_t i=0; i<6; i++) {
        LiteUDP28j60::my_mac[i] = mac[i];
    }
    for (uint8_t i=0; i<4; i++) {
        LiteUDP28j60::my_ip4[i] = ip[i];
    }
    LiteUDP28j60::listening = false;
    enc28j60Init(mac);
    // Serial.begin(9600);
    // Serial.println("Dev. initialized");
}

void LiteUDP28j60::Loop() {
    len_eth = enc28j60PacketReceive(sizeof(LiteUDP28j60::data), LiteUDP28j60::data);
    if (len_eth) {
        LiteUDP28j60::eth_read();
    }
}

// void LiteUDP28j60::PrintBytes(uint8_t *bytes, uint16_t count) {
//     uint8_t i = 0;
//      for(i=0; i<count;i++) {
//          Serial.print(" ");
//          if (bytes[i]<10) {
//              Serial.print("0");
//          }
//          Serial.print(bytes[i],HEX);
//      }
//      Serial.println(" --");
// }
