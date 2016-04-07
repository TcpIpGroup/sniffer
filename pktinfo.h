#ifndef PKTINFO_H
#define PKTINFO_H
#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>
#include "pro.h"
#include <string>
#include<iostream>
#include <sstream>
using namespace std;
class pktinfo
{
public:
    /**u_char mac_src[6];
    u_char mac_dest[6];
    char * eth_type;

    char * ip_type;
    u_int  ip_len;
    ip_address ip_src;
    ip_address ip_dest;

    u_short ipv6_src[8];
    u_short ipv6_dest[8];

    u_char ar_srcmac[6];
    u_char ar_desmac[6];
    ip_address ar_src;
    ip_address ar_dest;
    u_short ar_op;

    u_short tcp_sport;
    u_short tcp_dport;

    u_short udp_sport;
    u_short udp_dport;

    u_char icmp_code;
    u_char icmp_type;

    u_char icmpv6_code;
    u_char icmpv6_type;**/
    ethhdr * m_ethhdr;
    arphdr * m_arphdr;
    iphdr * m_iphdr;
    iphdr6 * m_iphdr6;
    icmphdr * m_icmphdr;
    icmphdr6 * m_icmphdr6;
    tcphdr * m_tcphdr;
    udphdr * m_udphdr;

    char * eth_type;
    char * ip_type;
    string ethinfo;
    string arpinfo;
    string ipinfo;
    string ipv6info;
    string icmpinfo;
    string tcpinfo;
    string udpinfo;
    pktinfo();
    pktinfo(const u_char * pktdata);
};

#endif // PKTINFO_H
