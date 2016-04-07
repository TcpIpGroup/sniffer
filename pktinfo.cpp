#include "pktinfo.h"
pktinfo::pktinfo()
{

}

pktinfo::pktinfo(const u_char *pktdata)
{

    this->ethinfo="";
    this->arpinfo="";
    this->icmpinfo="";
    this->ipinfo="";
    this->ipv6info="";
    this->tcpinfo="";
    this->udpinfo="";
    stringstream macss;
    macss<<"Ethernet Layer:"<<'\n'<<"src mac address：";
    this->m_ethhdr=(ethhdr *)pktdata;
    macss<<hex<<(short)this->m_ethhdr->src[0];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->src[1];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->src[2];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->src[3];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->src[4];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->src[5];
    macss<<'\n'<<"dest mac address:";
    macss<<hex<<(short)this->m_ethhdr->dest[0];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->dest[1];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->dest[2];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->dest[3];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->dest[4];
    macss<<":";
    macss<<hex<<(short)this->m_ethhdr->dest[5];
    u_short ethernet_type=ntohs(this->m_ethhdr->type);
    macss<<'\n'<<"upper protocol type:";
    switch (ethernet_type)
      {
         case 0x0800:
              {

               this->eth_type="IP";
               macss<<this->eth_type;
               this->ethinfo=macss.str();
               this->m_iphdr=(iphdr *)(pktdata+14);
               stringstream ipss;
               ipss<<"IP Layer:"<<'\n';
               u_short iplen=(m_iphdr->ihl&0xf)*4;
               ipss<<"header length:"<<iplen<<'\n';
               u_short len=ntohs(this->m_iphdr->tlen);
               ipss<<"IP data pocket lenght:"<<len<<'\n';
               ipss<<"source ip:"<<inet_ntoa(this->m_iphdr->saddr)<<'\n';
               ipss<<"dest ip:"<<inet_ntoa(this->m_iphdr->daddr)<<'\n';
               stringstream transs;
               transs<<"Transport Layer:"<<'\n';
               switch(m_iphdr->proto)
               {
                 case 1:
                   {
                    this->ip_type="ICMP";
                    this->m_icmphdr=(icmphdr *)(pktdata+14+iplen);
                    transs<<"check sum:"<<(u_short)this->m_icmphdr->chksum<<'\n';
                    transs<<"code:"<<(u_short)this->m_icmphdr->code<<'\n';
                    transs<<"seq:"<<(u_short)this->m_icmphdr->seq<<'\n';
                    transs<<"type:"<<(u_short)this->m_icmphdr->type<<'\n';
                   };break;
                 case 6:
                   {
                    this->ip_type="TCP";
                    this->m_tcphdr=(tcphdr *)(pktdata+14+iplen);
                    transs<<"dest port:"<<ntohs(this->m_tcphdr->dport)<<'\n';
                    transs<<"source port:"<<ntohs(this->m_tcphdr->sport)<<'\n';
                    transs<<"seq num:"<<ntohl(this->m_tcphdr->seq)<<'\n';
                    transs<<"ack num:"<<ntohl(this->m_tcphdr->ack_seq)<<'\n';
                   };break;
                  case 17:
                   {
                    this->ip_type="UDP";
                    this->m_udphdr=(udphdr *)(pktdata+14+iplen);
                    transs<<"dest port:"<<ntohs(this->m_udphdr->dport)<<'\n';
                    transs<<"source port:"<<ntohs(this->m_udphdr->sport)<<'\n';
                    transs<<"length:"<<ntohs(this->m_udphdr->len)<<'\n';
                    transs<<"check sum:"<<ntohs(this->m_udphdr->check)<<'\n';
                   };break;

               }
               ipss<<"upper protocol type:"<<this->ip_type<<'\n';
               this->ipinfo=ipss.str();
               this->tcpinfo=transs.str();
               //cout<<this->ipinfo;
               //cout<<this->tcpinfo;
              };break;
         case 0x0806:
              {
               this->eth_type="ARP";
               macss<<this->eth_type;
               this->ethinfo=macss.str();
               this->m_arphdr=(arphdr *)(pktdata+14);
               stringstream arpss;
               arpss<<"ARP Layer:"<<'\n';
               arpss<<"dest mac addrss:"<<hex<<(short)this->m_arphdr->ar_destmac[0];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_destmac[1];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_destmac[2];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_destmac[3];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_destmac[4];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_destmac[5]<<'\n';
               arpss<<"source mac addrss:"<<hex<<(short)this->m_arphdr->ar_srcmac[0];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_srcmac[1];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_srcmac[2];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_srcmac[3];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_srcmac[4];
               arpss<<":";
               arpss<<hex<<(short)this->m_arphdr->ar_srcmac[5]<<'\n';
               arpss<<"dest ip:"<<inet_ntoa(this->m_arphdr->ar_destip)<<'\n';
               arpss<<"source ip:"<<inet_ntoa(this->m_arphdr->ar_srcip)<<'\n';
               arpss<<"operation:"<<ntohs(this->m_arphdr->ar_op)<<'\n';
               this->arpinfo=arpss.str();
               };break;
         case 0x86DD :
               {
               this->eth_type="IPv6";
               macss<<this->eth_type;
               this->ethinfo=macss.str();
               this->m_iphdr6=(iphdr6 *)(pktdata+14);
               stringstream ipv6ss;
               ipv6ss<<"IPv6 Layer:"<<'\n';
               ipv6ss<<"source ip:";
               ipv6ss<<ntohs(this->m_iphdr6->saddr[0])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->saddr[1])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->saddr[2])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->saddr[3])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->saddr[4])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->saddr[5])<<'\n';
               ipv6ss<<"dest ip:";
               ipv6ss<<ntohs(this->m_iphdr6->daddr[0])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->daddr[1])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->daddr[2])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->daddr[3])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->daddr[4])<<':';
               ipv6ss<<ntohs(this->m_iphdr6->daddr[5])<<'\n';
               this->ipv6info=ipv6ss.str();
               };break;
         default:break;
      }


}
