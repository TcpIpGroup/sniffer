#ifndef UDP_H
#define UDP_H
#include "protocol.h"
#include "ipv4.h"
#include "dhcp.h"
class Ipv4;
class Dhcp;

class Udp : public Protocol
{
public:
    Udp(Ipv4 *ipv4);
    Ipv4 *ipv4;
    udphdr udph;

    /**
     * @brief getPortSrc 获取源端口
     * @return
     */
    int getPortSrc();
    /**
     * @brief getPortDest 获取目的端口
     * @return
     */
    int getPortDest();
    /**
     * @brief getLength 获取数据报长度
     * @return
     */
    int getLength();
    /**
     * @brief getCheckSum 获取校验和
     * @return
     */
    int getCheckSum();
    int getPackageLength();
    Protocol* analyse(const pcap_pkthdr *header, const u_char *packageData);
    QStringList briefInfo();
    QList<QPair<QString, QStringList>> detailInfo();
};

#endif // UDP_H
