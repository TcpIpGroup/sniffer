#ifndef ICMP_H
#define ICMP_H
#include "protocol.h"
#include "ipv4.h"
class Ipv4;

class Icmp : public Protocol
{
public:
    Ipv4 *ipv4;
    icmphdr icmph;
    Icmp(Ipv4 *ipv4);
    /**
     * @brief getType 获取类型
     * @return
     */
    int getType();
    /**
     * @brief getCode 获取代码
     * @return
     */
    int getCode();
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

#endif // ICMP_H
