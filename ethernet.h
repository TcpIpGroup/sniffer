#ifndef ETHERNET_H
#define ETHERNET_H
#include "protocol.h"
#include "ipv4.h"
#include "arp.h"
#include "rarp.h"
class Ipv4;
class Arp;
class Rarp;

class Ethernet: public Protocol {
public:
    Ethernet();
    ethhdr eth;
    pcap_pkthdr header;

    /**
     * @brief getMacDest 获取Mac目的地址
     * @return
     */
    QString getMacDest();

    /**
     * @brief getMacSrc 获取Mac源地址
     * @return
     */
    QString getMacSrc();

    /**
     * @brief getEtherType 获取EtherType
     * @return
     */
    int getEtherType();

    /**
     * @brief getPackageLength 获取包长度
     * @return
     */
    int getPackageLength();

    Protocol* analyse(const pcap_pkthdr *header, const u_char *packageData);

    QStringList briefInfo();

    QList<QPair<QString, QStringList>> detailInfo();
};

#endif // ETHERNET_H
