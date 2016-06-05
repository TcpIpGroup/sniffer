#ifndef ARP_H
#define ARP_H
#include "protocol.h"
#include "ethernet.h"
class Ethernet;

class Arp: public Protocol
{
public:
    Arp(Ethernet *ethernet);

    Ethernet *ethernet;
    arphdr arph;

    /**
     * @brief getHardwareType 获取硬件类型
     * @return
     */
    int getHardwareType();
    /**
     * @brief getProtocolType 获取协议类型
     * @return
     */
    int getProtocolType();
    /**
     * @brief getAddressLength 获取硬件地址长度
     * @return
     */
    int getAddressLength();
    /**
     * @brief getProtocolLength 获取协议地址长度
     * @return
     */
    int getProtocolLength();
    /**
     * @brief getOperation 获取操作码，1为请求 2为回复
     * @return
     */
    int getOperation();
    /**
     * @brief getMacSrc 获取源MAC
     * @return
     */
    QString getMacSrc();
    /**
     * @brief getMacDest 获取目的MAC
     * @return
     */
    QString getMacDest();
    /**
     * @brief getIpSrc 获取源IP
     * @return
     */
    QString getIpSrc();
    /**
     * @brief getIpDest 获取目的IP
     * @return
     */
    QString getIpDest();
    /**
     * @brief getPackageLength 获取包长度
     * @return
     */
    int getPackageLength();
    Protocol* analyse(const pcap_pkthdr *header, const u_char *packageData);
    QStringList briefInfo();
    QList<QPair<QString, QStringList>> detailInfo();
};

#endif // ARP_H
