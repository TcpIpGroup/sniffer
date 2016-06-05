#ifndef IPV4_H
#define IPV4_H
#include "protocol.h"
#include "ethernet.h"
#include "udp.h"
#include "tcp.h"
#include "icmp.h"
class Ethernet;
class Udp;
class tcp;
class Icmp;
class Ipv4: public Protocol
{
public:
    Ipv4(Ethernet *ethernet);
    Ethernet *ethernet;
    iphdr iph;

    /**
     * @brief getHeaderLength
     * @return 返回ip首部长度
     */
    int getHeaderLength();

    /**
     * @brief getVersion
     * @return 获取ip的版本号
     */
    int getVersion();

    /**
     * @brief getTos
     * @return 获取TOS服务类型
     */
    int getTos();

    /**
     * @brief getTotalLength
     * @return 获取ip数据包总长度
     */
    int getTotalLength();

    /**
     * @brief getId
     * @return 获取标识
     */
    int getId();

    /**
     * @brief getOffset
     * @return 获取片偏移
     */
    int getOffset();

    /**
     * @brief getTTL
     * @return 获取生存时间
     */
    int getTTL();

    /**
     * @brief getProtocol
     * @return 获取协议类型
     */
    int getProtocol();

    /**
     * @brief getCheckSum
     * @return 获取校验和
     */
    int getCheckSum();

    /**
     * @brief getIpSrc
     * @return 获取源ip地址
     */
    QString getIpSrc();
    /**
     * @brief getIpDest
     * @return 获取源ip地址
     */
    QString getIpDest();

    int getPackageLength();

    Protocol* analyse(const pcap_pkthdr *header, const u_char *packageData);

    QStringList briefInfo();

    QList<QPair<QString, QStringList>> detailInfo();
};

#endif // IPV4_H
