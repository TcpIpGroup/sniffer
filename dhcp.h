#ifndef DHCP_H
#define DHCP_H
#include "protocol.h"
#include "udp.h"
class Udp;

class Dhcp : public Protocol
{
public:
    dhcphdr dhcph;
    Udp *udp;
    Dhcp(Udp *udp);
    /**
     * @brief getOp 获取源端口
     * @return
     */
    int getOp();
    /**
     * @brief getHType 获取硬件类型
     * @return
     */
    int getHType();
    /**
     * @brief getHLen 获取硬件地址长度
     * @return
     */
    int getHLen();
    /**
     * @brief getHops 获取网关跳数
     * @return
     */
    int getHops();
    /**
     * @brief getXid 获取会话id
     * @return
     */
    unsigned long getXid();
    /**
     * @brief getSecs 获取Seconds elapsed
     * @return
     */
    int getSecs();
    /**
     * @brief getFlags 获取标志
     * @return
     */
    int getFlags();
    /**
     * @brief getCiaddr 获取客户端ip
     * @return
     */
    QString getCiaddr();
    /**
     * @brief getYiaddr 获取'你的'ip
     * @return
     */
    QString getYiaddr();
    /**
     * @brief getSiaddr 获取服务器ip
     * @return
     */
    QString getSiaddr();
    /**
     * @brief getGiaddr 获取网关ip
     * @return
     */
    QString getGiaddr();
    /**
     * @brief getChaddr 获取客户硬件地址
     * @return
     */
    /**
     * @brief getSname
     * @return
     */
    QString getSname();
    /**
     * @brief getFile
     * @return
     */
    QString getFile();
    QString getChaddr();
    int getPackageLength();
    Protocol* analyse(const pcap_pkthdr *header, const u_char *packageData);
    QStringList briefInfo();
    QList<QPair<QString, QStringList>> detailInfo();
};

#endif // DHCP_H
