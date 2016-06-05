#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <QStringList>
#include <QMap>
#include <pcap.h>
#include <QDebug>
#include "protocolheader.h"

class Protocol {
public:
    enum Type {
        ETHERNET,
        IPV4,
        IPV6,
        ICMP,
        TCP,
        UDP,
        DHCP,
        ARP,
        RARP,
        NONE
    };

public:
    Type type = Type::NONE;
    Protocol();
    Protocol(Type type);

    /**
     * @brief analyse 协议分析
     * @param header 包数据的头
     * @param packageData 包数据
     * @return
     */
    virtual Protocol* analyse(const pcap_pkthdr *header, const u_char *packageData);

    /**
     * @brief briefInfo 获取协议简介(序号,ip源地址,ip目的地址,包长度,协议类型)
     * @return
     */
    virtual QStringList briefInfo();

    /**
     * @brief detailInfo 协议的详细信息
     * @return
     */
    virtual QList<QPair<QString, QStringList>> detailInfo();

    static QString charArrayToMacAdress(u_char array[]);
    static QString intToHexString(int value);
};

#endif //PROTOCOL_H
