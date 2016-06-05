#include "icmp.h"

Icmp::Icmp(Ipv4 *ipv4):Protocol(Type::ICMP) {
    this->ipv4 = ipv4;
}

/**
 * @brief getType 获取类型
 * @return
 */
int Icmp::getType() {
    return icmph.type;
}

/**
 * @brief getCode 获取代码
 * @return
 */
int Icmp::getCode() {
    return icmph.code;
}

/**
 * @brief getCheckSum 获取校验和
 * @return
 */
int Icmp::getCheckSum() {
    return ntohs(icmph.chksum);
}
int Icmp::getPackageLength() {
    return ipv4->getPackageLength();
}

Protocol* Icmp::analyse(const pcap_pkthdr *header, const u_char *packageData) {
    icmphdr *temp = (icmphdr *)(packageData);
    memcpy(&icmph, temp, sizeof(icmphdr));
    return this;
}

QStringList Icmp::briefInfo() {
    QStringList stringList = ipv4->briefInfo();
    stringList.replace(stringList.length() - 1, QString("icmp"));
    return stringList;
}

QList<QPair<QString, QStringList>> Icmp::detailInfo() {
    QList<QPair<QString, QStringList>> list = this->ipv4->detailInfo();
    QStringList stringList;
    stringList.append(QString("Type: ").append(QString::number(this->getType())));
    stringList.append(QString("Code: ").append(QString::number(this->getCode())));
    stringList.append(QString("Header checksum: ").append(Protocol::intToHexString(this->getCheckSum())));
    list.append(QPair<QString, QStringList>(QString("icmp"), stringList));
    return list;
}
