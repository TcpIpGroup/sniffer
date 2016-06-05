#include "udp.h"

Udp::Udp(Ipv4 *ipv4): Protocol(Type::UDP) {
    this->ipv4 = ipv4;
}

/**
 * @brief getPortSrc 获取源端口
 * @return
 */
int Udp::getPortSrc() {
    return ntohs(udph.sport);
}

/**
 * @brief getPortDest 获取目的端口
 * @return
 */
int Udp::getPortDest() {
    return ntohs(udph.dport);
}

/**
 * @brief getLength 获取数据报长度
 * @return
 */
int Udp::getLength() {
    return ntohs(udph.len);
}

/**
 * @brief getCheckSum 获取校验和
 * @return
 */
int Udp::getCheckSum() {
    return ntohs(udph.check);
}

int Udp::getPackageLength() {
    return this->ipv4->getPackageLength();
}

Protocol* Udp::analyse(const pcap_pkthdr *header, const u_char *packageData) {
    udphdr *temp = (udphdr *)(packageData);
    memcpy(&udph, temp, sizeof(udphdr));
    if ((ntohs(udph.dport) == 67 && ntohs(udph.sport) == 68) || (ntohs(udph.dport) == 68 && ntohs(udph.sport) == 67)) {//dhcp
        return ((new Dhcp(this))->analyse(header, packageData));
    }
    return this;
}

QStringList Udp::briefInfo() {
    QStringList stringList = ipv4->briefInfo();
    stringList.replace(stringList.length() - 1, QString("udp"));
    return stringList;
}

QList<QPair<QString, QStringList>> Udp::detailInfo() {
    QList<QPair<QString, QStringList>> list = this->ipv4->detailInfo();
    QStringList stringList;
    stringList.append(QString("Source port: ").append(QString::number(this->getPortSrc())));
    stringList.append(QString("Destination port: ").append(QString::number(this->getPortDest())));
    stringList.append(QString("Length: ").append(QString::number(this->getLength())));
    stringList.append(QString("Checksum: ").append(Protocol::intToHexString(this->getCheckSum())));
    list.append(QPair<QString, QStringList>(QString("udp"), stringList));
    return list;
}
