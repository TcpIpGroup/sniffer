#include "arp.h"

Arp::Arp(Ethernet *ethernet):Protocol(Type::ARP) {
    this->ethernet = ethernet;
}

int Arp::getHardwareType() {
    return ntohs(arph.ar_hrd);
}

/**
 * @brief getProtocolType 获取协议类型
 * @return
 */
int Arp::getProtocolType() {
    return ntohs(arph.ar_pro);
}

/**
 * @brief getAddressLength 获取硬件地址长度
 * @return
 */
int Arp::getAddressLength() {
    return arph.ar_hln;
}

/**
 * @brief getProtocolLength 获取协议地址长度
 * @return
 */
int Arp::getProtocolLength() {
    return arph.ar_pln;
}

/**
 * @brief getOperation 获取操作码，1为请求 2为回复
 * @return
 */
int Arp::getOperation() {
    return ntohs(arph.ar_op);
}

/**
 * @brief getMacSrc 获取源MAC
 * @return
 */
QString Arp::getMacSrc() {
    return Protocol::charArrayToMacAdress(arph.ar_srcmac);
}

/**
 * @brief getMacDest 获取目的MAC
 * @return
 */
QString Arp::getMacDest() {
    return Protocol::charArrayToMacAdress(arph.ar_destmac);
}

/**
 * @brief getIpSrc 获取源IP
 * @return
 */
QString Arp::getIpSrc() {
    return QString::fromStdString(inet_ntoa(arph.ar_srcip));
}

/**
 * @brief getIpDest 获取目的IP
 * @return
 */
QString Arp::getIpDest() {
    return QString::fromStdString(inet_ntoa(arph.ar_destip));
}

int Arp::getPackageLength() {
    return ethernet->getPackageLength();
}

Protocol* Arp::analyse(const pcap_pkthdr *header, const u_char *packageData) {
    arphdr *temp = (arphdr*)(packageData);
    memcpy(&arph, temp, sizeof(arphdr));
    return this;
}

QStringList Arp::briefInfo() {
    QStringList stringList = Protocol::briefInfo();
    stringList.append(getIpSrc());//无ip源地址
    stringList.append(getIpDest());//无ip目的地址
    stringList.append(QString::number(getPackageLength()));//长度忽略
    stringList.append(QString("arp"));//协议类型
    return stringList;
}

QList<QPair<QString, QStringList>> Arp::detailInfo() {
    QList<QPair<QString, QStringList>> list = ethernet->detailInfo();
    QStringList stringList;
    stringList.append(QString("Hardware type: ").append(QString::number(getHardwareType())));
    stringList.append(QString("Protocol type: ").append(Protocol::intToHexString(getProtocolType())));
    stringList.append(QString("Hardware address length: ").append(QString::number(getAddressLength())));
    stringList.append(QString("Protocol address length: ").append(QString::number(getProtocolLength())));
    stringList.append(QString("Operation: ").append(QString::number(getOperation())));
    stringList.append(QString("Sender hardware address: ").append(getMacSrc()));
    stringList.append(QString("Sender protocol address: ").append(getIpSrc()));
    stringList.append(QString("Target hardware address: ").append(getMacDest()));
    stringList.append(QString("Target protocol address: ").append(getIpDest()));
    list.append(QPair<QString, QStringList>("arp", stringList));
    return list;
}
