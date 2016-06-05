#include "ethernet.h"

Ethernet::Ethernet(): Protocol(Type::ETHERNET) {}

QString Ethernet::getMacDest() {
    return Protocol::charArrayToMacAdress(eth.dest);
}

QString Ethernet::getMacSrc() {
    return Protocol::charArrayToMacAdress(eth.src);
}

int Ethernet::getEtherType() {
    return ntohs(eth.type);
}

int Ethernet::getPackageLength() {
    return header.len;
}

Protocol* Ethernet::analyse(const pcap_pkthdr *header, const u_char *packageData) {
    memcpy(&(this->header), header, sizeof(pcap_pkthdr));
    ethhdr *temp = (ethhdr *)packageData;
    memcpy(&eth, temp, sizeof(ethhdr));
    u_short ethernetType = ntohs(eth.type);

    Protocol *protocol = nullptr;
    switch (ethernetType) {
    case 0x0800://上层协议是ipv4
        protocol = new Ipv4(this);
        break;
    case 0x0806://上层协议是arp
        protocol = new Arp(this);
        break;
    case 0x8035://上层协议是rarp
        protocol = new Rarp(this);
        break;
    case 0x814C://上层协议是简单网络管理协议snmp
        break;
    case 0x8137://上层协议是因特网包交换IPX：Internet Packet Exchange
        break;
    case 0x86DD://上层协议是ipv6协议
        break;
    case 0x880B://上层协议是点对点协议ppp：Point-to-Point Protocol
        break;
    default:
        //qDebug()<<&eth<<eth.type;
        break;
    }
    if (nullptr == protocol) {
        protocol = this;
    } else {
        protocol = protocol->analyse(header, packageData + sizeof(ethhdr));
    }
    return protocol;
}

QStringList Ethernet::briefInfo() {
    QStringList stringList = Protocol::briefInfo();
    stringList.append(QString(""));//无ip源地址
    stringList.append(QString(""));//无ip目的地址
    stringList.append(QString::number(getPackageLength()));//长度忽略
    stringList.append(QString("ethernet frame"));//协议类型
    return stringList;
}

QList<QPair<QString, QStringList>> Ethernet::detailInfo() {
    QList<QPair<QString, QStringList>> list;
    QStringList stringList;
    stringList.append(QString::fromStdString("Destination MAC Address: ").append(getMacDest()));
    stringList.append(QString::fromStdString("Source MAC Address: ").append(getMacSrc()));
    stringList.append(QString::fromStdString("EtherType: ").append(Protocol::intToHexString(getEtherType())));
    list.append(QPair<QString, QStringList>("ethernet frame", stringList));
    return list;
}
