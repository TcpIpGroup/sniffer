#include "Ipv4.h"

Ipv4::Ipv4(Ethernet *ethernet) {
    this->ethernet = ethernet;
    this->type = Type::IPV4;
}

int Ipv4::getHeaderLength() {
    return iph.ihl;
}

int Ipv4::getVersion() {
    return iph.version;
}

int Ipv4::getTos() {
    return iph.tos;
}

int Ipv4::getTotalLength() {
    return ntohs(iph.tlen);
}

int Ipv4::getId() {
    return ntohs(iph.id);
}

int Ipv4::getOffset() {
    return ntohs((iph.frag_off & 0x1fff) * 8);
}

int Ipv4::getTTL() {
    return iph.ttl;
}

int Ipv4::getProtocol() {
    return iph.proto;
}

int Ipv4::getCheckSum() {
    return ntohs(iph.check);
}

QString Ipv4::getIpSrc() {
    return QString::fromStdString(inet_ntoa(iph.saddr));
}

QString Ipv4::getIpDest() {
    return QString::fromStdString(inet_ntoa(iph.daddr));
}

int Ipv4::getPackageLength() {
    return ethernet->getPackageLength();
}

Protocol* Ipv4::analyse(const pcap_pkthdr *header, const u_char *packageData) {
    Protocol *protocol = nullptr;
    iphdr *temp = (iphdr *)(packageData);
    memcpy(&iph, temp, sizeof(iphdr));
    switch(iph.proto) {
    case 1://上层协议是ICMP
        protocol = new Icmp(this);
        break;
    case 2://上层协议是IGMP
        break;
    case 6://上层协议是TCP
        protocol = new Tcp(this);
        break;
    case 17://上层协议是UDP
        protocol = new Udp(this);
        break;
    default:
        break;
    }
    if (nullptr == protocol) {
        protocol = this;
    } else {
        protocol = protocol->analyse(header, packageData + sizeof(iphdr));
    }
    return protocol;
}

QStringList Ipv4::briefInfo() {
    QStringList stringList = Protocol::briefInfo();
    stringList.append(getIpSrc());//无ip源地址
    stringList.append(getIpDest());//无ip目的地址
    stringList.append(QString::number(getPackageLength()));//长度忽略
    stringList.append(QString("ipv4"));//协议类型
    return stringList;
}

QList<QPair<QString, QStringList>> Ipv4::detailInfo() {
    QList<QPair<QString, QStringList>> list = ethernet->detailInfo();
    QStringList stringList;
    stringList.append(QString("Version: ").append(QString::number(getVersion())));
    stringList.append(QString("Internet Header Length: ").append(QString::number(getHeaderLength())));
    stringList.append(QString("Type of service: ").append(QString::number(getTos())));
    stringList.append(QString("Total Length: ").append(QString::number(getTotalLength())));
    stringList.append(QString("Identification: ").append(QString::number(getId())));
    stringList.append(QString("Fragment Offset: ").append(QString::number(getOffset())));
    stringList.append(QString("Time To Live: ").append(QString::number(getTTL())));
    stringList.append(QString("Protocol: ").append(Protocol::intToHexString(getProtocol())));
    stringList.append(QString("Header Checksum: ").append(Protocol::intToHexString(getCheckSum())));
    stringList.append(QString("Source address: ").append(getIpSrc()));
    stringList.append(QString("Destination address: ").append(getIpDest()));

    list.append(QPair<QString, QStringList>("ipv4", stringList));
    return list;
}
