#include "dhcp.h"

Dhcp::Dhcp(Udp *udp):Protocol(Type::DHCP) {
    this->udp = udp;
}

/**
 * @brief getOp 获取源端口
 * @return
 */
int Dhcp::getOp() {
    return dhcph.dp_op;
}

/**
 * @brief getHType 获取硬件类型
 * @return
 */
int Dhcp::getHType() {
    return dhcph.dp_htype;
}
/**
 * @brief getHLen 获取硬件地址长度
 * @return
 */
int Dhcp::getHLen() {
    return dhcph.dp_hlen;
}
/**
 * @brief getHops 获取网关跳数
 * @return
 */
int Dhcp::getHops() {
    return dhcph.dp_hops;
}
/**
 * @brief getXid 获取会话id
 * @return
 */
unsigned long Dhcp::getXid() {
    return ntohl(dhcph.dp_xid);
}
/**
 * @brief getSecs 获取Seconds elapsed
 * @return
 */
int Dhcp::getSecs() {
    return ntohs(dhcph.dp_secs);
}
/**
 * @brief getFlags 获取标志
 * @return
 */
int Dhcp::getFlags() {
    return ntohs(dhcph.dp_flags);
}
/**
 * @brief getCiaddr 获取客户端ip
 * @return
 */
QString Dhcp::getCiaddr() {
    return QString::fromStdString(inet_ntoa(dhcph.dp_ciaddr));
}
/**
 * @brief getYiaddr 获取'你的'ip
 * @return
 */
QString Dhcp::getYiaddr() {
    return QString::fromStdString(inet_ntoa(dhcph.dp_yiaddr));
}
/**
 * @brief getSiaddr 获取服务器ip
 * @return
 */
QString Dhcp::getSiaddr() {
    return QString::fromStdString(inet_ntoa(dhcph.dp_siaddr));
}
/**
 * @brief getGiaddr 获取网关ip
 * @return
 */
QString Dhcp::getGiaddr() {
    return QString::fromStdString(inet_ntoa(dhcph.dp_giaddr));
}
/**
 * @brief getChaddr 获取客户硬件地址
 * @return
 */
QString Dhcp::getChaddr() {
    return QString((const char*)dhcph.dp_chaddr);
}

/**
 * @brief getSname
 * @return
 */
QString Dhcp::getSname() {
    return QString((const char*)dhcph.dp_sname);
}

/**
 * @brief getFile
 * @return
 */
QString Dhcp::getFile() {
    return QString((const char*)dhcph.dp_file);
}

int Dhcp::getPackageLength() {
    return this->udp->getPackageLength();
}

Protocol* Dhcp::analyse(const pcap_pkthdr *header, const u_char *packageData) {
    dhcphdr *temp = (dhcphdr *)(packageData);
    memcpy(&dhcph, temp, sizeof(dhcphdr));
    return this;
}

QStringList Dhcp::briefInfo() {
    QStringList stringList = udp->briefInfo();
    stringList.replace(stringList.length() - 1, QString("dhcp"));
    return stringList;
}

QList<QPair<QString, QStringList>> Dhcp::detailInfo() {
    QList<QPair<QString, QStringList>> list = this->udp->detailInfo();
    QStringList stringList;
    stringList.append(QString("OP: ").append(QString::number(this->getOp())));
    stringList.append(QString("HTYPE: ").append(QString::number(this->getHType())));
    stringList.append(QString("HLEN: ").append(QString::number(this->getHLen())));
    stringList.append(QString("HOPS: ").append(QString::number(this->getHops())));
    stringList.append(QString("TRANSACTION ID: ").append(QString::number(this->getXid())));
    stringList.append(QString("SECONDS: ").append(QString::number(this->getSecs())));
    stringList.append(QString("CIADDR (Client IP address): ").append(this->getCiaddr()));
    stringList.append(QString("YIADDR (Your IP address): ").append(this->getYiaddr()));
    stringList.append(QString("SIADDR (Server IP address): ").append(this->getSiaddr()));
    stringList.append(QString("GIADDR (Gateway IP address): ").append(this->getGiaddr()));
    stringList.append(QString("CHADDR (Client hardware address): ").append(this->getChaddr()));
//    stringList.append(QString("sname: ").append(this->getSname()));
//    stringList.append(QString("file: ").append(this->getFile()));
    list.append(QPair<QString, QStringList>(QString("dhcp"), stringList));
    return list;
}
