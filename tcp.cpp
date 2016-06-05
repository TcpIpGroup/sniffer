#include "tcp.h"
Tcp::Tcp(Ipv4 *ipv4):Protocol(Type::TCP) {
    this->ipv4 = ipv4;
}

/**
 * @brief getPortSrc 获取源端口
 * @return
 */
int Tcp::getPortSrc() {
    return ntohs(tcph.sport);
}

/**
 * @brief getPortDest 获取目的端口
 * @return
 */
int Tcp::getPortDest() {
    return ntohs(tcph.dport);
}

/**
 * @brief getLength 获取序列号
 * @return
 */
unsigned long Tcp::getSeq() {
    return ntohl(tcph.seq);
}

/**
 * @brief getSeqAck 获取确认序列号
 * @return
 */
unsigned long Tcp::getSeqAck() {
    return ntohl(tcph.ack_seq);
}

/**
 * @brief getResl 获取保留位
 * @return
 */
int Tcp::getResl() {
    return tcph.resl;
}

/**
 * @brief getDoff 获取偏移
 * @return
 */
int Tcp::getDoff() {
    return tcph.doff;
}

/**
 * @brief getFin 获取关闭连接标志
 * @return
 */
int Tcp::getFin() {
    return tcph.fin;
}

/**
 * @brief getSyn 获取请求连接标志
 * @return
 */
int Tcp::getSyn() {
    return tcph.syn;
}

/**
 * @brief getRst 获取重置连接标志
 * @return
 */
int Tcp::getRst() {
    return tcph.rst;
}

/**
 * @brief getPsh 获取接收方尽快将数据放到应用层标志
 * @return
 */
int Tcp::getPsh() {
    return tcph.psh;
}

/**
 * @brief getAck 获取确认序号标志
 * @return
 */
int Tcp::getAck() {
    return tcph.ack;
}

/**
 * @brief getUrg 获取紧急指针标志
 * @return
 */
int Tcp::getUrg() {
    return tcph.urg;
}

/**
 * @brief getEce 获取拥塞标志位
 * @return
 */
int Tcp::getEce() {
    return tcph.ece;
}

/**
 * @brief getCwr 获取拥塞标志位
 * @return
 */
int Tcp::getCwr() {
    return tcph.cwr;
}

/**
 * @brief getWindow 获取滑动窗口大小
 * @return
 */
int Tcp::getWindow() {
    return ntohs(tcph.window);
}

/**
 * @brief getCheckSum 获取获取校验和
 * @return
 */
int Tcp::getCheckSum() {
    return ntohs(tcph.check);
}

/**
 * @brief getUrgPtr 获取紧急指针
 * @return
 */
int Tcp::getUrgPtr() {
    return ntohs(tcph.urg_ptr);
}

int Tcp::getPackageLength() {
    return ipv4->getPackageLength();
}

Protocol* Tcp::analyse(const pcap_pkthdr *header, const u_char *packageData) {
    tcphdr *temp = (tcphdr *)packageData;
    memcpy(&tcph, temp, sizeof(tcphdr));
    return this;
}

QStringList Tcp::briefInfo() {
    QStringList stringList = ipv4->briefInfo();
    stringList.replace(stringList.length() - 1, QString("tcp"));
    return stringList;
}

QList<QPair<QString, QStringList>> Tcp::detailInfo() {
    QList<QPair<QString, QStringList>> list = ipv4->detailInfo();
    QStringList stringList;
    stringList.append(QString("Source port: ").append(QString::number(getPortSrc())));
    stringList.append(QString("Destination port: ").append(QString::number(getPortDest())));
    stringList.append(QString("Sequence number: ").append(QString::number(getSeq())));
    stringList.append(QString("Acknowledgment number: ").append(QString::number(getSeqAck())));
    stringList.append(QString("Reserved: ").append(QString::number(getResl())));
    stringList.append(QString("Data offset: ").append(QString::number(getDoff())));
    stringList.append(QString("FIN: ").append(QString::number(getFin())));
    stringList.append(QString("SYN: ").append(QString::number(getSyn())));
    stringList.append(QString("RST: ").append(QString::number(getRst())));
    stringList.append(QString("PSH: ").append(QString::number(getPsh())));
    stringList.append(QString("ACK: ").append(QString::number(getAck())));
    stringList.append(QString("URG: ").append(QString::number(getUrg())));
    stringList.append(QString("ECE: ").append(QString::number(getEce())));
    stringList.append(QString("CWR: ").append(QString::number(getCwr())));
    stringList.append(QString("Window size: ").append(QString::number(getWindow())));
    stringList.append(QString("Checksum: ").append(Protocol::intToHexString(getCheckSum())));
    stringList.append(QString("Urgent pointer: ").append(QString::number(getUrgPtr())));
    list.append(QPair<QString, QStringList>("tcp", stringList));
    return list;
}
