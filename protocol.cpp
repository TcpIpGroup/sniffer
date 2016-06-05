#include "protocol.h"
#include "statistics.h"
Protocol::Protocol() {}

Protocol::Protocol(Type type) {
    this->type = type;
}

Protocol* Protocol::analyse(const pcap_pkthdr *header, const u_char *packageData) {
    return this;
}

QStringList Protocol::briefInfo() {
    QStringList stringList;
    stringList.append(QString::number(++(Statistics::instance()->countProtocol)));
    return stringList;
}

QList<QPair<QString, QStringList>> Protocol::detailInfo() {
    return QList<QPair<QString, QStringList>>();
}

QString Protocol::charArrayToMacAdress(u_char array[]) {
    return QString("%1-%2-%3-%4-%5-%6")
            .arg(array[0], 2, 16, QLatin1Char('0'))
            .arg(array[1], 2, 16, QLatin1Char('0'))
            .arg(array[2], 2, 16, QLatin1Char('0'))
            .arg(array[3], 2, 16, QLatin1Char('0'))
            .arg(array[4], 2, 16, QLatin1Char('0'))
            .arg(array[5], 2, 16, QLatin1Char('0'));
}

QString Protocol::intToHexString(int value) {
    return QString("0x%1").arg(value, 0, 16);
}
