#ifndef STATISTICS_H
#define STATISTICS_H
#include <stddef.h>
#include <QObject>
#include <protocol.h>

class Statistics: public QObject
{
    Q_OBJECT
private:
    static Statistics *statistics;
    Statistics();
public:
    static Statistics *instance();

    int countProtocol = 0;
    int countEthernet = 0;
    int countIpv4 = 0;
    int countArp = 0;
    int countRarp = 0;
    int countUdp = 0;
    int countTcp = 0;
    int countIcmp = 0;
    int countDhcp = 0;
    void resetCount();
    void increase(Protocol::Type type);
signals:
    /**
     * @brief 捕获包信号
     */
    void edited_count(Protocol::Type type);
};
#endif // STATISTICS_H
