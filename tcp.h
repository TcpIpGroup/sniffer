#ifndef TCP_H
#define TCP_H
#include "protocol.h"
#include "ipv4.h"
class Ipv4;


class Tcp : public Protocol
{
public:
    Ipv4 *ipv4;
    tcphdr tcph;

    Tcp(Ipv4 *ipv4);
    /**
     * @brief getPortSrc 获取源端口
     * @return
     */
    int getPortSrc();
    /**
     * @brief getPortDest 获取目的端口
     * @return
     */
    int getPortDest();
    /**
     * @brief getLength 获取序列号
     * @return
     */
    unsigned long getSeq();
    /**
     * @brief getSeqAck 获取确认序列号
     * @return
     */
    unsigned long getSeqAck();
    /**
     * @brief getResl 获取保留位
     * @return
     */
    int getResl();
    /**
     * @brief getDoff 获取偏移
     * @return
     */
    int getDoff();
    /**
     * @brief getFin 获取关闭连接标志
     * @return
     */
    int getFin();
    /**
     * @brief getSyn 获取请求连接标志
     * @return
     */
    int getSyn();
    /**
     * @brief getRst 获取重置连接标志
     * @return
     */
    int getRst();
    /**
     * @brief getPsh 获取接收方尽快将数据放到应用层标志
     * @return
     */
    int getPsh();
    /**
     * @brief getAck 获取确认序号标志
     * @return
     */
    int getAck();
    /**
     * @brief getUrg 获取紧急指针标志
     * @return
     */
    int getUrg();
    /**
     * @brief getEce 获取拥塞标志位
     * @return
     */
    int getEce();
    /**
     * @brief getCwr 获取拥塞标志位
     * @return
     */
    int getCwr();
    /**
     * @brief getWindow 获取滑动窗口大小
     * @return
     */
    int getWindow();
    /**
     * @brief getCheckSum 获取获取校验和
     * @return
     */
    int getCheckSum();
    /**
     * @brief getUrgPtr 获取紧急指针
     * @return
     */
    int getUrgPtr();
    int getPackageLength();
    Protocol* analyse(const pcap_pkthdr *header, const u_char *packageData);
    QStringList briefInfo();
    QList<QPair<QString, QStringList>> detailInfo();
};

#endif // TCP_H
