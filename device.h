#ifndef DEVICE_H
#define DEVICE_H

#include <QMessageBox>
#include <QMap>
#include <QStringList>
#include <QObject>
#include <QDebug>

#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock2.h>
    #include<ws2tcpip.h>
#endif

#include <packageobject.h>
class PackageObject;

class Device: public QObject
{
    Q_OBJECT

private:
    Device();
    ~Device();
public:

    /**
     * @brief 获取设备是否出错
     * @return
     */
    bool isError();

    /**
     * @brief 获取所有设备名字
     * @return
     */
    QStringList getNameList();

    /**
     * @brief 根据名字获取详细信息
     * @param name
     * @return
     */
    QMap<QString, QString> getDetailsByName(const QString &name);

    /**
     * @brief 判断是否存在改名字的设备
     * @param name
     * @return
     */
    bool hasName(const QString &name);

    /**
     * @brief 根据设备名字获取设备的描述
     * @param name
     * @return
     */
    QString getDescriptionByName(const QString &name);

    /**
     * @brief 实例化Device类
     * @return
     */
    static Device* instance();
    /**
     * @brief 释放设备列表
     */
    void free();
    /**
     * @brief 设置设备列表头指针
     */
    void setHead();

    /**
     * @brief 获取设备句柄
     * @param object
     */
    pcap_t* getHandleByName(const QString &name);

private:
    static Device *device;
    bool error = false;
    pcap_if_t *head = NULL;

    char* iptos(u_long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

};

#endif // DEVICE_H
