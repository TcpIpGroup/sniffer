#ifndef DEVICE_H
#define DEVICE_H

#include <QMessageBox>
#include <QMap>
#include <QStringList>

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

class Device
{
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
    QMap<QString, QString> getDescriptionByName(QString name);

    /**
     * @brief 判断是否存在改名字的设备
     * @param name
     * @return
     */
    bool hasName(QString name);

    /**
     * @brief 根据设备名字获取设备指针
     * @param name
     * @return
     */
    pcap_if_t* getPacpIfTByName(QString name);

    /**
     * @brief 实例化Device类
     * @return
     */
    static Device* instance();
private:
    static Device *device;
    bool error = false;
    pcap_if_t *head = NULL;

    char* iptos(u_long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
};

#endif // DEVICE_H
