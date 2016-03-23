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
public:
    Device();
    ~Device();

    /**
     * @brief 是否获取设备出错
     * @return
     */
    bool isError();
    QStringList getNameList();
    QMap<QString, QString> getDescriptionByName(QString name);
    bool hasName(QString name);

private:
    bool error = false;
    pcap_if_t *head = NULL;

    char* iptos(u_long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
};

#endif // DEVICE_H
