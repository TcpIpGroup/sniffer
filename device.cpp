#include "device.h"

Device::Device()
{
    setHead();
}

Device::~Device()
{
    free();
}

void Device::setHead()
{
    if (!isError())
    {
        if (head == NULL)
        {
            char errbuf[PCAP_ERRBUF_SIZE];
            /* Retrieve the device list from the local machine */
            if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &head, errbuf) == -1)
            {
                error = true;
                QMessageBox::warning(NULL, "获取设备失败", errbuf);
            }
        }
    }
}

void Device::free()
{
    if (head) {
        pcap_freealldevs(head);
    }
}

bool Device::isError()
{
    return error;
}

QStringList Device::getNameList()
{
    pcap_if_t *d;
    QStringList list;
    for(d = head; d != NULL; d= d->next)
    {
        list << d->name;
    }
    return list;
}

QMap<QString, QString> Device::getDetailsByName(const QString &name)
{
    QMap<QString, QString> map;
    pcap_if_t *d;
    for(d = head; d != NULL; d= d->next)
    {
        if (d->name == name)
        {
            map.insert("name", d->name);
            if (d->description)
            {
                map.insert("description", d->description);
            }
            map.insert("loopback", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

            //Ip addresses
            pcap_addr_t *a;
            char ip6str[128];
            QStringList list;
            for (a = d->addresses; a; a = a->next)
            {
                switch(a->addr->sa_family)
                {
                case AF_INET:
                    map.insert("Address Family", "AF_INET");
                    if (a->addr)
                    {
                        map.insert("Address", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                    }
                    if (a->netmask)
                    {
                        map.insert("Netmask", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                    }
                    if (a->broadaddr)
                    {
                        map.insert("Broadcast Address", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                    }
                    if (a->dstaddr)
                    {
                        map.insert("Destination Address", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                    }
                    break;
                case AF_INET6:
                    map.insert("Address Family", "AF_INET6");
                    if (a->addr)
                    {
                        map.insert("Address", ip6tos(a->addr, ip6str, sizeof(ip6str)));
                    }
                    break;
                }
            }
            break;
        }
    }
    return map;
}

bool Device::hasName(const QString &name)
{
    pcap_if_t *d;
    for(d = head; d != NULL; d= d->next)
    {
        if (d->name == name) {
            return true;
        }
    }
    return false;
}

QString Device::getDescriptionByName(const QString &name)
{
    pcap_if_t *d;
    for(d = head; d != NULL; d= d->next)
    {
        if (d->name == name) {
            break;
        }
    }
    if (d->description)
    {
        return d->description;
    }
    return name;
}

pcap_t* Device::getHandleByName(const QString &name)
{
    pcap_t* handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    //打开设备
    if ((handle = pcap_open(name.toStdString().c_str(),          // 设备名
                              65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
                              )) == NULL)
    {
        QString errname = name;
        QMessageBox::warning(NULL,"error","\nUnable to open the adapter. "+ errname +"is not supported by WinPcap\n");
    }
    return handle;
}

Device* Device::instance()
{
    if (device == NULL)
    {
        device = new Device();
    }
    return device;
}

Device* Device::device = NULL;

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
char* Device::iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* Device::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif


    if(getnameinfo(sockaddr,
        sockaddrlen,
        address,
        addrlen,
        NULL,
        0,
        NI_NUMERICHOST) != 0) address = NULL;

    return address;
}
