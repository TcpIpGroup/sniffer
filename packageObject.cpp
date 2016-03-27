#include "packageobject.h"

PackageObject::PackageObject()
{
    connect(this, SIGNAL(capturePackage()), this, SLOT(on_capturePackage()));
    this->moveToThread(&thread);
    thread.start();
}

PackageObject::~PackageObject()
{
    thread.quit();
}

void PackageObject::on_capturePackage()
{
    handle = Device::instance()->getHandleByName(deviceName);
    if (handle)
    {
        int res;
        struct pcap_pkthdr *header;
        const u_char *packageData;
        /* Retrieve the packets */
        while ((res = pcap_next_ex(handle, &header, &packageData)) >= 0)
        {
            qDebug() << res;
            if(res == 0)
            {    /* Timeout elapsed */
                continue;
            }
            qDebug()<<"PackageObject:"<<QThread::currentThreadId();
            emit package(header, packageData);
        }
        if (res == -1)
        {
            qDebug()<<"Error reading the packets: "<<pcap_geterr(handle);
        }
    }
}



void PackageObject::start()
{
    if (handle)
    {
        pcap_close(handle);
        handle = NULL;
    }
    emit capturePackage();
}

void PackageObject::stop()
{
    if (handle)
    {
        pcap_close(handle);
        handle = NULL;
    }
}

void PackageObject::setDeviceName(const QString &name)
{
    this->deviceName = name;
}

