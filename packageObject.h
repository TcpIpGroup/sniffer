#ifndef PACKAGETHREAD_H
#define PACKAGETHREAD_H

#include <QObject>
#include <QThread>
#include <QStandardItemModel>
#include <QDebug>
#include <device.h>
class Device;

class PackageObject : public QObject
{
    Q_OBJECT

public:
    PackageObject();
    ~PackageObject();

    void start();
    void stop();
    void setDeviceName(const QString &name);

protected slots:
    void on_capturePackage();

private:
    QThread thread;
    QString deviceName;

    pcap_t* handle;
signals:
    /**
     * @brief 捕获包信号
     */
    void capturePackage();

    /**
     * @brief 包数据信号
     * @param header
     * @param packageData
     */
    void package(const struct pcap_pkthdr *header, const u_char *packageData);
};

#endif // PACKAGETHREAD_H
