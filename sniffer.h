#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
#include <QThread>
#include <QScrollBar>

#include <adapter.h>
#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>
#include "device.h"

namespace Ui {
class Sniffer;
}

class Sniffer : public QMainWindow
{
    Q_OBJECT

public:
    explicit Sniffer(QWidget *parent = 0);
    ~Sniffer();

private slots:
    void on_actionSelectAdapter_triggered();
    void on_actionStart_triggered();
    void on_actionPause_triggered();
    void on_actionHelp_triggered();
    void on_actionExit_triggered();

    void on_adapter_itemClicked(const QString &name);

public slots:
    /**
     * @brief 处理数据包信号的槽
     * @param header
     * @param packageData
     */
    void on_package(const struct pcap_pkthdr *header, const u_char *packageData);

private:
    Ui::Sniffer *ui;
    PackageObject *packageObject;

private:
    void setHelpEnabled(bool enabled);
    void setPauseEnabled(bool enabled);
    void setStartEnabled(bool enabled);
    void setTableViewHeader();

};

#endif // SNIFFER_H
