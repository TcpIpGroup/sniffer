#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
#include <QThread>
#include <QScrollBar>

#include <adapter.h>
#include<winsock2.h>
#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>
#include "device.h"
#include "pro.h"
#include "pktinfo.h"
#include<vector>
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

    void on_tableViewPackage_clicked(const QModelIndex &index);

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
    vector<pktinfo> vec;
    int count;

private:
    void setHelpEnabled(bool enabled);
    void setPauseEnabled(bool enabled);
    void setStartEnabled(bool enabled);
    void setTableViewHeader();
    void setTreeViewHeader();

};

#endif // SNIFFER_H
