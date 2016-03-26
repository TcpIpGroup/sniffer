#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
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
    static Ui::Sniffer *uiHander;

private slots:
    void on_actionSelectAdapter_triggered();
    void on_action_triggered();
    void on_adapter_itemClicked(const QString &name);
    void on_action_start_triggered();
    void on_action_help_triggered();
    void on_action_start_2_triggered();
private:
    Ui::Sniffer *ui;
    pcap_t *adhandle;
    struct pcap_pkthdr *header;
    int ischooseed = 0;
};

#endif // SNIFFER_H
