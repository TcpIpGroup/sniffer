#include "count.h"
#include "ui_count.h"

Count::Count(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Count)
{
    setWindowFlags(Qt::CustomizeWindowHint | Qt::WindowCloseButtonHint);
    ui->setupUi(this);
    connect(statistics, SIGNAL(edited_count(Protocol::Type)), this, SLOT(on_edited_increase(Protocol::Type)));
}

Count::~Count()
{
    delete ui;
}

void Count::on_edited_increase(Protocol::Type type) {
    switch(type) {
    case Protocol::Type::ARP:
        ui->labelArp->setText(QString("   arp:").append(QString::number(statistics->countArp)));
        break;
    case Protocol::Type::RARP:
        ui->labelRarp->setText(QString("   rarp:").append(QString::number(statistics->countRarp)));
        break;
    case Protocol::Type::IPV4:
        ui->labelIpv4->setText(QString("   ipv4:").append(QString::number(statistics->countIpv4)));
        break;
    case Protocol::Type::UDP:
        ui->labelUdp->setText(QString("   udp:").append(QString::number(statistics->countUdp)));
        break;
    case Protocol::Type::TCP:
        ui->labelTcp->setText(QString("   tcp:").append(QString::number(statistics->countTcp)));
        break;
    case Protocol::Type::ICMP:
        ui->labelIcmp->setText(QString("   icmp:").append(QString::number(statistics->countIcmp)));
        break;
    case Protocol::Type::DHCP:
        ui->labelDhcp->setText(QString("   dhcp:").append(QString::number(statistics->countDhcp)));
        break;
    }
}
