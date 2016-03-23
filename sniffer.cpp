#include "sniffer.h"
#include "ui_sniffer.h"

Sniffer::Sniffer(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Sniffer)
{
    ui->setupUi(this);

}

Sniffer::~Sniffer()
{
    delete ui;
}

void Sniffer::on_actionSelectAdapter_triggered()
{
    Adapter adapter;
    connect(&adapter, SIGNAL(itemClicked(const QString&)), this, SLOT(on_adapter_itemClicked(const QString&)));
    adapter.exec();
}

void Sniffer::on_adapter_itemClicked(const QString &name)
{

}
