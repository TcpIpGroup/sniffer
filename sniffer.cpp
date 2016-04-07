#include "sniffer.h"
#include "ui_sniffer.h"
#include <stdlib.h>

Sniffer::Sniffer(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Sniffer)
{
    ui->setupUi(this);

    connect(ui->actionMenuSelectAdapter, SIGNAL(triggered()), this, SLOT(on_actionSelectAdapter_triggered()));
    connect(ui->actionMenuStart, SIGNAL(triggered()), this, SLOT(on_actionStart_triggered()));
    connect(ui->actionMenuPause, SIGNAL(triggered()), this, SLOT(on_actionPause_triggered()));
    connect(ui->actionMenuHelp, SIGNAL(triggered()), this, SLOT(on_actionHelp_triggered()));

    setHelpEnabled(false);
    setPauseEnabled(false);
    setStartEnabled(false);

    setTableViewHeader();

    packageObject = new PackageObject();
    connect(packageObject, SIGNAL(package(const pcap_pkthdr*,const u_char*)), this, SLOT(on_package(const pcap_pkthdr*,const u_char*)));
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


void Sniffer::on_actionStart_triggered()
{
    ui->tableViewPackage->horizontalHeader()->show();
    setStartEnabled(false);
    setPauseEnabled(true);
    QStandardItemModel *model = (QStandardItemModel *)(ui->tableViewPackage->model());
    model->removeRows(0, model->rowCount());
    packageObject->start();
}

void Sniffer::on_actionPause_triggered()
{
    packageObject->stop();
    setStartEnabled(true);
    setPauseEnabled(false);
}

void Sniffer::on_actionHelp_triggered()
{

}

void Sniffer::on_actionExit_triggered()
{
    this->close();
}

void Sniffer::on_adapter_itemClicked(const QString &name)
{
    statusBar()->showMessage(tr("已选择设备: ") + Device::instance()->getDescriptionByName(name));
    packageObject->setDeviceName(name);
    this->setStartEnabled(true);
}

void Sniffer::on_package(const pcap_pkthdr *header, const u_char *packageData)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    QStandardItem *item1=new QStandardItem(timestr);
    QStandardItem *item2=new QStandardItem(QString::number(header->ts.tv_usec));
    QStandardItem *item3=new QStandardItem(QString::number(header->len));
    QList<QStandardItem*> item;
    item<<item1<<item2<<item3;
    qDebug()<<"Sniffer:"<<QThread::currentThreadId();
    ((QStandardItemModel *)(ui->tableViewPackage->model()))->appendRow(item);
}

void Sniffer::setHelpEnabled(bool enabled)
{
    ui->actionHelp->setEnabled(enabled);
    ui->actionMenuHelp->setEnabled(enabled);
}

void Sniffer::setPauseEnabled(bool enabled)
{
    ui->actionPause->setEnabled(enabled);
    ui->actionMenuPause->setEnabled(enabled);
}

void Sniffer::setStartEnabled(bool enabled)
{
    ui->actionStart->setEnabled(enabled);
    ui->actionMenuStart->setEnabled(enabled);
}


void Sniffer::setTableViewHeader()
{
    QStandardItemModel *model = new QStandardItemModel();
    //列
    QStringList headerList;
    headerList << "time" << "usec" << "head";
    model->setHorizontalHeaderLabels(headerList);
    ui->tableViewPackage->horizontalHeader()->setStretchLastSection(true);
    ui->tableViewPackage->setModel(model);
    ui->tableViewPackage->verticalHeader()->hide();
    ui->tableViewPackage->horizontalHeader()->hide();

    //设置选中时为整行选中
    ui->tableViewPackage->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置表格的单元为只读属性，即不能编辑
    ui->tableViewPackage->setEditTriggers(QAbstractItemView::NoEditTriggers);
}
