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
    setTreeViewHeader();
    packageObject = new PackageObject();
    connect(packageObject, SIGNAL(ethernet_protocol_package(const pcap_pkthdr*,const u_char*)), this, SLOT(on_ethernet_protocol_package(const pcap_pkthdr*,const u_char*)));
    count=0;
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
    setStartEnabled(false);
    setPauseEnabled(true);
    QStandardItemModel *model = (QStandardItemModel *)(ui->tableViewPackage->model());
    model->removeRows(0, model->rowCount());
    protocolVec.clear();
    Statistics::instance()->resetCount();
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

void Sniffer::on_actionView_triggered() {
    Count count;
    count.exec();
}

void Sniffer::on_adapter_itemClicked(const QString &name)
{
    statusBar()->showMessage(tr("Selected device: ") + Device::instance()->getDescriptionByName(name));
    packageObject->setDeviceName(name);
    this->setStartEnabled(true);
}

void Sniffer::on_ethernet_protocol_package(const pcap_pkthdr *header, const u_char *packageData)
{
    Protocol *protocol = (new Ethernet())->analyse(header, packageData);
    this->protocolVec.push_back(protocol);
    Statistics::instance()->increase(protocol->type);
    QStringList briefs = protocol->briefInfo();
    QList<QStandardItem*> item;
    for (QStringList::Iterator it = briefs.begin(); it != briefs.end(); ++it) {
        item.append(new QStandardItem(*it));
    }
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
    headerList << "No."<<"Source" << "Destination" << "Length" << "Protocol";
    model->setHorizontalHeaderLabels(headerList);
    ui->tableViewPackage->horizontalHeader()->setStretchLastSection(true);
    ui->tableViewPackage->setSelectionBehavior(QTableView::SelectRows);
    ui->tableViewPackage->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableViewPackage->resizeColumnsToContents();
    ui->tableViewPackage->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->tableViewPackage->setModel(model);
    ui->tableViewPackage->verticalHeader()->hide();

    //设置选中时为整行选中
    ui->tableViewPackage->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置表格的单元为只读属性，即不能编辑
    ui->tableViewPackage->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void Sniffer::setTreeViewHeader()
{
    ui->treeView->setHeaderHidden(true);
    ui->treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void Sniffer::on_tableViewPackage_clicked(const QModelIndex &index)
{
    //qDebug()<<index.row()<<protocolVec.at(index.row());
    QStandardItemModel *treeViewModel = new QStandardItemModel();
    QList<QPair<QString, QStringList>> lists = protocolVec.at(index.row())->detailInfo();
    for (QList<QPair<QString, QStringList>>::iterator itl = lists.begin(); itl != lists.end(); ++itl) {
        QStandardItem *item = new QStandardItem(itl->first);
        QStringList list = itl->second;
        QList<QStandardItem *> items;
        for (QStringList::iterator it = list.begin(); it != list.end(); ++it) {
            items.push_back(new QStandardItem(*it));
        }
        item->appendRows(items);
        treeViewModel->appendRow(item);
    }
    ui->treeView->setModel(treeViewModel);
    ui->treeView->expandAll();
}

