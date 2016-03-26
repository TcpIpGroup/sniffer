#include "sniffer.h"
#include "ui_sniffer.h"
#include <stdlib.h>

Sniffer::Sniffer(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Sniffer)
{
    ui->setupUi(this);
    uiHander = ui;
}

Ui::Sniffer *Sniffer::uiHander = NULL;

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

void Sniffer::on_action_triggered()
{
    on_actionSelectAdapter_triggered();
}

/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    QStandardItemModel *model = (QStandardItemModel*)Sniffer::uiHander->pak_tableView->model();
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
    model->appendRow(item);
}

void Sniffer::on_adapter_itemClicked(const QString &name)
{
    ischooseed = 1;
    char errbuf[PCAP_ERRBUF_SIZE];
    QByteArray ba = name.toLatin1();
    char *dname=ba.data();
    //打开设备
    if ( (adhandle= pcap_open(dname,          // 设备名
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
    Device::instance()->free();

    //利用setModel()方法将数据模型与QtableView绑定
    QStandardItemModel *pak_model = new QStandardItemModel();
    ui->pak_tableView->setModel(pak_model);
    //列
    pak_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("time")));
    pak_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("usec")));
    pak_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("head")));
    //属性
//    ui->pak_tableView->horizontalHeader()->setResizeMode(0, QHeaderView::Fixed);//定宽
//    ui->pak_tableView->horizontalHeader()->setResizeMode(1, QHeaderView::Fixed);
//    ui->pak_tableView->setColumnWidth(0,100);
//    ui->pak_tableView->setColumnWidth(1,100);
    ui->pak_tableView->verticalHeader()->hide();
    //设置选中时为整行选中
    ui->pak_tableView->setSelectionBehavior(QAbstractItemView::SelectRows);

    //设置表格的单元为只读属性，即不能编辑
    ui->pak_tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    /* 开始捕获 */
    pcap_loop(adhandle, 2, packet_handler, NULL);

}

void Sniffer::on_action_start_triggered()
{
    if(ischooseed == 0)
    {
        QMessageBox::information(NULL,"啊哦","请先选择一个设备");
        return;
    }

    //利用setModel()方法将数据模型与QtableView绑定
    QStandardItemModel *pak_model = new QStandardItemModel();
    ui->pak_tableView->setModel(pak_model);
    //列
    pak_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("time")));
    pak_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("usec")));
    pak_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("head")));
    //属性
//    ui->pak_tableView->horizontalHeader()->setResizeMode(0, QHeaderView::Fixed);//定宽
//    ui->pak_tableView->horizontalHeader()->setResizeMode(1, QHeaderView::Fixed);
//    ui->pak_tableView->setColumnWidth(0,100);
//    ui->pak_tableView->setColumnWidth(1,100);
    ui->pak_tableView->verticalHeader()->hide();
    //设置选中时为整行选中
    ui->pak_tableView->setSelectionBehavior(QAbstractItemView::SelectRows);

    //设置表格的单元为只读属性，即不能编辑
    ui->pak_tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    /* 开始捕获 */
    pcap_loop(adhandle, 1, packet_handler, NULL);
}


void Sniffer::on_action_start_2_triggered()
{
    on_action_start_triggered();
}

void Sniffer::on_action_help_triggered()
{
    QStandardItemModel *pak_model = new QStandardItemModel();
    //利用setModel()方法将数据模型与QtableView绑定
    ui->pak_tableView->setModel(pak_model);
    QStandardItem *item1=new QStandardItem("a");
    QStandardItem *item2=new QStandardItem("b");
    QStandardItem *item3=new QStandardItem("c");
    QList<QStandardItem*> item;
    item<<item1<<item2<<item3;
    pak_model->appendRow(item);
}

