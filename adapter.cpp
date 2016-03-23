#include "adapter.h"
#include "ui_adapter.h"

Adapter::Adapter(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Adapter)
{
    ui->setupUi(this);
    device = new Device();

    QStandardItem *item = new QStandardItem("Network Adapter");
    QStandardItemModel *adapterModel = new QStandardItemModel();
    adapterModel->appendRow(item);

    //
    if (!device->isError())
    {
        QList<QStandardItem *> adapterItems;
        for(QString name : device->getNameList())
        {
            adapterItems.push_back(new QStandardItem(name));
        }
        item->appendRows(adapterItems);
    }

    ui->treeViewAdapter->setModel(adapterModel);
    //hide the treeView's header
    ui->treeViewAdapter->setHeaderHidden(true);
    ui->treeViewAdapter->setEditTriggers(QAbstractItemView::NoEditTriggers);


    //
    QStandardItemModel *adapterDescModel = new QStandardItemModel();
    adapterDescModel->setColumnCount(2);
    adapterDescModel->setHorizontalHeaderItem(0, new QStandardItem("Field"));
    adapterDescModel->setHorizontalHeaderItem(1, new QStandardItem("Value"));
    ui->treeViewAdapterDesc->setModel(adapterDescModel);
}

Adapter::~Adapter()
{
    delete ui;
}

void Adapter::on_treeViewAdapter_clicked(const QModelIndex &index)
{
    QStandardItemModel *model = (QStandardItemModel *)ui->treeViewAdapterDesc->model();
    model->removeRows(0, model->rowCount());
    if (!(QStandardItemModel *)index.model()->hasChildren(index))
    {
        QMap<QString, QString> map = device->getDescriptionByName(index.data().toString());
        for (QMap<QString, QString>::Iterator it = map.begin(); it != map.end(); ++it)
        {
            QList<QStandardItem *> list;
            list.push_back(new QStandardItem(it.key()));
            list.push_back(new QStandardItem(it.value()));
            model->appendRow(list);
        }
    }
}

void Adapter::on_treeViewAdapter_doubleClicked(const QModelIndex &index)
{
    QStandardItemModel *model = (QStandardItemModel *)index.model();
    if (!model->hasChildren(index))
    {
        QString name = index.data().toString();
        if (device->hasName(name))
        {
            this->close();
            emit itemClicked(name);
        }
    }
}
