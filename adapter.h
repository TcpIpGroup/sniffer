#ifndef ADAPTER_H
#define ADAPTER_H

#include <QDialog>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QMessageBox>
#include "device.h"

namespace Ui {
class Adapter;
}

class Adapter : public QDialog
{
    Q_OBJECT

public:
    explicit Adapter(QWidget *parent = 0);
    ~Adapter();

private:
    Ui::Adapter *ui;
    Device *device;

signals:
    void itemClicked(const QString &name);

private slots:
    void on_treeViewAdapter_clicked(const QModelIndex&);
    void on_treeViewAdapter_doubleClicked(const QModelIndex&);
};

#endif // ADAPTER_H
