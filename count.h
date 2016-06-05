#ifndef COUNT_H
#define COUNT_H

#include <QDialog>
#include "statistics.h"

namespace Ui {
class Count;
}

class Count : public QDialog
{
    Q_OBJECT

public:
    explicit Count(QWidget *parent = 0);
    ~Count();

private slots:
    void on_edited_increase(Protocol::Type type);

private:
    Ui::Count *ui;
    Statistics *statistics = Statistics::instance();
};

#endif // COUNT_H
