#-------------------------------------------------
#
# Project created by QtCreator 2016-03-18T12:46:51
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniffer
TEMPLATE = app

LIBS += -llibwpcap\
    -lws2_32

SOURCES += main.cpp\
        sniffer.cpp \
    adapter.cpp \
    device.cpp \
    packageobject.cpp \
    pktinfo.cpp

HEADERS  += sniffer.h \
    adapter.h \
    device.h \
    pro.h \
    packageobject.h \
    pktinfo.h

FORMS    += sniffer.ui \
    adapter.ui
RESOURCES += \
    images.qrc \
    qdarkstyle/style.qrc
