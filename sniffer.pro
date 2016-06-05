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
    statistics.cpp \
    arp.cpp \
    ipv4.cpp \
    ethernet.cpp \
    protocol.cpp \
    udp.cpp \
    tcp.cpp \
    icmp.cpp \
    rarp.cpp \
    dhcp.cpp \
    count.cpp

HEADERS  += sniffer.h \
    adapter.h \
    device.h \
    packageobject.h \
    statistics.h \
    arp.h \
    ipv4.h \
    ethernet.h \
    protocolheader.h \
    protocol.h \
    udp.h \
    tcp.h \
    icmp.h \
    rarp.h \
    dhcp.h \
    count.h

FORMS    += sniffer.ui \
    adapter.ui \
    count.ui
RESOURCES += \
    images.qrc \
    qdarkstyle/style.qrc
