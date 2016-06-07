# sniffer
抓包分析实验(Tcp/Ip实验一)
程序中实现了:以太网帧(frame),ipv4,arp,rarp,dhcp,icmp,tcp,udp协议的分析
##开发环境
win7 + Qt Creator + winpcap库

winpcap配置见：http://www.cnblogs.com/jecyhw/p/5290700.html

如果要在其他操作系统下运行,可能还需要修改.pro工程配置文件修改链接外部库的格式，不然可能会报找不到lib的错。
可能有用的参考链接：http://www.qtcentre.org/threads/32920-Using-external-libraries 和 http://stackoverflow.com/questions/718447/adding-external-library-into-qt-creator-project
##界面类
1. 主界面:Sniffer类
2. 适配器选择界面:Adapter类
3. 统计界面:Count类

##协议类
Protocol类是所有协议类的基类
Protocol子类:Arp,Dhcp,Ethernet,Icmp,Ipv4,Rarp,Tcp,Udp

1. Ethernet类用来分析以太网帧协议,分析完之后如果存在上层协议就再把数据交给上层协议(arp,rarp,ipv4)去解析.在程序中其它未实现的的以太网帧上层协议则默认为以太网帧协议
2. Arp类用来分析arp协议
3. Rarp类用来分析rarp协议
4. Ipv4类用来分析ipv4协议,分析完之后如果存在上层协议就再把数据交给上层协议(Icmp,Tcp,Udp)去解析.在程序中其它未实现的的ipv4上层协议则默认为Ipv4协议
5. Icmp类用来分析icmp协议
6. Tcp类用来分析Tcp协议
7. Udp类用来分析Udp协议,分析完之后如果存在上层协议就再把数据交给上层协议(Dhcp)去解析
8. Dhcp类用来分析Dhcp协议

其中,protocolheader.h文件中定义各个协议的结构(对应的结构体

##捕获数据包类
PackageObject类和Device类是用来选择设备捕获数据包，然后交给协议类去分析

##统计类
Statistic类是用来统计各协议的总数
