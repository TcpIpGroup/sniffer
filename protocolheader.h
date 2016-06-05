#ifndef PROTOCOLHEADER_H
#define PROTOCOLHEADER_H

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4231

//Mac帧头 占14个字节
struct ethhdr
{
    u_char dest[6];         //6个字节 目标地址
    u_char src[6];              //6个字节 源地址
    u_short type;               //2个字节 类型
};

//ARP头
struct arphdr
{
    u_short ar_hrd;                     //硬件类型
    u_short ar_pro;                     //协议类型
    u_char ar_hln;                      //硬件地址长度
    u_char ar_pln;                      //协议地址长度
    u_short ar_op;                      //操作码，1为请求 2为回复
    u_char ar_srcmac[6];            //发送方MAC
    struct in_addr ar_srcip;             //发送方IP
    u_char ar_destmac[6];           //接收方MAC
    struct in_addr ar_destip;                //接收方IP
};

//定义IP头
struct iphdr
{
#if defined(LITTLE_ENDIAN)
    /**
     * @brief 首部长度
     */
    u_char ihl:4;
    /**
     * @brief 版本号
     */
    u_char version:4;
#elif defined(BIG_ENDIAN)
    u_char version:4;
    u_char  ihl:4;
#endif
    u_char tos;             //TOS 服务类型
    u_short tlen;           //包总长 u_short占两个字节
    u_short id;             //标识
    u_short frag_off;       //片位移
    u_char ttl;             //生存时间
    u_char proto;           //协议
    u_short check;          //校验和
    struct in_addr  saddr;  //源地址
    struct in_addr  daddr;  //目的地址
    //u_int   op_pad;         //选项等
};

//定义TCP头
struct tcphdr
{
    u_short sport;                          //源端口地址  16位
    u_short dport;                          //目的端口地址 16位
    u_int seq;                              //序列号 32位
    u_int ack_seq;                          //确认序列号
#if defined(LITTLE_ENDIAN)
    u_short resl:4, /*保留*/
        doff:4, /*偏移*/
        fin:1,  /*关闭连接标志*/
        syn:1,  /*请求连接标志*/
        rst:1,  /*重置连接标志*/
        psh:1,  /*接收方尽快将数据放到应用层标志*/
        ack:1,  /*确认序号标志*/
        urg:1,  /*紧急指针标志*/
        ece:1,  /*拥塞标志位*/
        cwr:1;  /*拥塞标志位*/
#elif defined(BIG_ENDIAN)
    u_short doff:4, /*偏移*/
        res1:4,     /*保留*/
        cwr:1,      /*拥塞标志位*/
        ece:1,      /*拥塞标志位*/
        urg:1,      /*紧急指针标志*/
        ack:1,      /*确认序号标志*/
        psh:1,      /*接收方尽快将数据放到应用层标志*/
        rst:1,      /*重置连接标志*/
        syn:1,      /*请求连接标志*/
        fin:1;      /*关闭连接标志*/
#endif
    u_short window;       //滑动窗口大小 16位
    u_short check;        //校验和 16位
    u_short urg_ptr;      //紧急指针 16位
    u_int opt;            //选项
};

//定义UDP头
struct udphdr
{
    u_short sport;      //源端口  16位
    u_short dport;      //目的端口 16位
    u_short len;            //数据报长度 16位
    u_short check;      //校验和 16位
};

//定义ICMP
struct icmphdr
{
    u_char type;            //8位 类型
    u_char code;            //8位 代码
    u_short chksum;      //8位校验和
};

//定义IPv6
struct iphdr6
{
    //#if defined(BIG_ENDIAN)
    u_int version:4,                //版本
        flowtype:8,         //流类型
        flowid:20;              //流标签
    /*#elif defined(LITTLE_ENDIAN)
u_int  flowid:20,               //流标签
            flowtype:8,         //流类型
            version:4;              //版本
//#endif*/
    u_short plen;                   //有效载荷长度
    u_char nh;                      //下一个头部
    u_char hlim;                    //跳限制
    u_short saddr[8];           //源地址
    u_short daddr[8];           //目的地址
};

//定义ICMPv6
struct icmphdr6
{
    u_char type;            //8位 类型
    u_char code;            //8位 代码
    u_char seq;         //序列号 8位
    u_char chksum;      //8位校验和
    u_char op_type; //选项：类型
    u_char op_len;      //选项：长度
    u_char op_ethaddr[6];       //选项：链路层地址
};

struct dhcphdr {
    u_char		dp_op;		/* packet opcode type; OP:*/
    u_char		dp_htype;	/* hardware addr type; HTYPE(硬件类别):*/
    u_char		dp_hlen;	/* hardware addr length; HLEN(硬件地址长度):*/
    u_char		dp_hops;	/* gateway hops; HOPS:*/
    u_int		dp_xid;		/* transaction ID; TRANSACTION ID:*/
    u_short		dp_secs;	/* seconds since boot began SECONDS(Client 端启动时间):*/
    u_short		dp_flags;	/* flags; FLAGS: */
    struct in_addr	dp_ciaddr;	/* client IP address; ciaddr: */
    struct in_addr	dp_yiaddr;	/* 'your' IP address; yiaddr: */
    struct in_addr	dp_siaddr;	/* server IP address; siaddr: */
    struct in_addr	dp_giaddr;	/* gateway IP address; giaddr: */
    u_char		dp_chaddr[16];	/* client hardware address; chaddr: */
    u_char		dp_sname[64];	/* server host name; sname: */
    u_char		dp_file[128];	/* boot file name; file: */
    u_char		dp_options[0];	/* variable-length options field; options: */
};
#endif


