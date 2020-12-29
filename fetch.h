//
// Created by 机械革命 on 2020/12/22.
//

#ifndef FETCHDNS_FETCH_H
#define FETCHDNS_FETCH_H

#include <iostream>
#include <winsock2.h>
#include <Iphlpapi.h>

#define PACK_STRUCT_FIELD(x) x __attribute__((1))

struct DNSHeader {
    unsigned short id;                  //标识字段，服务器将会原封不动的返回，客户端用以区分对应的应答报文
    unsigned short flags;               //标志字段，服务器与客户端交互时的信息传递，详细见README
    unsigned short requestNum;          //查询记录数
    unsigned short responseNum;         //应答记录数
    unsigned short authorNum;           //授权回答记录数
    unsigned short additionNum;         //附加信息记录数
};


//DNS报文查询部分，因为查询名称是变长字段，在运行时动态分配空间
struct DNSRequest {
    unsigned short type;                //查询类型
    unsigned short queryClass;          //查询类
};

//DNS报文响应部分
struct DNSResponse {
    unsigned short domain;               //域名
    unsigned short type;
    unsigned short responseClass;
    unsigned long ttl;
    unsigned short length;
} __attribute__((packed));


/**
 * 可以向本机默认的本地DNS服务器发送DNS数据报
 * 实现了域名到IP地址的解析
 * IP地址到域名的解析暂未实现
 */
using namespace std;
class fetch {
private:
    WSADATA version;            //winsock版本信息
    char sendBuf[1024];         //DNS发送缓冲区
    char recvBuf[1024 * 10];    //DNS接收缓冲区
    sockaddr_in serverAddr;     //dns服务器的套接字地址
    sockaddr_in hostAddr;       //本地套接字地址
    char dnsSeverIp[16];        //dns服务器IP地址
    SOCKET dnsSocket;           //数据报套接字用于和DNS服务器通信
    const int TIMEOUT = 8000;   //dns报文超时时间
    const short srcPort = 12345;//源端默认端口号
    const short id = 0;       //给定一个id号，便于判定是否本程序的数据报
public:
    /**
     * 构造函数
     * 启动网络库，并打开一个数据报套接字
     */
    fetch();
    ~fetch();
    /**
     * 获取本地DNS服务器的IP地址并以点分十进制的方式存储在severIp中
     */
    bool getDNSServer();
    /**
     * 根据用户输入的信息打包一个DNS报文
     * 如果输入exit则退出程序
     * @param domain 用户输入信息
     * @return DNS请求报文的长度
     */
    int getDNSPackage(char* domain);
    /**
     * 实现将域名转化为IP地址
     * @param requestMessage
     * @return 方法是否正确调用
     */
    bool queryDomainToIP(char* requestMessage);
    /**
     * 解析套接字收到的数据报
     * 并判断是否收到对应数据报
     * @param responseMessage 套接字收到的数据
     * @return 如果收到对应数据报则返回true
     */
    bool decodeDNSPacket(char* responseMessage, int responseMessageLen);
};


#endif //FETCHDNS_FETCH_H
