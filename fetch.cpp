//
// Created by 机械革命 on 2020/12/22.
//

#include "fetch.h"

fetch::fetch() {
    //启动网络库
    if(WSAStartup(MAKEWORD(2, 2), &version) != ERROR_SUCCESS) {
        cout<<"failed to start winsock2.dll"<<endl;
        cout<<"error code:"<<WSAGetLastError()<<endl;
        return;
    }
    //创建数据报套接字
    dnsSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(dnsSocket == SOCKET_ERROR) {
        cout<<"failed to open a SOCK_DGRAM"<<endl;
        cout<<"error code:"<<GetLastError()<<endl;
        WSACleanup();
        return;
    }
    int timeout = TIMEOUT;
    if(setsockopt(dnsSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)(&timeout), sizeof(timeout)) == SOCKET_ERROR) {
        cout<<"failed to set recv timeout"<<endl;
        cout<<"error code:"<<WSAGetLastError()<<endl;
        closesocket(dnsSocket);
        WSACleanup();
        return;
    }
    hostAddr.sin_family = AF_INET;
    hostAddr.sin_addr.S_un.S_addr = htonl(ADDR_ANY);
    hostAddr.sin_port = htons(12345);

    if(!getDNSServer()) {
        cout<<"failed to use getDNSServer()"<<endl;
        closesocket(dnsSocket);
        WSACleanup();
        return;
    }
    cout<<"Default DNS Sever IP:"<<(char*)dnsSeverIp<<endl;
    serverAddr.sin_family = AF_INET;
    //这里不需要转换字节顺序，inet_addr()函数将输入的“127.0.0.1”类型的地址转换为网络字节顺序
    serverAddr.sin_addr.S_un.S_addr = inet_addr(dnsSeverIp);
    serverAddr.sin_port = htons(53);

    //将socket与本地网卡绑定
    if(bind(dnsSocket, (sockaddr*)&hostAddr, sizeof(hostAddr)) == SOCKET_ERROR) {
        cout<<"failed to bind socket and hostAddr"<<endl;
        cout<<"error code"<<GetLastError()<<endl;
        closesocket(dnsSocket);
        WSACleanup();
        return;
    }
    //封装dns请求报文
    char queryMess[1024];
    strcpy(queryMess, "baidu.com");
    getDNSPackage(queryMess);
}

bool fetch::getDNSServer() {
    DWORD nLen;
    //先获取长度
    if(GetNetworkParams(nullptr, &nLen) != ERROR_BUFFER_OVERFLOW) {
        return false;
    }
    //这里有问题，
    // 如果直接PFIXED_INFO pFixedInfo = (PFIXED_INFO)malloc(sizeof(PFIXED_INFO));
    // 会出现错误，应该在GetNetworkParams()函数内部出现错误
    PFIXED_INFO pFixedInfo = (PFIXED_INFO)malloc(sizeof(char[nLen]));
    if(GetNetworkParams(pFixedInfo, &nLen) != ERROR_SUCCESS) {
        return false;
    }
    //获取到的dns地址为空，则直接返回，可能主机为联网
    if(pFixedInfo->DnsServerList.IpAddress.String == NULL) {
        cout<<"host not on line"<<endl;
        return false;
    }
    strcpy(dnsSeverIp, pFixedInfo->DnsServerList.IpAddress.String);
    return true;
}

int fetch::getDNSPackage(char* domain) {
    int DNSPackageLen = 0;
    memset(sendBuf, 0, sizeof(sendBuf));            //清空发送缓冲区
    DNSHeader* dnsHeader = (DNSHeader*)sendBuf;

    /*dns报文首部封装，dns请求报文头部只需要将RD位置为1，查询记录数置为1即可*/
    dnsHeader -> id = htons(id);
    dnsHeader -> flags = htons(0x0100);          //期望服务器递归查询
    dnsHeader -> requestNum = htons(1);
    DNSPackageLen += sizeof(DNSHeader);

    /*dns报文查询部分封装*/
    char* pTrace = domain;
    char* pChar = domain;
    int queryLen = 1;           //查询名称长度
    while(*pTrace != '\0') {
        pTrace ++;
    }
    //比较内存地址，向后移动一位
    while (pTrace != domain) {
        *(pTrace + 1) = *pTrace;
        pTrace -- ;
    }
    *(pTrace + 1) = *pTrace;
    pTrace ++;
    unsigned char counter = 0;
    while(*pTrace != '\0') {
        if(*pTrace == '.') {
            queryLen += (counter + 1);
            *pChar = counter;
            counter = 0;
            pChar = pTrace;
        }else {
            counter ++;
        }
        pTrace++;
    }
    *pChar = counter;
    queryLen += (counter + 1);
    *(pTrace + 1) = '\0';
    memcpy(sendBuf + sizeof(DNSHeader), domain, queryLen);
    DNSPackageLen += queryLen;

    DNSRequest* dnsRequest = (DNSRequest*)(sendBuf + sizeof(DNSHeader) + queryLen);
    dnsRequest -> type = htons(0x0001);
    dnsRequest -> queryClass = htons(0x0001);
    DNSPackageLen += sizeof(DNSRequest);
    return DNSPackageLen;
}

bool fetch::queryDomainToIP(char *requestMessage) {
    int dnsPackageLen = getDNSPackage(requestMessage);
    if(SOCKET_ERROR == sendto(dnsSocket, sendBuf, dnsPackageLen, 0, (sockaddr*)&serverAddr, sizeof(serverAddr))) {
        cout<<"failed to send package"<<endl;
        cout<<"error code:"<<WSAGetLastError()<<endl;
        return false;
    }
    bool haveRes = false;
    int serverAddrLen = sizeof(serverAddr);
    int recvLen = 0;
    while(!haveRes) {
        recvLen = recvfrom(dnsSocket, recvBuf, sizeof(recvBuf), 0, (sockaddr*)&serverAddr, &serverAddrLen);
        if(recvLen == SOCKET_ERROR) {
            cout<<"failed to recv package"<<endl;
            cout<<"error code: "<<WSAGetLastError()<<endl;
            return false;
        }
        if(decodeDNSPacket(recvBuf, recvLen)) {
            haveRes = true;
        }
    }
}

bool fetch::decodeDNSPacket(char *responseMessage, int responseMessageLen) {
    DNSHeader* dnsHeader = (DNSHeader*)responseMessage;
    if(id != ntohs(dnsHeader -> id)) {
        //不属于本程序应接受的东西
        return false;
    }
    int requestNum = ntohs(dnsHeader -> requestNum);
    int responseNum = ntohs(dnsHeader -> responseNum);
    int authorNum = ntohs(dnsHeader -> authorNum);
    int additionNum = ntohs(dnsHeader -> additionNum);
    unsigned short resId = ntohs(dnsHeader -> id);
    unsigned short flags = dnsHeader -> flags;
    unsigned short RA = flags & 0x0080;                 //递归响应位

    if(id == resId && flags >> 15 == 1) {
        //这是对应刚发送的dns请求报文的递归响应报文
        if(!RA) {
            //表示服务器无法给出递归响应
            cout<<"DNS sever can not give a digui response"<<endl;
            return true;
        }
        if(!(flags & 0x000F)) {
            //响应报文无错误
            if((flags >> 10) & 0x0001) {
                //权威回答
                cout<<"Authoritative answer:"<<endl;
            } else {
                //非权威回答
                cout<<"None-authoritative answer:"<<endl;
            }
        }
        unsigned char* pTraceResponse = (unsigned char*)(responseMessage + sizeof(DNSHeader));
        while(*pTraceResponse != '\0') {    //跳过域名字段
            pTraceResponse ++;
        }
        pTraceResponse++;
        pTraceResponse += sizeof(long);
        DNSResponse* dnsResponse;
        in_addr targetIP;
        for(int i = 1; i <= responseNum; i ++) {
            dnsResponse = (DNSResponse*)pTraceResponse;
            if(ntohs(dnsResponse -> type) == 1) {
                //类型值为1表示返回与之前发送的域名相匹配的IP地址
                pTraceResponse += sizeof(DNSResponse);
                targetIP.S_un.S_addr = *(unsigned long*)pTraceResponse;
                if(i == responseNum) {
                    cout<<inet_ntoa(targetIP)<<endl;
                } else {
                    cout<<inet_ntoa(targetIP)<<", ";
                }
                pTraceResponse += sizeof(long);
            } else if(ntohs(dnsResponse -> type) == 5) {
                //类型字段为5返回的是域名的别名,长度为不定长，需要用length字段解析别名
                pTraceResponse += sizeof(DNSResponse);
                pTraceResponse += dnsResponse -> length;
            }
        }
    } else {
        return false;
    }
    return true;
}

fetch::~fetch() {
    closesocket(dnsSocket);
    WSACleanup();
}