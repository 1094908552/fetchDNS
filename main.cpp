#include <iostream>
#include "fetch.h"

int main() {
    fetch dnsFetch;
    bool loop = true;
    char inBuf[1024];
    while(loop) {
        cout<<">";
        cin>>inBuf;
        if(strcmp("quit", inBuf) == 0) {
            loop = false;
        } else {
            loop = dnsFetch.queryDomainToIP(inBuf);
        }
    }
    return 0;
}
