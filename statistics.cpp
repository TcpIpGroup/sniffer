#include "statistics.h"

Statistics::Statistics() {}

Statistics* Statistics::instance() {
    if (statistics == NULL) {
        statistics = new Statistics();
    }
    return statistics;
}

Statistics* Statistics::statistics = NULL;

void Statistics::resetCount() {
    countProtocol = 0;
    countEthernet = 0;
    countIpv4 = 0;
    countArp = 0;
    countRarp = 0;
    countUdp = 0;
    countTcp = 0;
    countIcmp = 0;
    countDhcp = 0;
}

void Statistics::increase(Protocol::Type type) {
    switch(type) {
    case Protocol::Type::ARP:
        this->countArp++;
        break;
    case Protocol::Type::RARP:
        this->countRarp++;
        break;
    case Protocol::Type::IPV4:
        this->countIpv4++;
        break;
    case Protocol::Type::UDP:
        this->countUdp++;
        break;
    case Protocol::Type::TCP:
        this->countTcp++;
        break;
    case Protocol::Type::ICMP:
        this->countIcmp++;
        break;
    case Protocol::Type::DHCP:
        this->countDhcp++;
        break;
    }
    emit edited_count(type);
}
