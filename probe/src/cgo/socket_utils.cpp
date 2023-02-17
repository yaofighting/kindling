#include "socket_utils.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>

void ipv4_int_to_str(int ip, char ip_str[]) {
	int a = ip / (1 << 24) % (1 << 8);
	int b = ip / (1 << 16) % (1 << 8);
	int c = ip / (1 << 8) % (1 << 8);
	int d = ip % (1 << 8);
	sprintf(ip_str, "%d.%d.%d.%d",a,b,c,d);
}

bool is_host_ip(char *ip) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (!strcmp(ifa->ifa_name, "lo"))
            continue;
        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if(strcmp(host, ip) == 0) return true;
        }
    }
    freeifaddrs(ifaddr);
    return false;
}

void init_tcp_kindling_event(kindling_event_t_for_go *p_kindling_event){
    p_kindling_event->name = (char*)malloc(sizeof(char) * 1024);

    for (int i = 0; i < 8; i++) {
      p_kindling_event->userAttributes[i].key = (char*)malloc(sizeof(char) * 128);
      p_kindling_event->userAttributes[i].value = (char*)malloc(sizeof(char) * EVENT_DATA_SIZE);
    }
}

int aggregate_tcp_handshake_rtt(tcp_handshake_buffer_elem *results, int *reslen, kindling_event_t_for_go evt[], int *evtlen) {
    map<agg_tcp_key, agg_tcp_value> mp;
    map<agg_tcp_key, agg_tcp_value>::iterator it;
    int i, evtcnt = 0;
    char ip_str[20];
    for(i = 0;i < *reslen;i++)
    {
        agg_tcp_key k = {results[i].tp.dport, results[i].tp.saddr, results[i].tp.daddr};
        it = mp.find(k);
        if(it == mp.end())
        {
            agg_tcp_value val = {1, results[i].synrtt, results[i].ackrtt, results[i].timestamp, results[i].timestamp};
            mp[k] = val;
        }   
        else
        {
            it->second.data_counts++;
            it->second.synrtt_delta += results[i].synrtt;
            it->second.ackrtt_delta += results[i].ackrtt;
            it->second.end_time = results[i].timestamp;
        }
    }

    for(auto &e: mp)
    {
        ipv4_int_to_str(e.first.src_ip, ip_str);
        if(is_host_ip(ip_str))
        {
            e.second.ackrtt_delta = -1; //If host a client, ackrtt is invalid
        }
        else
        {
            e.second.synrtt_delta = -1; //If host a server, synrtt is invalid
        }

        //fill the kindling event
        init_tcp_kindling_event(&evt[evtcnt]);

        strcpy(evt[evtcnt].name, "tcp_handshake_rtt");

        int userAttNumber = 0;

        strcpy(evt[evtcnt].userAttributes[userAttNumber].key, "sip");
        memcpy(evt[evtcnt].userAttributes[userAttNumber].value, &e.first.src_ip, 4);
        evt[evtcnt].userAttributes[userAttNumber].valueType = UINT32;
        evt[evtcnt].userAttributes[userAttNumber].len = 4;
        userAttNumber++;

        strcpy(evt[evtcnt].userAttributes[userAttNumber].key, "dip");
        memcpy(evt[evtcnt].userAttributes[userAttNumber].value, &e.first.dst_ip, 4);
        evt[evtcnt].userAttributes[userAttNumber].valueType = UINT32;
        evt[evtcnt].userAttributes[userAttNumber].len = 4;
        userAttNumber++;

        strcpy(evt[evtcnt].userAttributes[userAttNumber].key, "dport");
        memcpy(evt[evtcnt].userAttributes[userAttNumber].value, &e.first.dst_port, 2);
        evt[evtcnt].userAttributes[userAttNumber].valueType = UINT16;
        evt[evtcnt].userAttributes[userAttNumber].len = 2;
        userAttNumber++;

        strcpy(evt[evtcnt].userAttributes[userAttNumber].key, "data_counts");
        memcpy(evt[evtcnt].userAttributes[userAttNumber].value, &e.second.data_counts, 8);
        evt[evtcnt].userAttributes[userAttNumber].valueType = UINT64;
        evt[evtcnt].userAttributes[userAttNumber].len = 8;
        userAttNumber++;

        strcpy(evt[evtcnt].userAttributes[userAttNumber].key, "synrtt_delta");
        memcpy(evt[evtcnt].userAttributes[userAttNumber].value, &e.second.synrtt_delta, 8);
        evt[evtcnt].userAttributes[userAttNumber].valueType = INT64;
        evt[evtcnt].userAttributes[userAttNumber].len = 8;
        userAttNumber++;

        strcpy(evt[evtcnt].userAttributes[userAttNumber].key, "ackrtt_delta");
        memcpy(evt[evtcnt].userAttributes[userAttNumber].value, &e.second.ackrtt_delta, 8);
        evt[evtcnt].userAttributes[userAttNumber].valueType = INT64;
        evt[evtcnt].userAttributes[userAttNumber].len = 8;
        userAttNumber++;

        strcpy(evt[evtcnt].userAttributes[userAttNumber].key, "start_time");
        memcpy(evt[evtcnt].userAttributes[userAttNumber].value, &e.second.start_time, 8);
        evt[evtcnt].userAttributes[userAttNumber].valueType = UINT64;
        evt[evtcnt].userAttributes[userAttNumber].len = 8;
        userAttNumber++;

        strcpy(evt[evtcnt].userAttributes[userAttNumber].key, "end_time");
        memcpy(evt[evtcnt].userAttributes[userAttNumber].value, &e.second.end_time, 8);
        evt[evtcnt].userAttributes[userAttNumber].valueType = UINT64;
        evt[evtcnt].userAttributes[userAttNumber].len = 8;
        userAttNumber++;

        evt[evtcnt].paramsNumber = userAttNumber;

        evtcnt++;
        // cout << "src_ip: " << ip_str << "  dst_ip: " <<  ipv4_int_to_str(e.first.dst_ip, ip_str) << "  dst_port: " << e.first.dst_port
        //     << "  data_counts: " << e.second.data_counts << "  synrtt_delta: " << e.second.synrtt_delta << "  ackrtt_delta: " << e.second.ackrtt_delta
        //     << "  start_time: " << e.second.start_time << "  end_time: " << e.second.end_time << endl;
    }
    *evtlen = evtcnt;
    mp.clear();
    return 0;
}