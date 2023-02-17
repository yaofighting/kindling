#ifndef KINDLING_SOCKET_UTILS_H
#define KINDLING_SOCKET_UTILS_H
#include "kindling.h"
#include <stdint.h>

struct agg_tcp_key {
	uint16_t dst_port;
	uint32_t src_ip;
	uint32_t dst_ip;
    bool operator <(const agg_tcp_key& e)const{
        return dst_port < e.dst_port;
    }
};

struct agg_tcp_value{
	uint64_t data_counts;
	int64_t synrtt_delta;
	int64_t ackrtt_delta;
    uint64_t start_time;
	uint64_t end_time;
};

void ipv4_int_to_str(int ip, char ip_str[]);

bool is_host_ip(char *ip); 

void init_tcp_kindling_event(kindling_event_t_for_go *p_kindling_event);

int aggregate_tcp_handshake_rtt(tcp_handshake_buffer_elem *results, int *reslen, kindling_event_t_for_go evt[], int *evtlen);

#endif