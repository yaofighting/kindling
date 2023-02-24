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


struct agg_tcp_ip_key{
    uint32_t saddr;
    uint32_t daddr;
    agg_tcp_ip_key(uint32_t s, uint32_t d): saddr(s), daddr(d){}
};

struct agg_tcp_ack {
    uint64_t data_counts;
	int64_t acktime_delta;
    uint64_t start_time;
	uint64_t end_time;
    agg_tcp_ack(uint64_t t):start_time(t), end_time(t), data_counts(0),acktime_delta(0){}
};

tcp_tuple get_reverse_tuple(tcp_tuple *tp);

struct tcp_tuple_hash {
    size_t operator()(const tcp_tuple &tp) const {
        return hash<uint32_t>()(tp.saddr) ^ hash<uint32_t>()(tp.daddr) ^ hash<uint16_t>()(tp.sport) ^ hash<uint16_t>()(tp.daddr);
    }
};

struct tcp_tuple_equal {
    size_t operator()(const tcp_tuple &a, const tcp_tuple &b) const {
        return a.saddr == b.saddr && a.sport == b.sport && a.daddr == b.daddr && a.dport == b.dport;
    }
};

struct tcp_ip_key_hash {
    size_t operator()(const agg_tcp_ip_key &tp) const {
        return hash<uint32_t>()(tp.saddr) ^ hash<uint32_t>()(tp.daddr);
    }
};

struct tcp_ip_key_equal {
    size_t operator()(const agg_tcp_ip_key &a, const agg_tcp_ip_key &b) const {
        return a.saddr == b.saddr && a.daddr == b.daddr;
    }
};

bool ip_filter(uint32_t ip);

int32_t get_tcp_ack_delay(tcp_datainfo *results, int *reslen, kindling_event_t_for_go evt[],
                           int* evtlen);

int32_t get_total_tcp_packets(tcp_datainfo *results, int *reslen, kindling_event_t_for_go evt[],
                           int* evtlen);

#endif