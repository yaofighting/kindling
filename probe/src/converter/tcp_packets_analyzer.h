#ifndef TCP_PACKETS_ANALYZER_H
#define TCP_PACKETS_ANALYZER_H
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <sinsp.h>
#include <unistd.h>
#include <iomanip>
#include <iostream>
#include <net/if.h>
#include "../cgo/kindling.h"

// const int MAX_TCP_BUFFER_LEN = 1024 * 512;

const int MAX_TCP_BUFFER = 1024 * 512;

struct agg_handshake_rtt_value {
  uint64_t data_counts;
  int64_t synrtt_delta;
  int64_t ackrtt_delta;
  uint64_t start_time;
  uint64_t end_time;
};


struct interface_info{
  int ifindex;
  uint32_t ip;
  uint32_t netmask;
};

class tcp_analyer_base {
    unordered_map <uint32_t, uint32_t> host_map;
    unordered_map<string, int> focus_container_interface_by_user;
public:
    sinsp *inspector;
    interface_info cni0;
    unordered_map <uint32_t, uint32_t> ifindex_type_map;

    void add_focus_container_interface_by_user(string name);

    void init_virtual_interface_ip();

    bool is_ip_from_cni0_network(uint32_t ip);

    void init_host_ip();

    uint32_t get_interface_by_ip(uint32_t ip_int);

    void ipv4_int_to_str(uint32_t ip, char ip_str[]);

    tcp_tuple get_reverse_tuple(tcp_tuple *tp);

    // void init_tcp_kindling_event(kindling_event_t_for_go *p_kindling_event, int number);
};

struct tcp_tuple_hash {
  size_t operator()(const tcp_tuple& tp) const {
    return hash<uint32_t>()(tp.saddr) ^ hash<uint32_t>()(tp.daddr) ^ hash<uint16_t>()(tp.sport) ^
           hash<uint32_t>()(tp.dport) ^ hash<uint32_t>()(tp.ifindex);
  }
};

struct tcp_tuple_equal {
  size_t operator()(const tcp_tuple& a, const tcp_tuple& b) const {
    return a.saddr == b.saddr && a.daddr == b.daddr && a.sport == b.sport && a.dport == b.dport;
  }
};

struct packets_total {
  uint64_t total_counts;
  int direction_type;  // 1: send, 0: received, 2: in cni0 network
};

struct agg_tcp_ack {
  uint64_t data_counts;
  int64_t acktime_delta;
  uint64_t start_time;
  uint64_t end_time;
  agg_tcp_ack(uint64_t t) : start_time(t), end_time(t), data_counts(0), acktime_delta(0) {}
};

class tcp_handshake_analyzer : public tcp_analyer_base {
  unordered_map<tcp_tuple, agg_handshake_rtt_value, tcp_tuple_hash, tcp_tuple_equal>
      handshake_agg_map;
  unordered_map<tcp_tuple, tcp_handshake_rtt, tcp_tuple_hash, tcp_tuple_equal>
      handshake_match_map;
  unordered_map<tcp_tuple, agg_handshake_rtt_value, tcp_tuple_hash, tcp_tuple_equal>::iterator
      map_ptr;

 public:
  tcp_handshake_analyzer(sinsp* inspector);
  int match_tcp_handshake(tcp_tuple *tp, bool SYN, bool ACK, uint64_t cur_time);
  bool consume_tcp_handshake(tcp_raw_data raw_data[], int head, int tail, kindling_event_t_for_go evt[], int *evtlen, int max_len);
};

class tcp_packets_analyzer : public tcp_analyer_base {
  /*
      for get_total_tcp_packets() function.
      count the number of tcp packets.
  */
  unordered_map<tcp_tuple, packets_total, tcp_tuple_hash, tcp_tuple_equal> quadruples_total_map;
  // quadruples_total_map(src,dst,sport,dport) --- aggregate ---> iptuples_total_map(src, dst)
  // unordered_map<agg_iptuple_key, packets_total, agg_iptuple_key_hash, agg_iptuple_key_equal>
  // iptuples_total_map;
  /*
      for get_tcp_ack_delay() function.
      to match and caculate the ack delay.
  */
  unordered_map<tcp_tuple, agg_tcp_ack, tcp_tuple_hash, tcp_tuple_equal> ack_delay_map;
  unordered_map<tcp_tuple, agg_tcp_ack, tcp_tuple_hash, tcp_tuple_equal>::iterator dmap_ptr;
  unordered_map<tcp_tuple, queue<tcp_raw_data*>, tcp_tuple_hash, tcp_tuple_equal>
      ack_match_queue_map;
  unordered_map<tcp_tuple, queue<tcp_raw_data*>, tcp_tuple_hash, tcp_tuple_equal>::iterator
      qmap_ptr;

 public:
  tcp_packets_analyzer(sinsp* inspector);
  bool get_total_tcp_packets(tcp_raw_data raw_data[], int head, int tail, kindling_event_t_for_go evt[], int *evtlen, int max_len);
  int match_tcp_ack_delay(tcp_raw_data *raw_p);
  bool consume_tcp_ack_delay(tcp_raw_data raw_data[], int head, int tail, kindling_event_t_for_go evt[], int *evtlen, int max_len);
};

#endif