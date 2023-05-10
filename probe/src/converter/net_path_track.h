//
// Created by jundi on 2023/3/30.
//

#ifndef KINDLING_PROBE_NET_PATH_TRACK_H
#define KINDLING_PROBE_NET_PATH_TRACK_H
#include <chrono>
#include "sinsp.h"
#include "../cgo/kindling.h"
#include "string"
#include "tcp_packets_analyzer.h"

struct net_track_data {  
  struct tcp_tuple tp;
  uint64_t interval;
  uint64_t time_stamp;
  bool unreachable;
  uint64_t seq;
};

struct pod_track_data {  
  struct tcp_tuple tp;
  uint32_t seq;
  uint64_t timestamp;
  pod_track_data(struct tcp_tuple tt, uint32_t sq, uint64_t t):tp(tt), seq(sq), timestamp(t){}
};

struct pod_key {
  uint32_t saddr;
  uint32_t daddr;
};

struct pod_key_hash {
  size_t operator()(const pod_key& pk) const {
    return hash<uint32_t>()(pk.saddr) ^ hash<uint32_t>()(pk.daddr);
  }
};

struct pod_key_equal {
  size_t operator()(const pod_key& a, const pod_key& b) const {
    return a.saddr == b.saddr && a.daddr == b.daddr;
  }
};

struct pod_value {
  uint64_t begin_time;
  uint64_t end_time;
};

struct ip_pair {
  uint32_t dst_ip;
  uint64_t seq;
  uint64_t timestamp;
  ip_pair(uint32_t dst, uint64_t s, uint64_t t): dst_ip(dst), seq(s), timestamp(t){}
};

enum focus_pod_operation {
  FOCUS_POD_UPDATE = 0,
  FOCUS_POD_DELETE = 1
};

class net_path_track : public tcp_analyer_base {
 public:
  unordered_map<pod_key, pod_value, pod_key_hash, pod_key_equal> focus_pod_map;
  unordered_map<uint32_t, int> focus_pod_ip;
  // void get_exception_event(kindling_event_t_for_go evt[],int* evt_len);
  net_path_track(sinsp* inspector);
  // inline void insert(uint32_t seq, net_track_data t){
  //   net_track_map[seq] = t;
  // }
  // inline void setTimeout(uint64_t timeout){
  //   this->time_out = timeout;
  // }
  // void countTimeoutEvent();
  template <typename T1, typename T2, typename MAP_T>
  void clear_timeout_pod_track(uint64_t &cur_time, T1 &map_it, T2 &vec_it, MAP_T &my_map);
  void consume_pod_track_by_seq(kindling_event_t_for_go evt[], int &evtcnt, uint32_t seq, uint64_t begin_time, uint64_t end_time, int maxlen);
  // void analyze_net_track(tcp_raw_data* results, int len);
  void analyze_pod_net_track(sinsp_evt *ev);
  void get_pod_track_event(kindling_event_t_for_go evt[], int *evt_len, int max_len);
 private:
  unordered_map<uint32_t, vector<ip_pair> > ip_to_seq_map;
  unordered_map<uint32_t, vector<pod_track_data> > pod_track_map;

  // vector<net_track_data> exception_list;
  // unordered_map<uint32_t , net_track_data> net_track_map;
  uint64_t time_out=20*1000;
  uint64_t clear_cycle = 1e10;
  uint64_t slow_interval = 20*1000*1000;

  uint64_t last_pod_track_send_time;
};

#endif  // KINDLING_PROBE_NET_PATH_TRACK_H