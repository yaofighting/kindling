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

struct net_track_data {  //tcp raw data in buffer
  struct tcp_tuple tp;
  uint64_t interval;
  uint64_t time_stamp;
  bool unreachable;
  uint64_t seq;
};


class net_path_track : public tcp_analyer_base {
 public:
  void get_exception_event(kindling_event_t_for_go evt[],int* evt_len);
  net_path_track(sinsp* inspector);
  inline void insert(uint32_t seq, net_track_data t){
    net_track_map[seq] = t;
  }
  inline void setTimeout(uint64_t timeout){
    this->time_out = timeout;
  }
  void countTimeoutEvent();
  void analyze_net_track(tcp_raw_data* results, int len);
 private:
  vector<net_track_data> exception_list;
  unordered_map<uint32_t , net_track_data> net_track_map;
  uint64_t time_out=20*1000;
  uint64_t slow_interval = 20*1000*1000;
};

#endif  // KINDLING_PROBE_NET_PATH_TRACK_H