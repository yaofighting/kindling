//
// Created by jundi on 2023/3/30.
//

#include "net_path_track.h"
#include "tcp_packets_analyzer.h"
#include "../cgo/utils.h"


net_path_track::net_path_track(sinsp* inspector){
  this->inspector = inspector;
  init_host_ip();
}

void net_path_track::countTimeoutEvent(){
  chrono::nanoseconds ns = std::chrono::duration_cast< std::chrono::nanoseconds>(
      std::chrono::system_clock::now().time_since_epoch()
  );
  uint64_t cur = ns.count();
  unordered_map<uint32_t , net_track_data>::iterator it = net_track_map.begin();
  while(it != net_track_map.end()){
    if((cur - it->second.time_stamp) / 1e6 >= time_out && it->second.interval == 0){
      it->second.unreachable = true;
      exception_list.push_back(it->second);
      net_track_map.erase(it++);
    }else{
      it++;
    }
  }
}

void net_path_track::analyze_net_track(tcp_raw_data* results, int len){
  for(int i=0;i<len;i++){
    if(is_ip_from_cni0_network(results[i].tp.saddr) && is_ip_from_cni0_network(results[i].tp.daddr)){
      continue ;
    }
    uint64_t interval = 0;
    tcp_raw_data trd = results[i];
    char if_name[IFNAMSIZ];
    if_indextoname(trd.tp.ifindex, if_name);

    net_track_data* ntd = new net_track_data;
    ntd->time_stamp = trd.timestamp;
    ntd->tp = trd.tp;
    ntd->unreachable = false;
    ntd->seq = trd.seq;
    bool is_phy = false;
    if(ntd->tp.sport == 53 || ntd->tp.dport == 53){
      continue ;
    }
    if(strncmp(if_name, "en", 2)==0 || strncmp(if_name, "eth", 3)==0) {
      is_phy = true;
    }
    unordered_map<uint32_t , net_track_data>::iterator it = net_track_map.find(results[i].seq);
    if(is_ip_from_cni0_network(results[i].tp.saddr) || (is_phy && get_interface_by_ip(results[i].tp.saddr) != 0)){
          // client
      if(strncmp(if_name, "en", 2)==0 || strncmp(if_name, "eth", 3)==0){
        //cout<<"is client && is enoreth"<<endl;
        if(it != net_track_map.end()){
          net_track_data old_ntd = it->second;
          interval = trd.timestamp - old_ntd.time_stamp;
          net_track_map.erase(it);
        }
      }else {
        if(it == net_track_map.end()){
          net_track_map.insert(std::make_pair(trd.seq, *ntd));
        }
      }
    }else {
      if(strncmp(if_name, "en", 2)==0 || strncmp(if_name, "eth", 3)==0){
        //cout<<"is server && is enoreth"<<endl;
        if(it == net_track_map.end()){
          net_track_map.insert(std::make_pair(trd.seq, *ntd));
        }
      }else {
        if(it != net_track_map.end()){
          net_track_data old_ntd = it->second;
          interval = trd.timestamp - old_ntd.time_stamp;
          net_track_map.erase(it);
        }
      }
    }
    ntd->interval = interval;
    //cout<<"catch seq:"<<ntd->seq<<" ts:"<<ntd->time_stamp<<" sip:"<<ntd->tp.saddr<<" sport:"<<ntd->tp.sport<<" dip:"<<ntd->tp.daddr<<" dport:"<<ntd->tp.dport<<" interval:"<<ntd->interval<<" ifindex:"<<if_name<<" number:"<<trd.tp.ifindex<<endl;
    if (interval > slow_interval){
      exception_list.push_back(*ntd);
    }
  }
}


void net_path_track::get_exception_event(kindling_event_t_for_go evt[],int* evt_len) {
  int evtcnt = *evt_len;
  for(int i=0;i<exception_list.size();i++){
    init_tcp_kindling_event(&evt[evtcnt]);
    int userAttNumber = 0;
    net_track_data ntd = exception_list[i];
    KeyValue kindling_event_params[7] = {
        {(char*)("sip"), (char*)(&ntd.tp.saddr), 4, UINT32},
        {(char*)("dip"), (char*)(&ntd.tp.daddr), 4, UINT32},
        {(char*)("sport"), (char*)(&ntd.tp.sport), 2, UINT16},
        {(char*)("dport"), (char*)(&ntd.tp.dport), 2, UINT16},
        {(char*)("interval"), (char*)(&ntd.interval), 8, UINT64},
        {(char*)("unreachable"), (char*)(&ntd.unreachable), 1, BOOL},
        {(char*)("start_time"), (char*)(&ntd.time_stamp), 8, UINT64},
    };
    //cout<<"exception seq:"<<ntd.seq<< " sip:"<<ntd.tp.saddr<<" sport:"<<ntd.tp.sport<<" dip:"<<ntd.tp.daddr<<" dport:"<<ntd.tp.dport<<" interval:"<<ntd.interval<<endl;
    fill_kindling_event_param(&evt[evtcnt], kindling_event_params, 7, userAttNumber);
    evt[evtcnt].paramsNumber = userAttNumber;
    evtcnt++;
  }

}

