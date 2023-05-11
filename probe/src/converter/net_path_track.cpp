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

// void net_path_track::countTimeoutEvent(){
//   chrono::nanoseconds ns = std::chrono::duration_cast< std::chrono::nanoseconds>(
//       std::chrono::system_clock::now().time_since_epoch()
//   );
//   uint64_t cur = ns.count();
//   unordered_map<uint32_t , net_track_data>::iterator it = net_track_map.begin();
//   while(it != net_track_map.end()){
//     if((cur - it->second.time_stamp) / 1e6 >= time_out && it->second.interval == 0){
//       it->second.unreachable = true;
//       exception_list.push_back(it->second);
//       net_track_map.erase(it++);
//     }else{
//       it++;
//     }
//   }
// }

// void net_path_track::analyze_net_track(tcp_raw_data* results, int len){
//   for(int i=0;i<len;i++){
//     if(is_ip_from_cni0_network(results[i].tp.saddr) && is_ip_from_cni0_network(results[i].tp.daddr)){
//       continue ;
//     }
//     uint64_t interval = 0;
//     tcp_raw_data trd = results[i];
//     char if_name[IFNAMSIZ];
//     if_indextoname(trd.tp.ifindex, if_name);

//     net_track_data* ntd = new net_track_data;
//     ntd->time_stamp = trd.timestamp;
//     ntd->tp = trd.tp;
//     ntd->unreachable = false;
//     ntd->seq = trd.seq;
//     bool is_phy = false;
//     if(ntd->tp.sport == 53 || ntd->tp.dport == 53){
//       continue ;
//     }
//     if(strncmp(if_name, "en", 2)==0 || strncmp(if_name, "eth", 3)==0) {
//       is_phy = true;
//     }
//     unordered_map<uint32_t , net_track_data>::iterator it = net_track_map.find(results[i].seq);
//     if(is_ip_from_cni0_network(results[i].tp.saddr) || (is_phy && get_interface_by_ip(results[i].tp.saddr) != 0)){
//           // client
//       if(strncmp(if_name, "en", 2)==0 || strncmp(if_name, "eth", 3)==0){
//         //cout<<"is client && is enoreth"<<endl;
//         if(it != net_track_map.end()){
//           net_track_data old_ntd = it->second;
//           interval = trd.timestamp - old_ntd.time_stamp;
//           net_track_map.erase(it);
//         }
//       }else {
//         if(it == net_track_map.end()){
//           net_track_map.insert(std::make_pair(trd.seq, *ntd));
//         }
//       }
//     }else {
//       if(strncmp(if_name, "en", 2)==0 || strncmp(if_name, "eth", 3)==0){
//         //cout<<"is server && is enoreth"<<endl;
//         if(it == net_track_map.end()){
//           net_track_map.insert(std::make_pair(trd.seq, *ntd));
//         }
//       }else {
//         if(it != net_track_map.end()){
//           net_track_data old_ntd = it->second;
//           interval = trd.timestamp - old_ntd.time_stamp;
//           net_track_map.erase(it);
//         }
//       }
//     }
//     ntd->interval = interval;
//     //cout<<"catch seq:"<<ntd->seq<<" ts:"<<ntd->time_stamp<<" sip:"<<ntd->tp.saddr<<" sport:"<<ntd->tp.sport<<" dip:"<<ntd->tp.daddr<<" dport:"<<ntd->tp.dport<<" interval:"<<ntd->interval<<" ifindex:"<<if_name<<" number:"<<trd.tp.ifindex<<endl;
//     if (interval > slow_interval){
//       exception_list.push_back(*ntd);
//     }
//   }
// }


// void net_path_track::get_exception_event(kindling_event_t_for_go evt[],int* evt_len) {
//   int evtcnt = *evt_len;
//   for(int i=0;i<exception_list.size();i++){
//     init_tcp_kindling_event(&evt[evtcnt]);
//     int userAttNumber = 0;
//     net_track_data ntd = exception_list[i];
//     KeyValue kindling_event_params[7] = {
//         {(char*)("sip"), (char*)(&ntd.tp.saddr), 4, UINT32},
//         {(char*)("dip"), (char*)(&ntd.tp.daddr), 4, UINT32},
//         {(char*)("sport"), (char*)(&ntd.tp.sport), 2, UINT16},
//         {(char*)("dport"), (char*)(&ntd.tp.dport), 2, UINT16},
//         {(char*)("interval"), (char*)(&ntd.interval), 8, UINT64},
//         {(char*)("unreachable"), (char*)(&ntd.unreachable), 1, BOOL},
//         {(char*)("start_time"), (char*)(&ntd.time_stamp), 8, UINT64},
//     };
//     //cout<<"exception seq:"<<ntd.seq<< " sip:"<<ntd.tp.saddr<<" sport:"<<ntd.tp.sport<<" dip:"<<ntd.tp.daddr<<" dport:"<<ntd.tp.dport<<" interval:"<<ntd.interval<<endl;
//     fill_kindling_event_param(&evt[evtcnt], kindling_event_params, 7, userAttNumber);
//     evt[evtcnt].paramsNumber = userAttNumber;
//     evtcnt++;
//   }

// }

/*
    Flannel: veth <----> cni0 <----> flannel.1 <----> ens192
    send:
      veth(pod ---> Service)
      cni0(pod ---> pod)
      flannel.1(pod ---> pod)
      ens192(pod ---> pod)
    receive:
      ens192(pod ---> pod)
      flannel.1(pod ---> pod)
      cni0(Service ---> pod)
      veth(Service ---> pod)
*/
void net_path_track::analyze_pod_net_track(tcp_raw_data raw_data[], int head, int tail) {
  for (int i = head; i != tail; i = (i + 1) % MAX_TCP_BUFFER) {
    if (raw_data[i].tp.sport == 53 || raw_data[i].tp.dport == 53 ||
        (is_ip_from_cni0_network(raw_data[i].tp.saddr) &&
         is_ip_from_cni0_network(raw_data[i].tp.daddr)) ||
        (focus_pod_ip.find(raw_data[i].tp.saddr) == focus_pod_ip.end() &&
         focus_pod_ip.find(raw_data[i].tp.daddr) == focus_pod_ip.end())) {
      return;
    }
    //    cout<<"ts:"<<ev_ts<<endl;
    //    printf("push into ip_to_seq_map... saddr = %u, daddr = %u, seq = %u\n", tp.saddr,
    //    tp.daddr, seq);
    ip_to_seq_map[raw_data[i].tp.daddr].emplace_back(raw_data[i].tp.saddr, raw_data[i].seq, raw_data[i].timestamp);
    ip_to_seq_map[raw_data[i].tp.saddr].emplace_back(raw_data[i].tp.daddr, raw_data[i].seq, raw_data[i].timestamp);
    pod_track_data ptd = pod_track_data(raw_data[i].tp, raw_data[i].seq, raw_data[i].timestamp);
    pod_track_map[raw_data[i].seq].emplace_back(ptd);
  }
}

void net_path_track::consume_pod_track_by_seq(kindling_event_t_for_go evt[], int &evtcnt, uint32_t seq, uint64_t begin_time, uint64_t end_time, int maxlen){
  for(auto &event: pod_track_map[seq]){
    if(!(event.timestamp >= begin_time && event.timestamp <= end_time)) continue;
    // init_tcp_kindling_event(&evt[evtcnt]);
    strcpy(evt[evtcnt].name, "pod_net_track");
    int userAttNumber = 0;
    KeyValue kindling_event_params[7] = {
      {(char*)("sip"), (char*)(&event.tp.saddr), 4, UINT32},
      {(char*)("dip"), (char*)(&event.tp.daddr), 4, UINT32},
      {(char*)("sport"), (char*)(&event.tp.sport), 2, UINT16},
      {(char*)("dport"), (char*)(&event.tp.dport), 2, UINT16},
      {(char*)("ifindex"), (char*)(&event.tp.ifindex), 4, UINT32},
      {(char*)("seq"), (char*)(&event.seq), 4, UINT32},
      {(char*)("timestamp"), (char*)(&event.timestamp), 8, UINT64},
    };
    fill_kindling_event_param(&evt[evtcnt], kindling_event_params, 7, userAttNumber);
    evt[evtcnt].paramsNumber = userAttNumber;
    evtcnt++;
//    printf("consume_pod_track_by_seq...sip = %u, dip = %u, sport = %d, dport =%d, ifindex = %d, seq = %u, timestamp = %llu\n",
//      event.tp.saddr, event.tp.daddr, event.tp.sport, event.tp.dport, event.tp.ifindex, event.seq, event.timestamp);
    pod_track_map.erase(seq);
    if(evtcnt >= maxlen) return;
  }
}

template <typename T1, typename T2, typename MAP_T>
void net_path_track::clear_timeout_pod_track(uint64_t &cur_time, T1 &map_it, T2 &vec_it, MAP_T &my_map){
  while(map_it != my_map.end()){
    vec_it = map_it->second.begin();
    while(vec_it != map_it->second.end() && cur_time - vec_it->timestamp <= clear_cycle){
      vec_it++;
    }
    if(vec_it != map_it->second.end()){
      map_it->second.erase(vec_it, map_it->second.end());
    }
    if(map_it->second.empty()){
      my_map.erase(map_it++);
    }else{
      map_it++;
    }
  }
}

void net_path_track::get_pod_track_event(kindling_event_t_for_go evt[], int* evt_len, int max_len) {
  int evtcnt = *evt_len;

  chrono::nanoseconds ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::system_clock::now().time_since_epoch());
  uint64_t cur_time = ns.count();

  for (auto& pod_pair : focus_pod_map) {
    for (auto& focus_seq : ip_to_seq_map[pod_pair.first.saddr]) {
      consume_pod_track_by_seq(evt, evtcnt, focus_seq.seq, pod_pair.second.begin_time,
                               pod_pair.second.end_time, max_len);
    }
    for (auto& focus_seq : ip_to_seq_map[pod_pair.first.daddr]) {
      consume_pod_track_by_seq(evt, evtcnt, focus_seq.seq, pod_pair.second.begin_time,
                               pod_pair.second.end_time, max_len);
    }
  }
  // clear timeout event from map
  unordered_map<uint32_t, vector<pod_track_data> >::iterator pt_it = pod_track_map.begin();
  unordered_map<uint32_t, vector<ip_pair> >::iterator itsm_it = ip_to_seq_map.begin();
  vector<pod_track_data>::iterator vec_it1;
  vector<ip_pair>::iterator vec_it2;
  clear_timeout_pod_track(cur_time, pt_it, vec_it1, pod_track_map);
  clear_timeout_pod_track(cur_time, itsm_it, vec_it2, ip_to_seq_map);

  // clear timeout pods from focus map
  unordered_map<pod_key, pod_value, pod_key_hash, pod_key_equal>::iterator it =
      focus_pod_map.begin();
  while (it != focus_pod_map.end()) {
    if (cur_time > it->second.end_time) {
      focus_pod_ip[it->first.saddr]--;
      focus_pod_ip[it->first.daddr]--;
      if (!focus_pod_ip[it->first.saddr]) focus_pod_ip.erase(it->first.saddr);
      if (!focus_pod_ip[it->first.daddr]) focus_pod_ip.erase(it->first.daddr);
      focus_pod_map.erase(it++);
    } else {
      it++;
    }
  }
  *evt_len = evtcnt;
}