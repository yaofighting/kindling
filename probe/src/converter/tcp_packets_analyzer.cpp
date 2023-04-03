#include "tcp_packets_analyzer.h"
#include "../cgo/utils.h"

#define PROC_NET_ROUTE "/proc/net/route"
void tcp_analyer_base::init_virtual_interface_ip() {
  char line[512] = {};
  FILE* fp = NULL;
  fp = fopen(PROC_NET_ROUTE, "r");
  if (fp == NULL) return;

  bool first_line = true;
  char* delimiters = " \t";
  char* token;

  while (fgets(line, sizeof(line), fp)) {
    char* scratch;
    if (first_line)  // skip the first line
    {
      first_line = false;
      continue;
    }

    // interface
    token = strtok_r(line, delimiters, &scratch);
    if (token && strncmp(token, "veth", 4) == 0 || strncmp(token, "cali", 4) == 0) {
      uint32_t ifindex = if_nametoindex(token);
      // Destination
      token = strtok_r(NULL, delimiters, &scratch);
      if (token) {
        char* end;
        uint32_t ip = strtoul(token, &end, 16);
        ip = ntohl(ip);
        host_map[ip] = ifindex;
      }
    }
  }
  fclose(fp);
}

void tcp_analyer_base::init_host_ip() {
  struct ifaddrs *ifaddr, *ifa;
  int family, s, ifcount = 0, pifcount = 0;
  char host[NI_MAXHOST];
  int container_interface[1024];
  int physical_interface[1024];

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) continue;

    family = ifa->ifa_addr->sa_family;

    if (!strcmp(ifa->ifa_name, "lo"))  // filter out localhost/127.0.0.1
      continue;

    if (!strncmp(ifa->ifa_name, "veth", 4) || !strncmp(ifa->ifa_name, "cali", 4)) {
      container_interface[ifcount++] = if_nametoindex(ifa->ifa_name);
    }

    if(!strncmp(ifa->ifa_name, "en", 2) || !strncmp(ifa->ifa_name, "eth", 3))
		{
			physical_interface[pifcount++] = if_nametoindex(ifa->ifa_name);
		}

    if (family == AF_INET) {
      s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0,
                      NI_NUMERICHOST);
      string str_ip = host;
      uint32_t ip = ipv4string_to_int(str_ip);
      host_map[ip] = if_nametoindex(ifa->ifa_name);
    }
  }
  container_interface[ifcount] = -1;
  physical_interface[pifcount] = -1;
  // init container network interface map
  inspector->init_focus_network_interface(container_interface, CONTAINER_INTERFACE);
	//init physical network interface map
	inspector->init_focus_network_interface(physical_interface, PHYSICAL_INTERFACE);
  // init virtual interface info (ip, ifindex)
  init_virtual_interface_ip();
  freeifaddrs(ifaddr);
}

uint32_t tcp_analyer_base::get_interface_by_ip(uint32_t ip_int) { return host_map[ip_int]; }

void tcp_analyer_base::ipv4_int_to_str(uint32_t ip, char ip_str[]) {
  int a = ip / (1 << 24) % (1 << 8);
  int b = ip / (1 << 16) % (1 << 8);
  int c = ip / (1 << 8) % (1 << 8);
  int d = ip % (1 << 8);
  sprintf(ip_str, "%d.%d.%d.%d", a, b, c, d);
}

tcp_tuple tcp_analyer_base::get_reverse_tuple(tcp_tuple* tp) {
  tcp_tuple rtp;
  rtp.saddr = tp->daddr;
  rtp.daddr = tp->saddr;
  rtp.sport = tp->dport;
  rtp.dport = tp->sport;
  rtp.ifindex = tp->ifindex;
  return rtp;
}

void tcp_analyer_base::init_tcp_kindling_event(kindling_event_t_for_go* p_kindling_event) {
  p_kindling_event->name = (char*)malloc(sizeof(char) * 1024);

  for (int i = 0; i < 10; i++) {
    p_kindling_event->userAttributes[i].key = (char*)malloc(sizeof(char) * 128);
    p_kindling_event->userAttributes[i].value = (char*)malloc(sizeof(char) * EVENT_DATA_SIZE);
  }
}

tcp_handshake_analyzer::tcp_handshake_analyzer(sinsp* inspector) {
  this->inspector = inspector;
  init_host_ip();
}

void tcp_handshake_analyzer::aggregate_handshake_info(tcp_handshake_buffer_elem* results,
                                                      int* reslen, kindling_event_t_for_go evt[],
                                                      int* evtlen) {
  int evtcnt = *evtlen;
  for (int i = 0; i < *reslen; i++) {
    if (results[i].timestamp == 0) continue;
    // agg_triple_key k = {results[i].tp.dport, results[i].tp.saddr, results[i].tp.daddr};
    map_ptr = handshake_agg_map.find(results[i].tp);
    if (map_ptr == handshake_agg_map.end()) {
      agg_handshake_rtt_value val = {1, results[i].synrtt, results[i].ackrtt, results[i].timestamp,
                                     results[i].timestamp};
      handshake_agg_map[results[i].tp] = val;
    } else {
      map_ptr->second.data_counts++;
      map_ptr->second.synrtt_delta += results[i].synrtt;
      map_ptr->second.ackrtt_delta += results[i].ackrtt;
      map_ptr->second.end_time = results[i].timestamp;
    }
  }
  for (auto& e : handshake_agg_map) {
    if (get_interface_by_ip(e.first.saddr) == e.first.ifindex) {
      e.second.ackrtt_delta = -1;  // If host a client, ackrtt is invalid
    } else {
      e.second.synrtt_delta = -1;  // If host a server, synrtt is invalid
    }

    // fill the kindling event
    init_tcp_kindling_event(&evt[evtcnt]);
    strcpy(evt[evtcnt].name, "tcp_handshake_rtt");
    int userAttNumber = 0;

    KeyValue kindling_event_params[9] = {
        {(char*)("sip"), (char*)(&e.first.saddr), 4, UINT32},
        {(char*)("dip"), (char*)(&e.first.daddr), 4, UINT32},
        {(char*)("sport"), (char*)(&e.first.sport), 2, UINT16},
        {(char*)("dport"), (char*)(&e.first.dport), 2, UINT16},
        {(char*)("data_counts"), (char*)(&e.second.data_counts), 8, UINT64},
        {(char*)("synrtt_delta"), (char*)(&e.second.synrtt_delta), 8, INT64},
        {(char*)("ackrtt_delta"), (char*)(&e.second.ackrtt_delta), 8, INT64},
        {(char*)("start_time"), (char*)(&e.second.start_time), 8, UINT64},
        {(char*)("end_time"), (char*)(&e.second.end_time), 8, UINT64},
    };
    fill_kindling_event_param(&evt[evtcnt], kindling_event_params, 9, userAttNumber);

    evt[evtcnt].paramsNumber = userAttNumber;
    evtcnt++;
  }
  *evtlen = evtcnt;
  handshake_agg_map.clear();
}

tcp_packets_analyzer::tcp_packets_analyzer(sinsp* inspector) {
  this->inspector = inspector;
  init_host_ip();
}

void tcp_packets_analyzer::get_total_tcp_packets(tcp_datainfo* results, int* reslen,
                                                 kindling_event_t_for_go evt[], int* evtlen) {
  int evtcnt = *evtlen;
  for (int i = 0; i < *reslen; i++) {
    if (results[i].timestamp == 0) continue;
    if (quadruples_total_map.find(results[i].tp) == quadruples_total_map.end()) {
      packets_total pt = packets_total{results[i].package_counts, 0};
      if (get_interface_by_ip(results[i].tp.saddr) == results[i].tp.ifindex) {
        pt.direction_type = 1;
      }
      quadruples_total_map[results[i].tp] = pt;
    } else {
      quadruples_total_map[results[i].tp].total_counts =
          quadruples_total_map[results[i].tp].total_counts > results[i].package_counts
              ? quadruples_total_map[results[i].tp].total_counts
              : results[i].package_counts;
    }
  }

  for (auto& e : quadruples_total_map) {
    // fill the kindling event
    init_tcp_kindling_event(&evt[evtcnt]);
    strcpy(evt[evtcnt].name, "tcp_packet_counts");
    int userAttNumber = 0;

    KeyValue kindling_event_params[6] = {
        {(char*)("sip"), (char*)(&e.first.saddr), 4, UINT32},
        {(char*)("dip"), (char*)(&e.first.daddr), 4, UINT32},
        {(char*)("sport"), (char*)(&e.first.sport), 2, UINT16},
        {(char*)("dport"), (char*)(&e.first.dport), 2, UINT16},
        {(char*)("packet_counts"), (char*)(&e.second.total_counts), 8, UINT64},
        {(char*)("direction_type"), (char*)(&e.second.direction_type), 4, INT32},
    };

    fill_kindling_event_param(&evt[evtcnt], kindling_event_params, 6, userAttNumber);

    evt[evtcnt].paramsNumber = userAttNumber;
    evtcnt++;
  }
  *evtlen = evtcnt;
  quadruples_total_map.clear();
}

void tcp_packets_analyzer::get_tcp_ack_delay(tcp_datainfo* results, int* reslen,
                                             kindling_event_t_for_go evt[], int* evtlen) {
  int i, evtcnt = *evtlen;
  for (i = 0; i < *reslen; i++) {
    if (results[i].timestamp == 0) continue;
    if (get_interface_by_ip(results[i].tp.saddr) != results[i].tp.ifindex) {
      ack_match_queue_map[results[i].tp].push(&results[i]);
      continue;  // only calculate src(host) ---> dst
    }

    tcp_tuple rtp = get_reverse_tuple(&results[i].tp);
    qmap_ptr = ack_match_queue_map.find(rtp);
    if (qmap_ptr != ack_match_queue_map.end()) {
      tcp_datainfo* cur = qmap_ptr->second.front();
      tcp_datainfo* pre = NULL;
      while (!qmap_ptr->second.empty() && cur->seq <= results[i].ack_seq &&
             cur->ack_seq <= results[i].seq) {
        pre = cur;
        qmap_ptr->second.pop();
        cur = qmap_ptr->second.front();
      }
      if (pre) {
        // agg_tcp_key agg_key = agg_iptuple_key{results[i].tp.saddr, results[i].tp.daddr};
        if (ack_delay_map.find(results[i].tp) == ack_delay_map.end()) {
          ack_delay_map.emplace(piecewise_construct, forward_as_tuple(results[i].tp),
                                forward_as_tuple(results[i].timestamp));  // construct in place
        }
        dmap_ptr = ack_delay_map.find(results[i].tp);
        dmap_ptr->second.acktime_delta += results[i].timestamp - pre->timestamp;
        dmap_ptr->second.data_counts++;
        dmap_ptr->second.end_time = results[i].timestamp;
      }
    }
  }

  for (auto& e : ack_delay_map) {
    init_tcp_kindling_event(&evt[evtcnt]);
    strcpy(evt[evtcnt].name, "tcp_ack_delay");
    int userAttNumber = 0;

    KeyValue kindling_event_params[8] = {
        {(char*)("sip"), (char*)(&e.first.saddr), 4, UINT32},
        {(char*)("dip"), (char*)(&e.first.daddr), 4, UINT32},
        {(char*)("sport"), (char*)(&e.first.sport), 2, UINT16},
        {(char*)("dport"), (char*)(&e.first.dport), 2, UINT16},
        {(char*)("data_counts"), (char*)(&e.second.data_counts), 8, UINT64},
        {(char*)("acktime_delta"), (char*)(&e.second.acktime_delta), 8, INT64},
        {(char*)("start_time"), (char*)(&e.second.start_time), 8, UINT64},
        {(char*)("end_time"), (char*)(&e.second.end_time), 8, UINT64},
    };
    fill_kindling_event_param(&evt[evtcnt], kindling_event_params, 8, userAttNumber);

    evt[evtcnt].paramsNumber = userAttNumber;
    evtcnt++;
  }
  *evtlen = evtcnt;
  ack_match_queue_map.clear();
  ack_delay_map.clear();
}