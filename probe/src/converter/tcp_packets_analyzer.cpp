#include "tcp_packets_analyzer.h"
#include "../cgo/utils.h"

#define PROC_NET_ROUTE "/proc/net/route"
/*
  For calico network: we can get container interface(ip, ifindex) from route table.
  For flannel+VXLAN network: we can't get container interface, so we get the cni0 interface to use. 
*/
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
    if (token && (strncmp(token, "veth", 4) == 0 || strncmp(token, "cali", 4) == 0 ||
                  strncmp(token, "cni0", 4) == 0)) {
      uint32_t ifindex = if_nametoindex(token);
      char ifname[30];
      strncpy(ifname, token, 20);
      // Destination
      token = strtok_r(NULL, delimiters, &scratch);
      if (token) {
        char* end;
        uint32_t ip = strtoul(token, &end, 16);
        ip = ntohl(ip);
        if (strncmp(ifname, "cni0", 4) != 0) {
          host_map[ip] = ifindex;
        } else { 
          cni0.ifindex = ifindex;
          cni0.ip = ip;
          for (int i = 0; i < 6; i++) {
            if (token) {
              token = strtok_r(NULL, delimiters, &scratch);
            }
          }
          // netmask
          uint32_t netmask = strtoul(token, &end, 16);
          netmask = ntohl(netmask);
          cni0.netmask = netmask;
          // printf("cni0_name = %s, netmask = %u\n", ifname, netmask);
        }
      }
    }
  }
  fclose(fp);
}

bool tcp_analyer_base::is_ip_from_cni0_network(uint32_t ip)
{
	uint32_t net = ip & cni0.netmask;
	return net == cni0.ip;
}


void tcp_analyer_base::init_host_ip() {
  struct ifaddrs *ifaddr, *ifa;
  int family, s, ifcount = 0, pifcount = 0, ndifcount = 0;
  char host[NI_MAXHOST];
  int container_interface[1024];
  int physical_interface[1024];
  int network_device_interface[1024];

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
      container_interface[ifcount] = if_nametoindex(ifa->ifa_name);
      ifindex_type_map[container_interface[ifcount]] = CONTAINER_INTERFACE;
      ifcount++;
    }

    if(!strncmp(ifa->ifa_name, "en", 2) || !strncmp(ifa->ifa_name, "eth", 3))
		{
			physical_interface[pifcount] = if_nametoindex(ifa->ifa_name);
      ifindex_type_map[physical_interface[pifcount]] = PHYSICAL_INTERFACE;
      pifcount++;
		}

    if(!strncmp(ifa->ifa_name, "cni0", 4) || !strncmp(ifa->ifa_name, "flannel", 7))
		{
			network_device_interface[ndifcount] = if_nametoindex(ifa->ifa_name);
      ifindex_type_map[network_device_interface[ndifcount]] = NETWORK_DEVICE_INTERFACE;
      ndifcount++;
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
  network_device_interface[ndifcount] = -1;
  // init container network interface map
  inspector->init_focus_network_interface(container_interface, CONTAINER_INTERFACE);
	//init physical network interface map
	inspector->init_focus_network_interface(physical_interface, PHYSICAL_INTERFACE);
  //init network device interface map(cni0, flannel.1, etc)
	inspector->init_focus_network_interface(network_device_interface, NETWORK_DEVICE_INTERFACE);
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

tcp_tuple tcp_analyer_base::get_reverse_tuple(tcp_tuple* tp) { //reverse tuple from a interface
  tcp_tuple rtp;
  rtp.saddr = tp->daddr;
  rtp.daddr = tp->saddr;
  rtp.sport = tp->dport;
  rtp.dport = tp->sport;
  rtp.ifindex = tp->ifindex;
  return rtp;
}

tcp_handshake_analyzer::tcp_handshake_analyzer(sinsp* inspector) {
  this->inspector = inspector;
  init_host_ip();
}

int tcp_handshake_analyzer::match_tcp_handshake(tcp_tuple* tp, bool SYN, bool ACK,
                                                uint64_t cur_time) {
  unordered_map<tcp_tuple, tcp_handshake_rtt, tcp_tuple_hash, tcp_tuple_equal>::iterator hdsm_ptr;

  if (SYN == 0 && ACK == 1) {
    hdsm_ptr = handshake_match_map.find(*tp);
    // the third handshake
    if (hdsm_ptr != handshake_match_map.end()) {
      hdsm_ptr->second.synrtt =
          hdsm_ptr->second.ackrtt - hdsm_ptr->second.synrtt;         // synrtt = second - first
      hdsm_ptr->second.ackrtt = cur_time - hdsm_ptr->second.ackrtt;  // ackrtt = third - second
      return 0;
    } 
  } else if (SYN == 1) {
    if (ACK == 0) {  // the first handshake
      struct tcp_handshake_rtt f_rtt = {};
      f_rtt.synrtt = cur_time;
      handshake_match_map[*tp] = f_rtt;
      return 1;
    } else {  // the second handshake
      tcp_tuple rtp = get_reverse_tuple(tp);
      hdsm_ptr = handshake_match_map.find(rtp);
      if (hdsm_ptr != handshake_match_map.end()) {
        hdsm_ptr->second.ackrtt = cur_time;  // update to the second handshake timestamp
      } else {                               // only drop if not match
        // printf("handshake map error, the first handshake not found.\n");
        return -1;
      }
    }
  }
  return -1;
}

bool tcp_handshake_analyzer::consume_tcp_handshake(tcp_raw_data raw_data[], int head, int tail,
                                                   kindling_event_t_for_go evt[], int* evtlen,
                                                   int max_len) {
  for (int i = head; i != tail; i = (i + 1) % MAX_TCP_BUFFER) {
    if (ifindex_type_map[raw_data[i].tp.ifindex] != CONTAINER_INTERFACE)
      continue;  // only analyze packet from container interface.
    bool SYN = raw_data[i].flag & (1 << 1);
    bool ACK = raw_data[i].flag & (1 << 4);
    if (match_tcp_handshake(&raw_data[i].tp, SYN, ACK, raw_data[i].timestamp) ==
        0) {  // finish 3 handshakes.
      unordered_map<tcp_tuple, tcp_handshake_rtt, tcp_tuple_hash, tcp_tuple_equal>::iterator
          hdsm_ptr = handshake_match_map.find(raw_data[i].tp);

      map_ptr = handshake_agg_map.find(raw_data[i].tp);
      if (map_ptr == handshake_agg_map.end()) {
        agg_handshake_rtt_value val = {1, hdsm_ptr->second.synrtt, hdsm_ptr->second.ackrtt,
                                       raw_data[i].timestamp, raw_data[i].timestamp};
        /*
      Note:
      For the Veth pair, the receiving and sending directions of the network cards on both sides of
      the container are opposite. We monitor the network cards on the outside of the Veth pair, so
      when the direction is RECEIVE_PACKET, the container's behavior is to send data packets.
    */
        if (raw_data[i].type == RECEIVE_PACKET) {
          val.ackrtt_delta = -1;    // If host is a client, ackrtt is invalid
        } else {
          val.synrtt_delta = -1;  // If host is a server, synrtt is invalid
        }
        handshake_agg_map[raw_data[i].tp] = val;
      } else {
        map_ptr->second.data_counts++;
        map_ptr->second.synrtt_delta += hdsm_ptr->second.synrtt;
        map_ptr->second.ackrtt_delta += hdsm_ptr->second.ackrtt;
        map_ptr->second.end_time = raw_data[i].timestamp;
      }
      handshake_match_map.erase(hdsm_ptr);
    }
  }

  int evtcnt = *evtlen;

  for (auto& e : handshake_agg_map) {
    if(e.second.synrtt_delta < 0) e.second.synrtt_delta = -1;
    else if(e.second.ackrtt_delta) e.second.ackrtt_delta = -1;
    // fill the kindling event
    // init_tcp_kindling_event(&evt[evtcnt]);
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
    if (evtcnt >= max_len) break;
  }

  *evtlen = evtcnt;
  handshake_agg_map.clear();
  return true;
}

tcp_packets_analyzer::tcp_packets_analyzer(sinsp* inspector) {
  this->inspector = inspector;
  init_host_ip();
}

bool tcp_packets_analyzer::get_total_tcp_packets(tcp_raw_data raw_data[], int head, int tail,
                                                 kindling_event_t_for_go evt[], int* evtlen,
                                                 int max_len) {
  for (int i = head; i != tail; i = (i + 1) % MAX_TCP_BUFFER) {
    if (ifindex_type_map[raw_data[i].tp.ifindex] != CONTAINER_INTERFACE)
      continue;  // only analyze packet from container interface.
    if (quadruples_total_map.find(raw_data[i].tp) == quadruples_total_map.end()) {
      packets_total pt = packets_total{1, 0};
      /*
      Note:
      For the Veth pair, the receiving and sending directions of the network cards on both sides of
      the container are opposite. We monitor the network cards on the outside of the Veth pair, so
      when the direction is RECEIVE_PACKET, the container's behavior is to send data packets.
    */
      if (raw_data[i].type == RECEIVE_PACKET) {
        pt.direction_type = 1;
      }
      quadruples_total_map[raw_data[i].tp] = pt;
    } else {
      quadruples_total_map[raw_data[i].tp].total_counts++;
    }
  }

  int evtcnt = *evtlen;

  for (auto& e : quadruples_total_map) {
    // fill the kindling event
    // init_tcp_kindling_event(&evt[evtcnt]);
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

    // printf(
    //     "get packet total...sip = %u, dip = %u, sport = %u, dport = %u, packet_counts = %d, "
    //     "direction_type = %d\n",
    //     e.first.saddr, e.first.daddr, e.first.sport, e.first.dport, e.second.total_counts,
    //     e.second.direction_type);
    fill_kindling_event_param(&evt[evtcnt], kindling_event_params, 6, userAttNumber);

    evt[evtcnt].paramsNumber = userAttNumber;
    evtcnt++;
    if (evtcnt >= max_len) break;
  }
  *evtlen = evtcnt;
  quadruples_total_map.clear();
  return true;  // consume them successfully.
}

int tcp_packets_analyzer::match_tcp_ack_delay(tcp_raw_data* rawp) {
  bool SYN = rawp->flag & (1 << 1);
  bool ACK = rawp->flag & (1 << 4);
  if (SYN == 0 && ACK == 1) {
    /*
      Note:
      For the Veth pair, the receiving and sending directions of the network cards on both sides of
      the container are opposite. We monitor the network cards on the outside of the Veth pair, so
      when the direction is RECEIVE_PACKET, the container's behavior is to send data packets.
    */
    if (rawp->type == SEND_PACKET) {
      ack_match_queue_map[rawp->tp].push(rawp);
      // printf("match_tcp_ack_delay...push seq = %u, src = %u, dst = %u, ifindex = %d\n", rawp->seq,
      //        rawp->tp.saddr, rawp->tp.daddr, rawp->tp.ifindex);
      return -1;  // only calculate src(host) ---> dst
    }

    tcp_tuple rtp = get_reverse_tuple(&rawp->tp);
    qmap_ptr = ack_match_queue_map.find(rtp); printf("match_tcp_ack_delay...find seq = %u, src = %u, dst = %u, ifindex = %d\n", rawp->seq, rawp->tp.saddr, rawp->tp.daddr, rawp->tp.ifindex);
    if (qmap_ptr != ack_match_queue_map.end()) {
      // printf("match_tcp_ack_delay...find success seq = %u, src = %u, dst = %u, ifindex = %d\n", rawp->seq, rawp->tp.saddr, rawp->tp.daddr, rawp->tp.ifindex);
      tcp_raw_data* cur = qmap_ptr->second.front();
      tcp_raw_data* pre = NULL;
      while (!qmap_ptr->second.empty() && cur->seq <= rawp->ack_seq && cur->ack_seq <= rawp->seq) {
        pre = cur;
        qmap_ptr->second.pop();
        cur = qmap_ptr->second.front();
      }
      if (pre) {
        // agg_tcp_key agg_key = agg_iptuple_key{results[i].tp.saddr, results[i].tp.daddr};
        if (ack_delay_map.find(rawp->tp) == ack_delay_map.end()) {
          ack_delay_map.emplace(piecewise_construct, forward_as_tuple(rawp->tp),
                                forward_as_tuple(rawp->timestamp));  // construct in place
        }
        dmap_ptr = ack_delay_map.find(rawp->tp);
        dmap_ptr->second.acktime_delta += rawp->timestamp - pre->timestamp;
        dmap_ptr->second.data_counts++;
        dmap_ptr->second.end_time = rawp->timestamp;
      }
    }
  }
  return 0;
}

bool tcp_packets_analyzer::consume_tcp_ack_delay(tcp_raw_data raw_data[], int head, int tail,
                                                 kindling_event_t_for_go evt[], int* evtlen,
                                                 int max_len) {
  for (int i = head; i != tail; i = (i + 1) % MAX_TCP_BUFFER) {
    if (ifindex_type_map[raw_data[i].tp.ifindex] != CONTAINER_INTERFACE)
      continue;  // only analyze packet from container interface.
    match_tcp_ack_delay(&raw_data[i]);
  }

  int evtcnt = *evtlen;

  for (auto& e : ack_delay_map) {
    // init_tcp_kindling_event(&evt[evtcnt]);
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
    //  printf(
    //     "consume_tcp_ack_delay...sip = %u, dip = %u, sport = %u, dport = %u, data_counts = %d, "
    //     "e.second.acktime_delta = %d, e.second.start_time = %d, e.second.end_time = %d\n",
    //     e.first.saddr, e.first.daddr, e.first.sport, e.first.dport, e.second.data_counts,
    //     e.second.acktime_delta, e.second.start_time, e.second.end_time);

    evt[evtcnt].paramsNumber = userAttNumber;
    evtcnt++;
    if (evtcnt >= max_len) break;
  }
  *evtlen = evtcnt;
  ack_match_queue_map.clear();
  ack_delay_map.clear();
  return true;
}