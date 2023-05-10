//
// Created by jundi zhou on 2022/6/1.
//

#include "cgo_func.h"
#include "kindling.h"
#include "catch_sig.h"

int runForGo() { return init_probe(); }

int getKindlingEvent(void* kindlingEvent, void *count, void *maxlen) { return getEvent((kindling_event_t_for_go*)kindlingEvent, (int *)count, (int*)maxlen); }
// int getTcpPacketsEvent(void *tcpKindlingEvent, void *count) {
//   return get_tcp_packets_event(tcpKindlingEvent, count);
// }

//int getExceptionNetEvent(void *tcpKindlingEvent, void *count) {
//  return get_exception_net_event(tcpKindlingEvent, count);
//}
//int analyzePacketsEvent() { return analyze_packets_event(); }

// int analyzePodNetTrackEvent() { return analyze_pod_net_track_event();}
// int getPodTrackEvent(void *tcpKindlingEvent, void *count) {
//   return get_pod_track_event(tcpKindlingEvent, count);
// }
int updateFocusPodInfo(uint32_t src, uint32_t dst, uint64_t begin_time, uint64_t end_time, int op){
  return update_focus_pod_info(src, dst, begin_time, end_time, op);
}

int initKindlingEventForGo(int number, void *kindlingEvent){
  init_kindling_event_for_go(number, kindlingEvent);
}

int startProfile() { return start_profile(); }
int stopProfile() { return stop_profile(); }

char* startAttachAgent(int pid) { return start_attach_agent(pid); }
char* stopAttachAgent(int pid) { return stop_attach_agent(pid); }

void subEventForGo(char* eventName, char* category, void *params) { sub_event(eventName, category, (event_params_for_subscribe *)params); }
void startProfileDebug(int pid, int tid) { start_profile_debug(pid, tid); }

void stopProfileDebug() { stop_profile_debug(); }

void getCaptureStatistics() { get_capture_statistics(); }
void catchSignalUp() { sig_set_up(); }