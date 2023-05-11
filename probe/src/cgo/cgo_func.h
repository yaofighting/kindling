//
// Created by jundi zhou on 2022/6/1.
//

#ifndef SYSDIG_CGO_FUNC_H
#define SYSDIG_CGO_FUNC_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int runForGo();
int getKindlingEvent(void** kindlingEvent);
int getTcpPacketsEvent(void *tcpKindlingEvent, void *count, void *maxlen);
int analyzePodNetTrackEvent();
int getPodTrackEvent(void *tcpKindlingEvent, void *count, void *maxlen);
int initTcpKindlingEventForGo(void **kindlingEvent);
int updateFocusPodInfo(uint32_t src, uint32_t dst, uint64_t begin_time, uint64_t end_time, int op);
void subEventForGo(char* eventName, char* category, void* params);
int startProfile();
int stopProfile();
char* startAttachAgent(int pid);
char* stopAttachAgent(int pid);
void startProfileDebug(int pid, int tid);
void stopProfileDebug();
void getCaptureStatistics();
void catchSignalUp();
#ifdef __cplusplus
}
#endif

#endif  // SYSDIG_CGO_FUNC_H
