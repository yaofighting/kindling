//
// Created by jundi zhou on 2022/6/1.
//

#ifndef SYSDIG_CGO_FUNC_H
#define SYSDIG_CGO_FUNC_H
#include "kindling.h"
#ifdef __cplusplus
extern "C" {
#endif
void runForGo();
int getKindlingEvent(void **kindlingEvent);
int getPageFaultInitEvent(void **kindlingEvent);
int getSlowSyscallTimeoutEvent(void **kindlingEvent);
void subEventForGo(char* eventName, char* category, void *params);
#ifdef __cplusplus
}
#endif

#endif //SYSDIG_CGO_FUNC_H
