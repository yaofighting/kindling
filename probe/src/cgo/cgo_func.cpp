//
// Created by jundi zhou on 2022/6/1.
//

#include "cgo_func.h"
#include "kindling.h"


void runForGo(){
	init_probe();
}

int getKindlingEvent(void **kindlingEvent){
	return getEvent(kindlingEvent);
}

int getPageFaultInitEvent(void **kindlingEvent){
	return getPageFaultThreadEvent(kindlingEvent);
}

int getSlowSyscallTimeoutEvent(void **kindlingEvent){
	return getSyscallTimeoutEvent(kindlingEvent);
}

void subEventForGo(char* eventName, char* category, void *params){
	sub_event(eventName, category, (event_params_for_subscribe *)params);
}

