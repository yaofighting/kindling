//
// Created by jundi zhou on 2022/6/1.
//

#ifndef SYSDIG_CGO_FUNC_H
#define SYSDIG_CGO_FUNC_H

#ifdef __cplusplus
extern "C" {
#endif
void runForGo();
int getKindlingEvent(void **kindlingEvent);
int getPageFaultInitEvent(void **kindlingEvent);
int subEventForGo(char* eventName, char* category, int params[]);
#ifdef __cplusplus
}

#endif

#endif //SYSDIG_CGO_FUNC_H

struct kindling_event_t_for_go{
	uint64_t timestamp;
	char *name;
	uint32_t category;
	uint16_t paramsNumber;
    struct KeyValue {
	char *key;
	char* value;
	uint32_t len;
	uint32_t valueType;
    }userAttributes[8];
    struct event_context {
        struct thread_info {
            uint32_t pid;
            uint32_t tid;
            uint32_t uid;
            uint32_t gid;
            char *comm;
            char *containerId;
        }tinfo;
        struct fd_info {
            int32_t num;
            uint32_t fdType;
            char *filename;
            char *directory;
            uint32_t protocol;
            uint8_t role;
            uint32_t sip;
            uint32_t dip;
            uint32_t sport;
            uint32_t dport;

            uint64_t source;
            uint64_t destination;
        }fdInfo;
    }context;
};
