//
// Created by siyao zhou on 2022/7/21.
//
#ifndef SYSDIG_SLOW_SYSCALL
#define SYSDIG_SLOW_SYSCALL
#include "sinsp.h"
#include <chrono>

struct SyscallElem{
    uint64_t timestamp;
    uint16_t type;
    int pid;
};

enum{
    NOT_SLOW_SYSCALL = 0,
    IS_SLOW_SYSCALL = 1,
    IS_SYSCALL_TIMEOUT = 2
};

class slow_syscall{
    public:
        slow_syscall(){
            iter_flag = false;
        }
        inline bool getTidExist(int tid, std::mutex *mtx){
            std::lock_guard<std::mutex> guard(*mtx);
            return syscall_map.find(tid) != syscall_map.end();
        }
        inline SyscallElem &getElem(int tid, std::mutex *mtx){
            std::lock_guard<std::mutex> guard(*mtx);
            return syscall_map[tid];
        }
        inline void erase(int tid, std::mutex *mtx){
            std::lock_guard<std::mutex> guard(*mtx);
            syscall_map.erase(tid);
        }
        inline void insert(int tid, SyscallElem s, std::mutex *mtx){
            std::lock_guard<std::mutex> guard(*mtx);
            syscall_map[tid] = s;
        }
        inline void setLatency(uint64_t latency){
            this->m_latency = latency;
        }
        inline void setTimeout(uint64_t timeout){
            this->m_timeout = timeout;
        }
        inline uint64_t getLatency(){
            return m_latency;
        }
        inline uint64_t getTimeout(){
            return m_timeout;
        }
        void subSyscall(sinsp *inspector, map<string, ppm_event_type> &m_events);
        void getSlowSyscallTimeoutEvent(std::mutex * mtx);

        vector<int> m_timeout_list;
        vector<SyscallElem> m_timeout_elems;
        bool iter_flag;
        
    private:
        int m_latency;
        int m_timeout;
        unordered_map<int, SyscallElem> syscall_map;
};

#endif